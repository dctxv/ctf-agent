"""Trial runners: provision an isolated environment, run the agent, verify.

The Runner interface is the one seam a future DistributedRunner slots into. Two
implementations ship now:

- StubRunner: no Docker, no API. A caller-supplied `populate` writes evidence
  into the trial workspace; used to test the controller/store/verify pipeline.
- LocalDockerRunner: per-trial container + workspace + egress firewall + hard
  wall-clock budget, running the real agent in a subprocess. All side-effecting
  steps (provision/teardown/firewall/agent) are injected callables with real
  defaults, so the orchestration is testable with fakes.

Per-trial isolation note: independent targets (code audits, generated
challenges) parallelize cleanly. A single shared live target such as one Juice
Shop instance must be run sequentially with a reset between trials - the
controller worker limit and the runner's reset hook handle that.
"""
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from eval import registry
from eval import verify as verifier
from eval.taxonomy import Outcome, FailureReason

ROOT = Path(__file__).resolve().parent.parent


class InfraError(Exception):
    """Raised for environment/runner faults - retried, never charged to the agent."""


# ---------------- provenance ----------------

def git_sha():
    try:
        r = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=10, cwd=str(ROOT))
        return r.stdout.strip() or "nogit"
    except Exception:
        return "nogit"


def prompt_version():
    try:
        h = hashlib.sha1((ROOT / "agent" / "agent.py").read_bytes()).hexdigest()
        return h[:8]
    except Exception:
        return "unknown"


def image_digest(image, docker="docker"):
    try:
        r = subprocess.run([docker, "image", "inspect", "-f", "{{.Id}}", image],
                           capture_output=True, text=True, timeout=15)
        return (r.stdout.strip() or "unknown")[:19]
    except Exception:
        return "unknown"


def _result(manifest, *, run_index, experiment_id, config, outcome, reason, detail,
            metrics=None, workspace="", container="", env_digest="unknown", model=""):
    m = metrics or {}
    return {
        "experiment_id": experiment_id,
        "challenge_id": manifest["id"],
        "challenge_version": manifest["version"],
        "dataset": manifest["dataset"],
        "tier": manifest["tier"],
        "category": manifest["category"],
        "config_name": config.get("name", "default"),
        "run_index": run_index,
        "outcome": outcome.value if isinstance(outcome, Outcome) else outcome,
        "failure_reason": (reason.value if isinstance(reason, FailureReason) else reason) or "",
        "detail": detail,
        "steps": m.get("steps", 0),
        "cost_usd": m.get("cost_usd", 0.0),
        "tokens_in": m.get("tokens_in", 0),
        "tokens_out": m.get("tokens_out", 0),
        "duration_s": m.get("duration_s", 0),
        "escalations": m.get("escalations", 0),
        "ask_human": m.get("ask_human", 0),
        "budget_hits": m.get("budget_hits", 0),
        "finished_naturally": m.get("finished_naturally", False),
        "agent_commit": git_sha(),
        "model": model or config.get("model", ""),
        "model_config": config,
        "policy": config.get("policy", "loop-escalate"),
        "prompt_version": prompt_version(),
        "env_digest": env_digest,
        "memory_snapshot": config.get("memory", "none"),
        "verifier_version": verifier.VERIFIER_VERSION,
        "container": container,
        "workspace": workspace,
    }


def _slug(*parts):
    return re.sub(r'[^a-z0-9]+', '-', "-".join(str(p) for p in parts).lower()).strip('-')


def _provider_fault_guard(metrics, outcome, reason, detail):
    """Reclassify a 'failure' where the model was never successfully called as an
    INFRA_ERROR so it is excluded from solve-rate denominators.

    A provider outage (rate limit, auth, network) can let the agent loop exit with
    zero tokens and zero cost; verification then finds no flag and scores it a
    verified_failure, silently deflating the model's score. A genuine agent run
    always costs something, and even a refusal consumes input tokens, so keying on
    (no tokens AND no cost) never swallows a real result. Successes are left alone.
    """
    if outcome == Outcome.VERIFIED_SUCCESS:
        return outcome, reason, detail

    def num(k):
        try:
            return float((metrics or {}).get(k, 0) or 0)
        except (TypeError, ValueError):
            return 0.0

    made_call = num("cost_usd") > 0 or num("tokens_in") > 0 or num("tokens_out") > 0
    if not made_call:
        return (Outcome.INFRA_ERROR, FailureReason.INFRASTRUCTURE,
                f"no successful model call (0 tokens, $0.00) - provider/infra fault; {detail}")
    return outcome, reason, detail


class Runner:
    def run_trial(self, manifest, *, run_index, experiment_id, config):
        raise NotImplementedError


class StubRunner(Runner):
    """Offline runner for testing the pipeline. `populate(ws, manifest)` writes
    evidence (or raises InfraError / any Exception to simulate faults)."""

    def __init__(self, populate, workspace_root=None):
        self.populate = populate
        self.workspace_root = Path(workspace_root or tempfile.mkdtemp(prefix="evalstub-"))

    def run_trial(self, manifest, *, run_index, experiment_id, config):
        ws = self.workspace_root / _slug(experiment_id, manifest["id"], f"r{run_index}")
        (ws / "evidence").mkdir(parents=True, exist_ok=True)
        t0 = time.time()
        try:
            self.populate(ws, manifest)
        except InfraError as e:
            return _result(manifest, run_index=run_index, experiment_id=experiment_id,
                           config=config, outcome=Outcome.INFRA_ERROR,
                           reason=FailureReason.INFRASTRUCTURE, detail=str(e)[:200],
                           workspace=str(ws))
        except Exception as e:
            return _result(manifest, run_index=run_index, experiment_id=experiment_id,
                           config=config, outcome=Outcome.AGENT_ERROR,
                           reason=FailureReason.MODEL_REASONING, detail=str(e)[:200],
                           workspace=str(ws))
        outcome, reason, detail = verifier.verify(manifest["verifier"], ws)
        return _result(manifest, run_index=run_index, experiment_id=experiment_id,
                       config=config, outcome=outcome, reason=reason, detail=detail,
                       metrics={"duration_s": round(time.time() - t0, 2)}, workspace=str(ws))


# ---------------- default side-effecting steps for LocalDockerRunner ----------------

def _default_provision(cname, ws_host, image, docker, ttl):
    subprocess.run([docker, "rm", "-f", cname], capture_output=True, text=True)
    r = subprocess.run(
        [docker, "run", "-d", "--rm", "--cap-add=NET_ADMIN",
         "-v", f"{Path(ws_host).resolve()}:/workspace",
         "--name", cname, image, "sleep", str(ttl)],
        capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise InfraError(f"provision failed: {(r.stderr or '').strip()[:160]}")


def _default_teardown(cname, docker):
    subprocess.run([docker, "rm", "-f", cname], capture_output=True, text=True)


def _default_agent_runner(eng, config, manifest, run_index, ws_host, container, docker, timeout_s):
    """Run the real agent in a subprocess (spends API). Returns a metrics dict."""
    import os
    metrics_out = Path(ws_host) / "_trial_metrics.json"
    eng_path = Path(ws_host) / "_engagement.json"
    eng_path.write_text(json.dumps(eng), encoding="utf-8")
    env = dict(os.environ)
    env["WORKSPACE_HOST"] = str(Path(ws_host).resolve())
    env["AGENT_CONTAINER"] = container
    try:
        subprocess.run(
            ["python", "-m", "eval._trial_entry", str(eng_path), str(metrics_out)],
            cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        raise InfraError(f"trial exceeded wall-clock budget {timeout_s}s")
    if metrics_out.exists():
        try:
            return json.loads(metrics_out.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _default_raw_runner(eng, ws_host):
    """No-tools baseline: hand the model the raw file contents in a single call and
    take its answer. No container, no tool loop - shows where tool use is essential."""
    from agent.llm import LLMClient
    ws = Path(ws_host)
    skip = {"_engagement.json", "_trial_metrics.json"}
    blobs = []
    for p in sorted(ws.iterdir()):
        if p.is_file() and p.name not in skip:
            try:
                blobs.append(f"=== {p.name} ===\n" + p.read_bytes()[:6000].decode("latin-1"))
            except Exception:
                pass
    prompt = (eng.get("goal", "") +
              "\n\nYou have NO tools and cannot run code. Using ONLY the file contents below, "
              "work out the answer and reply with ONLY the FLAG{...} value.\n\n" + "\n\n".join(blobs))
    llm = LLMClient()
    resp = llm.complete(messages=[{"role": "user", "content": prompt}], role="loop", temperature=0.0)
    ans = resp.choices[0].message.content or ""
    ev = ws / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    (ev / "flag.txt").write_text(ans, encoding="utf-8")
    return {"steps": 1, "cost_usd": round(llm.cost_usd, 4),
            "technique": "raw-model (no tools)", "finished_naturally": True}


class LocalDockerRunner(Runner):
    def __init__(self, image="pentest-tools:latest", workspace_root="workspace/eval",
                 reset_fn=None, firewall=True, docker="docker", ttl=1800,
                 wall_clock_s=1200, provision=None, teardown=None,
                 apply_firewall=None, agent_runner=None, raw_runner=None):
        self.image = image
        self.workspace_root = Path(workspace_root)
        self.reset_fn = reset_fn
        self.firewall = firewall
        self.docker = docker
        self.ttl = ttl
        self.wall_clock_s = wall_clock_s
        self._provision = provision or _default_provision
        self._teardown = teardown or _default_teardown
        self._agent_runner = agent_runner or _default_agent_runner
        self._raw_runner = raw_runner or _default_raw_runner
        if apply_firewall is not None:
            self._apply_firewall = apply_firewall
        else:
            from agent import net
            self._apply_firewall = lambda c, hosts: net.apply_egress_firewall(c, hosts, docker=self.docker)

    def run_trial(self, manifest, *, run_index, experiment_id, config):
        slug = _slug(experiment_id, manifest["id"], f"r{run_index}")
        cname = f"evalbox-{slug}"[:60]
        ws_host = self.workspace_root / slug
        if ws_host.exists():
            shutil.rmtree(ws_host, ignore_errors=True)
        (ws_host / "evidence").mkdir(parents=True, exist_ok=True)

        # generated challenge (randomized, key kept host-side) vs static challenge file
        if manifest.get("generator"):
            from eval.generators import get_generator
            gen = get_generator(manifest["generator"]["name"])
            res = gen.generate(ws_host, f"{experiment_id}:{manifest['id']}:r{run_index}",
                               spec=manifest["generator"])
            eng = dict(res["engagement"])
            kdir = ROOT / "eval" / "keys"
            kdir.mkdir(parents=True, exist_ok=True)
            (kdir / f"{slug}.json").write_text(
                json.dumps({"challenge": manifest["id"], "run": run_index, "key": res["key"]}),
                encoding="utf-8")   # host-side only, never mounted into the container
            verifier_spec = {**manifest["verifier"], "_expected": res["key"]}
        else:
            eng = dict(registry.load_engagement(manifest))
            verifier_spec = manifest["verifier"]

        eng["workspace"] = str(ws_host)
        eng["container"] = cname
        eng["_mode"] = config.get("mode", "agent")
        for k in ("max_steps", "max_cost_usd", "loop_model", "escalate_model", "escalate_after"):
            if k in config:
                eng[k] = config[k]

        # experience memory (opt-in via config["memory"]). Retrieve relevant past
        # lessons and inject them into the goal; the authoritative outcome is
        # recorded after verification. Memory is host-side, never in the container.
        base_goal = eng.get("goal", "")
        mem = None
        if str(config.get("memory", "off")).lower() in ("on", "true", "1"):
            from agent.memory import MemoryStore
            ns = config.get("memory_namespace") or experiment_id
            mem = MemoryStore(ROOT / "eval" / "memory" / f"{ns}.jsonl", namespace=ns)
            hints = mem.format_hints(
                mem.retrieve(goal=base_goal, category=manifest.get("category", "")))
            if hints:
                eng["goal"] = base_goal + \
                    "\n\nPrior experience (from past engagements; may not apply):\n" + hints

        env_digest = image_digest(self.image, self.docker)
        t0 = time.time()

        # no-tools baseline: single model call, no container, no tool loop
        if str(config.get("mode", "agent")) == "raw-model":
            try:
                metrics = self._raw_runner(eng, ws_host) or {}
            except Exception as e:
                return _result(manifest, run_index=run_index, experiment_id=experiment_id,
                               config=config, outcome=Outcome.AGENT_ERROR,
                               reason=FailureReason.MODEL_REASONING, detail=str(e)[:200],
                               metrics={"duration_s": round(time.time() - t0, 2)},
                               workspace=str(ws_host), env_digest=env_digest,
                               model=config.get("model", ""))
            metrics.setdefault("duration_s", round(time.time() - t0, 2))
            outcome, reason, detail = verifier.verify(verifier_spec, ws_host)
            if metrics.get("refusals") and outcome != Outcome.VERIFIED_SUCCESS:
                reason = FailureReason.POLICY
                detail = f"{metrics['refusals']} policy refusal(s); {detail}"
            outcome, reason, detail = _provider_fault_guard(metrics, outcome, reason, detail)
            if mem is not None:
                mem.record(category=manifest.get("category", ""),
                           outcome="solved" if outcome == Outcome.VERIFIED_SUCCESS else "failed",
                           technique=metrics.get("technique", ""), goal=base_goal)
            return _result(manifest, run_index=run_index, experiment_id=experiment_id,
                           config=config, outcome=outcome, reason=reason, detail=detail,
                           metrics=metrics, workspace=str(ws_host), container="(raw-model)",
                           env_digest=env_digest, model=config.get("model", ""))

        try:
            self._provision(cname, ws_host, self.image, self.docker, self.ttl)
            if self.firewall:
                self._apply_firewall(cname, eng.get("allowed_hosts", []))
            if self.reset_fn:
                self.reset_fn()
            metrics = self._agent_runner(eng, config, manifest, run_index, ws_host,
                                         cname, self.docker, self.wall_clock_s) or {}
            metrics.setdefault("duration_s", round(time.time() - t0, 2))
            outcome, reason, detail = verifier.verify(verifier_spec, ws_host)
            if metrics.get("refusals") and outcome != Outcome.VERIFIED_SUCCESS:
                reason = FailureReason.POLICY
                detail = f"{metrics['refusals']} policy refusal(s); {detail}"
            outcome, reason, detail = _provider_fault_guard(metrics, outcome, reason, detail)
            if mem is not None:
                mem.record(category=manifest.get("category", ""),
                           outcome="solved" if outcome == Outcome.VERIFIED_SUCCESS else "failed",
                           technique=metrics.get("technique", ""), goal=base_goal)
            return _result(manifest, run_index=run_index, experiment_id=experiment_id,
                           config=config, outcome=outcome, reason=reason, detail=detail,
                           metrics=metrics, workspace=str(ws_host), container=cname,
                           env_digest=env_digest, model=config.get("model", ""))
        except InfraError as e:
            return _result(manifest, run_index=run_index, experiment_id=experiment_id,
                           config=config, outcome=Outcome.INFRA_ERROR,
                           reason=FailureReason.INFRASTRUCTURE, detail=str(e)[:200],
                           metrics={"duration_s": round(time.time() - t0, 2)},
                           workspace=str(ws_host), container=cname, env_digest=env_digest)
        except Exception as e:
            return _result(manifest, run_index=run_index, experiment_id=experiment_id,
                           config=config, outcome=Outcome.AGENT_ERROR,
                           reason=FailureReason.ORCHESTRATION, detail=str(e)[:200],
                           metrics={"duration_s": round(time.time() - t0, 2)},
                           workspace=str(ws_host), container=cname, env_digest=env_digest)
        finally:
            self._teardown(cname, self.docker)
