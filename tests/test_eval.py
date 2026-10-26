"""Tier A - evaluation subsystem tests (offline, no Docker, no API).

Run from the repo root:  python -m unittest tests.test_eval -v
"""
import base64
import json
import tempfile
import unittest
from pathlib import Path

from eval import registry, verify, controller
from eval import store as store_mod
from eval.runner import StubRunner, LocalDockerRunner, InfraError, Runner


def _write(ws, rel, text):
    p = Path(ws) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


class TestRegistry(unittest.TestCase):
    def test_loads_all(self):
        ms = registry.load_manifests()
        self.assertEqual(len(ms), 15)  # 10 Juice Shop + 3 generated + 2 hard generated

    def test_ids_unique_and_challenges_exist(self):
        ms = registry.load_manifests()
        self.assertEqual(len(ms), len({m["id"] for m in ms}))
        for m in ms:
            self.assertIn("path", m["verifier"])

    def test_select(self):
        ms = registry.load_manifests()
        self.assertTrue(all(m["tier"] == "B" for m in registry.select(ms, tiers={"B"})))
        self.assertEqual(len(registry.select(ms, ids={"c01-version-leak"})), 1)

    def test_validate_rejects_missing_field(self):
        with self.assertRaises(ValueError):
            registry._validate({"id": "x"}, "inline")

    def test_validate_rejects_bad_tier(self):
        base = registry.load_manifests()[0].copy()
        base["tier"] = "Z"
        with self.assertRaises(ValueError):
            registry._validate(base, "inline")


class TestVerify(unittest.TestCase):
    def setUp(self):
        self.ws = tempfile.mkdtemp()

    def test_missing_evidence_fails(self):
        oc, reason, _ = verify.verify({"path": "evidence/none.txt"}, self.ws)
        self.assertEqual(oc.value, "verified_failure")

    def test_contains(self):
        _write(self.ws, "evidence/a.txt", "the score-board is at /x")
        oc, _, _ = verify.verify({"path": "evidence/a.txt", "contains": "score-board"}, self.ws)
        self.assertEqual(oc.value, "verified_success")

    def test_matches(self):
        _write(self.ws, "evidence/v.txt", "version 15.3.0")
        oc, _, _ = verify.verify({"path": "evidence/v.txt", "matches": r"\d+\.\d+\.\d+"}, self.ws)
        self.assertEqual(oc.value, "verified_success")

    def test_min_count(self):
        _write(self.ws, "evidence/u.txt", "a@juice-sh.op b@juice-sh.op c@juice-sh.op")
        oc, _, _ = verify.verify(
            {"path": "evidence/u.txt", "min_count": {"substr": "@juice-sh.op", "n": 3}}, self.ws)
        self.assertEqual(oc.value, "verified_success")

    def test_jwt_contains(self):
        payload = base64.urlsafe_b64encode(
            json.dumps({"email": "admin@juice-sh.op"}).encode()).decode().rstrip("=")
        _write(self.ws, "evidence/t.txt", "eyJhbGciOiJIUzI1NiJ9." + payload + ".sig")
        oc, _, _ = verify.verify(
            {"path": "evidence/t.txt", "type": "jwt_contains", "value": "admin@juice-sh.op"}, self.ws)
        self.assertEqual(oc.value, "verified_success")

    def test_jwt_wrong_user_fails(self):
        payload = base64.urlsafe_b64encode(
            json.dumps({"email": "nobody@x"}).encode()).decode().rstrip("=")
        _write(self.ws, "evidence/t.txt", "eyJhbGciOiJIUzI1NiJ9." + payload + ".sig")
        oc, _, _ = verify.verify(
            {"path": "evidence/t.txt", "type": "jwt_contains", "value": "admin@juice-sh.op"}, self.ws)
        self.assertEqual(oc.value, "verified_failure")

    def test_failure_phrase_rejected(self):
        _write(self.ws, "evidence/f.txt", "I could not crack the database.")
        oc, _, _ = verify.verify({"path": "evidence/f.txt", "reject_failure_phrases": True}, self.ws)
        self.assertEqual(oc.value, "verified_failure")


class TestStore(unittest.TestCase):
    def test_roundtrip_and_export(self):
        d = tempfile.mkdtemp()
        s = store_mod.Store(Path(d) / "r.sqlite")
        s.record({"experiment_id": "e", "config_name": "flash", "challenge_id": "c01",
                  "run_index": 1, "outcome": "verified_success", "cost_usd": 0.01,
                  "finished_naturally": True, "agent_commit": "abc"})
        self.assertIn(("flash", "c01", "1"), s.completed("e"))
        csvp = s.export_csv(Path(d) / "out.csv", "e")
        head = Path(csvp).read_text().splitlines()[0]
        self.assertTrue(head.startswith("timestamp_utc,git_sha,model,challenge"))
        s.close()

    def test_infra_error_not_marked_complete(self):
        d = tempfile.mkdtemp()
        s = store_mod.Store(Path(d) / "r.sqlite")
        s.record({"experiment_id": "e", "config_name": "flash", "challenge_id": "c01",
                  "run_index": 1, "outcome": "infra_error"})
        self.assertNotIn(("flash", "c01", "1"), s.completed("e"))
        s.close()


class _FakeRunner(Runner):
    """Returns controlled outcomes/costs without touching disk."""
    def __init__(self, cost=0.05, outcome="verified_success"):
        self.cost = cost
        self.outcome = outcome
        self.n = 0

    def run_trial(self, manifest, *, run_index, experiment_id, config):
        self.n += 1
        return {"experiment_id": experiment_id, "config_name": config["name"],
                "challenge_id": manifest["id"], "run_index": run_index,
                "outcome": self.outcome, "cost_usd": self.cost, "detail": "fake"}


class TestController(unittest.TestCase):
    def setUp(self):
        self.ms = registry.select(registry.load_manifests(), ids={"c01-version-leak", "c03-sqli-admin"})
        self.cfg = {"name": "flash"}
        self.d = tempfile.mkdtemp()

    def _store(self):
        return store_mod.Store(Path(self.d) / "r.sqlite")

    def test_matrix_and_record(self):
        st = self._store()
        r = _FakeRunner()
        summ = controller.run_experiment(experiment_id="e1", manifests=self.ms,
            configs=[self.cfg], runner=r, runs=2, store=st,
            export_csv=str(Path(self.d) / "o.csv"))
        self.assertEqual(summ["ran"], 4)  # 2 challenges x 2 runs
        st.close()

    def test_resume_skips(self):
        st = self._store()
        controller.run_experiment(experiment_id="e2", manifests=self.ms, configs=[self.cfg],
            runner=_FakeRunner(), runs=1, store=st, export_csv=None)
        summ = controller.run_experiment(experiment_id="e2", manifests=self.ms, configs=[self.cfg],
            runner=_FakeRunner(), runs=1, store=st, export_csv=None)
        self.assertEqual(summ["ran"], 0)
        self.assertEqual(summ["skipped"], 2)
        st.close()

    def test_cost_cap(self):
        st = self._store()
        summ = controller.run_experiment(experiment_id="e3", manifests=self.ms, configs=[self.cfg],
            runner=_FakeRunner(cost=0.05), runs=3, store=st, global_cost_cap=0.07,
            randomize=False, export_csv=None)
        self.assertTrue(summ["cost_cap_hit"])
        self.assertLessEqual(summ["ran"], 2)  # stops once >= 0.07 spent
        st.close()

    def test_campaign_cap_stops_across_the_run(self):
        from pathlib import Path
        from eval.campaign import Campaign
        st = self._store()
        camp = Campaign(Path(self.d) / "camp.json", cap_usd=0.08)
        summ = controller.run_experiment(experiment_id="ecamp", manifests=self.ms, configs=[self.cfg],
            runner=_FakeRunner(cost=0.05), runs=3, store=st, campaign=camp,
            randomize=False, export_csv=None)
        self.assertTrue(summ["campaign_cap_hit"])
        self.assertLessEqual(summ["ran"], 2)      # halts once the ledger hits the cap
        self.assertGreaterEqual(camp.spent(), 0.08)
        st.close()


class TestStubRunnerPipeline(unittest.TestCase):
    def test_pass_fail_infra(self):
        ms = registry.select(registry.load_manifests(),
                             ids={"c01-version-leak", "c04-find-scoreboard", "c02-ftp-bypass"})

        def populate(ws, m):
            if m["id"] == "c01-version-leak":
                _write(ws, "evidence/c1_version.txt", "version 15.3.0 at /rest")
            elif m["id"] == "c04-find-scoreboard":
                _write(ws, "evidence/c4_scoreboard_url.txt", "nope")  # missing 'score-board'
            else:
                raise InfraError("docker gone")

        runner = StubRunner(populate)
        out = {m["id"]: runner.run_trial(m, run_index=1, experiment_id="e", config={"name": "x"})
               for m in ms}
        self.assertEqual(out["c01-version-leak"]["outcome"], "verified_success")
        self.assertEqual(out["c04-find-scoreboard"]["outcome"], "verified_failure")
        self.assertEqual(out["c02-ftp-bypass"]["outcome"], "infra_error")


class TestLocalDockerRunnerOrchestration(unittest.TestCase):
    """All side effects injected - exercises provision/firewall/verify/teardown
    without Docker or API."""
    def _manifest(self):
        return registry.select(registry.load_manifests(), ids={"c01-version-leak"})[0]

    def test_success_path_calls_all_steps(self):
        calls = []
        tmp = tempfile.mkdtemp()

        def prov(c, ws, img, dk, ttl):
            calls.append("prov")

        def tear(c, dk):
            calls.append("tear")

        def fw(c, hosts):
            calls.append("fw")

        def agent(eng, cfg, m, ri, ws, c, dk, to):
            _write(ws, "evidence/c1_version.txt", "found 15.3.0 at /rest/admin")
            return {"steps": 5, "cost_usd": 0.01, "finished_naturally": True}

        r = LocalDockerRunner(workspace_root=tmp, provision=prov, teardown=tear,
                              apply_firewall=fw, agent_runner=agent, firewall=True)
        res = r.run_trial(self._manifest(), run_index=1, experiment_id="e",
                          config={"name": "flash", "model": "deepseek-flash"})
        self.assertEqual(res["outcome"], "verified_success")
        self.assertEqual(calls, ["prov", "fw", "tear"])
        self.assertTrue(res["container"].startswith("evalbox-"))
        self.assertEqual(res["model"], "deepseek-flash")
        self.assertNotEqual(res["prompt_version"], "")
        self.assertEqual(res["verifier_version"], verify.VERIFIER_VERSION)

    def test_provision_infra_error_still_tears_down(self):
        calls = []
        tmp = tempfile.mkdtemp()

        def prov(c, ws, img, dk, ttl):
            raise InfraError("no docker")

        def tear(c, dk):
            calls.append("tear")

        r = LocalDockerRunner(workspace_root=tmp, provision=prov, teardown=tear,
                              apply_firewall=lambda c, h: None,
                              agent_runner=lambda *a: {}, firewall=True)
        res = r.run_trial(self._manifest(), run_index=1, experiment_id="e",
                          config={"name": "flash"})
        self.assertEqual(res["outcome"], "infra_error")
        self.assertIn("tear", calls)


class TestNYUStagingGuard(unittest.TestCase):
    """A NYU challenge whose listed handout is missing/empty in git must raise
    InfraError at stage time (so it scores as infra, not an agent failure),
    while a challenge whose files stage non-empty proceeds normally."""
    def _gen(self, files_map, flag="flag{t}"):
        from eval.generators import nyu
        orig = nyu._show

        def fake(path):
            if path.endswith("challenge.json"):
                return json.dumps({"category": "misc", "description": "x",
                                   "flag": flag, "files": list(files_map)}).encode()
            name = path.split("/")[-1]
            return files_map.get(name, b"")
        nyu._show = fake
        try:
            return nyu.generate(tempfile.mkdtemp(), "seed", spec={"dir": "test/x"})
        finally:
            nyu._show = orig

    def test_empty_listed_file_raises_infra(self):
        from eval.runner import InfraError
        with self.assertRaises(InfraError):
            self._gen({"payload.bin": b""})        # listed but empty in git

    def test_present_files_stage_ok(self):
        res = self._gen({"payload.bin": b"data"})  # non-empty -> normal
        self.assertEqual(res["key"], "flag{t}")

    def test_flag_format_hint_uses_real_wrapper(self):
        # the goal must tell the agent the challenge's real flag wrapper, not a hardcoded one
        res = self._gen({"payload.bin": b"data"}, flag="csawctf{abc}")
        self.assertIn("csawctf{...}", res["engagement"]["goal"])
        self.assertNotIn("flag{...}", res["engagement"]["goal"])


class TestNYUImportRules(unittest.TestCase):
    """Import-time exclusion rules: service (remote flag) and synthetic flags."""
    def test_is_service(self):
        import run_import_nyu as imp
        self.assertTrue(imp._is_service({"box": "pwn.chal.csaw.io"}, "pwn"))
        self.assertTrue(imp._is_service({"box": "x", "internal_port": 2000}, "crypto"))
        self.assertTrue(imp._is_service({"box": "x", "description": "nc host 1234"}, "crypto"))
        # a crypto/rev challenge that merely lists a box but ships the artifact locally stays
        self.assertFalse(imp._is_service({"box": "x", "description": "decrypt this file"}, "crypto"))
        self.assertFalse(imp._is_service({}, "pwn"))   # no remote endpoint at all

    def test_is_synthetic_flag(self):
        import run_import_nyu as imp
        self.assertTrue(imp._is_synthetic_flag("flag{flag_created_in_validation_mission_payload}"))
        self.assertFalse(imp._is_synthetic_flag("flag{a_real_flag}"))


class TestProviderFaultGuard(unittest.TestCase):
    """A 'failure' where the model was never called (0 tokens, $0) is a provider
    outage, not an agent loss, so it is reclassified as infra_error and excluded
    from the solve rate. A real-cost failure is left as a failure."""
    def _manifest(self):
        return registry.select(registry.load_manifests(), ids={"c01-version-leak"})[0]

    def _run(self, metrics):
        tmp = tempfile.mkdtemp()
        r = LocalDockerRunner(workspace_root=tmp, provision=lambda *a: None,
                              teardown=lambda *a: None, apply_firewall=lambda *a: None,
                              agent_runner=lambda *a: dict(metrics), firewall=False)
        return r.run_trial(self._manifest(), run_index=1, experiment_id="e",
                           config={"name": "flash", "model": "deepseek-flash"})

    def test_zero_token_zero_cost_failure_is_infra_error(self):
        # no evidence written -> verifier fails; 0 tokens/0 cost -> provider fault
        res = self._run({"steps": 1, "cost_usd": 0.0, "tokens_in": 0, "tokens_out": 0})
        self.assertEqual(res["outcome"], "infra_error")
        self.assertIn("provider/infra fault", res["detail"])

    def test_real_cost_failure_stays_a_failure(self):
        res = self._run({"steps": 20, "cost_usd": 0.05, "tokens_in": 4000, "tokens_out": 500})
        self.assertEqual(res["outcome"], "verified_failure")


class TestRawModelBaseline(unittest.TestCase):
    """The no-tools baseline path: no container is provisioned, the injected raw
    runner produces the answer, and it is verified like any trial."""
    def test_raw_model_skips_provision(self):
        import json
        from eval.runner import LocalDockerRunner
        tmp = tempfile.mkdtemp()
        calls = []

        def raw(eng, ws):
            slug = Path(ws).name
            key = json.loads((Path("eval/keys") / f"{slug}.json").read_text())["key"]
            (Path(ws) / "evidence").mkdir(parents=True, exist_ok=True)
            (Path(ws) / "evidence" / "flag.txt").write_text(key, encoding="utf-8")
            return {"steps": 1, "cost_usd": 0.004, "technique": "raw"}

        man = registry.select(registry.load_manifests(), ids={"gen-xor-flag"})[0]
        r = LocalDockerRunner(workspace_root=tmp, provision=lambda *a: calls.append("prov"),
                              teardown=lambda *a: calls.append("tear"),
                              apply_firewall=lambda *a: None, raw_runner=raw)
        res = r.run_trial(man, run_index=1, experiment_id="e",
                          config={"name": "raw-model", "mode": "raw-model"})
        self.assertEqual(res["outcome"], "verified_success")
        self.assertEqual(res["container"], "(raw-model)")
        self.assertNotIn("prov", calls)   # no container for the no-tools baseline


class TestProfilePassthrough(unittest.TestCase):
    """Adaptive-scaling knobs in a config reach the engagement the agent runs."""
    def test_knobs_reach_engagement(self):
        from eval.runner import LocalDockerRunner
        seen = {}

        def agent(eng, cfg, m, ri, ws, c, dk, to):
            seen.update(eng)
            (Path(ws) / "evidence").mkdir(parents=True, exist_ok=True)
            (Path(ws) / "evidence" / "c1_version.txt").write_text("v 1.2.3", encoding="utf-8")
            return {"steps": 4, "cost_usd": 0.02}

        man = registry.select(registry.load_manifests(), ids={"c01-version-leak"})[0]
        r = LocalDockerRunner(workspace_root=tempfile.mkdtemp(), provision=lambda *a: None,
                              teardown=lambda *a: None, apply_firewall=lambda *a: None,
                              agent_runner=agent)
        r.run_trial(man, run_index=1, experiment_id="e",
                    config={"name": "maximum", "loop_model": "deepseek-v4-pro",
                            "escalate_after": 1, "max_steps": 40})
        self.assertEqual(seen.get("loop_model"), "deepseek-v4-pro")
        self.assertEqual(seen.get("escalate_after"), 1)
        self.assertEqual(seen.get("max_steps"), 40)


if __name__ == "__main__":
    unittest.main()
