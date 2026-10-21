"""CLI for the evaluation subsystem (the new first-class harness).

Examples:
  python run_experiment.py --tier B --dry-run        # list selected trials, run nothing
  python run_experiment.py --tier B --runs 3         # real agent trials (spends API)
  python run_experiment.py --ids c03-sqli-admin

The legacy run_eval.py still works unchanged; this drives the new eval/ package
(versioned manifests, independent verifiers, structured store, isolated runner).
Juice Shop is a single shared target, so trials run sequentially with a reset
between them.
"""
import argparse
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from dotenv import load_dotenv

from eval import controller, registry
from eval.runner import LocalDockerRunner


def main():
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("--experiment", default="juiceshop-dev")
    ap.add_argument("--tier", action="append", help="filter by tier (repeatable)")
    ap.add_argument("--dataset", action="append", help="filter by dataset (repeatable)")
    ap.add_argument("--ids", nargs="*", help="explicit challenge ids")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--cost-cap", type=float, default=2.0, help="global USD cap for the run")
    ap.add_argument("--image", default="pentest-tools:latest")
    ap.add_argument("--no-firewall", action="store_true")
    ap.add_argument("--no-reset", action="store_true")
    ap.add_argument("--no-resume", action="store_true")
    ap.add_argument("--memory", action="store_true", help="enable experience memory (namespaced to the experiment)")
    ap.add_argument("--memory-namespace", default=None,
                    help="share a memory namespace across experiments (for cold->warm cycles)")
    ap.add_argument("--baselines", action="store_true",
                    help="run no-tools raw-model + single-step baselines alongside the full agent")
    ap.add_argument("--profiles", action="store_true",
                    help="run Economy/Balanced/Maximum adaptive-scaling profiles")
    ap.add_argument("--multiagent", action="store_true",
                    help="A/B the single agent against the supervisor+specialist multi-agent")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    ms = registry.load_manifests()
    sel = registry.select(ms,
                          tiers=set(a.tier) if a.tier else None,
                          datasets=set(a.dataset) if a.dataset else None,
                          ids=set(a.ids) if a.ids else None)
    if not sel:
        print("no manifests match the selection.")
        return
    print(f"[experiment {a.experiment}] {len(sel)} challenge(s) x {a.runs} run(s):")
    for m in sel:
        print(f"  - {m['id']}  (tier {m['tier']}, {m['dataset']}, {m['category']})")
    if a.dry_run:
        print("dry-run: nothing executed.")
        return

    reset = None
    if not a.no_reset:
        try:
            from run_eval import reset_juice
            reset = reset_juice
        except Exception as e:
            print(f"(no juice reset available: {e})")

    runner = LocalDockerRunner(image=a.image, firewall=not a.no_firewall, reset_fn=reset)
    cfg = {"name": "flash-baseline", "model": "deepseek-flash", "policy": "loop-escalate"}
    if a.memory:
        cfg["name"] = "flash-memory"
        cfg["memory"] = "on"
        cfg["memory_namespace"] = a.memory_namespace or a.experiment
    configs = [cfg]
    if a.baselines:
        configs = [
            {"name": "agent-full", "model": "deepseek-flash", "policy": "loop-escalate"},
            {"name": "agent-1step", "model": "deepseek-flash", "max_steps": 1},
            {"name": "raw-model", "model": "deepseek-flash", "mode": "raw-model"},
        ]
    if a.profiles:
        configs = [
            {"name": "economy", "model": "deepseek-flash", "loop_model": "deepseek-flash",
             "escalate_after": 999, "max_steps": 12, "max_cost_usd": 0.3},
            {"name": "balanced", "model": "deepseek-flash", "loop_model": "deepseek-flash",
             "escalate_model": "deepseek-v4-pro", "escalate_after": 2, "max_steps": 25, "max_cost_usd": 0.5},
            {"name": "maximum", "model": "deepseek-v4-pro", "loop_model": "deepseek-v4-pro",
             "escalate_model": "deepseek-v4-pro", "escalate_after": 1, "max_steps": 40, "max_cost_usd": 0.8},
        ]
    if a.multiagent:
        configs = [
            {"name": "single-agent", "model": "deepseek-flash"},
            {"name": "multi-agent", "model": "deepseek-flash", "mode": "multi-agent"},
        ]
    summary = controller.run_experiment(
        experiment_id=a.experiment, manifests=sel, configs=configs, runner=runner,
        runs=a.runs, global_cost_cap=a.cost_cap, resume=not a.no_resume,
        on_trial=lambda r: print(f"  [{r['challenge_id']} r{r['run_index']}] "
                                 f"{r['outcome']} ${r['cost_usd']} - {str(r['detail'])[:60]}"))
    print("summary:", summary)


if __name__ == "__main__":
    main()
