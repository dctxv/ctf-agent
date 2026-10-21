"""Experiment controller: the matrix of {config x challenge x run}, with
randomized order, resume, and hard budget caps.

The store is the checkpoint - each trial is recorded the instant it finishes, so
an interrupted run resumes by skipping what is already present (infra errors are
retried). A global cost cap stops launching new trials once spend is reached.
"""
import random

from eval import store as store_mod


def build_matrix(manifests, configs, runs):
    out = []
    for cfg in configs:
        for m in manifests:
            for ri in range(1, runs + 1):
                out.append((cfg, m, ri))
    return out


def run_experiment(*, experiment_id, manifests, configs, runner, runs=1,
                   store=None, store_path="eval/results.sqlite",
                   global_cost_cap=None, randomize=True, seed=0, resume=True,
                   export_csv="eval/results.csv", on_trial=None):
    st = store or store_mod.Store(store_path)
    trials = build_matrix(manifests, configs, runs)
    if randomize:
        random.Random(seed).shuffle(trials)
    done = st.completed(experiment_id) if resume else set()
    spent = 0.0
    summary = {"experiment_id": experiment_id, "ran": 0, "skipped": 0,
               "by_outcome": {}, "cost_cap_hit": False}
    for cfg, m, ri in trials:
        key = (cfg.get("name", "default"), m["id"], str(ri))
        if key in done:
            summary["skipped"] += 1
            continue
        if global_cost_cap is not None and spent >= global_cost_cap:
            summary["cost_cap_hit"] = True
            break
        res = runner.run_trial(m, run_index=ri, experiment_id=experiment_id, config=cfg)
        st.record(res)
        spent += float(res.get("cost_usd") or 0)
        summary["ran"] += 1
        oc = res.get("outcome")
        summary["by_outcome"][oc] = summary["by_outcome"].get(oc, 0) + 1
        if on_trial:
            on_trial(res)
    if export_csv:
        st.export_csv(export_csv, experiment_id)
    summary["total_cost_usd"] = round(spent, 4)
    return summary
