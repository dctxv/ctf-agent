"""Compare two eval runs in results.csv by git SHA, per challenge.

  python compare_runs.py --baseline <sha> --target <sha>

Flags a regression when the target solves a challenge less often than the
baseline, or when mean steps/cost rise materially (> 50% and above the baseline's
own spread). Baselines and targets may have different run counts; small samples
are reported as-is. Default: the two most recent distinct SHAs in the file.
"""
import argparse
import csv
import statistics as st
from collections import OrderedDict, defaultdict

RESULTS = "results.csv"


def load():
    rows = []
    with open(RESULTS, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows


def sha_order(rows):
    seen = OrderedDict()
    for r in rows:
        seen.setdefault(r["git_sha"], r["timestamp_utc"])
    return list(seen.keys())


def agg(rows):
    n = len(rows)
    if not n:
        return None
    solved = sum(1 for r in rows if r["solved"] == "True")
    steps = [int(r["steps"]) for r in rows]
    cost = [float(r["cost_usd"]) for r in rows]
    return {
        "n": n, "solved": solved, "rate": solved / n,
        "steps_m": st.mean(steps), "steps_sd": st.stdev(steps) if n > 1 else 0.0,
        "cost_m": st.mean(cost), "cost_sd": st.stdev(cost) if n > 1 else 0.0,
    }


def main():
    rows = load()
    shas = sha_order(rows)
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline")
    ap.add_argument("--target")
    a = ap.parse_args()
    target = a.target or (shas[-1] if shas else None)
    baseline = a.baseline or (shas[-2] if len(shas) > 1 else None)
    if not baseline or not target:
        raise SystemExit("need at least two distinct git SHAs in results.csv")

    def by_chal(sha):
        d = defaultdict(list)
        for r in rows:
            if r["git_sha"] == sha:
                d[r["challenge"]].append(r)
        return {c: agg(rs) for c, rs in d.items()}

    b, t = by_chal(baseline), by_chal(target)
    print(f"baseline {baseline}  vs  target {target}\n")
    hdr = f"{'challenge':<24} {'solved b>t':>12} {'steps b>t':>18} {'cost b>t':>22}  flags"
    print(hdr); print("-" * len(hdr))

    regressions = []
    for c in sorted(set(b) & set(t)):
        bb, tt = b[c], t[c]
        flags = []
        if tt["rate"] < bb["rate"]:
            flags.append("SOLVE-DOWN")
        if tt["steps_m"] > bb["steps_m"] * 1.5 and tt["steps_m"] - bb["steps_m"] > bb["steps_sd"]:
            flags.append("STEPS-UP")
        if tt["cost_m"] > bb["cost_m"] * 1.5 and tt["cost_m"] - bb["cost_m"] > bb["cost_sd"]:
            flags.append("COST-UP")
        if flags:
            regressions.append((c, flags))
        solved_s = f"{bb['solved']}/{bb['n']}>{tt['solved']}/{tt['n']}"
        steps_s = f"{bb['steps_m']:.1f}>{tt['steps_m']:.1f}"
        cost_s = f"${bb['cost_m']:.4f}>${tt['cost_m']:.4f}"
        print(f"{c:<24} {solved_s:>12} {steps_s:>18} {cost_s:>22}  {' '.join(flags)}")

    only_b = sorted(set(b) - set(t))
    only_t = sorted(set(t) - set(b))
    if only_b:
        print(f"\n(only in baseline: {only_b})")
    if only_t:
        print(f"(only in target: {only_t})")
    print("\n" + ("REGRESSIONS: " + ", ".join(f"{c}[{'/'.join(fl)}]" for c, fl in regressions)
                   if regressions else "No regressions flagged."))


if __name__ == "__main__":
    main()
