"""M8: offline policy-proposal tool. Reads the evaluation store, compares the
configs that ran on a challenge set, and writes human-reviewable proposals. It
changes nothing - no config, no code - and requires human approval to act on.

  python run_optimize.py                                 # dataset=test (held-out generated set)
  python run_optimize.py --dataset dev
  python run_optimize.py --experiments m6-profiles m7-multiagent
"""
import argparse
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from agent import optimize
from eval import store as store_mod


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default="eval/results.sqlite")
    ap.add_argument("--dataset", default="test")
    ap.add_argument("--experiments", nargs="*", help="pool these experiment ids instead of a dataset")
    ap.add_argument("--out", default="docs/OPTIMIZATION.md")
    a = ap.parse_args()

    st = store_mod.Store(a.store)
    try:
        rows = st.all_rows()
        if a.experiments:
            keep = set(a.experiments)
            rows = [r for r in rows if r.get("experiment_id") in keep]
            scope = "experiments " + ", ".join(a.experiments)
        else:
            rows = [r for r in rows if r.get("dataset") == a.dataset]
            scope = f"dataset={a.dataset}"
    finally:
        st.close()

    cc = optimize.contamination_check(rows)
    props = optimize.analyze(rows)
    md = optimize.render_proposals(props, scope=scope, contamination=cc)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(md + "\n")
    print(f"wrote {a.out}: {len(props)} proposal(s); "
          f"contamination {'clean' if cc['clean'] else 'FLAGGED'}")
    for p in props:
        print(f"  [{p['gate']}] {p['title']}")


if __name__ == "__main__":
    main()
