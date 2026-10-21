"""Generate BENCHMARK.md + benchmark.json from the evaluation store.

  python run_report.py                          # all rows in the store
  python run_report.py --experiment smoke-m2    # one experiment
  python run_report.py --regression BEFORE AFTER  # per-challenge solved delta

The store is the source of truth; these outputs are derived views (the human
BENCHMARK.md and a machine-readable JSON).
"""
import argparse
import json
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from eval import report
from eval import store as store_mod


def _rows(st, exp=None):
    return [r for r in st.all_rows() if (not exp or r.get("experiment_id") == exp)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default="eval/results.sqlite")
    ap.add_argument("--experiment")
    ap.add_argument("--out-md", default="eval/BENCHMARK.md")
    ap.add_argument("--out-json", default="eval/benchmark.json")
    ap.add_argument("--regression", nargs=2, metavar=("BEFORE", "AFTER"))
    a = ap.parse_args()

    st = store_mod.Store(a.store)
    try:
        if a.regression:
            reg = report.regression(_rows(st, a.regression[0]), _rows(st, a.regression[1]))
            print(json.dumps(reg, indent=2))
            moved = [c for c, d in reg.items() if d["delta"] != 0]
            print(f"\n{len(moved)} challenge(s) changed between "
                  f"{a.regression[0]} and {a.regression[1]}: {moved or 'none'}")
            return

        rows = _rows(st, a.experiment)
        if not rows:
            print("no rows in the store for this selection.")
            return
        summ = report.summarize(rows)
        md = report.render_markdown(summ, title="CTF-Agent benchmark",
                                    experiment_id=a.experiment)
        with open(a.out_md, "w", encoding="utf-8") as f:
            f.write(md)
        with open(a.out_json, "w", encoding="utf-8") as f:
            json.dump(summ, f, indent=2)
        o = summ["overall"]
        print(f"wrote {a.out_md} and {a.out_json}")
        print(f"overall: {o['solved']}/{o['n']} verified "
              f"({o['solve_rate']:.0%}, CI {o['ci_low']:.0%}-{o['ci_high']:.0%}), "
              f"{o['infra_errors']} infra error(s)")
    finally:
        st.close()


if __name__ == "__main__":
    main()
