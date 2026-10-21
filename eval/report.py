"""Analytics and reporting over the evaluation store.

Turns trial rows into verified solve-rates with confidence intervals, per-category
and per-config breakdowns, cost/latency/step aggregates, failure-reason
distributions, and a regression diff between two experiments. Produces a human
BENCHMARK.md and a machine-readable JSON.

Honesty guardrails baked in:
- Infra errors are excluded from solve-rate denominators (they are harness
  failures, not agent failures) and reported separately.
- Solve-rate confidence uses the Wilson score interval, so small-n results carry
  visibly wide bounds instead of a misleading point estimate.
- The report states trial counts and flags when coverage is a single dataset or
  a single category family (e.g. Juice Shop only), so a number is never read as
  generalization when it is not.
"""
import math
from collections import defaultdict


def wilson(k, n, z=1.96):
    """Wilson score interval for k successes in n trials. Returns (p, low, high)."""
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (p, max(0.0, center - half), min(1.0, center + half))


def _fnum(rows, key):
    vals = []
    for r in rows:
        v = r.get(key)
        if v in (None, "", "None"):
            continue
        try:
            vals.append(float(v))
        except (TypeError, ValueError):
            pass
    return round(sum(vals) / len(vals), 4) if vals else 0.0


def _agg(rows):
    """Aggregate a list of trial rows. Infra errors are counted apart and removed
    from the solve-rate denominator."""
    infra = sum(1 for r in rows if r.get("outcome") == "infra_error")
    scored = [r for r in rows if r.get("outcome") != "infra_error"]
    n = len(scored)
    solved = sum(1 for r in scored if r.get("outcome") == "verified_success")
    p, lo, hi = wilson(solved, n)
    fr = defaultdict(int)
    for r in scored:
        if r.get("outcome") != "verified_success" and r.get("failure_reason"):
            fr[r["failure_reason"]] += 1
    return {
        "n": n, "solved": solved, "infra_errors": infra,
        "solve_rate": round(p, 4), "ci_low": round(lo, 4), "ci_high": round(hi, 4),
        "mean_cost_usd": _fnum(scored, "cost_usd"),
        "mean_steps": _fnum(scored, "steps"),
        "mean_duration_s": _fnum(scored, "duration_s"),
        "failure_reasons": dict(fr),
    }


def _group(rows, key):
    g = defaultdict(list)
    for r in rows:
        g[r.get(key) or "(none)"].append(r)
    return {k: _agg(v) for k, v in sorted(g.items())}


def summarize(rows):
    rows = list(rows)
    datasets = sorted({r.get("dataset") for r in rows if r.get("dataset")})
    categories = sorted({r.get("category") for r in rows if r.get("category")})
    caveats = []
    if datasets and datasets == ["dev"]:
        caveats.append("All trials are dev-tier (not held-out): these numbers measure "
                       "development performance, not generalization.")
    if len(categories) <= 1:
        caveats.append(f"Coverage is a single category family ({categories or ['unknown']}): "
                       "results reflect recall on one family, not breadth.")
    return {
        "overall": _agg(rows),
        "by_challenge": _group(rows, "challenge_id"),
        "by_category": _group(rows, "category"),
        "by_config": _group(rows, "config_name"),
        "datasets": datasets,
        "categories": categories,
        "caveats": caveats,
    }


def regression(rows_before, rows_after):
    """Per-challenge solved-count delta between two sets of rows (e.g. two
    experiments or two git SHAs). Returns challenge -> {before, after, delta}."""
    def by_ch(rows):
        d = defaultdict(lambda: {"n": 0, "solved": 0})
        for r in rows:
            if r.get("outcome") == "infra_error":
                continue
            c = r.get("challenge_id")
            d[c]["n"] += 1
            d[c]["solved"] += 1 if r.get("outcome") == "verified_success" else 0
        return d
    a, b = by_ch(rows_before), by_ch(rows_after)
    out = {}
    for c in sorted(set(a) | set(b)):
        sa = a.get(c, {}).get("solved", 0)
        sb = b.get(c, {}).get("solved", 0)
        out[c] = {"before": sa, "after": sb, "delta": sb - sa,
                  "n_before": a.get(c, {}).get("n", 0), "n_after": b.get(c, {}).get("n", 0)}
    return out


def _rate_line(a):
    return (f"{a['solved']}/{a['n']} "
            f"({a['solve_rate']:.0%}, 95% CI {a['ci_low']:.0%}-{a['ci_high']:.0%})"
            if a["n"] else "0/0 (n/a)")


def render_markdown(summary, title="Benchmark report", experiment_id=None):
    s = summary
    o = s["overall"]
    L = [f"# {title}", ""]
    if experiment_id:
        L.append(f"Experiment: `{experiment_id}`")
    L += [f"Datasets: {', '.join(s['datasets']) or 'n/a'} | "
          f"Categories: {', '.join(s['categories']) or 'n/a'}", ""]
    if s["caveats"]:
        L.append("> **Read with care:**")
        for c in s["caveats"]:
            L.append(f"> - {c}")
        L.append("")
    L += ["## Overall", "", f"- Verified solve rate: **{_rate_line(o)}**",
          f"- Infra errors (excluded from the rate): {o['infra_errors']}",
          f"- Mean cost ${o['mean_cost_usd']} | mean steps {o['mean_steps']} | "
          f"mean duration {o['mean_duration_s']}s", ""]
    if o["failure_reasons"]:
        L.append("- Failure reasons: " +
                 ", ".join(f"{k} x{v}" for k, v in sorted(o["failure_reasons"].items())))
        L.append("")

    def table(title_, grp):
        rows = [f"### {title_}", "", "| key | solve rate | mean $ | mean steps | infra |",
                "|---|---|---|---|---|"]
        for k, a in grp.items():
            rows.append(f"| {k} | {_rate_line(a)} | {a['mean_cost_usd']} | "
                        f"{a['mean_steps']} | {a['infra_errors']} |")
        rows.append("")
        return rows

    L += table("By category", s["by_category"])
    L += table("By challenge", s["by_challenge"])
    if len(s["by_config"]) > 1:
        L += table("By config", s["by_config"])
    return "\n".join(L)
