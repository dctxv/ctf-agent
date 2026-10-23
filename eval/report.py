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


def paired_compare(rows_a, rows_b, label_a="A", label_b="B"):
    """Challenge-by-challenge paired join of two experiments by challenge_id.

    Each challenge is placed in exactly one bucket by whether each side produced
    a verified success. Infra errors are not fair failures, so a side whose only
    trials for a challenge were infra errors counts as 'no fair attempt' and the
    pair is set aside as unpaired rather than silently scored as a loss.

    Buckets (paired, both sides had a fair attempt):
      a_only  - solved by A, not by B      (A's edge)
      b_only  - solved by B, not by A      (B's edge)
      both    - solved by both             (shared success)
      neither - solved by neither          (shared failure)
    Plus `unpaired` for challenges where at least one side never got a fair run.

    Returns a dict with the bucketed challenge lists (each entry carries
    category and the per-side cost), their counts, a per-category tally of the
    four paired buckets, and the McNemar discordant totals (a_only vs b_only).
    With one run per challenge a single discordant flip is noise, not a verdict;
    the caller is expected to say so.
    """
    def fold(rows):
        d = defaultdict(lambda: {"fair": 0, "solved": 0, "cat": None, "cost": 0.0})
        for r in rows:
            c = r.get("challenge_id")
            e = d[c]
            if e["cat"] is None:
                e["cat"] = r.get("category")
            e["cost"] += float(r.get("cost_usd") or 0)
            if r.get("outcome") == "infra_error":
                continue
            e["fair"] += 1
            if r.get("outcome") == "verified_success":
                e["solved"] += 1
        return d

    a, b = fold(rows_a), fold(rows_b)
    buckets = {"a_only": [], "b_only": [], "both": [], "neither": [], "unpaired": []}
    by_cat = defaultdict(lambda: {"a_only": 0, "b_only": 0, "both": 0, "neither": 0})
    for c in sorted(set(a) | set(b)):
        ea, eb = a.get(c), b.get(c)
        cat = (ea or eb or {}).get("cat")
        entry = {"challenge_id": c, "category": cat,
                 f"cost_{label_a}": round((ea or {}).get("cost", 0.0), 4),
                 f"cost_{label_b}": round((eb or {}).get("cost", 0.0), 4)}
        if not ea or not eb or ea["fair"] == 0 or eb["fair"] == 0:
            entry["note"] = "no fair attempt on one side"
            buckets["unpaired"].append(entry)
            continue
        sa, sb = ea["solved"] > 0, eb["solved"] > 0
        bucket = "both" if (sa and sb) else "a_only" if sa else "b_only" if sb else "neither"
        buckets[bucket].append(entry)
        if cat is not None:
            by_cat[cat][bucket] += 1
    counts = {k: len(v) for k, v in buckets.items()}
    return {
        "label_a": label_a, "label_b": label_b,
        "buckets": buckets, "counts": counts,
        "by_category": {k: dict(v) for k, v in sorted(by_cat.items())},
        "mcnemar": {"a_only": counts["a_only"], "b_only": counts["b_only"],
                    "discordant": counts["a_only"] + counts["b_only"]},
    }


def render_paired_markdown(pc, title="Paired comparison"):
    """Human-readable markdown for a paired_compare() result."""
    la, lb = pc["label_a"], pc["label_b"]
    c = pc["counts"]
    L = [f"# {title}", "",
         f"Paired by `challenge_id`: **{la}** vs **{lb}**. "
         f"Infra errors are not counted as failures; pairs where one side never "
         f"got a fair run are listed under *unpaired*.",
         "",
         "## Four buckets", "",
         "| bucket | meaning | n |", "|---|---|---|",
         f"| {la} only | {la} solved, {lb} failed | {c['a_only']} |",
         f"| {lb} only | {lb} solved, {la} failed | {c['b_only']} |",
         f"| shared success | both solved | {c['both']} |",
         f"| shared failure | both failed | {c['neither']} |",
         f"| unpaired | one side had no fair run | {c['unpaired']} |",
         "",
         f"Discordant pairs (McNemar): {la}-only {pc['mcnemar']['a_only']} vs "
         f"{lb}-only {pc['mcnemar']['b_only']}. With one run per challenge a single "
         f"flip is noise, not a verdict.", ""]

    def listing(key, heading):
        rows = [f"### {heading} ({c[key]})", ""]
        items = pc["buckets"][key]
        if not items:
            return rows + ["_(none)_", ""]
        rows += ["| challenge | category | "
                 f"cost {la} | cost {lb} |", "|---|---|---|---|"]
        for e in items:
            rows.append(f"| {e['challenge_id']} | {e.get('category') or '?'} | "
                        f"${e.get('cost_' + la, 0)} | ${e.get('cost_' + lb, 0)} |")
        return rows + [""]

    L += listing("a_only", f"{la} only wins")
    L += listing("b_only", f"{lb} only wins")
    L += listing("both", "Shared successes")
    L += listing("neither", "Shared failures")
    if pc["counts"]["unpaired"]:
        L += listing("unpaired", "Unpaired (no fair run on one side)")
    if pc["by_category"]:
        L += ["## By category (paired buckets only)", "",
              f"| category | {la} only | {lb} only | both | neither |",
              "|---|---|---|---|---|"]
        for cat, v in pc["by_category"].items():
            L.append(f"| {cat} | {v['a_only']} | {v['b_only']} | "
                     f"{v['both']} | {v['neither']} |")
        L.append("")
    return "\n".join(L)


def pareto_front(by_config):
    """Config names that are Pareto-efficient on (mean cost ascending, solve rate
    descending): no other config is at least as cheap AND at least as successful
    while being strictly better on one of the two."""
    items = [(c, a.get("mean_cost_usd", 0.0), a.get("solve_rate", 0.0))
             for c, a in by_config.items()]
    eff = []
    for c, cost, sr in items:
        dominated = any(oc != c and ocost <= cost and osr >= sr and (ocost < cost or osr > sr)
                        for oc, ocost, osr in items)
        if not dominated:
            eff.append(c)
    return sorted(eff)


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
        eff = pareto_front(s["by_config"])
        L += [f"Pareto-efficient (best verified success per dollar): **{', '.join(eff)}**", ""]
    return "\n".join(L)
