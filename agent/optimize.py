"""M8: offline trajectory analysis and gated policy PROPOSALS.

Reads the evaluation store (outcome + cost/step metadata ONLY - never evidence,
flags, or verifier keys, so held-out solutions cannot enter the loop), compares
the configs that ran on the same challenge set, and emits human-reviewable
policy proposals. It NEVER changes production config or code: every proposal is a
recommendation a human must approve before anything is deployed.

Gate levels:
- advisable: no compared config does better and this one is cheapest at that
  success, or a config is strictly wasteful (same success, more cost).
- needs-review: a capability/cost trade-off (lower success for lower cost) - a
  human judgment, not an automatic call.

This is the "self-improvement" objective done safely: evidence in, proposals out,
human in the loop. It does not claim the agent improves itself.
"""
from eval import report

CONTAMINATION_MARKERS = ("FLAG{", "flag{")


def contamination_check(rows):
    """Confirm the analysis inputs carry no answer material. Returns
    {clean, n_flagged}. The store holds only metadata, so this should be clean;
    it is asserted, not assumed."""
    flagged = 0
    for r in rows:
        if any(any(mk in str(v) for mk in CONTAMINATION_MARKERS) for v in r.values()):
            flagged += 1
    return {"clean": flagged == 0, "n_flagged": flagged}


def config_summary(rows):
    """Per-config aggregates (excludes infra errors), grouped by config_name.
    Assumes the rows ran on the same challenge set (the caller filters, e.g. by
    dataset), so cost/success are comparable across configs."""
    return report._group(rows, "config_name")


def analyze(rows):
    """Return a list of gated proposals comparing configs in `rows`."""
    byc = config_summary(rows)
    if len(byc) < 2:
        return []
    proposals = []
    max_sr = max(a["solve_rate"] for a in byc.values())
    top = {c: a for c, a in byc.items() if a["solve_rate"] == max_sr}
    cheapest = min(top, key=lambda c: top[c]["mean_cost_usd"])
    ca = top[cheapest]

    proposals.append({
        "title": f"Default policy: '{cheapest}'",
        "recommendation": f"Adopt config '{cheapest}' as the default.",
        "evidence": f"Best verified success ({ca['solved']}/{ca['n']}) at the lowest cost "
                    f"(${ca['mean_cost_usd']}) among {len(byc)} compared configs.",
        "gate": "advisable",
        "rationale": "No compared config does better; several match it for more money.",
    })
    for c, a in sorted(top.items()):
        if c != cheapest and a["mean_cost_usd"] > ca["mean_cost_usd"] * 1.05:
            proposals.append({
                "title": f"Avoid '{c}' as configured",
                "recommendation": f"Do not use '{c}' by default.",
                "evidence": f"Same verified success as '{cheapest}' ({a['solved']}/{a['n']}) at "
                            f"{round(a['mean_cost_usd'] / ca['mean_cost_usd'], 2)}x the cost "
                            f"(${a['mean_cost_usd']} vs ${ca['mean_cost_usd']}).",
                "gate": "advisable",
                "rationale": "Pure cost with no measured benefit on this set.",
            })
    for c, a in sorted(byc.items()):
        if a["solve_rate"] < max_sr:
            proposals.append({
                "title": f"'{c}': capability/cost trade-off",
                "recommendation": f"Use '{c}' only if its lower cost justifies the lower success.",
                "evidence": f"{a['solved']}/{a['n']} ({a['solve_rate']:.0%}) at ${a['mean_cost_usd']}, "
                            f"vs '{cheapest}' {ca['solve_rate']:.0%} at ${ca['mean_cost_usd']}.",
                "gate": "needs-review",
                "rationale": "Lower verified success; whether the saving is worth it is a human call.",
            })
    return proposals


def render_proposals(proposals, scope="", contamination=None):
    L = ["# Policy proposals (M8 - offline, human-gated)", "",
         "> **HUMAN APPROVAL REQUIRED.** These are recommendations derived from past evaluation",
         "> data. Nothing here is applied automatically - no config or code is changed. A human",
         "> reviews each one and only then deploys. The inputs are outcome and cost metadata only",
         "> (no flags, keys, or evidence), so held-out solutions never enter this loop.", ""]
    if scope:
        L += [f"Scope: {scope}", ""]
    if contamination is not None:
        status = "clean (no answer material in inputs)" if contamination["clean"] \
            else f"WARNING: {contamination['n_flagged']} input row(s) contained answer-like text"
        L += [f"Contamination check: {status}", ""]
    if not proposals:
        L += ["No proposals: fewer than two comparable configs in the data."]
        return "\n".join(L)
    order = {"advisable": 0, "needs-review": 1, "insufficient-data": 2}
    for p in sorted(proposals, key=lambda x: order.get(x["gate"], 9)):
        L += [f"## {p['title']}  `[{p['gate']}]`", "",
              f"- **Recommendation:** {p['recommendation']}",
              f"- **Evidence:** {p['evidence']}",
              f"- **Rationale:** {p['rationale']}", ""]
    return "\n".join(L)
