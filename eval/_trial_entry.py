"""Subprocess entry: run ONE agent trial for the evaluation runner.

Usage:  python -m eval._trial_entry <engagement.json> <metrics_out.json>

Reads the engagement, runs AgentSession non-interactively, and writes a metrics
JSON. Scope and isolation come from the environment the runner set
(WORKSPACE_HOST, AGENT_CONTAINER) and the per-trial container's egress firewall.
Running this spends API budget - the runner invokes it only for real trials.
"""
import json
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from pathlib import Path

from dotenv import load_dotenv


def _auto_human(_question):
    return ("You are authorized for this engagement; all listed targets are in scope. "
            "Proceed, and save the actual result data to the evidence file.")


def main():
    load_dotenv()
    eng = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    out = Path(sys.argv[2])

    mode = eng.get("_mode", "agent")
    extra_cost, prefix, err, session = 0.0, "", "", None
    try:
        if mode == "multi-agent":
            from agent.multiagent import run_multiagent
            r = run_multiagent(eng, _auto_human)
            session, extra_cost = r["session"], r["supervisor_cost"]
            prefix = f"supervisor->{r['specialist']} > "
        else:
            from agent.agent import AgentSession
            session = AgentSession(eng, _auto_human)
            session.run()
    except Exception as e:
        err = str(e)[:300]
    if session is None:
        out.write_text(json.dumps({"steps": 0, "cost_usd": round(extra_cost, 4),
                                   "technique": "multi-agent (failed before run)",
                                   "error": err, "finished_naturally": False}), encoding="utf-8")
        return

    ev = session.events

    def count(t):
        return sum(1 for e in ev if e.get("type") == t)

    toks_in = sum(e["data"].get("tokens_in", 0) for e in ev if e.get("type") == "cost_update")
    toks_out = sum(e["data"].get("tokens_out", 0) for e in ev if e.get("type") == "cost_update")
    budget = count("budget_hit")
    tool_seq = [e["data"].get("tool") for e in ev
                if e.get("type") == "tool_call" and e.get("data", {}).get("tool")]
    summary = next((e["data"].get("summary", "") for e in reversed(ev)
                    if e.get("type") == "session_end"), "")
    technique = prefix + " > ".join(list(dict.fromkeys(tool_seq))[:8])
    if summary:
        technique += " | " + str(summary)[:220]   # the approach, not just tool names (flags scrubbed on store)
    out.write_text(json.dumps({
        "steps": session.steps,
        "technique": technique,
        "cost_usd": round(session.cost_usd + extra_cost, 4),
        "tokens_in": toks_in,
        "tokens_out": toks_out,
        "escalations": count("escalation"),
        "ask_human": count("ask_human"),
        "refusals": count("refusal"),
        "budget_hits": budget,
        "finished_naturally": bool(session.finished and budget == 0),
        "error": err,
    }), encoding="utf-8")


if __name__ == "__main__":
    main()
