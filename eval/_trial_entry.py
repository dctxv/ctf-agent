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

    from agent.agent import AgentSession
    session = AgentSession(eng, _auto_human)
    err = ""
    try:
        session.run()
    except Exception as e:
        err = str(e)[:300]

    ev = session.events

    def count(t):
        return sum(1 for e in ev if e.get("type") == t)

    toks_in = sum(e["data"].get("tokens_in", 0) for e in ev if e.get("type") == "cost_update")
    toks_out = sum(e["data"].get("tokens_out", 0) for e in ev if e.get("type") == "cost_update")
    budget = count("budget_hit")
    tool_seq = [e["data"].get("tool") for e in ev
                if e.get("type") == "tool_call" and e.get("data", {}).get("tool")]
    technique = " > ".join(list(dict.fromkeys(tool_seq))[:10])
    out.write_text(json.dumps({
        "steps": session.steps,
        "technique": technique,
        "cost_usd": round(session.cost_usd, 4),
        "tokens_in": toks_in,
        "tokens_out": toks_out,
        "escalations": count("escalation"),
        "ask_human": count("ask_human"),
        "budget_hits": budget,
        "finished_naturally": bool(session.finished and budget == 0),
        "error": err,
    }), encoding="utf-8")


if __name__ == "__main__":
    main()
