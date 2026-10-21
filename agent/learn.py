"""Phase 3 learning layer: turn a finished session into a study aid.

Reads a saved session's events.json (goal + tool-call methodology + the agent's
final summary) and asks the LLM for a writeup, key concepts, and flashcards.
Writes learning.md and flashcards.json next to the events file. This is a single
LLM call (not a tool loop), so it is cheap.
"""
import json
import os
import re
from pathlib import Path

from agent.llm import LLMClient

MODEL = "deepseek-flash"  # cheap; this is summarization, not reasoning-heavy


def _client():
    return LLMClient()


def _events_path(session_dir) -> Path:
    d = Path(session_dir)
    if (d / "events.json").exists():
        return d / "events.json"
    runs = sorted(d.glob("run_*"))  # eval sessions store artifacts under run_NN/
    for r in reversed(runs):
        if (r / "events.json").exists():
            return r / "events.json"
    raise FileNotFoundError(f"no events.json under {session_dir}")


def summarize_session(session_dir) -> dict:
    ev_path = _events_path(session_dir)
    events = json.loads(ev_path.read_text(encoding="utf-8"))
    eng = next((e["data"] for e in events if e["type"] == "session_start"), {})
    steps = []
    for e in events:
        if e["type"] != "tool_call":
            continue
        args = e["data"].get("args", {}) or {}
        detail = args.get("command") or args.get("path") or args.get("url") or args.get("query") or ""
        steps.append(f"{e['data'].get('tool')}: {str(detail)[:160]}")
    summary = next((e["data"].get("summary", "") for e in reversed(events)
                    if e["type"] == "session_end"), "")
    return {
        "name": eng.get("engagement_name", "session"),
        "goal": eng.get("goal", ""),
        "targets": eng.get("targets", ""),
        "steps": steps,
        "summary": summary,
        "events_path": ev_path,
    }


_PROMPT = """You are a security tutor. From this completed pentest/CTF session, make a study aid.

Engagement: {name}
Target: {targets}
Goal: {goal}

Methodology (tool calls in order):
{steps}

Agent's final summary:
{summary}

Write Markdown with exactly these sections:
## Writeup
A concise technical narrative: the target, the vulnerability/finding, how it was discovered and exploited, and how it was verified.
## Key concepts
3-6 bullets naming the security concepts/techniques involved, each with a one-line explanation.
## Flashcards
A single fenced ```json code block containing an array of 6-10 objects {{"q": "...", "a": "..."}} - specific recall questions drawn from THIS session.

Base everything ONLY on the session above. Be concrete (endpoints, payloads, tools, file:line). If the session failed or was inconclusive, say so and make the flashcards about the approach and why it stalled."""


def generate_learning(session_dir, client=None, model=MODEL) -> dict:
    info = summarize_session(session_dir)
    client = client or _client()
    prompt = _PROMPT.format(
        name=info["name"],
        targets=str(info["targets"])[:300],
        goal=str(info["goal"])[:600],
        steps="\n".join(f"- {s}" for s in info["steps"][:60]) or "(none recorded)",
        summary=(info["summary"] or "(no summary)")[:4000],
    )
    resp = client.complete(
        model=model, messages=[{"role": "user", "content": prompt}], temperature=0.3)
    md = resp.choices[0].message.content or ""

    out_dir = info["events_path"].parent
    (out_dir / "learning.md").write_text(md, encoding="utf-8")

    cards = []
    m = re.search(r"```json\s*(\[.*?\])\s*```", md, re.S)
    if m:
        try:
            cards = json.loads(m.group(1))
        except json.JSONDecodeError:
            cards = []
    (out_dir / "flashcards.json").write_text(json.dumps(cards, indent=2), encoding="utf-8")

    u = resp.usage
    return {
        "learning_md": str(out_dir / "learning.md"),
        "flashcards": str(out_dir / "flashcards.json"),
        "n_cards": len(cards),
        "tokens_in": u.prompt_tokens,
        "tokens_out": u.completion_tokens,
    }


_CLIENT_PROMPT = """You are a penetration tester writing a formal, client-facing report.

Engagement: {name}
Target / scope: {targets}
Objective: {goal}

Methodology (tool calls in order):
{steps}

Tester's findings summary:
{summary}

Produce a professional Markdown penetration-test report with these sections:
# Penetration Test Report - {name}
## Executive summary
Non-technical, 3-5 sentences: what was tested, the overall risk posture, and the headline findings.
## Scope and methodology
## Findings
For EACH finding use `### <n>. <Title> - <Severity>` then cover: Affected asset/endpoint, Description,
Evidence (cite PoC/artifact paths from the session), Impact, and Remediation. Map to a CWE where possible.
## Risk summary
A table mapping each finding to its severity.
## Appendix: tools and artifacts

Base everything ONLY on the session above. If the engagement was inconclusive or failed, report that
honestly. Professional, client-appropriate tone; no invented findings."""


def generate_client_report(session_dir, client=None, model=MODEL) -> dict:
    info = summarize_session(session_dir)
    client = client or _client()
    prompt = _CLIENT_PROMPT.format(
        name=info["name"],
        targets=str(info["targets"])[:300],
        goal=str(info["goal"])[:600],
        steps="\n".join(f"- {s}" for s in info["steps"][:60]) or "(none recorded)",
        summary=(info["summary"] or "(no summary)")[:4000],
    )
    resp = client.complete(
        model=model, messages=[{"role": "user", "content": prompt}], temperature=0.3)
    md = resp.choices[0].message.content or ""
    out_dir = info["events_path"].parent
    (out_dir / "client_report.md").write_text(md, encoding="utf-8")
    u = resp.usage
    return {"client_report": str(out_dir / "client_report.md"),
            "tokens_in": u.prompt_tokens, "tokens_out": u.completion_tokens}
