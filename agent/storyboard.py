"""Attack-map storyboard: turn a finished session into an animated, plain-English story.

Reads a saved session's events.json (goal + scope + the ordered tool-call
methodology + the agent's final summary) and the ground-truth loot it produced
(CTF evidence file / audit findings.json), then asks the LLM for a structured
"storyboard": an attack-path graph (nodes = milestones the agent reached, edges =
the actions that got there, grouped into kill-chain phases) plus a narrated,
step-by-step story a non-expert can follow. This is a single LLM call (not a tool
loop), cached to storyboard.json next to the events file, so replays/exports are free.

The event stream has NO per-step reasoning (model_message is never emitted in a
tool-driven loop), so narration is synthesised from the commands + the rich
session_end.summary + the real loot. If the model returns unparseable JSON we fall
back to a deterministic skeleton so a storyboard is always produced.
"""
import json
import re
from datetime import datetime
from pathlib import Path

from agent.findings import load_findings
from agent.learn import _events_path
from agent.llm import LLMClient

ROOT = Path(__file__).resolve().parent.parent
WORKSPACE = ROOT / "workspace"
MODEL = "deepseek-flash"  # cheap; narration/summarisation, not reasoning-heavy
SCHEMA = 1
PHASES = ["recon", "discovery", "exploit", "exfil", "report"]
_NODE_KINDS = {"attacker", "target", "host", "endpoint", "finding", "loot", "tool", "node"}


def _client():
    return LLMClient()


# ---------------------------------------------------------------- extraction

def _parse_ts(s):
    try:
        return datetime.fromisoformat(s)
    except (TypeError, ValueError):
        return None


def extract(session_dir) -> dict:
    """Pull everything a storyboard needs from a saved session: scope, the ordered
    action list, the final summary, and the real loot. No LLM, no network."""
    ev_path = _events_path(session_dir)
    events = json.loads(ev_path.read_text(encoding="utf-8"))
    eng = next((e["data"] for e in events if e.get("type") == "session_start"), {})

    actions, markers = [], []
    for e in events:
        t = e.get("type")
        if t == "tool_call":
            a = e["data"].get("args", {}) or {}
            detail = a.get("command") or a.get("path") or a.get("url") or a.get("query") or ""
            actions.append({"i": len(actions), "ts": e.get("ts", ""),
                            "tool": e["data"].get("tool", ""), "detail": str(detail)})
        elif t in ("budget_hit", "escalation", "refusal"):
            markers.append({"type": t, **(e.get("data") or {})})
    summary = next((e["data"].get("summary", "") for e in reversed(events)
                    if e.get("type") == "session_end"), "")

    # pacing / cost
    cost = 0.0
    for e in events:
        if e.get("type") == "cost_update":
            cost = e["data"].get("total_usd", cost)
    ts_all = [t for t in (_parse_ts(e.get("ts", "")) for e in events) if t]
    duration_s = round((ts_all[-1] - ts_all[0]).total_seconds(), 1) if len(ts_all) > 1 else 0.0

    # ground-truth loot
    loot = _extract_loot(eng)

    return {
        "session": eng.get("engagement_name") or Path(ev_path).parent.name,
        "goal": eng.get("goal", ""),
        "targets": eng.get("targets", ""),
        "allowed_hosts": eng.get("allowed_hosts", []) or [],
        "audit": eng.get("_audit"),
        "evidence_spec": eng.get("evidence"),
        "actions": actions,
        "markers": markers,
        "summary": summary,
        "loot": loot,
        "stats": {"steps": len(actions), "cost_usd": round(float(cost), 4),
                  "duration_s": duration_s, "findings": len(loot.get("findings", []))},
        "events_path": ev_path,
    }


def _extract_loot(eng) -> dict:
    """The real deliverable: audit findings, or the CTF evidence file + success token."""
    audit = eng.get("_audit") or {}
    if audit.get("findings"):
        audit_dir = (WORKSPACE / Path(audit["findings"]).parent)
        try:
            fs = load_findings(audit_dir)
        except Exception:
            fs = []
        return {"kind": "findings",
                "findings": [{"id": f.get("id"), "title": f.get("title"),
                              "severity": f.get("severity"), "file": f.get("file"),
                              "line": f.get("line"), "cwe": f.get("cwe")} for f in fs],
                "report": audit.get("report")}
    ev = eng.get("evidence") or {}
    if ev.get("type") == "file_exists" and ev.get("path"):
        p = (WORKSPACE / ev["path"])
        present, head = p.is_file(), ""
        if present:
            try:
                head = p.read_text(encoding="utf-8", errors="replace")[:800]
            except OSError:
                head = ""
        return {"kind": "evidence", "path": ev["path"], "contains": ev.get("contains"),
                "present": present, "head": head,
                "token_hit": bool(ev.get("contains")) and ev.get("contains", "") in head}
    return {"kind": "none"}


def _outcome_guess(ex) -> str:
    loot = ex["loot"]
    if loot["kind"] == "findings":
        return "success" if loot["findings"] else "partial"
    if loot["kind"] == "evidence":
        if loot.get("contains"):
            return "success" if loot.get("token_hit") else ("partial" if loot["present"] else "failed")
        return "success" if loot["present"] else "partial"
    return "partial"


# ---------------------------------------------------------------- narration

_PROMPT = """You turn a finished security test into an ANIMATED ATTACK MAP with a plain-English story \
that a non-technical person can follow. Output STRICT JSON only - no prose, no markdown fences.

== The run ==
Target / scope: {targets}
In-scope hosts: {hosts}
Goal: {goal}
Likely outcome (from the real evidence on disk): {outcome}

Actions the agent took, in order (tool: detail):
{steps}

The agent's own final summary (its real reasoning path - trust this for WHAT each move proved):
{summary}

Real loot / proof it produced:
{loot}

== What to produce ==
A JSON object describing an attack-path graph and a narrated walkthrough:
{{
  "title": "<=8-word headline of how it broke in",
  "subtitle": "one clause of extra context",
  "target": "the host or repo in <=6 words",
  "outcome": "success" | "partial" | "failed",
  "tldr": "2-3 sentences, plain English, how it broke in - no jargon",
  "nodes": [
    {{"id":"n0","label":"Attacker","kind":"attacker","phase":null}},
    {{"id":"n1","label":"<target>","kind":"target","phase":"recon"}},
    {{"id":"n2","label":"<endpoint/asset reached>","kind":"endpoint","phase":"discovery"}},
    {{"id":"n3","label":"<vuln confirmed>","kind":"finding","phase":"exploit","severity":"critical"}},
    {{"id":"n4","label":"<what was stolen/proven>","kind":"loot","phase":"exfil"}}
  ],
  "steps": [
    {{"i":1,"phase":"recon","node":"n1","edge":["n0","n1"],
      "headline":"<=6 words, active voice",
      "say":"1-2 plain-English sentences explaining this move to a layperson",
      "action_idx":0}}
  ]
}}

Rules:
- phase is one of: recon, discovery, exploit, exfil, report (use only the ones that happened, in that order).
- node.kind is one of: attacker, target, host, endpoint, finding, loot, tool.
- Always include the attacker node "n0" and a target node. Each milestone the agent REACHED is a node.
- Give 4-12 steps. Each step: node = an existing node id; edge = [fromId, toId] of existing ids (the move);
  action_idx = the 0-based index of the action it maps to (from the list above), or null for a summarising milestone.
- "say" and "tldr" must be understandable by someone non-technical. Base everything ONLY on the run above;
  do not invent findings. If it failed or stalled, say so honestly."""


def _fmt_loot(loot) -> str:
    if loot["kind"] == "findings":
        if not loot["findings"]:
            return "(audit produced no findings)"
        return "\n".join(f"- [{f.get('severity')}] {f.get('title')} ({f.get('file')}:{f.get('line')}, {f.get('cwe')})"
                         for f in loot["findings"][:20])
    if loot["kind"] == "evidence":
        tok = f", must contain '{loot['contains']}'" if loot.get("contains") else ""
        state = "PRESENT" if loot["present"] else "MISSING"
        hit = " (success token found)" if loot.get("token_hit") else ""
        head = ("\n  first bytes: " + loot["head"][:200].replace("\n", " ")) if loot.get("head") else ""
        return f"- evidence file {loot['path']} [{state}{hit}]{tok}{head}"
    return "(no structured loot recorded)"


def _build_prompt(ex) -> str:
    steps = "\n".join(f"{a['i']}. {a['tool']}: {a['detail'][:200]}" for a in ex["actions"][:60]) or "(none)"
    return _PROMPT.format(
        targets=str(ex["targets"])[:300] or "(unspecified)",
        hosts=", ".join(ex["allowed_hosts"]) or "(none / local source)",
        goal=str(ex["goal"])[:600] or "(unspecified)",
        outcome=_outcome_guess(ex),
        steps=steps,
        summary=(ex["summary"] or "(no summary recorded)")[:4000],
        loot=_fmt_loot(ex["loot"]),
    )


def _parse_json(text):
    t = (text or "").strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", t, re.S)
    if m:
        t = m.group(1).strip()
    s, e = t.find("{"), t.rfind("}")
    if s != -1 and e > s:
        t = t[s:e + 1]
    return json.loads(t)


def narrate(ex, *, client, model=MODEL) -> dict:
    """One LLM call -> validated storyboard dict. Falls back to a deterministic
    skeleton only if the model cannot produce usable JSON."""
    prompt = _build_prompt(ex)
    raw = ""
    for attempt in range(2):  # one retry on bad JSON
        msgs = [{"role": "user", "content": prompt}]
        if attempt == 1:
            msgs.append({"role": "user",
                         "content": "Your previous reply was not valid JSON. Reply with ONLY the JSON object."})
        try:
            resp = client.complete(model=model, messages=msgs, temperature=0.3)
            raw = resp.choices[0].message.content or ""
            return _normalize(_parse_json(raw), ex, model)
        except Exception:
            continue
    return _skeleton(ex, model)


def _normalize(sb, ex, model) -> dict:
    nodes, ids, seen = [], set(), set()
    for n in (sb.get("nodes") or []):
        if not isinstance(n, dict):
            continue
        nid = str(n.get("id") or f"n{len(nodes)}")
        if nid in seen:
            continue
        seen.add(nid)
        ids.add(nid)
        phase = n.get("phase") if n.get("phase") in PHASES else None
        kind = n.get("kind") if n.get("kind") in _NODE_KINDS else "node"
        nodes.append({"id": nid, "label": str(n.get("label") or nid)[:80], "kind": kind,
                      "phase": phase, "severity": n.get("severity")})
    if not nodes:
        raise ValueError("no nodes")

    steps = []
    for st in (sb.get("steps") or []):
        if not isinstance(st, dict):
            continue
        node = str(st.get("node") or "")
        if node not in ids:
            node = nodes[-1]["id"]
        edge = st.get("edge")
        if not (isinstance(edge, list) and len(edge) == 2 and all(str(x) in ids for x in edge)):
            edge = None
        nphase = next((n["phase"] for n in nodes if n["id"] == node), None)
        phase = st.get("phase") if st.get("phase") in PHASES else (nphase or "recon")
        ai = st.get("action_idx")
        ai = ai if isinstance(ai, int) and 0 <= ai < len(ex["actions"]) else None
        cmd = str(st.get("command") or (ex["actions"][ai]["detail"] if ai is not None else ""))[:600]
        steps.append({"i": len(steps) + 1, "phase": phase, "node": node,
                      "edge": [str(edge[0]), str(edge[1])] if edge else None,
                      "headline": str(st.get("headline") or "")[:120],
                      "say": str(st.get("say") or "")[:600],
                      "action_idx": ai, "command": cmd, "evidence": st.get("evidence")})
    if not steps:
        raise ValueError("no steps")

    present = [p for p in PHASES if any(n["phase"] == p for n in nodes) or any(s["phase"] == p for s in steps)]
    outcome = sb.get("outcome") if sb.get("outcome") in ("success", "partial", "failed") else _outcome_guess(ex)
    return {
        "schema": SCHEMA, "session": ex["session"],
        "generated_utc": datetime.utcnow().isoformat(), "model": model,
        "title": str(sb.get("title") or ex["session"])[:120],
        "subtitle": str(sb.get("subtitle") or "")[:160],
        "target": str(sb.get("target") or ex["targets"])[:120],
        "outcome": outcome,
        "tldr": str(sb.get("tldr") or "")[:600],
        "phases": present, "nodes": nodes, "steps": steps,
        "stats": ex["stats"],
    }


# ---------------------------------------------------------------- deterministic fallback

_PHASE_RE = [
    ("report", re.compile(r"report\.md|findings\.json|disclosure|client_report", re.I)),
    ("exfil", re.compile(r"evidence/|loot/|dump|exfil|> ?\S+\.(txt|json|csv)|union\s+select", re.I)),
    ("exploit", re.compile(r"union|sqlmap|'--|or 1=1|exploit|poc|hydra|metasploit|nc |reverse|payload", re.I)),
    ("discovery", re.compile(r"search\?|/rest/|/api/|login|\?q=|%27|order by|dirb|gobuster|enum|nmap", re.I)),
]


def _phase_of(detail) -> str:
    for phase, rx in _PHASE_RE:
        if rx.search(detail or ""):
            return phase
    return "recon"


def _skeleton(ex, model) -> dict:
    """Guaranteed-usable storyboard built with no LLM: one node per phase reached,
    one step per action. Blunter prose, but never crashes."""
    tgt = (str(ex["targets"]).split("(")[0].strip() or "target")[:60]
    nodes = [{"id": "n0", "label": "Attacker", "kind": "attacker", "phase": None},
             {"id": "n1", "label": tgt, "kind": "target", "phase": "recon", "severity": None}]
    phase_node = {"recon": "n1"}
    steps = []
    for a in ex["actions"][:40]:
        ph = _phase_of(a["detail"])
        if ph not in phase_node:
            nid = f"n{len(nodes)}"
            nodes.append({"id": nid, "label": ph.capitalize(), "kind": "endpoint" if ph == "discovery" else ph,
                          "phase": ph, "severity": None})
            phase_node[ph] = nid
        node = phase_node[ph]
        prev = steps[-1]["node"] if steps else "n0"
        steps.append({"i": len(steps) + 1, "phase": ph, "node": node,
                      "edge": [prev, node] if prev != node else None,
                      "headline": f"{a['tool']} ({ph})",
                      "say": f"The agent ran {a['tool']}: {a['detail'][:140]}",
                      "action_idx": a["i"], "command": a["detail"][:600], "evidence": None})
    loot = ex["loot"]
    if loot["kind"] != "none":
        nid = f"n{len(nodes)}"
        label = (f"{len(loot['findings'])} findings" if loot["kind"] == "findings"
                 else f"evidence: {Path(loot.get('path', 'loot')).name}")
        nodes.append({"id": nid, "label": label[:80], "kind": "loot", "phase": "exfil", "severity": None})
        prev = steps[-1]["node"] if steps else "n1"
        steps.append({"i": len(steps) + 1, "phase": "exfil", "node": nid,
                      "edge": [prev, nid], "headline": "Captured the proof",
                      "say": "The agent saved the proof that the attack worked.",
                      "action_idx": None, "command": "", "evidence": None})
    if not steps:
        steps = [{"i": 1, "phase": "recon", "node": "n1", "edge": ["n0", "n1"],
                  "headline": "Reached the target", "say": "The run recorded no actions.",
                  "action_idx": None, "command": "", "evidence": None}]
    present = [p for p in PHASES if any(n["phase"] == p for n in nodes)]
    return {
        "schema": SCHEMA, "session": ex["session"],
        "generated_utc": datetime.utcnow().isoformat(), "model": f"{model} (fallback)",
        "title": (ex["session"] or "Attack map")[:120], "subtitle": "",
        "target": tgt, "outcome": _outcome_guess(ex),
        "tldr": (ex["summary"] or "")[:400],
        "phases": present, "nodes": nodes, "steps": steps, "stats": ex["stats"],
    }


# ---------------------------------------------------------------- build + render

def build_storyboard(session_dir, *, client=None, model=None, force=False) -> dict:
    """Return {storyboard, cost_usd, cached, path}. Cached to storyboard.json next
    to events.json; only (re)generates (an LLM call) when missing or force=True."""
    ev_path = _events_path(session_dir)
    out = ev_path.parent / "storyboard.json"
    if out.exists() and not force:
        return {"storyboard": json.loads(out.read_text(encoding="utf-8")),
                "cost_usd": 0.0, "cached": True, "path": str(out)}
    ex = extract(session_dir)
    client = client or _client()
    sb = narrate(ex, client=client, model=model or MODEL)
    out.write_text(json.dumps(sb, indent=2), encoding="utf-8")
    return {"storyboard": sb, "cost_usd": round(getattr(client, "cost_usd", 0.0), 6),
            "cached": False, "path": str(out)}


_TEMPLATE = ROOT / "dashboard" / "player.html"
_PLACEHOLDER = "__STORYBOARD__"


def render_html(storyboard, template_path=None) -> str:
    """Inline a storyboard into the self-contained player template -> standalone HTML.
    Used identically by the dashboard /replay endpoint and the CLI export."""
    tpl = Path(template_path or _TEMPLATE).read_text(encoding="utf-8")
    payload = json.dumps(storyboard).replace("</", "<\\/")  # safe inside <script>
    return tpl.replace(_PLACEHOLDER, payload)
