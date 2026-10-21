"""Vuln-regression diff between two audit sessions.

  python run_retest.py <baseline-session> <current-session>

Loads each session's findings.json and reports new / fixed / still-open,
writing retest.md next to the current session's findings.
"""
import argparse
import json
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from pathlib import Path

from agent.findings import load_findings
from agent.regression import diff_findings, render_retest

ROOT = Path(__file__).resolve().parent
SESSIONS = ROOT / "workspace" / "sessions"


def _findings_dir(session):
    sdir = SESSIONS / session
    ev = next((p for p in (sdir / "events.json", sdir / "events.jsonl") if p.exists()), None)
    if ev is None:
        raise SystemExit(f"session not found: {session}")
    events = ([json.loads(l) for l in ev.read_text(encoding="utf-8").splitlines() if l.strip()]
              if ev.suffix == ".jsonl" else json.loads(ev.read_text(encoding="utf-8")))
    audit = next((e["data"].get("_audit") for e in events if e.get("type") == "session_start"), None)
    if not audit or "findings" not in audit:
        raise SystemExit(f"{session} is not an audit session")
    return (ROOT / "workspace" / audit["findings"]).parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("baseline", help="earlier audit session")
    ap.add_argument("current", help="later audit session")
    a = ap.parse_args()
    old = load_findings(_findings_dir(a.baseline))
    cur_dir = _findings_dir(a.current)
    new = load_findings(cur_dir)
    diff = diff_findings(old, new)
    print(f"[retest] {a.baseline} ({len(old)}) -> {a.current} ({len(new)}): "
          f"new={len(diff['new'])} fixed={len(diff['fixed'])} still_open={len(diff['still_open'])}")
    out = cur_dir / "retest.md"
    out.write_text(render_retest(diff, a.baseline, a.current), encoding="utf-8", newline="\n")
    print(f"[retest] {out}")


if __name__ == "__main__":
    main()
