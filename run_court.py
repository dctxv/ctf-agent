"""Run the findings court over an audit's findings.json (adversarial verify).

  python run_court.py <audit-session>          # verify with the cheap loop model
  python run_court.py <audit-session> --pro    # verify with the stronger model

Merges verdict / court_confidence / court_reason into findings.json and prints a
confirmed / refuted / uncertain summary.
"""
import argparse
import json
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from pathlib import Path

from dotenv import load_dotenv

from agent.court import verify_findings, MODEL
from agent.agent import MODELS

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
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("session", help="audit session name under workspace/sessions")
    ap.add_argument("--pro", action="store_true", help="use the stronger model for verification")
    a = ap.parse_args()
    model = MODELS["escalate"] if a.pro else MODEL
    findings, summary = verify_findings(_findings_dir(a.session), model=model)
    print(f"[court] model={model} | {summary}")
    mark = {"confirmed": "OK ", "refuted": "XX ", "uncertain": "?? "}
    for f in findings:
        print(f"  {mark.get(f.get('verdict'), '?? ')}"
              f"{(f.get('severity', '?') or '?').upper().ljust(8)} "
              f"{(f.get('title', '') or '')[:48]}  -> {(f.get('court_reason', '') or '')[:70]}")


if __name__ == "__main__":
    main()
