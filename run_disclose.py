"""Responsible-disclosure export from an audit's findings.json.

  python run_disclose.py <audit-session>                 # render disclosure.md + issue drafts
  python run_disclose.py <audit-session> --file-issues   # also file them, OWN repos only

Auto-filing is gated: issues are filed only if the GITHUB_TOKEN (in .env) has
push/admin on the target repo. Third-party repos are refused and get the
advisory Markdown for manual, coordinated disclosure.
"""
import argparse
import json
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from pathlib import Path

from dotenv import load_dotenv

from agent.findings import load_findings
from agent import disclosure as D

ROOT = Path(__file__).resolve().parent
SESSIONS = ROOT / "workspace" / "sessions"


def _audit_meta(session):
    sdir = SESSIONS / session
    ev = next((p for p in (sdir / "events.json", sdir / "events.jsonl") if p.exists()), None)
    if ev is None:
        raise SystemExit(f"session not found or has no events: {session}")
    if ev.suffix == ".jsonl":
        events = [json.loads(l) for l in ev.read_text(encoding="utf-8").splitlines() if l.strip()]
    else:
        events = json.loads(ev.read_text(encoding="utf-8"))
    audit = next((e["data"].get("_audit") for e in events if e.get("type") == "session_start"), None)
    if not audit or "findings" not in audit:
        raise SystemExit(f"{session} is not an audit session (no findings path)")
    return audit


def main():
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("session", help="audit session name under workspace/sessions")
    ap.add_argument("--repo", help="owner/name (defaults to the audited GitHub repo)")
    ap.add_argument("--file-issues", action="store_true", help="file GitHub issues (own repos only)")
    a = ap.parse_args()

    audit = _audit_meta(a.session)
    findings_dir = (ROOT / "workspace" / audit["findings"]).parent
    findings = load_findings(findings_dir)
    refuted = [f for f in findings if f.get("verdict") == "refuted"]
    if refuted:  # court-refuted findings are likely hallucinations; keep them out of disclosure
        findings = [f for f in findings if f.get("verdict") != "refuted"]
    repo = a.repo or audit.get("repo")
    print(f"[{a.session}] {len(findings)} findings"
          + (f" ({len(refuted)} refuted, dropped)" if refuted else "")
          + f" | repo: {repo or '(none)'}")
    if not findings:
        raise SystemExit("no findings to export")

    out = findings_dir / "disclosure.md"
    out.write_text(D.render_advisory(findings, repo), encoding="utf-8", newline="\n")
    print(f"[advisory] {out}")

    issues = D.render_issues(findings, repo)
    print(f"[issues] {len(issues)} drafted:")
    for iss in issues[:8]:
        print("  -", iss["title"])

    if not a.file_issues:
        print("\n(dry run) pass --file-issues to file these on a repo you own.")
        return

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GITHUB_TOKEN not set in .env - cannot file issues.")
    if not repo or "/" not in repo:
        raise SystemExit("no owner/name repo for this audit; pass --repo owner/name.")
    owner, name = repo.split("/", 1)

    can_write, code = D.repo_access(owner, name, token)
    if not can_write:
        print(f"\nREFUSING to auto-file: the token has no push/admin on {repo} (HTTP {code}).")
        print(f"This is not your repo (or not authorized). Use {out} for responsible")
        print("disclosure to the maintainers (their security policy / a private Security Advisory).")
        return

    who = D.whoami(token)
    print(f"\n{repo} is writable by {who}. Filing {len(issues)} issues "
          f"(note: a public issue is public disclosure)...")
    for iss in issues:
        try:
            print("  filed:", D.create_issue(owner, name, iss["title"], iss["body"], iss["labels"], token))
        except Exception as e:
            print("  FAILED:", iss["title"], "->", str(e)[:120])


if __name__ == "__main__":
    main()
