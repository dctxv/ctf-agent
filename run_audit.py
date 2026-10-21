"""Run a code-audit engagement against a local source tree (Phase 2.5).

  python run_audit.py <source_dir> [--name N] [--dry-run] [--config auto]

--dry-run stages the code and runs semgrep in the toolbox container, printing a
findings summary, WITHOUT invoking the agent (no API cost). Without --dry-run it
builds the engagement and runs the agent on it (file-only: no network in scope).
"""
import argparse
import subprocess
import sys

from dotenv import load_dotenv

from agent.agent import AgentSession
from agent.adapters import build_code_audit_engagement
from agent.privacy import from_engagement
from agent.tools import CONTAINER

try:  # subprocess/semgrep output is UTF-8; don't let a cp1252 console crash on it
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def human_input(q):
    print(f"\n>>> AGENT NEEDS YOU: {q}")
    return input("Your answer: ")


def auto_human(q):
    print(f"[ask_human] {q[:150]}")
    return ("Unattended audit; the operator is not available. Use your best judgment, "
            "stay within the source tree, and write findings backed by real file:line "
            "evidence to the report. Do not ask again.")


def semgrep_dry_run(eng, config):
    staged = eng["_audit"]["staged"]
    name = eng["engagement_name"][len("audit-"):]
    out = f"/workspace/audit/{name}/semgrep.json"
    summary = (
        "import json,sys,os\n"
        f"p='{out}'\n"
        "if not os.path.exists(p): print('NO semgrep.json (semgrep failed - see stderr)'); sys.exit()\n"
        "d=json.load(open(p)); res=d.get('results',[])\n"
        "print('findings:',len(res))\n"
        "for r in res[:25]: print(' -',r.get('check_id'), r.get('path','').split('/')[-1]+':'+str(r.get('start',{}).get('line')))\n"
    )
    cmd = (f"semgrep --config {config} --json -o {out} {staged} 2>/tmp/sg.err; "
           f"echo \"semgrep exit=$?\"; tail -3 /tmp/sg.err; python3 - <<'PY'\n{summary}PY")
    r = subprocess.run(["docker", "exec", CONTAINER, "bash", "-lc", cmd],
                       capture_output=True, encoding="utf-8", errors="replace", timeout=400)
    print(r.stdout)
    if r.returncode != 0 and r.stderr.strip():
        print("stderr:", r.stderr[:600])


def dep_scan_dry_run(eng):
    staged = eng["_audit"]["staged"]
    cmd = (
        "echo '--- osv-scanner ---'; "
        f"(osv-scanner scan source -r {staged} 2>/tmp/osv.err || osv-scanner -r {staged} 2>>/tmp/osv.err) | tail -40; "
        "tail -2 /tmp/osv.err 2>/dev/null; "
        "echo; echo '--- pip-audit ---'; "
        f"if ls {staged}/requirements*.txt >/dev/null 2>&1; then "
        f"for rq in {staged}/requirements*.txt; do echo \"[$rq]\"; pip-audit --no-deps -r \"$rq\" 2>&1 | tail -40; done; "
        "else echo '(no requirements.txt)'; fi"
    )
    r = subprocess.run(["docker", "exec", CONTAINER, "bash", "-lc", cmd],
                       capture_output=True, encoding="utf-8", errors="replace", timeout=400)
    print(r.stdout)
    if r.stderr.strip():
        print("stderr:", r.stderr[:400])


def main():
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("source_dir")
    ap.add_argument("--name")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--unattended", action="store_true", help="answer ask_human automatically (no prompts)")
    ap.add_argument("--privacy", action="store_true",
                    help="anonymize target identifiers before the model API")
    ap.add_argument("--config", default="auto", help="semgrep --config (default: auto)")
    ap.add_argument("--workspace", default="workspace")
    ap.add_argument("--max-steps", type=int, default=40)
    ap.add_argument("--max-cost", type=float, default=1.0)
    a = ap.parse_args()

    eng = build_code_audit_engagement(a.source_dir, a.name, workspace=a.workspace,
                                      max_steps=a.max_steps, max_cost_usd=a.max_cost)
    print(f"[staged] {eng['_audit']['source']} -> {eng['_audit']['staged']}")
    print(f"[engagement] {eng['engagement_name']} | allowed_hosts={eng['allowed_hosts']} (file-only)")
    print(f"[report target] {eng['_audit']['report']}")

    if a.dry_run:
        print(f"[dry-run] running semgrep (--config {a.config}) in container...\n")
        semgrep_dry_run(eng, a.config)
        print("\n[dry-run] running dependency scanners in container...\n")
        dep_scan_dry_run(eng)
        return

    session = AgentSession(eng, auto_human if a.unattended else human_input, auto_learn=True,
                           privacy=from_engagement(eng) if a.privacy else None)
    try:
        session.run()
    except KeyboardInterrupt:
        session._emit("session_end", {"summary": "interrupted by human"})
        session._save_artifacts()
    print(f"\nSession cost: ${session.cost_usd:.4f} | steps: {session.steps}")


if __name__ == "__main__":
    main()
