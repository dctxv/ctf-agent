"""Validate the GitHub audit mode by recall against repos with known issues.

For each repo in the spec it checks whether the audit's findings cover the
expected issue classes (by CWE or keyword), computes recall, and appends a row
to results.csv (challenge = ghval-<owner>-<repo>).

  python validate_github.py                 # reuse existing audits (free)
  python validate_github.py --audit         # (re)audit each repo first (costs API)
"""
import argparse
import csv
import json
import subprocess
import sys
from datetime import datetime, timezone

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from pathlib import Path

from dotenv import load_dotenv

from agent.findings import load_findings
from agent.adapters import github_engagement_name

ROOT = Path(__file__).resolve().parent
SESSIONS = ROOT / "workspace" / "sessions"
RESULTS = ROOT / "results.csv"
FIELDS = ["timestamp_utc", "git_sha", "model", "challenge", "run_index", "solved",
          "finished_naturally", "steps", "cost_usd", "escalations", "ask_human",
          "budget_hits", "duration_s", "error"]


def _git_sha():
    try:
        r = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() or "nogit"
    except Exception:
        return "nogit"


def _session_stats(name):
    sdir = SESSIONS / name
    ev = next((p for p in (sdir / "events.json", sdir / "events.jsonl") if p.exists()), None)
    if not ev:
        return None
    events = ([json.loads(l) for l in ev.read_text(encoding="utf-8").splitlines() if l.strip()]
              if ev.suffix == ".jsonl" else json.loads(ev.read_text(encoding="utf-8")))
    audit = next((e["data"].get("_audit") for e in events if e.get("type") == "session_start"), None)
    cost = max([e["data"].get("total_usd", 0) for e in events if e.get("type") == "cost_update"] + [0])
    steps = sum(1 for e in events if e.get("type") == "tool_call")
    fdir = (ROOT / "workspace" / audit["findings"]).parent if (audit and "findings" in audit) else None
    return {"findings_dir": fdir, "cost": cost, "steps": steps}


def _matched(expected, findings):
    for f in findings:
        if expected.get("cwe") and str(f.get("cwe", "")).upper() == expected["cwe"].upper():
            return True
        if expected.get("keyword") and expected["keyword"].lower() in \
                (str(f.get("title", "")) + " " + str(f.get("description", ""))).lower():
            return True
    return False


def main():
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", default="challenges/github_validation.json")
    ap.add_argument("--audit", action="store_true", help="(re)audit each repo before scoring")
    ap.add_argument("--max-steps", type=int, default=40)
    a = ap.parse_args()

    spec = json.loads((ROOT / a.spec).read_text(encoding="utf-8"))
    sha = _git_sha()
    rows = []
    for entry in spec:
        url, expected = entry["repo"], entry.get("expected", [])
        name = github_engagement_name(url)
        if a.audit or not (SESSIONS / name).exists():
            print(f"[audit] {url} ...")
            subprocess.run([sys.executable, str(ROOT / "run_audit.py"), "--github", url,
                            "--unattended", "--max-steps", str(a.max_steps)], cwd=str(ROOT))
        stats = _session_stats(name)
        if not stats or not stats["findings_dir"]:
            print(f"[{name}] no audit output; skipping")
            continue
        findings = load_findings(stats["findings_dir"])
        hits = [e for e in expected if _matched(e, findings)]
        missing = [e["label"] for e in expected if e not in hits]
        recall = len(hits) / len(expected) if expected else 0.0
        print(f"[{name}] recall {len(hits)}/{len(expected)} ({recall:.0%}) | "
              f"findings={len(findings)} | missing={missing or 'none'}")
        rows.append({
            "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "git_sha": sha, "model": "deepseek-flash",
            "challenge": f"ghval-{name[len('audit-'):]}", "run_index": 1,
            "solved": recall == 1.0, "finished_naturally": True,
            "steps": stats["steps"], "cost_usd": round(stats["cost"], 4),
            "escalations": 0, "ask_human": 0, "budget_hits": 0, "duration_s": 0,
            "error": f"recall {len(hits)}/{len(expected)}" + (f" missing {missing}" if missing else ""),
        })

    new = not RESULTS.exists()
    with open(RESULTS, "a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        if new:
            w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"[validate] appended {len(rows)} row(s) to results.csv")


if __name__ == "__main__":
    main()
