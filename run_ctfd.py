"""Run an engagement sourced from a CTFd instance via CTFdAdapter.

  python run_ctfd.py --list                       # enumerate challenges
  python run_ctfd.py <id> --dry-run               # build engagement + download files, no agent run
  python run_ctfd.py <id> --allowed-hosts 10.0.0.5[,host2]
  python run_ctfd.py <id> --submit                # after the run, submit the recovered flag

CTFD_URL and CTFD_TOKEN come from the environment (.env). Scope is NOT taken from
platform data: the agent can reach a network target only via --allowed-hosts that
you pass. With none, the engagement runs file-only (every host blocked).
"""
import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

from agent.agent import AgentSession
from agent.adapters import CTFdAdapter
from agent.privacy import from_engagement

try:  # remote/tool output is UTF-8; don't let a cp1252 console crash on it
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def human_input(question):
    print(f"\n>>> AGENT NEEDS YOU: {question}")
    return input("Your answer: ")


def main():
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("challenge_id", nargs="?", help="CTFd challenge id")
    ap.add_argument("--list", action="store_true", help="list challenges and exit")
    ap.add_argument("--dry-run", action="store_true", help="build engagement + download files, do not run the agent")
    ap.add_argument("--allowed-hosts", default="", help="comma-separated authorized hosts for scope")
    ap.add_argument("--workspace", default="workspace", help="workspace dir (default: workspace)")
    ap.add_argument("--submit", action="store_true", help="submit the recovered flag after the run")
    ap.add_argument("--privacy", action="store_true",
                    help="anonymize target identifiers before the model API")
    ap.add_argument("--max-steps", type=int, default=40)
    ap.add_argument("--max-cost", type=float, default=1.0)
    args = ap.parse_args()

    adapter = CTFdAdapter()
    if not adapter.base:
        sys.exit("CTFD_URL not set (put it in .env or the environment).")

    if args.list:
        for c in adapter.list_challenges():
            print(f"  [{c['id']}] {c['name']}  ({c.get('category')}, {c.get('value')} pts)")
        return
    if not args.challenge_id:
        sys.exit("Give a challenge id, or --list.")

    hosts = [h.strip() for h in args.allowed_hosts.split(",") if h.strip()]
    eng = adapter.build_engagement(args.challenge_id, allowed_hosts=hosts,
                                   workspace=args.workspace,
                                   max_steps=args.max_steps, max_cost_usd=args.max_cost)

    if eng["_suggested_hosts"]:
        print(f"[scope] challenge text mentions hosts {eng['_suggested_hosts']} - "
              f"NOT applied automatically. allowed_hosts = {eng['allowed_hosts'] or '[] (file-only)'}")

    files_dir = Path(args.workspace) / "loot" / eng["engagement_name"]
    try:
        got = adapter.download_files(args.challenge_id, files_dir)
        if got:
            print(f"[files] downloaded {len(got)}: {got}")
    except Exception as e:
        print(f"[files] download skipped/failed: {e}")

    if args.dry_run:
        print("\n[dry-run] engagement:\n" + json.dumps(
            {k: v for k, v in eng.items() if not k.startswith("_")}, indent=2))
        return

    session = AgentSession(eng, human_input, auto_learn=True,
                           privacy=from_engagement(eng) if a.privacy else None)
    try:
        session.run()
    except KeyboardInterrupt:
        session._emit("session_end", {"summary": "interrupted by human"})
        session._save_artifacts()
    print(f"\nSession cost: ${session.cost_usd:.4f} | steps: {session.steps}")

    if args.submit:
        flag_path = Path(args.workspace) / eng["evidence"]["path"]
        if not flag_path.exists():
            print(f"[submit] no flag file at {flag_path}; nothing to submit.")
            return
        flag = flag_path.read_text(errors="replace").strip()
        res = adapter.submit_flag(args.challenge_id, flag)
        print(f"[submit] {flag[:40]!r} -> {res}")


if __name__ == "__main__":
    main()
