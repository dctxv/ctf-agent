"""Generate a post-session study aid (writeup + concepts + flashcards) from a saved session.

  python run_learn.py <session_dir_or_name>

Examples:
  python run_learn.py audit-dvpwa
  python run_learn.py workspace/sessions/c03-sqli-admin

Reads the session's events.json and writes learning.md + flashcards.json next to it.
"""
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from pathlib import Path

from dotenv import load_dotenv

from agent.learn import generate_learning


def resolve(arg):
    p = Path(arg)
    if p.exists():
        return p
    cand = Path("workspace") / "sessions" / arg
    if cand.exists():
        return cand
    raise SystemExit(f"session not found: {arg}")


def main():
    load_dotenv()
    if len(sys.argv) < 2:
        raise SystemExit("usage: python run_learn.py <session_dir_or_name>")
    sd = resolve(sys.argv[1])
    r = generate_learning(sd)
    print(f"[learning]   {r['learning_md']}")
    print(f"[flashcards] {r['flashcards']} ({r['n_cards']} cards)")
    print(f"[tokens] in={r['tokens_in']} out={r['tokens_out']}")


if __name__ == "__main__":
    main()
