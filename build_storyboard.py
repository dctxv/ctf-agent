"""Build an attack-map storyboard for a finished session, and optionally export a
standalone, shareable HTML replay.

  python build_storyboard.py <session>            # generate storyboard.json (one LLM call)
  python build_storyboard.py <session> --export out.html --open
  python build_storyboard.py <session> --force    # regenerate even if cached

<session> is a session id under workspace/sessions (e.g. c05-sqli-union-dump/run_01
or audit-anxolerd-dvpwa) or a path to a session directory. Generation makes a single
cheap LLM call and caches storyboard.json next to events.json; --export renders that
into the self-contained player (dashboard/player.html) that anyone can open offline.
"""
import argparse
import sys
import webbrowser
from pathlib import Path

from dotenv import load_dotenv

from agent import storyboard

try:  # keep a cp1252 console from crashing on UTF-8 output
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SESSIONS = storyboard.WORKSPACE / "sessions"


def resolve_session(arg: str) -> Path:
    p = Path(arg)
    if p.is_dir():
        return p
    cand = SESSIONS / arg
    if cand.is_dir():
        return cand
    sys.exit(f"session not found: {arg}\n(looked for a directory, and under {SESSIONS})")


def main():
    ap = argparse.ArgumentParser(description="Build an animated attack-map storyboard for a session.")
    ap.add_argument("session", help="session id under workspace/sessions, or a session directory")
    ap.add_argument("--model", default=None, help="LLM model id (default: deepseek-flash)")
    ap.add_argument("--force", action="store_true", help="regenerate even if storyboard.json exists")
    ap.add_argument("--export", metavar="PATH", help="also write a standalone shareable HTML replay")
    ap.add_argument("--open", action="store_true", help="open the exported HTML in a browser")
    args = ap.parse_args()

    load_dotenv()
    sdir = resolve_session(args.session)

    r = storyboard.build_storyboard(sdir, model=args.model, force=args.force)
    sb = r["storyboard"]
    where = "cached" if r["cached"] else f"generated (${r['cost_usd']})"
    print(f"storyboard {where}: {r['path']}")
    print(f"  title   : {sb.get('title')}")
    print(f"  outcome : {sb.get('outcome')}  |  {len(sb.get('steps', []))} steps  |  "
          f"{len(sb.get('nodes', []))} nodes  |  phases: {', '.join(sb.get('phases', []))}")
    if "(fallback)" in str(sb.get("model", "")):
        print("  note    : the model did not return usable JSON; used the deterministic fallback.")

    if args.export:
        out = Path(args.export)
        out.write_text(storyboard.render_html(sb), encoding="utf-8")
        print(f"exported standalone replay: {out.resolve()}")
        if args.open:
            webbrowser.open(out.resolve().as_uri())
    elif args.open:
        print("(--open needs --export: there is no standalone file to open otherwise)")


if __name__ == "__main__":
    main()
