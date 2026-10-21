"""Bug-bounty scope mode: build a PROPOSED engagement from a program's scope.

  python run_bugbounty.py --handle <program>                      # HackerOne API (H1_API_USERNAME + H1_API_TOKEN in .env)
  python run_bugbounty.py --scope-file scope.json --name <program>

Writes workspace/engagements/bb-<program>.json for you to REVIEW, then launch
manually (`python main.py <that file>`). Scope is never auto-applied and the
agent is not started here - the allowlist stays operator-controlled.
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

from agent.bugbounty import (parse_scope, build_engagement_proposal,
                             fetch_hackerone_scope, wildcard_overlaps)

ROOT = Path(__file__).resolve().parent


def main():
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("--handle", help="HackerOne program handle")
    ap.add_argument("--platform", default="hackerone", choices=["hackerone"])
    ap.add_argument("--scope-file", help="local JSON scope (a list, or a HackerOne data[] object)")
    ap.add_argument("--name", help="program name (for --scope-file)")
    ap.add_argument("--workspace", default="workspace")
    a = ap.parse_args()

    if a.scope_file:
        data = json.loads(Path(a.scope_file).read_text(encoding="utf-8"))
        items = data.get("data", data) if isinstance(data, dict) else data
        program = a.name or Path(a.scope_file).stem
    elif a.handle:
        user, tok = os.environ.get("H1_API_USERNAME"), os.environ.get("H1_API_TOKEN")
        if not (user and tok):
            raise SystemExit("set H1_API_USERNAME + H1_API_TOKEN in .env to fetch HackerOne scope, "
                             "or use --scope-file <file>")
        items = fetch_hackerone_scope(a.handle, user, tok)
        program = a.handle
    else:
        raise SystemExit("give --handle <program> or --scope-file <file> [--name <program>]")

    scope = parse_scope(items)
    eng = build_engagement_proposal(program, scope, workspace=a.workspace)

    outdir = ROOT / "workspace" / "engagements"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / f"{eng['engagement_name']}.json"
    runnable = {k: v for k, v in eng.items() if not k.startswith("_")}
    out.write_text(json.dumps(runnable, indent=2), encoding="utf-8", newline="\n")

    print(f"[{program}] parsed scope: {len(scope['in_scope_hosts'])} in-scope hosts, "
          f"{len(scope['out_of_scope'])} out-of-scope, {len(scope['other_assets'])} non-host assets")
    print("PROPOSED allowed_hosts (REVIEW before running):")
    for h in scope["in_scope_hosts"]:
        print("   ", h)
    if scope["out_of_scope"]:
        print("excluded (out of scope):", ", ".join(e["host"] for e in scope["out_of_scope"] if e["host"]))
    overlaps = wildcard_overlaps(scope["in_scope_hosts"],
                                 [e["host"] for e in scope["out_of_scope"] if e["host"]])
    if overlaps:
        print("\n!! SCOPE WARNING: these out-of-scope hosts fall UNDER an in-scope wildcard and")
        print("   would be allowed by it. Narrow the allowlist manually before running:")
        for h in overlaps:
            print("     -", h)
    print(f"\n[proposal] {out}")
    print(f"Review the allowed_hosts, then launch manually:  python main.py {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
