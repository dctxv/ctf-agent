#!/usr/bin/env python3
"""
c04-find-scoreboard : discover the hidden, unlinked "score board" page URL
on OWASP Juice Shop (authorized lab instance).

Discovery path (3 independent signals, all cross-checked):

 1. RFC 9116 security.txt disclosure
    GET /.well-known/security.txt  ->  "Acknowledgements: /#/score-board"
    (Juice Shop ships this field pointing at the score board as a
     "thanks for reporting" link -> information leak of a hidden route)

 2. Client source code / Angular route table
    GET /main.js  ->  {path:`score-board`,component:f0}
    The route exists in the SPA router but the nav-bar link is only
    rendered inside the "score board" side-menu that is not part of the
    default UI, i.e. the page is unlinked/hidden.

 3. Routing strategy -> decides whether the URL needs a '#'
    GET /main.js  ->  RouterModule.forRoot(...,{useHash:!0})
    HashLocationStrategy is in use, so the client-side URL is
    <base>/#/score-board.  Requesting '/score-board' without the hash
    does NOT reach the component (it falls through to the 404 view)
    even though the SPA returns HTTP 200 for every path.

Output: /workspace/evidence/c4_scoreboard_url.txt
"""

import re
import sys
import urllib.request

BASE = "http://host.docker.internal:3000"
OUT = "/workspace/evidence/c4_scoreboard_url.txt"


def get(path, timeout=20):
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "c04-pentest/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")


def main():
    findings = {}

    # ---- Signal 1: security.txt -------------------------------------------
    try:
        st, body = get("/.well-known/security.txt")
        m = re.search(r"(?im)^\s*Acknowledgements:\s*(\S+)\s*$", body)
        findings["security_txt"] = m.group(1) if m else None
        print(f"[1] security.txt (HTTP {st}) Acknowledgements -> {findings['security_txt']}")
    except Exception as e:
        findings["security_txt"] = None
        print(f"[1] security.txt fetch failed: {e}")

    # ---- Signal 2 & 3: bundled Angular app --------------------------------
    st, js = get("/main.js")
    print(f"[2] main.js fetched (HTTP {st}, {len(js)} bytes)")

    route = re.search(r"path:`score-board`,component:(\w+)", js)
    use_hash = re.search(r"useHash:\s*!0", js)          # !0 === true
    guard = re.search(r"path:`score-board`,component:\w+,canActivate", js)

    findings["route_present"] = bool(route)
    findings["route_component"] = route.group(1) if route else None
    findings["hash_routing"] = bool(use_hash)
    findings["guarded"] = bool(guard)

    print(f"[2] route 'score-board' in router: {findings['route_present']} "
          f"(component {findings['route_component']})")
    print(f"[3] HashLocationStrategy (useHash:!0): {findings['hash_routing']}")
    print(f"[3] route has canActivate guard (auth required): {findings['guarded']}")

    # nav-link evidence: the entry point is buried in a settings/side menu
    for m in re.finditer(r"routerLink`,?`/score-board", js):
        snippet = js[max(0, m.start() - 60):m.start() + 60]
        print(f"[2] nav entry point found: ...{snippet.strip()}...")
        break

    # ---- Decide the exact URL --------------------------------------------
    if findings["route_present"] and findings["hash_routing"]:
        url = BASE + "/#/score-board"
    elif findings["route_present"]:
        url = BASE + "/score-board"
    else:
        print("[-] could not confirm the route", file=sys.stderr)
        return 1

    print(f"\n[+] HIDDEN SCORE BOARD URL: {url}")

    with open(OUT, "w", newline="\n") as f:
        f.write(url + "\n")
    print(f"[+] saved -> {OUT}")

    ok = findings["route_present"] and findings["hash_routing"]
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
