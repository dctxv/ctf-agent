# c06 — Verbose Error / Stack-Trace Disclosure

**Target:** `http://host.docker.internal:3000` (OWASP Juice Shop, lab)
**PoC:** `pocs/c6_error_disclosure.py` (run: `python3 pocs/c6_error_disclosure.py`)
**Evidence:** `evidence/c6_error.txt`, raw HTTP transcripts in `evidence/c6_error_raw_responses.txt`

## Root cause
The Express app is deployed with the **default (development) error handler**, so any
uncaught exception is rendered to the client as an HTML page containing the exception
message, the Express/app version banner, and the full Node.js stack trace with
absolute container paths. Nothing is logged-only; everything is reflected.

## Triggers (5/5 confirmed, all HTTP 500)

| # | Request | Disclosed error |
|---|---------|-----------------|
| 1 | `POST /rest/user/login` with body `{"email":` | `SyntaxError: Unexpected end of JSON input` + 15-frame stack incl. `/juice-shop/build/server.js:357:33` |
| 2 | `GET /rest/products/search?q=%27--` | `Error: SQLITE_ERROR: incomplete input` (raw DB engine message) |
| 3 | `POST /api/Feedbacks` with `{}` | `Error: WHERE parameter "captchaId" has invalid "undefined" value` + Sequelize stack, `/juice-shop/build/routes/captcha.js:33:25` |
| 4 | `POST /dataerasure` with `{}` | `Error: Blocked illegal activity by ::ffff:172.17.0.1` + stack, `/juice-shop/build/routes/dataErasure.js:104:18` |
| 5 | `GET /rest/products/search?q=apple%27` | `Error: SQLITE_ERROR: near "'%'": syntax error` |

Every page also carried the banner `OWASP Juice Shop (Express ^4.22.1)`.

## Impact
* Absolute filesystem paths + module layout (`/juice-shop/build/...`, `node_modules/sequelize/...`)
  → reconnaissance for path traversal / LFI / source review.
* Framework & ORM versions → CVE targeting.
* Raw SQLite error strings → error-based SQL injection iteration (ties directly into the
  UNION SQLi finding in `poc2_sqli_union_dump.py`).
* Internal source IP `::ffff:172.17.0.1` → internal network mapping.

## Remediation
* Run Express in `production` (`NODE_ENV=production`) so the generic error handler is used.
* Never return ORM/DB error strings; map to opaque codes and log server-side only.
* Add central error middleware that returns a generic message + correlation ID.
* Validate body content-type/size and reject malformed JSON with a 400, not a 500.
