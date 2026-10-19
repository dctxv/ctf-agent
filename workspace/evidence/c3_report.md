# c03-sqli-admin — SQL injection in Juice Shop login → admin takeover

## Vulnerability
`POST /rest/user/login` builds its Sequelize query by string concatenation on the
`email` field. No parameterization, so injection is possible:

```
POST /rest/user/login HTTP/1.1
Content-Type: application/json

{"email":"' OR 1=1--","password":"anything"}
```

The payload closes the string literal, makes the WHERE clause always true, and
`--` comments out the remainder of the query (the password comparison). The DB
therefore returns the **first row of the Users table — id 1, admin@juice-sh.op
(role: admin)** — and the app signs a JWT for that identity. No password needed.

## Impact
- Unauthenticated admin authentication / full administrative API access.
- Token leaks the admin user object, including the MD5 password hash
  `0192023a7bbd73250516f069df18b500` (= "admin123") and email address.

## Evidence
- `evidence/c3_admin_token.txt` — admin RS256 JWT (starts with `eyJ`)
- Decoded claims: `sub/data.id=1`, `email=admin@juice-sh.op`, `role=admin`, `bid=1`

### Privilege verification (with token vs. without)
| endpoint | with token | anonymous |
|---|---|---|
| GET /rest/user/authentication-details | 200 | 401 |
| GET /api/Users | 200 | 401 |
| GET /rest/admin/application-configuration | 200 | — |

## PoC
`pocs/c03_sqli_admin_login.py` — sends the injection, validates `role=admin`,
writes the token to `/workspace/evidence/c3_admin_token.txt`, and re-checks an
admin-only endpoint.

```
python3 pocs/c03_sqli_admin_login.py
```

## Remediation
Use parameterized queries (Sequelize `where: { email }` with escaping/validation),
reject syntactically invalid emails, and never rely on DB row ordering for
identity resolution.
