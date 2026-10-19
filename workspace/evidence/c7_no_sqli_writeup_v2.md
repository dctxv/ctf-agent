# c07 — Admin session token WITHOUT SQL injection (independent re-verification)

**Target:** http://host.docker.internal:3000 — OWASP Juice Shop **20.3.0**
**Constraint:** no SQLi whatsoever — no `' OR 1=1`, no `UNION`, no tautology, no quote characters in any payload.
**Deliverable:** `/workspace/evidence/c7_no_sqli_token.txt` — **genuine RS256 admin JWT** (`data.role = admin`, `data.id = 1`)
**PoCs:**
- `pocs/c7_no_sqli_admin_login.py` — vector A (default credentials) → writes the deliverable
- `pocs/c7_forge_hs256_admin.py` — vector B (JWT algorithm confusion) → `evidence/c7_forged_hs256_admin_token.txt`
- `pocs/c7_jwt_confusion_check.py` — minimal independent check of vector B

Every claim below was executed in this session; nothing is asserted from prior notes.

---

## Vector A (deliverable) — weak/default administrator credential

`POST /rest/user/login` with `{"email":"admin@juice-sh.op","password":"admin123"}` → **HTTP 200**,
returns an RS256 JWT whose payload is:

```
{"data":{"id":1,"email":"admin@juice-sh.op","role":"admin","password":"0192023a7bbd73250516f069df18b500",...},
 "bid":1,"iat":...}
```

`md5("admin123") = 0192023a7bbd73250516f069df18b500` — matches the hash embedded in the token.

Proof of privilege (not just a claim in a JSON field):

| request (Bearer token) | result |
|---|---|
| `GET /rest/user/authentication-details/` (admin-only) | **200**, 23 accounts incl. 2 admins |
| `GET /api/Users` (admin-only, hashes + PII) | **200**, 6618 bytes |
| `GET /api/Feedbacks` (admin-only) | **200** |

## Vector B (credential-independent) — JWT algorithm confusion RS256 → HS256

`/encryptionkeys/` is directory-listed and `jwt.pub` (248-byte `BEGIN RSA PUBLIC KEY`) is served
anonymously. The server verifies JWTs without an `algorithms` allow-list, so `jsonwebtoken` trusts the
token's own `alg` header: an `alg: HS256` token is verified as HMAC-SHA256 using the **public key text
as the HMAC secret**. Forging `data.role="admin"` and signing with that public text yields an accepted
admin session — no login, no password, no injection.

| token | `GET /api/Users` | meaning |
|---|---|---|
| forged HS256(public-key), role=admin | **200** (6618 B) | accepted as admin |
| same payload, **tampered** signature | **401** `invalid signature` | signatures *are* verified → bypass is real |
| `{"alg":"none"}`, empty signature | **200** | secondary flaw: unsigned JWTs accepted |

## Corroborating exposure (used only to strengthen impact)
- The JWT payload, `/api/Users` and `/rest/user/authentication-details` all leak **unsalted MD5**
  password hashes for all 23 users → offline cracking / credential reuse.
- A second administrative account exists: `bjoern.kimminich@gmail.com` (role `admin`).
- `/encryptionkeys/jwt.pub` and `/encryptionkeys/premium.key` are downloadable.

## Root causes
1. `jsonwebtoken.verify(token, pubkey)` called without `{ algorithms: ['RS256'] }` → algorithm
   confusion (CWE-347 / CWE-327); `none` also permitted.
2. Built-in admin account with a trivial, well-known password (`admin123`); MD5 without salt.
3. Sensitive password hashes placed inside the JWT payload.
4. Directory listing of cryptographic key material.

## Remediation
- Pin `algorithms: ['RS256']`; reject `none`; never let one key serve both asymmetric and symmetric verification.
- Force a strong unique admin password; migrate from unsalted MD5 to Argon2id/bcrypt.
- Remove the `password` field from JWT claims.
- Disable directory listing on `/encryptionkeys/`; rotate exposed `premium.key`.
