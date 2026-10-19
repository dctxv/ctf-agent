# c07 — Admin session token WITHOUT SQL injection

**Target:** http://host.docker.internal:3000 (OWASP Juice Shop **20.3.0**)
**Goal:** obtain an admin-session token with **no SQLi** (no `' OR 1=1`, no `UNION`, no tautology).
**Status:** ✅ COMPLETE — admin-session token minted and accepted by the server.
**Deliverable:** `/workspace/evidence/c7_no_sqli_token.txt` (forged HS256 admin JWT)
**PoC:** `/workspace/pocs/forge_admin_jwt.py`

---

## Primary method — JWT algorithm confusion (RS256 → HS256)

### What we observed
1. The app exposes its RSA **public** key (public by design):
   ```
   GET /encryptionkeys/jwt.pub   ->  248-byte PEM "BEGIN RSA PUBLIC KEY"
   ```
2. A normal login returns an **RS256** JWT:
   `header {"typ":"JWT","alg":"RS256"}`, payload `{"data":{...,"role":"customer"...},"bid":N,"iat":...}`.
3. Signature handling is **not algorithm-pinned** server-side. The app calls effectively
   `jwt.verify(token, publicKey)` with no `{ algorithms: ['RS256'] }`, so the
   `jsonwebtoken` library selects the verification primitive from the token's own
   `alg` header. A token declaring `alg: HS256` is verified as **HMAC-SHA256 with the
   RSA public-key text as the HMAC secret** — and that text is public.

### Exploit
Forge a token whose payload sets `data.role = "admin"`, `data.id = 1`,
`data.email = "admin@juice-sh.op"`, and sign it:
```
HMAC-SHA256(key = PEM contents of /encryptionkeys/jwt.pub, msg = base64url(header)+"."+base64url(payload))
```
Result is a signature-valid token the server accepts as an admin session.
`pocs/forge_admin_jwt.py` downloads the key, mints the token, proves acceptance,
and writes the deliverable.

### Proof the server really verifies signatures (not just decodes)
| token | `GET /api/Users` | meaning |
|---|---|---|
| forged, correct HMAC(pubkey) signature | **200** (24 users, role admin) | accepted |
| forged payload, **tampered** signature (`00…`) | **401 `invalid signature`** | signature is checked |
| `alg:none`, empty signature | **200** | secondary flaw: unsigned JWTs also accepted |

Because the tampered token is rejected while the correctly-HMAC-signed token
(with the *public* key as secret) is accepted, the RS256→HS256 confusion is real.

---

## Corroborating / alternative non-SQLi paths (also verified this run)

- **`alg:none` unsigned JWT** — a header `{"alg":"none"}` with empty signature and
  `role:admin` is also accepted (HTTP 200). Root cause: `none` not disallowed in verify options.
- **Default / weak admin credential** — `POST /rest/user/login`
  `admin@juice-sh.op` : `admin123` returns **HTTP 200** with a *genuine* RS256 admin JWT
  (payload `data.role == "admin"`, `data.id == 1`).
  This token is saved separately at
  `/workspace/evidence/c7_genuine_rs256_admin_token.txt` and was used as an
  independent control to confirm that `role:admin` is the correct admin session.
  (`md5("admin123") = 0192023a7bbd73250516f069df18b500`, matching the hash embedded
  in the JWT payload.)

Both alternative paths involve **zero SQL syntax**.

---

## Note on `/api/Users/:id` PUT/DELETE
Those mutation routes return `401 DECODER routines::unsupported` for **every** token,
including the genuine RS256 admin token — i.e., that code path is mis-configured /
broken independently of our forgery. It does not diminish the admin session: all
working authenticated endpoints (`GET /api/Users`, `GET /rest/user/authentication-details`)
accept the forged token and return role-admin data.

## Root cause
`jsonwebtoken.verify()` called without an `algorithms` allow-list → algorithm
confusion (CWE-347 / CWE-327), combined with public exposure of the RSA public key.
Secondary: `alg:none` accepted; weak default administrator password.

## Remediation
- Always pass `jwt.verify(token, pubkey, { algorithms: ['RS256'] })`; reject `none`.
- Never reuse the same key material for both asymmetric and symmetric verification.
- Enforce a strong, randomised admin password (no `admin123`); migrate off MD5.
