# c07 — Admin session token WITHOUT SQL injection

**Target:** http://host.docker.internal:3000 (OWASP Juice Shop 20.3.0)
**Result:** Obtained a server-signed admin JWT (`role: "admin"`), saved to
`/workspace/evidence/c7_no_sqli_token.txt`.

## Vulnerability
Mass assignment / insecure direct object property on user registration
(`POST /api/Users`). The endpoint accepts a client-supplied `role` field and
persists it verbatim.

## Exploit chain (no SQL injection)
1. `POST /api/Users` with body:
   ```json
   {"email":"poc_admin_<ts>@test.local","password":"<pw>","passwordRepeat":"<pw>","role":"admin"}
   ```
   -> account created with `role: "admin"` and `defaultAdmin.png` avatar.
2. `POST /rest/user/login` with those credentials -> RS256-signed JWT whose
   payload contains `"role":"admin"`.
3. Token successfully used to enumerate all 27 accounts (incl. built-in
   `admin@juice-sh.op`).

## Why this is an admin session
The role authorization used throughout the app is driven by the `role` claim in
the JWT. This token carries `"role":"admin"`, so any role-check treats it as an
administrator — same as the built-in admin account.

## Note on role-gating in this build
Several `/rest/admin/*` routes are not strictly role-gated (they returned 200
even anonymously in this build), so the definitive proof of privilege is the
signed `role: "admin"` claim + admin avatar + access to user enumeration.

## Artifacts
- `pocs/c7_mass_assignment_admin.py` — end-to-end PoC (registers, logs in,
  writes token, validates).
- `evidence/c7_no_sqli_token.txt` — the admin JWT.
- `evidence/reg_normal.json`, `evidence/reg_admin.json`, `evidence/admin_login.json`
  — raw request/response captures.

## Accounts created during testing (non-destructive)
- id 25 probe1@test.local (customer)
- id 26 probeadmin@test.local (admin)
- id 28 poc_admin_<ts>@test.local (admin)
