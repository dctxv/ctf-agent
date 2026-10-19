# C10 — announcement_encrypted.md: obtain + decrypt

## Vulnerabilities / techniques
1. **Directory listing enabled on `/ftp/`** (info disclosure) → revealed
   `announcement_encrypted.md` (369,237 B), `encrypt.pyc`, `incident-support.kdbx`, etc.
2. **Poison null byte** → `/ftp/encrypt.pyc` is blocked with
   `403 "Only .md and .pdf files are allowed!"`.
   `GET /ftp/encrypt.pyc%2500.md` returns the real 573-byte Python 2.7 pyc
   (magic `03 f3 0d 0a`).
3. **Textbook RSA applied per character** (no padding, tiny alphabet) → the
   cipher is a 256-symbol substitution cipher and is invertible *without
   factoring N*.

## Encryption logic (from encrypt.pyc)
```python
N = 1459067680...618740053   # 1024-bit
e = 65537
for char in open('announcement.md'):
    out.write(str(pow(ord(char), e, N)) + "\n")
```

## Decryption
For every possible plaintext byte `b` in 0..255 compute `pow(b, e, N)`; the
resulting 256-entry dict is the inverse mapping of the ciphertext alphabet.
All 1194 ciphertext blocks mapped into it (0 misses), producing coherent text —
proof that N/e are correct. Re-encrypting the plaintext reproduces the leaked
file **byte-for-byte**.

- Plaintext: 1194 bytes, sha256 `88bdee0a0834796c52cf1184fca21c89a58d6f84f646b35d0a6d84436c1dc453`
- Final line (= evidence answer): `URL: /#/tokensale-ico-ea`
  (the hidden Juice Shop "Blockchain Hype" token-sale route)

## Artifacts
- `pocs/c10_full_chain.py` — one-shot PoC (fetch ciphertext, bypass pyc filter,
  extract N/e from pyc, brute-force decrypt, verify, write evidence)
- `pocs/c10_decrypt_announcement.py` — decryption + verification only
- `loot/encrypt.real.pyc`, `loot/c10_recovered.md`
- `evidence/c10_plaintext.txt` (final line), `evidence/c10_announcement_plaintext.md` (full text)
