# C10 — /ftp/announcement_encrypted.md : obtain + decrypt

## Result
- **Plaintext final (non-empty) line → `/workspace/evidence/c10_plaintext.txt`**:
  `URL: /#/tokensale-ico-ea`
- Full recovered plaintext: `loot/announcement_plaintext_verified.md` (1194 chars, 7 lines)
- Verified PoC: `pocs/c10_full_chain_verified.py` (run log: `evidence/c10_verified_run.log`)

## Vulnerability chain
1. **Exposed directory listing** — `GET /ftp/` lists files; `announcement_encrypted.md`
   is on the extension allowlist → `GET /ftp/announcement_encrypted.md`
   = 200, 369237 bytes, md5 `034a8cabcaab13796222fa9b327f097b`, 1194 numeric lines.
2. **Encryption program disclosure (allowlist bypass)** — `GET /ftp/encrypt.pyc` is blocked by the
   allowlist, but the double-encoded null-byte trick `GET /ftp/encrypt.pyc%2500.md` returns the real
   Python 2.7 bytecode (573 bytes, sha256 `b66ff063…6788b`). Pydisasm recovers:

   ```python
   N = 1459067680075833…4618740053        # 1024-bit textbook RSA modulus, shipped with ciphertext
   e = 65537
   for char in open('announcement.md'):
       write(str(pow(ord(char), e, N)) + '\n')
   ```
3. **Broken crypto → plaintext without the key** — unpadded, deterministic RSA applied
   *per character*. Per-block plaintext space is 256, so a codebook
   `{pow(m,65537,N): chr(m) for m in range(256)}` inverts every block. No factoring needed.

## Verification
- Codebook: 256/256 entries, no collisions; 0 non-printable bytes in output.
- **Re-encryption check**: `pow(ord(c), e, N)` for all 1194 recovered chars reproduces the
  downloaded ciphertext byte-for-byte → plaintext is exact, not a guess.
- Cross-check: recovered plaintext is the canonical Juice Shop ICO page copy
  (i18n keys `TITLE_TOKENSALE`, `SECTION_ICO`, `GIVE_US_ALL_YOUR_MONEY` in `/assets/i18n/en.json`).

## Note on "final famous line"
The document's literal final line is the ICO easter-egg route `URL: /#/tokensale-ico-ea`
(this is what was saved). The only other memorable quote in the body is the ICO joke line
`Give us all your money.` (mid-paragraph, i18n key `GIVE_US_ALL_YOUR_MONEY`).
