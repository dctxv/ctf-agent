# C10 - announcement_encrypted.md: obtain + decrypt

## Path
1. `/ftp/` directory listing exposes `announcement_encrypted.md`, `encrypt.pyc` (+ .bak/.kdbx files).
2. `announcement_encrypted.md` is a whitelisted type -> direct `GET /ftp/announcement_encrypted.md`
   (HTTP 200, 369237 bytes, 1194 numeric lines).
3. `encrypt.pyc` is blocked: `GET /ftp/encrypt.pyc` -> HTTP 403 "Only .md and .pdf files are allowed!"
   Bypass (Poison Null Byte style, double URL-encode):
       GET /ftp/encrypt.pyc%2500.md   -> HTTP 200 (573 bytes, real pyc: magic 03 f3 0d 0a = Py2.7)
4. `uncompyle6 encrypt.pyc` reveals the algorithm:

       N = 1459067680075833...4618740053   (RSA modulus, in bytecode)
       e = 65537
       for char in open('announcement.md'):
           write(str(pow(ord(char), e, N)) + '\n')

   Textbook, unpadded RSA on each character => no private key needed (small plaintext space).
5. Invert by brute force per distinct ciphertext (43 distinct chars out of 1194 blocks):
       pow(code, 65537, N) == ciphertext  -> char
   Verified by re-encrypting the plaintext: all 1194 blocks match byte-for-byte.

## Result
Plaintext = the "Token Sale - Initial Coin Offering" announcement.
Final line (saved to /workspace/evidence/c10_plaintext.txt):

    URL: /#/tokensale-ico-ea

## PoC / artifacts
- pocs/c10_decrypt_announcement.py  (one-shot: fetch + bypass + decompile-check + decrypt + evidence)
- evidence/c10_poc_run.log
- c10b/announcement_encrypted.md, c10b/encrypt.pyc, c10b/announcement_plaintext.md
- evidence/c10_announcement_plaintext.md (full recovered plaintext)

## Note
/workspace/encrypt.pyc and /workspace/c10/ct.md from an earlier run: encrypt.pyc was the 403 HTML
error page (not bytecode); it has been replaced with the real pyc. The .md ciphertext was complete.

## Impact
Broken cryptography: per-character unpadded textbook RSA with the modulus shipped alongside the
ciphertext => full recovery of supposedly confidential documents. Combined with the /ftp null-byte
whitelist bypass, both the ciphertext and the encryption program are downloadable.
