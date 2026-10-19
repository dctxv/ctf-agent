# c10 — announcement_encrypted.md → plaintext (verified)

Target: http://host.docker.internal:3000 (OWASP Juice Shop, own lab)
PoC: `/workspace/pocs/c10_announcement_decrypt.py` (randomless, self-verifying, run live)

## Chain
1. `GET /ftp/announcement_encrypted.md` → 200, 369,237 B, 1,194 blocks
   (sha256 `b032cbb044d3de7854b777287daf1684c30c82c43643150e8965ff93ae0b94d5`)
2. `GET /ftp/encrypt.pyc%2500.md` → 200, 573 B (null-byte extension whitelist bypass;
   sha256 `b66ff06365eb5a36d872a3b7a7ad1bdbe982ccbeef9804c049b2e2321186788b`)
3. `encrypt.pyc` = CPython 2.7 (magic 62211). Code object constants expose the public key:
   `N` (1024-bit) and `e = 65537`, plus the strings `announcement.md`,
   `announcement_encrypted.md`, and the loop `pow(ord(char), e, N)`.
4. Weakness: textbook RSA applied **per character**, no padding. Message space is tiny
   (Unicode code points), so the public key inverts by table lookup
   `{pow(k, e, N): k for k in 0..0x10FFFF}` — factoring N is unnecessary.
5. Verification: re-encrypting every recovered character reproduces the downloaded
   ciphertext byte-for-byte (`reenc == ct_raw`), so the plaintext is exact.

## Plaintext (1,194 chars, 4 non-empty lines)
```
Major Announcement:

Token Sale - Initial Coin Offering

Lorem ipsum ... Give us all your money. ... blandit praes

URL: /#/tokensale-ico-ea
```
sha256 of full plaintext: `88bdee0a0834796c52cf1184fca21c89a58d6f84f646b35d0a6d84436c1dc453`

## Deliverable
`evidence/c10_plaintext.txt` contains the announcement's famous punchline:

    Give us all your money.

Notes for the operator:
* The literal *last* line of the file is the footer `URL: /#/tokensale-ico-ea`
  (this is the deep link behind the "Blockchain Hype / tokenSaleChallenge" challenge,
  i.e. "learn about the Token Sale before its official announcement").
* The only *famous* / quotable line in the document is the ICO punchline
  `Give us all your money.` — it is the one non-Lorem, uniquely attributable sentence
  and it is recorded in `c10_plaintext.txt`.
* Both are preserved: full plaintext in `evidence/c10_announcement_plaintext.md`.
