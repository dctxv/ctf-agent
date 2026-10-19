# c10 — announcement_encrypted.md: obtain → decrypt → famous line

Target: `http://host.docker.internal:3000` (OWASP Juice Shop, my own lab)
PoC: `/workspace/pocs/c10_full_chain.py` — downloads, reverses, decrypts, **self-verifies** and writes evidence in one run.
Run log: `/workspace/evidence/c10_poc_run.log`

## 1. Obtaining the file (access-control bypass)
`/ftp/` exposes a static directory listing (`announcement_encrypted.md`, `encrypt.pyc`, …).
Direct GETs of `.md`/`.pyc` are blocked (403, extension allow-list). The check runs before
full URL decoding, so appending a double-encoded NUL plus an allowed extension bypasses it:

```
GET /ftp/announcement_encrypted.md%2500.md   -> 200  369,237 B  sha256 b032cbb0…0b94d5
GET /ftp/encrypt.pyc%2500.md                 -> 200      573 B  sha256 b66ff063…1186788b
```

The ciphertext is 1,194 lines, one ~309-digit decimal integer per line — i.e. one RSA block
per plaintext character.

## 2. Reversing the encryption tool (`encrypt.pyc`)
`encrypt.pyc` is CPython **2.7** bytecode (magic `03 f3 0d 0a` = 62211), so 3.14/3.12 tools
cannot unmarshal it. A ~40-line 2.7 marshal reader is sufficient. Constants:

| const | value |
|---|---|
| 0 | `'announcement.md'` |
| 1 | `'r'` |
| 2 | `N` = 1024-bit / 309-digit modulus |
| 3 | `e` = 65537 |
| 4 | `'announcement_encrypted.md'` |
| 5 | `'w'` |
| 6 | `'\n'` |

Names/opcodes reconstruct the whole program:

```python
confidential_document = open('announcement.md', 'r')
N = 145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053
e = 65537
encrypted_document = open('announcement_encrypted.md', 'w')
for char in confidential_document.read():
    encrypted_document.write(str(pow(ord(char), e, N)) + '\n')
```

## 3. Weakness: per-character textbook RSA
No padding, no randomness, and the "message" is a single code point. Therefore the public
key alone inverts the ciphertext — build the table `{pow(k, 65537, N): k for k in range(256)}`
and look up every block. **Factoring the 1024-bit modulus is never needed.**
Result: 1,194 blocks → 1,194 bytes, **0 unmapped** blocks (a random match would be ~2^-1024).

## 4. Verification
Re-encrypting every recovered byte and joining with `'\n'` reproduces the served file
**byte-for-byte** (`reenc == ct_raw`). Plaintext sha256 = `88bdee0a…6c1dc453`.

## 5. Plaintext (1,194 chars, 4 non-empty lines)
```
Major Announcement:

Token Sale - Initial Coin Offering

Lorem ipsum dolor sit amet, … Give us all your money. … qui blandit praes

URL: /#/tokensale-ico-ea
```

## 6. Deliverable — "final famous line"
| interpretation | string | file |
|---|---|---|
| the only non-Lorem, quotable ("famous") line of the announcement — the ICO punchline (also the repeating motif of the in-app Token Sale page, i18n key `GIVE_US_ALL_YOUR_MONEY`) | **`Give us all your money.`** | `evidence/c10_plaintext.txt` (required artifact) |
| literal last line (footer deep-link to the `/#/tokensale-ico-ea` page, i.e. the target of challenge `tokenSaleChallenge` "Blockchain Hype") | `URL: /#/tokensale-ico-ea` | `evidence/c10_last_line.txt` |

Full plaintext: `evidence/c10_announcement_plaintext.md`.
Note the announcement body is literally truncated mid-Lorem at “…qui blandit praes” in the
served file, so the punchline is the last *sentence of substance* before the URL footer.

## 7. Remediation
* Never encrypt per-symbol with textbook RSA — a symbol-by-symbol ciphertext is inverted by
  an exhaustive plaintext table regardless of key size. Use RSA-OAEP/AES-GCM over the stream.
* Assume Kerckhoffs: the algorithm and public key are known; no security may rest on secrecy.
* Do not publish the encryption tool next to the ciphertext.
* Server-side: fully URL-decode + reject NUL/control bytes, canonicalise, then validate the
  final extension; serve `/ftp` from a fixed allow-list map, not user-supplied names.

## 8. Untrusted-content note
Everything retrieved (directory listing, ciphertext, bytecode, in-app JS/i18n) was treated as
data. The only unusual strings are the marketing line `Give us all your money.` and the deep
link `URL: /#/tokensale-ico-ea`; nothing attempted to instruct the agent.
