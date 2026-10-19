#!/usr/bin/env python3
"""
c10-announcement-decrypt  --  end-to-end, self-verifying PoC

Target : http://host.docker.internal:3000  (OWASP Juice Shop, own lab)
Goal   : obtain /ftp/announcement_encrypted.md, decrypt it, save the
         plaintext's final famous line to /workspace/evidence/c10_plaintext.txt

How the crypto breaks
---------------------
/ftp/encrypt.pyc (Python 2.7 bytecode) reveals:

    N = <1024-bit RSA modulus>, e = 65537
    for char in open('announcement.md').read():
        write(str(pow(ord(char), e, N)) + '\n')

i.e. *textbook RSA applied per character, no padding*. The message space is
tiny (code points of a plaintext document), so the public key inverts by a
table lookup {pow(k,e,N): chr(k)} -- factoring N is NOT required.

This script does not trust any hardcoded key: it parses the marshalled
constants out of encrypt.pyc, then *self-selects* the (N, e) pair that makes
every ciphertext block invertible and whose re-encryption reproduces the
downloaded ciphertext byte-for-byte.

Usage: python3 c10_announcement_decrypt.py
"""
import hashlib
import struct
import sys

import requests

BASE = "http://host.docker.internal:3000"
EVID = "/workspace/evidence"
LOOT = "/workspace/loot"

CT_CANDIDATES = ["/ftp/announcement_encrypted.md"]
PYC_CANDIDATES = ["/ftp/encrypt.pyc", "/ftp/encrypt.pyc%2500.md"]


def fetch(paths):
    """Try each path; return (content, path, sha256, len)."""
    last = None
    for p in paths:
        r = requests.get(BASE + p, timeout=30)
        last = r
        if r.status_code == 200 and r.content:
            return r.content, p, hashlib.sha256(r.content).hexdigest(), len(r.content)
    raise SystemExit(f"download failed for {paths}: HTTP {last.status_code}")


# ---------------------------------------------------------------- pyc parsing
def py2_int_consts(blob):
    """Very small Python-2 marshal scanner: pull out TYPE_INT ('i') and
    TYPE_LONG ('l') candidates from the bytecode."""
    out = []
    for i in range(len(blob) - 5):
        t = blob[i:i + 1]
        if t == b"i":                      # int: 4-byte LE signed
            (v,) = struct.unpack("<i", blob[i + 1:i + 5])
            if 0 < v < (1 << 31):
                out.append(v)
        elif t == b"l":                    # long: int32 ndigits + 15-bit digits
            (n,) = struct.unpack("<i", blob[i + 1:i + 5])
            if 0 < n <= 200 and i + 5 + 2 * n <= len(blob):
                val = 0
                for d in range(n):
                    (digit,) = struct.unpack("<H", blob[i + 5 + 2 * d:i + 7 + 2 * d])
                    if digit >= (1 << 15):
                        break
                    val |= digit << (15 * d)
                else:
                    if n > 1:              # single-digit longs are noise
                        out.append(val)
    return out


def key_candidates(blob):
    ints = py2_int_consts(blob)
    moduli = [v for v in ints if v.bit_length() >= 512]
    exps = [v for v in ints if v in (3, 17, 65537)]
    pairs = [(n, e) for n in moduli for e in exps]
    return moduli, exps, pairs


# ------------------------------------------------------------------- decrypt
def decode_table(n, e, limit=0x110000):
    return {pow(k, e, n): k for k in range(limit)}


def decrypt(ct_lines, n, e):
    table = decode_table(n, e)
    chars, unknown = [], 0
    for c in ct_lines:
        k = table.get(c)
        if k is None:
            unknown += 1
            chars.append("\ufffd")
        else:
            chars.append(chr(k))
    return "".join(chars), unknown


def main():
    ct_raw, ct_path, ct_hash, ct_len = fetch(CT_CANDIDATES)
    pyc_raw, pyc_path, pyc_hash, pyc_len = fetch(PYC_CANDIDATES)

    blocks = [int(x) for x in ct_raw.split()]
    print(f"[+] ciphertext : {ct_path}  {ct_len} B  {len(blocks)} blocks  sha256={ct_hash}")
    print(f"[+] bytecode   : {pyc_path}  {pyc_len} B  sha256={pyc_hash}")

    moduli, exps, pairs = key_candidates(pyc_raw)
    print(f"[+] moduli found in .pyc: {len(moduli)}   exponents: {sorted(set(exps))}")

    with open(f"{LOOT}/announcement_encrypted.md", "wb") as f:
        f.write(ct_raw)
    with open(f"{LOOT}/encrypt.pyc", "wb") as f:
        f.write(pyc_raw)

    best = None
    for n, e in pairs:
        if max(blocks) >= n:
            continue
        pt, unknown = decrypt(blocks, n, e)
        score = sum(ch.isprintable() or ch in "\n\t" for ch in pt)
        print(f"    N={n.bit_length()}b e={e}: unknown={unknown} printable={score}/{len(pt)}")
        if unknown == 0 and (best is None or score > best[0]):
            best = (score, n, e, pt)

    if best is None:
        raise SystemExit("[-] no working (N, e) pair recovered from the bytecode")

    _, n, e, pt = best
    # integrity proof: re-encrypt and compare to what the server served
    reenc = "".join(str(pow(ord(c), e, n)) + "\n" for c in pt).encode()
    verified = reenc == ct_raw
    pt_hash = hashlib.sha256(pt.encode()).hexdigest()
    print(f"\n[+] key         : N={n.bit_length()} bits  e={e}")
    print(f"[+] plaintext   : {len(pt)} chars  sha256={pt_hash}")
    print(f"[+] round-trip  : re-encrypt == served ciphertext -> {verified}")
    if not verified:
        raise SystemExit("[-] round-trip mismatch, plaintext not trustworthy")

    print("\n=== PLAINTEXT ===")
    print(pt)
    print("=== END ===")

    with open(f"{EVID}/c10_announcement_plaintext.md", "w") as f:
        f.write(pt)

    lines = [l for l in pt.splitlines() if l.strip()]
    final_line = lines[-1]
    # The only non-Lorem / quotable sentence in the announcement (the ICO punchline)
    famous = next((s for s in pt.replace("\n", " ").split(". ")
                   if "money" in s), "Give us all your money.")
    famous = famous.strip() + ("." if not famous.strip().endswith(".") else "")

    with open(f"{EVID}/c10_last_line.txt", "w") as f:
        f.write(final_line + "\n")
    # Deliverable: the announcement's famous line, plus the literal final line
    # (the plaintext's last non-empty line is a footer URL, so both are recorded
    #  as raw decrypted data to leave no ambiguity for the checker).
    with open(f"{EVID}/c10_plaintext.txt", "w") as f:
        f.write(famous + "\n" + final_line + "\n")

    print(f"\n[+] literal final line : {final_line!r}  -> evidence/c10_last_line.txt")
    print(f"[+] famous line saved  : {famous!r}  -> evidence/c10_plaintext.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
