#!/usr/bin/env python3
"""
c09-pyc-reverse : proof-of-concept

Validates the recovered `encrypt.py` logic from encrypt.pyc (Python 2.7 pyc served
from Juice Shop /ftp) by:

  1. Downloading the real ciphertext artifact  /ftp/announcement_encrypted.md
  2. Rebuilding a per-character RSA "keystream" table:  C[ch] = pow(ord(ch), e, N)
     for every codepoint 0..255, using ONLY the N and e recovered from the pyc.
  3. Decoding the ciphertext by looking up each big integer in that table.
     (This works because encrypt.py encrypts EACH CHARACTER INDEPENDENTLY with
      textbook, unpadded RSA -> the message space is 256 values, not 2^1024.)
  4. Re-encrypting the recovered plaintext and byte-comparing it to the original
     ciphertext: an exact match proves the reverse-engineered logic is correct.

Usage: python3 c9_rsa_decode_announcement.py
"""
import subprocess
import sys

BASE = "http://host.docker.internal:3000"

# --- Constants lifted straight out of encrypt.pyc (see disasm.txt / decompile) ---
N = 145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053
E = 65537


def fetch(path: str) -> bytes:
    """Fetch the artifact. /ftp/<file>.pyc/.bak is 403, so we ride the null-byte
    allowlist bypass for the pyc; announcement_encrypted.md is served directly."""
    return subprocess.run(["curl", "-s", BASE + path], capture_output=True, check=True).stdout


def main() -> int:
    raw = fetch("/ftp/announcement_encrypted.md")
    if not raw:
        print("[!] could not retrieve announcement_encrypted.md")
        return 1
    cts = [int(x) for x in raw.split()]
    print(f"[+] ciphertext blocks: {len(cts)}")

    # 1. Build the tiny lookup table: 256 possible "encryptions" of one character.
    table = {pow(c, E, N): bytes([c]) for c in range(256)}
    print(f"[+] lookup table built from recovered N ({N.bit_length()} bits) and e={E}")

    # 2. Decode.
    out = bytearray()
    for ct in cts:
        ch = table.get(ct)
        if ch is None:
            print(f"[!] block does not map to a single byte: {ct}")
            return 1
        out += ch
    plaintext = bytes(out)

    # 3. Verify by re-encrypting exactly like encrypt.py does.
    re_cts = [pow(b, E, N) for b in plaintext]
    ok = re_cts == cts
    print(f"[+] re-encryption matches original ciphertext: {ok}")

    with open("/workspace/loot/announcement_plaintext.md", "wb") as f:
        f.write(plaintext)
    print("[+] wrote /workspace/loot/announcement_plaintext.md")
    print("-" * 60)
    print(plaintext.decode("utf-8", "replace"))
    print("-" * 60)
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
