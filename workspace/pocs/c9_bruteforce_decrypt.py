#!/usr/bin/env python3
"""c09-pyc-reverse : demonstrate the weakness of the scheme in encrypt.pyc.

encrypt.pyc does textbook RSA on ONE CHARACTER AT A TIME:
    out.append( str(pow(ord(char), e, N)) + "\n" )   with e=65537, N = 1024-bit
No padding, no randomisation (deterministic), and the message space is only
0..255 per block -> instead of factoring N we simply precompute the ciphertext
of every possible plaintext byte and look each line up in the table.

Usage: c9_bruteforce_decrypt.py [encrypted_file] [output_file]
"""
import sys

E = 65537
N = int(
    "145906768007583323230186939349070635292401872375357164399581"
    "871019873438799005358938369571402670149802121818086292467422"
    "828157022922076746906543401224889672472407926969987100581290"
    "103199317858753663710862357656510507883714297115637342788911"
    "463535102712032765166518411726859837988672111837205085526346"
    "618740053"
)

SRC = sys.argv[1] if len(sys.argv) > 1 else "/workspace/loot/announcement_encrypted.md"
DST = sys.argv[2] if len(sys.argv) > 2 else "/workspace/loot/announcement_recovered.md"

# 256-entry codebook: ciphertext -> plaintext byte ("meet in the middle" over the
# entire, tiny, plaintext space; no key recovery / no factoring needed).
codebook = {pow(m, E, N): m for m in range(256)}

plain = bytearray()
misses = 0
for lineno, line in enumerate(open(SRC, "r"), 1):
    line = line.strip()
    if not line:
        continue
    m = codebook.get(int(line))
    if m is None:
        misses += 1
        plain += b"?"
    else:
        plain += bytes([m])

open(DST, "wb").write(plain)
print(f"[+] {lineno} ciphertext lines processed, {misses} unresolved")
print(f"[+] recovered {len(plain)} bytes -> {DST}")
print(f"[+] N is {N.bit_length()} bits, e = {E} (never factored)")
print("-" * 70)
print(plain.decode("utf-8", "replace"))
