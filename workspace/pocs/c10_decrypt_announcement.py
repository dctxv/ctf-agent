#!/usr/bin/env python3
"""
C10 - OWASP Juice Shop: /ftp/announcement_encrypted.md

Findings:
  1) Directory listing enabled on /ftp exposing confidential files
     (announcement_encrypted.md, encrypt.pyc, incident-support.kdbx, ...).
  2) encrypt.pyc performs *textbook RSA per character*:
         for char in open('announcement.md'):
             out.write(str(pow(ord(char), e, N)) + "\n")
     Because the plaintext alphabet is tiny (bytes 0..255), the cipher is
     invertible by brute force WITHOUT factoring N: build the table
     b -> pow(b, e, N) for b in 0..255 and look each ciphertext block up.

The script then verifies by re-encrypting the recovered plaintext and comparing
byte-for-byte with the original ciphertext. Only a full match counts as success.
"""
import sys, hashlib

N = 145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053
E = 65537

CIPHER = sys.argv[1] if len(sys.argv) > 1 else "/workspace/loot/announcement_encrypted.md"
OUT = sys.argv[2] if len(sys.argv) > 2 else "/workspace/loot/c10_recovered.md"

print("[*] N = %d bits, e = %d" % (N.bit_length(), E))

# 0. Sanity check: N must appear verbatim inside the leaked encrypt.pyc
pyc = "/workspace/loot/encrypt27.pyc"
try:
    raw = open(pyc, "rb").read()
    if raw.startswith(b"<html"):
        print("[!] local encrypt.pyc is the 403 error page (ext blocked), skipping cross-check")
    elif str(N).encode() in raw:
        print("[*] N matches the constant embedded in encrypt.pyc (cross-check OK)")
    else:
        sys.exit("[!] N does not match encrypt.pyc constant")
except FileNotFoundError:
    print("[!] encrypt.pyc not present locally, skipping cross-check")

# 1. Build inversion table: pow(b,e,N) -> b  for every possible plaintext byte
table = {}
for b in range(256):
    table[pow(b, E, N)] = b
assert len(table) == 256
print("[*] built %d-entry inversion table (all plaintext bytes 0..255)" % len(table))

# 2. Decrypt: one ciphertext line per plaintext character
cts = [int(x) for x in open(CIPHER).read().split()]
print("[*] %d ciphertext blocks read from %s" % (len(cts), CIPHER))

plain = bytearray()
for i, c in enumerate(cts):
    b = table.get(c)
    if b is None:
        sys.exit("[!] block %d has no preimage in 0..255 -- abort" % i)
    plain.append(b)

# 3. Verify by re-encryption (strict equality with the leaked file)
reenc = "".join("%d\n" % pow(b, E, N) for b in plain)
ok = reenc == open(CIPHER).read()
print("[*] re-encryption byte-for-byte match: %s" % ok)
print("[*] plaintext length: %d bytes" % len(plain))
print("[*] plaintext sha256: %s" % hashlib.sha256(bytes(plain)).hexdigest())
if not ok:
    sys.exit("[!] VERIFICATION FAILED")

open(OUT, "wb").write(bytes(plain))
print("[+] verified plaintext written -> %s" % OUT)
print("=" * 70)
print(bytes(plain).decode("utf-8", "replace"))
print("=" * 70)
