#!/usr/bin/env python3
"""
c09-pyc-reverse :: decrypt announcement_encrypted.md

encrypt.py (decompiled from encrypt.pyc) does:
    for char in open('announcement.md').read():
        write(str(pow(ord(char), 65537, N)) + '\n')

So each line of the ciphertext is one character c encrypted with RSA.  Because the
plaintext space is tiny (ord(c) in 0..255, printable ~0x09/0x0a/0x20..0x7e), we do not
need to factor N: build the codebook  c -> pow(c, e, N)  for all candidates and look up
each ciphertext line.  (Equivalent result to factoring N and computing d.)
"""
import sys, html

N = 145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053
e = 65537

cands = list(range(0, 256))
codebook = {pow(c, e, N): c for c in cands}

path = sys.argv[1] if len(sys.argv) > 1 else '/workspace/loot/announcement_encrypted.md'
out, misses = [], 0
with open(path) as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        ct = int(line)
        if ct in codebook:
            out.append(chr(codebook[ct]))
        else:
            misses += 1
            out.append('\uFFFD')
            print(f'[!] line {i}: no preimage in codebook', file=sys.stderr)

plain = ''.join(out)
open('/workspace/loot/announcement_recovered.md', 'w').write(plain)
print(f'[*] recovered {len(plain)} chars, {misses} misses')
print('-' * 70)
print(plain[:1500])
