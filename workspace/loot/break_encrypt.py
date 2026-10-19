#!/usr/bin/env python3
"""
PoC: break Juice Shop's encrypt.py (Python 2.7 .pyc).

What encrypt.py does (recovered via uncompyle6 / pydisasm):
  N = 1459...053 (2048-bit RSA modulus)
  e = 65537
  for char in open('announcement.md').read():
      open('announcement_encrypted.md','a').write(str(pow(ord(char), e, N)) + '\n')

It is textbook RSA applied *per character with no padding*, and the public key
(N, e) is embedded in the bytecode. That makes it reversible by a trivial
dictionary / chosen-plaintext attack: the plaintext alphabet is tiny, so we
precompute c = pow(ord(ch), e, N) for every possible character and invert
the mapping.

Input : announcement_encrypted.md  (one ciphertext integer per line)
Output: recovered plaintext
"""

# (N, e) lifted verbatim from the decompiled encrypt.pyc
N = 145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053
e = 65537

def build_dict():
    table = {}
    for ch in range(256):
        table[pow(ch, e, N)] = chr(ch)
    return table

def main():
    table = build_dict()
    out = []
    unknown = 0
    with open("announcement_encrypted.md") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            c = int(line)
            if c in table:
                out.append(table[c])
            else:
                out.append("?")
                unknown += 1
    plaintext = "".join(out)
    with open("announcement_recovered.md", "w") as f:
        f.write(plaintext)
    print("decoded characters:", len(out), "| unknown:", unknown)
    print("=== recovered plaintext (first 1200 chars) ===")
    print(plaintext[:1200])

if __name__ == "__main__":
    main()
