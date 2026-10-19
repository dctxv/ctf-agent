#!/usr/bin/env python3
"""
c10-announcement-decrypt
------------------------
OWASP Juice Shop exposes /ftp/encrypt.pyc (Python 2.7 bytecode). Reverse-engineered
it (custom marshal parser) to recover the encryption routine:

    N = <1024-bit modulus>          (LOAD_CONST 2)
    e = 65537                       (LOAD_CONST 3)
    for char in open('announcement.md','r').read():
        out.write(str(pow(ord(char), e, N)) + '\n')

So announcement_encrypted.md holds one RSA block per plaintext character,
C = ord(ch)^65537 mod N.

Because each plaintext "message" is only one byte (0..255), we don't need to
factor N: just forward-encrypt every candidate byte and build a lookup table.
"""
import sys

N = 145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053
E = 65537

ENC = '/workspace/loot/announcement_encrypted.md'


def main():
    table = {pow(m, E, N): bytes([m]) for m in range(256)}

    out = bytearray()
    miss = 0
    with open(ENC) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            c = int(line)
            ch = table.get(c)
            if ch is None:
                miss += 1
                out += b'?'
            else:
                out += ch
    print(f"chars: {len(out)}  unmapped blocks: {miss}", file=sys.stderr)
    text = out.decode('utf-8', 'replace')
    open('/workspace/loot/announcement_plaintext.md', 'w').write(text)
    print(text)


if __name__ == '__main__':
    main()
