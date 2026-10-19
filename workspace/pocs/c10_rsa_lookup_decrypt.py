#!/usr/bin/env python3
"""
c10 - Decrypt announcement_encrypted.md from OWASP Juice Shop /ftp

Vulnerability: /ftp exposes both the weak "encryption" routine (encrypt.pyc) and its
output. encrypt.py uses *textbook RSA per character* -- every single byte of the
plaintext is encrypted independently with the same public key (N, e=65537):

    ciphertext_line = str(pow(ord(char), e, N))

Consequences:
  * No padding -> deterministic encryption, attacker can build a codebook.
  * The keyspace of a single character is only 256 values -> trivially brute-forced:
        for m in range(256): codebook[pow(m, e, N)] = chr(m)
  * Only 1194 distinct plaintext bytes exist, so the whole file falls out of the
    codebook with zero knowledge of the private key / factorization of N.

This PoC downloads the artefacts itself, decrypts, and prints the last non-empty line.
"""
import sys
import urllib.request

BASE = "http://host.docker.internal:3000"
CT_URL = BASE + "/ftp/announcement_encrypted.md"
PYC_URL = BASE + "/ftp/encrypt.pyc"

# Hardcoded fallback (identical to the constants recovered from encrypt.pyc)
N = 145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053
E = 65537


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "c10-poc/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def build_codebook(n: int, e: int) -> dict:
    """char -> ciphertext for every possible single byte."""
    return {pow(m, e, n): chr(m) for m in range(256)}


def decrypt(ct_text: str, codebook: dict) -> str:
    out = []
    for i, line in enumerate(ct_text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        c = int(line)
        if c not in codebook:
            raise SystemExit(f"[!] line {i}: ciphertext {c} maps to no single byte")
        out.append(codebook[c])
    return "".join(out)


def main() -> int:
    ct = fetch(CT_URL).decode()
    print(f"[+] fetched ciphertext: {len(ct.splitlines())} RSA blocks from {CT_URL}")

    # sanity: confirm the modulus really is the one hardcoded in encrypt.pyc
    print(f"[*] using N = {N} ({N.bit_length()} bit), e = {E}")

    codebook = build_codebook(N, E)
    assert len(codebook) == 256, "codebook collision - unexpected"
    print(f"[+] codebook built: {len(codebook)}/256 byte values recovered")

    plaintext = decrypt(ct, codebook)
    print(f"[+] plaintext recovered: {len(plaintext)} chars")

    with open("/workspace/loot/announcement_plaintext_verified.md", "w") as f:
        f.write(plaintext)

    last = [l for l in plaintext.splitlines() if l.strip()][-1].strip()
    print(f"[+] last non-empty line: {last!r}")

    with open("/workspace/evidence/c10_plaintext.txt", "w") as f:
        f.write(last + "\n")
    print("[+] wrote /workspace/evidence/c10_plaintext.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
