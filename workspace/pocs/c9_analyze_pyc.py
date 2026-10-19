#!/usr/bin/env python3
"""c09-pyc-reverse : static analysis of /ftp/encrypt.pyc (Python 2.7 bytecode).

Loads the cross-version pyc with xdis (host python is 3.14 and cannot unmarshal 2.7
marshalled code objects directly), prints metadata / code constants, writes a
disassembly listing, and runs uncompyle6 to recover near-original source.
"""
import datetime
import pathlib
import subprocess
import sys

import xdis.load
from xdis.disasm import disco

PYC = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/workspace/loot/encrypt.pyc")
OUTDIR = PYC.parent

rec = xdis.load.load_module(str(PYC))
version_tuple, ts, magic, code, _isfrozen = rec[0], rec[1], rec[2], rec[3], rec[4]
print(f"[+] file        : {PYC}")
print(f"[+] bytecode ver: python {version_tuple[0]}.{version_tuple[1]} (magic {magic})")
print(f"[+] source name : {code.co_filename}")
print(f"[+] compile time: {ts} -> {datetime.datetime.fromtimestamp(ts, datetime.UTC)}")
print(f"[+] code size   : {len(code.co_code)} bytes, stack {code.co_stacksize}, flags {code.co_flags:#x}")

print("[+] co_names   :", ", ".join(code.co_names))
print("[+] constants  :")
for i, c in enumerate(code.co_consts):
    s = repr(c)
    print(f"      {i}: {s if len(s) < 100 else s[:60] + '...(%d digits)' % len(s)}")

# disassembly listing
dis_path = OUTDIR / "encrypt_disasm.txt"
disco(version_tuple, code, timestamp=ts, out=open(dis_path, "w"))
print(f"[+] disassembly -> {dis_path}")

# decompilation (uncompyle6 understands 2.7 and runs fine on modern CPython here)
src_path = OUTDIR / "encrypt_decompiled.py"
with open(src_path, "w") as fh:
    r = subprocess.run(["uncompyle6", str(PYC)], stdout=fh,
                       stderr=subprocess.DEVNULL, text=True)
print(f"[+] decompiled   -> {src_path}  (uncompyle6 rc={r.returncode})")
if r.returncode:
    print(r.stderr.strip()[:500])
print("-" * 70)
print(src_path.read_text())
