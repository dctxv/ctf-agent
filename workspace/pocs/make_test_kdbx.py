#!/usr/bin/env python3
"""Create a synthetic KDBX 3.1 file with a known master password (rounds=1).

Used to validate /workspace/pocs/kdbx_crack_fast.c before attacking the real DB.
Only the first encrypted block matters for verification.
"""
import hashlib, struct, os, sys

try:
    from Crypto.Cipher import AES as _AES
    HAVE_PYC = True
except ImportError:
    HAVE_PYC = False
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.ECB())
    e = c.encryptor()
    return e.update(data) + e.finalize()


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    e = c.encryptor()
    return e.update(data) + e.finalize()


def derive(password: str, master_seed: bytes, transform_seed: bytes, rounds: int):
    composite = hashlib.sha256(hashlib.sha256(password.encode()).digest()).digest()
    transformed = composite
    for _ in range(rounds):
        transformed = aes_ecb_encrypt(transform_seed, transformed)
    # KDBX3: SHA256 the transformed key before mixing with master seed
    transformed = hashlib.sha256(transformed).digest()
    return hashlib.sha256(master_seed + transformed).digest()


def field(fid: int, data: bytes) -> bytes:
    return struct.pack("<BH", fid, len(data)) + data


def main():
    password = sys.argv[1] if len(sys.argv) > 1 else "testpass"
    out = sys.argv[2] if len(sys.argv) > 2 else "/workspace/loot/test_known.kdbx"
    rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 1

    master_seed = os.urandom(32)
    transform_seed = os.urandom(32)
    iv = os.urandom(16)
    start_bytes = os.urandom(32)

    key = derive(password, master_seed, transform_seed, rounds)
    ct = aes_cbc_encrypt(key, iv, start_bytes)  # only first block needed

    hdr = struct.pack("<III", 0x9AA2D903, 0xB54BFB67, 0x00030001)
    hdr += field(2, bytes.fromhex("31c1f2e6bf714350be5805216afc5aff"))  # AES256
    hdr += field(3, struct.pack("<I", 1))                                # gzip
    hdr += field(4, master_seed)
    hdr += field(5, transform_seed)
    hdr += field(6, struct.pack("<Q", rounds))
    hdr += field(7, iv)
    hdr += field(8, os.urandom(32))   # protected stream key
    hdr += field(9, start_bytes)
    hdr += field(10, struct.pack("<I", 2))  # inner random stream
    hdr += field(0, b"\r\n\r\n")

    with open(out, "wb") as f:
        f.write(hdr + ct)
    print(f"wrote {out} password={password!r} rounds={rounds}")


if __name__ == "__main__":
    main()
