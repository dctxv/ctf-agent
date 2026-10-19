#!/usr/bin/env python3
"""
c08 - hypothesis test: incident-support.kdbx might need a KEYFILE (possibly one
of the other files exposed via /ftp) instead of / in addition to a password.

PyKeePass performs the authoritative KDBX 3.1 check (2xSHA256 composite ->
AES-KDF rounds -> SHA256 transformed -> SHA256(masterSeed||transformed) ->
AES-CBC check of stream start bytes), so a successful open == correct hypothesis.
"""
import glob
import itertools
import sys

from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

DB = "/workspace/loot/incident-support.kdbx"

PW = ["", "incident-support", "support", "keepass", "juiceshop", "juice-shop",
      "J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P", "admin123", "ncc-1701", "Passw0rd!23",
      "private", "demo", None]

KEYFILES = [None] + sorted(
    glob.glob("/workspace/loot/*.kdbx")  # excluded below
) if False else [None] + sorted(
    glob.glob("/workspace/loot/*") )
KEYFILES = [None] + [
    f for f in KEYFILES[1:]
    if not f.endswith(".kdbx") and "/incident-support" not in f
    and not f.endswith((".log", ".rec", ".pot", ".txt", ".hash", ".json"))
]


def try_open(pw, kf):
    try:
        PyKeePass(DB, password=pw, keyfile=kf)
        return True
    except (CredentialsError, Exception):
        return False


def main():
    print(f"[*] {len(KEYFILES)} keyfile candidates, {len(PW)} passwords "
          f"({(len(KEYFILES)) * len(PW)} combinations)")
    for kf in KEYFILES:
        for pw in PW:
            if try_open(pw, kf):
                print(f"[+] OPENED with password={pw!r} keyfile={kf}")
                return 0
    print("[-] no combination of (empty/simple password, /ftp file as keyfile) works")
    return 1


if __name__ == "__main__":
    sys.exit(main())
