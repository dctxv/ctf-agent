"""Import the file-only subset of NYU CTF Bench (the official test/ split) into
eval/manifests/benchmarks/nyu/nyu.json - one generator manifest per challenge.

Only challenges WITHOUT a Dockerfile/docker-compose (no running service) are
imported here; the networked service challenges need a multi-container adapter
(future work). Manifests carry no flags (read from the gitignored dataset at run
time), and the output dir is gitignored.

  git clone --depth 1 https://github.com/NYU-LLM-CTF/NYU_CTF_Bench benchmarks/nyu-ctf
  python run_import_nyu.py
  python run_experiment.py --manifests eval/manifests/benchmarks/nyu --dataset validation --dry-run
"""
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NYU = ROOT / "benchmarks" / "nyu-ctf"
OUT = ROOT / "eval" / "manifests" / "benchmarks" / "nyu" / "nyu.json"
# sidecar: the '_' prefix keeps the registry loader from treating it as a manifest
EXCLUDED = OUT.parent / "_excluded.json"
CATMAP = {"crypto": "crypto", "forensics": "forensics", "rev": "reverse",
          "misc": "misc", "web": "web", "pwn": "pwn", "ics": "misc"}


def _ls():
    return subprocess.run(["git", "-C", str(NYU), "ls-tree", "-r", "--name-only", "HEAD"],
                          capture_output=True, text=True).stdout.splitlines()


def _blob_size(path):
    """Size in bytes of a file at HEAD, or None if it is not tracked in git.

    NYU hosts some large handouts outside the repo, so a file listed in
    challenge.json can be absent (None) or an empty placeholder (0) in git - either
    way the challenge cannot be staged and must not enter the benchmark."""
    r = subprocess.run(["git", "-C", str(NYU), "cat-file", "-s", f"HEAD:{path}"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    try:
        return int(r.stdout.strip())
    except ValueError:
        return None


_CONNECT = re.compile(r'\bnc\b|remote:|\{box\}|\{port\}|connect to|chal\.csaw\.io', re.I)


def _is_service(cj, category):
    """True if the flag lives on a remote endpoint, so the file-only (no-network)
    harness cannot solve it. CSAW tags almost every challenge with a `box`, so that
    alone is not enough; we require a box/internal_port AND a real remote signal:
    an exploit category (pwn/web), an explicit internal_port, or a connect directive
    in the description. (A crypto/rev challenge that merely lists a box but ships the
    artifact locally - e.g. an encrypted-flag file - stays in the benchmark.)"""
    if not ("box" in cj or "internal_port" in cj):
        return False
    return (category in ("pwn", "web") or "internal_port" in cj
            or bool(_CONNECT.search(cj.get("description", ""))))


def _is_synthetic_flag(flag):
    """NYU replaced some flags with synthetic validation placeholders
    (e.g. flag{flag_created_in_validation_...}) that are not derivable from the
    challenge content, so a correct solve can never match. Exclude them."""
    return "flag_created_in_validation" in flag or "created_in_validation" in flag


def main():
    if not (NYU / ".git").exists():
        print("NYU data not found. Clone it first:\n  git clone --depth 1 "
              "https://github.com/NYU-LLM-CTF/NYU_CTF_Bench benchmarks/nyu-ctf")
        return
    files = _ls()
    fset = set(files)
    chal = [f.rsplit("/challenge.json", 1)[0] for f in files
            if f.endswith("/challenge.json") and f.startswith("test/")]
    fileonly = [d for d in chal
                if f"{d}/docker-compose.yml" not in fset and f"{d}/Dockerfile" not in fset
                and not re.search(r'[:?*<>"|]', d)]
    manifests = []
    excluded = []
    for d in fileonly:
        cj = json.loads(subprocess.run(["git", "-C", str(NYU), "show", f"HEAD:{d}/challenge.json"],
                                        capture_output=True, text=True).stdout)
        cat = CATMAP.get(cj.get("category", "misc").lower(), "misc")
        slug = "nyu-" + re.sub(r'[^a-z0-9]+', '-', d[len("test/"):].lower()).strip('-')
        # Exclusions (a challenge is kept only if it can be fairly solved offline from
        # its files). Each excluded challenge is recorded with a reason so the set is
        # reported separately rather than silently scored as an agent failure:
        #  - empty_handout: a file listed in challenge.json is missing/empty in git
        #    (NYU hosts some binaries outside the repo) -> unsolvable shell.
        #  - service: the flag lives on a remote endpoint the no-network harness can't
        #    reach (pwn/web services, nc challenges).
        #  - synthetic_flag: the gold flag is an NYU validation placeholder, not derivable.
        # A challenge that lists no files is kept - some misc tasks are description-only.
        listed = cj.get("files", [])
        bad = [f for f in listed if not (_blob_size(f"{d}/{f}") or 0)]
        reason = None
        if listed and bad:
            reason = {"reason": "empty_handout", "detail": bad}
        elif _is_synthetic_flag(cj.get("flag", "")):
            reason = {"reason": "synthetic_flag", "detail": cj.get("flag", "")}
        elif _is_service(cj, cat):
            reason = {"reason": "service",
                      "detail": cj.get("box") or f"internal_port {cj.get('internal_port')}"}
        if reason:
            excluded.append({"id": slug, "dir": d, "category": cat, **reason})
            continue
        manifests.append({
            "schema_version": 1, "id": slug, "version": 1, "category": cat,
            "tier": "D", "dataset": "validation", "difficulty": "csaw",
            "source": "nyu-ctf-bench", "generator": {"name": "nyu", "dir": d},
            "verifier": {"path": "evidence/flag.txt", "type": "flag_from_key"},
        })
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(manifests, indent=2), encoding="utf-8")
    EXCLUDED.write_text(json.dumps(excluded, indent=2), encoding="utf-8")
    print(f"wrote {OUT} with {len(manifests)} manifests (file-only, offline-solvable)")
    print("by category:", dict(Counter(m["category"] for m in manifests)))
    print(f"excluded {len(excluded)} challenge(s) -> {EXCLUDED}")
    print("  by reason:", dict(Counter(e["reason"] for e in excluded)))
    for e in sorted(excluded, key=lambda x: x["reason"]):
        print(f"  - [{e['reason']:14}] {e['id']}  ({e['category']})  {e['detail']}")


if __name__ == "__main__":
    main()
