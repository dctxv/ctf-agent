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
EXCLUDED = OUT.parent / "nyu_excluded.json"
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
        # Validation: every file listed in challenge.json must be present and non-empty
        # in git. Challenges that list handouts NYU hosts outside the repo stage as
        # empty shells and are unsolvable, so they are excluded from the benchmark
        # (not silently counted as agent failures). A challenge that lists no files is
        # kept - some misc tasks are description-only and solvable without a handout.
        listed = cj.get("files", [])
        bad = [f for f in listed if not (_blob_size(f"{d}/{f}") or 0)]
        if listed and bad:
            excluded.append({"id": slug, "dir": d, "category": cat,
                             "missing_or_empty": bad})
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
    print(f"wrote {OUT} with {len(manifests)} manifests (file-only test/ challenges)")
    print("by category:", dict(Counter(m["category"] for m in manifests)))
    print(f"excluded {len(excluded)} challenge(s) with missing/empty handouts "
          f"-> {EXCLUDED}")
    for e in excluded:
        print(f"  - {e['id']}  ({e['category']})  empty/missing: {e['missing_or_empty']}")


if __name__ == "__main__":
    main()
