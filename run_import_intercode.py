"""Import InterCode-CTF (100 picoCTF tasks) into a manifest registry.

Reads benchmarks/intercode/data/ctf/ic_ctf.json (clone princeton-nlp/intercode first)
and writes eval/manifests/benchmarks/intercode.json - one generator manifest per task.
The manifests carry no flags (flags stay in the gitignored dataset); they are regenerable
from the data, so the output dir is gitignored.

  git clone --depth 1 https://github.com/princeton-nlp/intercode benchmarks/intercode
  python run_import_intercode.py
  python run_experiment.py --manifests eval/manifests/benchmarks --dataset validation --dry-run
"""
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BENCH = ROOT / "benchmarks" / "intercode" / "data" / "ctf"
OUT = ROOT / "eval" / "manifests" / "benchmarks" / "intercode.json"

CATMAP = {
    "General Skills": "general", "Reverse Engineering": "reverse", "Cryptography": "crypto",
    "Forensics": "forensics", "Binary Exploitation": "pwn", "Web Exploitation": "web",
}


def main():
    src = BENCH / "ic_ctf.json"
    if not src.is_file():
        print(f"InterCode data not found at {src}.\n"
              "Clone it first: git clone --depth 1 "
              "https://github.com/princeton-nlp/intercode benchmarks/intercode")
        return
    tasks = json.loads(src.read_text(encoding="utf-8"))
    manifests = []
    for t in tasks:
        tid = int(t["task_id"])
        cat = CATMAP.get((t.get("tags") or ["misc"])[0], "misc")
        manifests.append({
            "schema_version": 1, "id": f"ic-ctf-{tid:03d}", "version": 1,
            "category": cat, "tier": "D", "dataset": "validation", "difficulty": "picoctf",
            "source": "intercode-ctf",
            "generator": {"name": "intercode", "task_id": tid},
            "verifier": {"path": "evidence/flag.txt", "type": "flag_from_key"},
        })
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(manifests, indent=2), encoding="utf-8")
    print(f"wrote {OUT} with {len(manifests)} manifests")
    print("by category:", dict(Counter(m["category"] for m in manifests)))


if __name__ == "__main__":
    main()
