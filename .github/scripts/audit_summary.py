"""Summarize semgrep.json + osv-scanner JSON into Markdown (for a GH Action job
summary). Usage: python audit_summary.py semgrep.json osv.json"""
import json
import sys
from pathlib import Path


def _load(p):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return {}


def semgrep_results(d):
    return d.get("results", []) if isinstance(d, dict) else []


def osv_counts(d):
    n, pkgs = 0, set()
    for r in (d.get("results", []) if isinstance(d, dict) else []):
        for pkg in r.get("packages", []):
            vulns = pkg.get("vulnerabilities", []) or []
            if vulns:
                n += len(vulns)
                pkgs.add((pkg.get("package", {}) or {}).get("name", ""))
    return n, {p for p in pkgs if p}


def main():
    sg = _load(sys.argv[1]) if len(sys.argv) > 1 else {}
    ov = _load(sys.argv[2]) if len(sys.argv) > 2 else {}
    results = semgrep_results(sg)
    nvuln, pkgs = osv_counts(ov)

    print("## Security audit (semgrep + osv-scanner)")
    print(f"- **semgrep:** {len(results)} finding(s)")
    print(f"- **osv-scanner:** {nvuln} dependency vuln(s) across {len(pkgs)} package(s)")
    if results:
        print("\n### semgrep findings")
        for r in results[:40]:
            path = r.get("path", "")
            line = (r.get("start", {}) or {}).get("line", "")
            print(f"- `{path}:{line}` {r.get('check_id', '')}")
    if pkgs:
        print("\n### vulnerable packages")
        print(", ".join(sorted(pkgs)))
    if not results and not nvuln:
        print("\nNo findings.")


if __name__ == "__main__":
    main()
