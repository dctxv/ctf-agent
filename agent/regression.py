"""Vuln-regression diff: compare two audits' findings into new / fixed / still-open.

A finding is matched across runs by (file, CWE) when both are present, else by
(file, normalized-title). Lets `--retest` confirm which issues a later commit
fixed, which remain, and which are new.
"""
import re


def _key(f):
    file = str(f.get("file", "")).strip()
    cwe = str(f.get("cwe", "")).strip().upper()
    if file and cwe:
        return (file, cwe)
    title = re.sub(r'[^a-z0-9]+', ' ', str(f.get("title", "")).lower()).strip()[:40]
    return (file, title)


def diff_findings(old, new):
    oldk = {_key(f): f for f in old}
    newk = {_key(f): f for f in new}
    return {
        "new": [newk[k] for k in newk if k not in oldk],
        "fixed": [oldk[k] for k in oldk if k not in newk],
        "still_open": [newk[k] for k in newk if k in oldk],
    }


def render_retest(diff, old_label="baseline", new_label="current") -> str:
    lines = [f"# Vuln-regression: {old_label} -> {new_label}", "",
             f"- **New:** {len(diff['new'])}",
             f"- **Fixed:** {len(diff['fixed'])}",
             f"- **Still open:** {len(diff['still_open'])}", ""]
    for section, key in (("New findings", "new"), ("Fixed", "fixed"), ("Still open", "still_open")):
        if not diff[key]:
            continue
        lines.append(f"## {section}")
        for f in diff[key]:
            loc = f"{f.get('file','')}{':' + str(f.get('line')) if f.get('line') else ''}"
            lines.append(f"- [{str(f.get('severity','?')).upper()}] {f.get('title','')} "
                         f"(`{loc}`, {f.get('cwe','')})")
        lines.append("")
    return "\n".join(lines)
