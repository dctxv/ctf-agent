"""Findings court: an adversarial second pass over an audit's findings.

For each finding it re-reads the cited source line and asks the model to REFUTE
it unless the code clearly shows the described vulnerability. This catches
hallucinated / misattributed findings before they reach a report or an issue.
Verdicts (confirmed | refuted | uncertain) are merged back into findings.json.
"""
import json
import os
import re
from pathlib import Path

from openai import OpenAI

MODEL = "deepseek-flash"


def _client():
    return OpenAI(api_key=os.environ["DEEPSEEK_API_KEY"], base_url="https://api.deepseek.com")


def _code_window(src_dir, file, line, ctx=15):
    p = Path(src_dir) / (file or "")
    if not p.is_file():
        return None  # cited file missing: a strong refute signal
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    if isinstance(line, int) and line > 0:
        a, b = max(1, line - ctx), min(len(lines), line + ctx)
    else:
        a, b = 1, min(len(lines), 40)
    return a, b, "\n".join(f"{i}: {lines[i - 1]}" for i in range(a, b + 1))


_PROMPT = """You are a skeptical security reviewer checking an automated tool's finding.
REFUTE it unless the cited code clearly shows the described vulnerability. A wrong file/line,
a missing sink, or a mitigation already present all mean "refuted".

Finding:
  title: {title}
  severity: {severity}   cwe: {cwe}
  location: {file}:{line}
  description: {description}

{code_block}

Respond with ONLY a JSON object:
{{"verdict": "confirmed" | "refuted" | "uncertain", "confidence": "high" | "medium" | "low", "reason": "<one sentence grounded in the code>"}}"""


def verify_finding(f, src_dir, client, model=MODEL):
    file = f.get("file", "")
    try:
        line = int(f.get("line"))
    except (TypeError, ValueError):
        line = None
    w = _code_window(src_dir, file, line)
    code_block = (f"The cited file `{file}` was not found in the source tree."
                  if w is None else
                  f"Actual code at `{file}` lines {w[0]}-{w[1]}:\n```\n{w[2]}\n```")
    prompt = _PROMPT.format(title=f.get("title", ""), severity=f.get("severity", ""),
                            cwe=f.get("cwe", ""), file=file, line=line,
                            description=f.get("description", ""), code_block=code_block)
    v = {}
    try:
        r = client.chat.completions.create(
            model=model, messages=[{"role": "user", "content": prompt}], temperature=0.0)
        m = re.search(r"\{.*\}", r.choices[0].message.content or "", re.S)
        if m:
            v = json.loads(m.group(0))
    except Exception:
        v = {}
    verdict = str(v.get("verdict", "uncertain")).lower()
    if verdict not in ("confirmed", "refuted", "uncertain"):
        verdict = "uncertain"
    return {"verdict": verdict,
            "court_confidence": str(v.get("confidence", "low")).lower(),
            "court_reason": v.get("reason", "(no verdict returned)")}


def verify_findings(audit_dir, client=None, model=MODEL):
    from agent.findings import load_findings
    audit_dir = Path(audit_dir)
    findings = load_findings(audit_dir)
    src_dir = audit_dir / "src"
    client = client or _client()
    for f in findings:
        f.update(verify_finding(f, src_dir, client, model))
    (audit_dir / "findings.json").write_text(
        json.dumps(findings, indent=2), encoding="utf-8", newline="\n")
    summary = {"total": len(findings)}
    for v in ("confirmed", "refuted", "uncertain"):
        summary[v] = sum(1 for f in findings if f.get("verdict") == v)
    return findings, summary
