"""Tolerant reader for an audit's findings.json (model-produced, so may be
missing or malformed). Shared by the dashboard and the disclosure exporter."""
import json
from pathlib import Path

_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def load_findings(audit_dir):
    p = Path(audit_dir) / "findings.json"
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    out = [f for f in data if isinstance(f, dict) and f.get("title")]
    out.sort(key=lambda f: _SEV.get(str(f.get("severity", "")).lower(), 9))
    return out
