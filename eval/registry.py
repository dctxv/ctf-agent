"""Challenge registry: load and validate versioned manifests.

A manifest is a thin overlay on an existing engagement config (challenges/*.json
stays the source of truth for goal/scope), adding evaluation metadata: tier,
dataset (dev|validation|test), category, a version, and the independent verifier
spec. Manifests live under eval/registry/ as individual files or JSON arrays.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = 1
_REQUIRED = {"schema_version", "id", "version", "category", "tier", "dataset", "verifier"}
_VALID_TIERS = {"A", "B", "C", "D", "E"}
_VALID_DATASETS = {"dev", "validation", "test"}


def _validate(m, src):
    missing = _REQUIRED - set(m)
    if missing:
        raise ValueError(f"{src}: manifest '{m.get('id', '?')}' missing fields {sorted(missing)}")
    if m["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"{src}: schema_version {m['schema_version']} != {SCHEMA_VERSION}")
    if m["tier"] not in _VALID_TIERS:
        raise ValueError(f"{src}: bad tier {m['tier']!r} (expected one of {sorted(_VALID_TIERS)})")
    if m["dataset"] not in _VALID_DATASETS:
        raise ValueError(f"{src}: bad dataset {m['dataset']!r}")
    if not m.get("challenge") and not m.get("generator"):
        raise ValueError(f"{src}: manifest '{m['id']}' needs 'challenge' or 'generator'")
    if m.get("challenge") and not (ROOT / m["challenge"]).exists():
        raise ValueError(f"{src}: challenge file not found: {m['challenge']}")
    if "path" not in (m["verifier"] or {}):
        raise ValueError(f"{src}: verifier for '{m['id']}' needs a 'path'")
    return m


def load_manifests(registry_dir="eval/manifests"):
    """Load, validate, and return all manifests. Raises on any invalid manifest
    or duplicate id - an evaluation never runs against an unvalidated registry."""
    out = []
    d = ROOT / registry_dir
    for f in sorted(d.glob("*.json")):
        data = json.loads(f.read_text(encoding="utf-8"))
        for m in (data if isinstance(data, list) else [data]):
            out.append(_validate(m, f.name))
    ids = [m["id"] for m in out]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ValueError(f"duplicate manifest ids: {dupes}")
    return out


def load_engagement(manifest):
    """The underlying engagement config for a manifest."""
    return json.loads((ROOT / manifest["challenge"]).read_text(encoding="utf-8"))


def select(manifests, *, tiers=None, datasets=None, ids=None, categories=None):
    def ok(m):
        return ((not tiers or m["tier"] in tiers)
                and (not datasets or m["dataset"] in datasets)
                and (not ids or m["id"] in ids)
                and (not categories or m["category"] in categories))
    return [m for m in manifests if ok(m)]
