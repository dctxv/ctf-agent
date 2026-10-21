"""Experience memory: a lightweight, namespaced store of past-engagement lessons.

What it stores: PROCEDURAL notes only - category, outcome, the tool/approach
sketch, and goal keywords. It never stores answers, flags, or evidence content
(flags are scrubbed), so a held-out solution cannot leak into memory and then
back to the agent.

Retrieval: keyword overlap + category match with recency decay. Deliberately no
embedding model - that keeps the project DeepSeek-only and dependency-free; a
vector-backed retriever is a future option, not a requirement.

Isolation: every record carries a namespace, and retrieval only sees its own.
Unrelated engagements or clients therefore never share memory.

Memory is not learning. Whether stored experience actually improves solving,
reduces mistakes, or lowers cost is an empirical question answered by an A/B on
held-out challenges - this module is the mechanism, not the claim.
"""
import json
import re
import time
import uuid
from pathlib import Path

_FLAG_RE = re.compile(r'FLAG\{[^}]*\}', re.I)
_WORD = re.compile(r'[a-z0-9]+')
_STOP = {"the", "a", "an", "to", "and", "of", "it", "is", "in", "on", "for", "then",
         "save", "file", "workspace", "evidence", "finish", "value", "contains", "its"}


def _scrub(text):
    return _FLAG_RE.sub("FLAG{...}", text or "")


def _tokens(text):
    return set(_WORD.findall((text or "").lower())) - _STOP


class MemoryStore:
    def __init__(self, path, namespace="default"):
        self.path = Path(path)
        self.namespace = namespace
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _read(self):
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return out

    def record(self, *, category, outcome, technique, goal="", keywords=None):
        rec = {
            "id": uuid.uuid4().hex[:12],
            "ts": time.time(),
            "namespace": self.namespace,
            "category": category or "",
            "outcome": outcome,
            "technique": _scrub(technique)[:400],
            "goal": _scrub(goal)[:300],
            "keywords": sorted(set(keywords or []) | _tokens(_scrub(goal)))[:20],
        }
        # dedup: identical lesson already in this namespace
        for r in self._read():
            if (r.get("namespace") == self.namespace and r.get("category") == rec["category"]
                    and r.get("technique") == rec["technique"]
                    and r.get("outcome") == rec["outcome"]):
                return r
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        return rec

    def retrieve(self, *, goal="", category="", k=3, solved_only=True, half_life_days=30):
        recs = [r for r in self._read() if r.get("namespace") == self.namespace]
        if solved_only:
            recs = [r for r in recs if r.get("outcome") == "solved"]
        q = _tokens(goal)
        now = time.time()
        scored = []
        for r in recs:
            kw = set(r.get("keywords", [])) | _tokens(r.get("technique", ""))
            overlap = len(q & kw) / (len(q) + 1)
            score = (2.0 if (category and r.get("category") == category) else 0.0) + overlap
            age_days = (now - r.get("ts", now)) / 86400.0
            score *= 0.5 ** (age_days / half_life_days)   # recency decay
            if score > 0:
                scored.append((score, r))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [r for _, r in scored[:k]]

    def format_hints(self, recs):
        return "\n".join(
            f"- [{r.get('category', '?')}, {r.get('outcome', '?')}] {r.get('technique', '')}"
            for r in recs)
