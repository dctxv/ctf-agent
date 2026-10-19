"""Platform adapters (Phase 2): turn a hosted CTF challenge into an engagement
dict the agent can run, instead of hand-writing engagement.json.

SAFETY CONTRACT: an adapter NEVER sets allowed_hosts from platform-supplied data
on its own. It may SUGGEST hosts parsed from a challenge's connection info (in
`_suggested_hosts`), but the operator must pass/confirm `allowed_hosts`
explicitly. An engagement built without allowed_hosts gets an empty list, which
is safe-by-default: run_command and the browser tools block every host against
an empty allowlist, so nothing can be touched until the operator approves scope.
"""
import os
import re
from pathlib import Path

import requests


def suggest_hosts(text: str) -> list:
    """Best-effort host candidates from challenge text. SUGGESTION ONLY - never
    fed into allowed_hosts automatically."""
    hosts = set()
    text = text or ""
    for m in re.finditer(r'https?://([A-Za-z0-9.\-]+)', text):
        hosts.add(m.group(1).lower())
    for m in re.finditer(r'\b(?:nc|ncat|telnet|ssh)\s+([A-Za-z0-9.\-]+)\s+\d+', text):
        hosts.add(m.group(1).lower())
    for m in re.finditer(r'\b((?:\d{1,3}\.){3}\d{1,3})\b', text):
        hosts.add(m.group(1))
    return sorted(hosts)


class PlatformAdapter:
    """Interface: fetch challenge metadata and produce an engagement dict."""

    def list_challenges(self) -> list:
        raise NotImplementedError

    def build_engagement(self, challenge_id, *, allowed_hosts=None,
                         workspace=".", max_steps=40, max_cost_usd=1.0) -> dict:
        raise NotImplementedError

    def submit_flag(self, challenge_id, flag: str) -> dict:
        raise NotImplementedError


class CTFdAdapter(PlatformAdapter):
    """Adapter for CTFd (and CTFd-compatible) instances via the v1 REST API.

    base_url/token default to the CTFD_URL / CTFD_TOKEN environment variables so
    the token never has to be passed through code or chat.
    """

    def __init__(self, base_url=None, token=None, session=None):
        self.base = (base_url or os.environ.get("CTFD_URL", "")).rstrip("/")
        self.token = token or os.environ.get("CTFD_TOKEN", "")
        self.s = session or requests.Session()
        if self.token:
            self.s.headers["Authorization"] = f"Token {self.token}"
        self.s.headers["Content-Type"] = "application/json"

    def _get(self, path):
        r = self.s.get(self.base + path, timeout=30)
        r.raise_for_status()
        j = r.json()
        if not j.get("success", False):
            raise RuntimeError(f"CTFd API error for {path}: {j}")
        return j["data"]

    def list_challenges(self) -> list:
        return [{"id": c["id"], "name": c.get("name"),
                 "category": c.get("category"), "value": c.get("value")}
                for c in self._get("/api/v1/challenges")]

    def get_challenge(self, challenge_id) -> dict:
        return self._get(f"/api/v1/challenges/{challenge_id}")

    def build_engagement(self, challenge_id, *, allowed_hosts=None,
                         workspace=".", max_steps=40, max_cost_usd=1.0) -> dict:
        c = self.get_challenge(challenge_id)
        name = c.get("name", f"challenge-{challenge_id}")
        slug = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-') or str(challenge_id)
        ename = f"ctfd-{slug}"
        desc = c.get("description", "") or ""
        conn = c.get("connection_info") or ""
        return {
            "engagement_name": ename,
            # The challenge's own prompt from the platform - not an authored attack.
            "goal": f"Solve the CTF challenge '{name}' ({c.get('category', '')}). "
                    f"{desc} Write the recovered flag to the evidence file.".strip(),
            "targets": conn or f"CTFd challenge {challenge_id} on {self.base}",
            # SAFE DEFAULT: empty unless the operator passes scope explicitly.
            "allowed_hosts": list(allowed_hosts) if allowed_hosts else [],
            "workspace": workspace,
            "max_steps": max_steps,
            "max_cost_usd": max_cost_usd,
            "evidence": {"type": "file_exists", "path": f"evidence/{ename}_flag.txt"},
            "_ctfd": {"challenge_id": challenge_id, "files": c.get("files", []),
                      "value": c.get("value"), "base_url": self.base},
            # Operator must review these before putting any into allowed_hosts.
            "_suggested_hosts": suggest_hosts(desc + " " + conn),
        }

    def download_files(self, challenge_id, dest_dir) -> list:
        c = self.get_challenge(challenge_id)
        out = []
        for f in c.get("files", []):
            url = f if f.startswith("http") else self.base + f
            r = self.s.get(url, timeout=60)
            r.raise_for_status()
            name = url.split("?")[0].rsplit("/", 1)[-1] or "file.bin"
            path = Path(dest_dir) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(r.content)
            out.append(str(path))
        return out

    def submit_flag(self, challenge_id, flag: str) -> dict:
        r = self.s.post(self.base + "/api/v1/challenges/attempt",
                        json={"challenge_id": challenge_id, "submission": flag}, timeout=30)
        r.raise_for_status()
        d = r.json().get("data", {})
        return {"status": d.get("status"), "message": d.get("message")}
