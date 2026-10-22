"""Persistent campaign spend ledger with a hard global cap across experiments.

This is an APPLICATION-SIDE estimate accumulated from per-trial cost, NOT the
provider's authoritative bill - always reconcile against the Anthropic / DeepSeek
dashboards. The controller checks over_cap() before launching each trial, so the
worst-case overshoot is one trial's own max_cost_usd (runs are sequential; there
are no concurrent in-flight requests to overshoot further).
"""
import json
import threading
from pathlib import Path

_LOCK = threading.Lock()


class Campaign:
    def __init__(self, path="eval/campaign.json", cap_usd=40.0):
        self.path = Path(path)
        self.cap = float(cap_usd)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def spent(self):
        try:
            return float(json.loads(self.path.read_text(encoding="utf-8")).get("spent", 0.0))
        except Exception:
            return 0.0

    def remaining(self):
        return max(0.0, self.cap - self.spent())

    def over_cap(self):
        return self.spent() >= self.cap

    def add(self, amount):
        with _LOCK:
            total = self.spent() + float(amount or 0)
            self.path.write_text(json.dumps({"spent": round(total, 6), "cap": self.cap}),
                                 encoding="utf-8")
            return total
