"""Privacy mode: anonymize target identifiers before they leave the machine to
the model API, and restore them before tools run locally.

The message history sent to the API holds only placeholders; real hostnames, IPs
and emails appear only transiently, when a tool call is executed. Scope
enforcement is unaffected: tool-call args are restored to their real values
BEFORE the allowlist check, so privacy never widens (or narrows) scope.
"""
import re

_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')


class Privacy:
    def __init__(self, seed_hosts=None, seed_text=""):
        self.map = {}      # real -> placeholder
        self.rmap = {}     # placeholder -> real
        self._n = {"HOST": 0, "IP": 0, "EMAIL": 0}
        for h in (seed_hosts or []):
            self._assign(h, "IP" if _IP.fullmatch(h or "") else "HOST")
        self._detect(seed_text)

    def _assign(self, real, kind):
        real = (real or "").strip()
        if not real:
            return None
        if real in self.map:
            return self.map[real]
        self._n[kind] += 1
        ph = f"TARGET{kind}{self._n[kind]}"
        self.map[real] = ph
        self.rmap[ph] = real
        return ph

    def _detect(self, text):
        for m in _IP.findall(text or ""):
            self._assign(m, "IP")
        for m in _EMAIL.findall(text or ""):
            self._assign(m, "EMAIL")

    def scrub(self, text):
        """Real -> placeholder. Registers any new IPs/emails first."""
        if not text:
            return text
        self._detect(text)
        for real in sorted(self.map, key=len, reverse=True):  # longest first
            text = text.replace(real, self.map[real])
        return text

    def restore(self, text):
        """Placeholder -> real."""
        if not text:
            return text
        for ph in sorted(self.rmap, key=len, reverse=True):
            text = text.replace(ph, self.rmap[ph])
        return text

    def scrub_obj(self, obj):
        if isinstance(obj, str):
            return self.scrub(obj)
        if isinstance(obj, dict):
            return {k: self.scrub_obj(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.scrub_obj(v) for v in obj]
        return obj

    def restore_obj(self, obj):
        if isinstance(obj, str):
            return self.restore(obj)
        if isinstance(obj, dict):
            return {k: self.restore_obj(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.restore_obj(v) for v in obj]
        return obj


def from_engagement(engagement) -> "Privacy":
    """Seed a Privacy map from an engagement's allowed_hosts + targets/goal text."""
    seed_text = " ".join(str(engagement.get(k, "")) for k in ("targets", "goal"))
    return Privacy(seed_hosts=engagement.get("allowed_hosts", []), seed_text=seed_text)
