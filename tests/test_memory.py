"""Tier A - experience-memory tests (offline, no Docker, no API).

Run from the repo root:  python -m unittest tests.test_memory -v
"""
import tempfile
import time
import unittest
from pathlib import Path

from agent.memory import MemoryStore


def _store(ns="default"):
    return MemoryStore(Path(tempfile.mkdtemp()) / "mem.jsonl", namespace=ns)


class TestMemory(unittest.TestCase):
    def test_record_and_retrieve(self):
        m = _store()
        m.record(category="crypto", outcome="solved",
                 technique="read_file > run_command python xor brute > write_file",
                 goal="decrypt a single-byte XOR file")
        hits = m.retrieve(goal="recover a XOR encrypted file", category="crypto")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["category"], "crypto")

    def test_namespace_isolation(self):
        d = Path(tempfile.mkdtemp()) / "mem.jsonl"
        a = MemoryStore(d, namespace="clientA")
        b = MemoryStore(d, namespace="clientB")
        a.record(category="crypto", outcome="solved", technique="xor brute", goal="xor")
        self.assertEqual(len(b.retrieve(goal="xor", category="crypto")), 0)   # B cannot see A
        self.assertEqual(len(a.retrieve(goal="xor", category="crypto")), 1)

    def test_flags_never_stored(self):
        m = _store()
        rec = m.record(category="crypto", outcome="solved",
                       technique="recovered FLAG{supersecret123} via xor",
                       goal="find FLAG{supersecret123}")
        self.assertNotIn("supersecret123", rec["technique"])
        self.assertNotIn("supersecret123", rec["goal"])
        self.assertNotIn("supersecret123", " ".join(rec["keywords"]))

    def test_solved_only_filter(self):
        m = _store()
        m.record(category="crypto", outcome="failed", technique="gave up", goal="xor")
        self.assertEqual(len(m.retrieve(goal="xor", category="crypto")), 0)
        self.assertEqual(len(m.retrieve(goal="xor", category="crypto", solved_only=False)), 1)

    def test_category_match_ranks_higher(self):
        m = _store()
        m.record(category="crypto", outcome="solved", technique="xor brute single byte", goal="xor decode")
        m.record(category="forensics", outcome="solved", technique="strings extraction", goal="xor decode")
        hits = m.retrieve(goal="xor decode", category="crypto")
        self.assertEqual(hits[0]["category"], "crypto")   # same category wins the tie

    def test_dedup(self):
        m = _store()
        m.record(category="crypto", outcome="solved", technique="xor brute", goal="x")
        m.record(category="crypto", outcome="solved", technique="xor brute", goal="x")
        self.assertEqual(len(m._read()), 1)

    def test_format_hints(self):
        m = _store()
        m.record(category="crypto", outcome="solved", technique="xor brute", goal="x")
        txt = m.format_hints(m.retrieve(goal="x", category="crypto"))
        self.assertIn("crypto", txt)
        self.assertIn("xor brute", txt)


class TestRunnerMemory(unittest.TestCase):
    """Full memory loop through LocalDockerRunner (offline, injected side effects):
    first trial records a solved lesson; the second retrieves and injects it."""

    def test_inject_and_record(self):
        import json
        from eval import registry
        from eval.runner import LocalDockerRunner

        tmp = tempfile.mkdtemp()
        seen = {}

        def agent(eng, cfg, m, ri, ws, c, dk, to):
            seen["goal"] = eng["goal"]
            slug = Path(ws).name
            key = json.loads((Path("eval/keys") / f"{slug}.json").read_text())["key"]
            (Path(ws) / "evidence" / "flag.txt").write_text("got " + key, encoding="utf-8")
            return {"steps": 6, "cost_usd": 0.01,
                    "technique": "read_file > run_command > write_file"}

        man = registry.select(registry.load_manifests(), ids={"gen-xor-flag"})[0]
        ns = "abtest-" + Path(tmp).name
        cfg = {"name": "flash", "memory": "on", "memory_namespace": ns}
        r = LocalDockerRunner(workspace_root=tmp, provision=lambda *a: None,
                              teardown=lambda *a: None, apply_firewall=lambda *a: None,
                              agent_runner=agent, firewall=False)
        r1 = r.run_trial(man, run_index=1, experiment_id="e", config=cfg)
        self.assertEqual(r1["outcome"], "verified_success")
        self.assertNotIn("Prior experience", seen["goal"])   # cold on the first trial
        r.run_trial(man, run_index=2, experiment_id="e", config=cfg)
        self.assertIn("Prior experience", seen["goal"])       # warm on the second


if __name__ == "__main__":
    unittest.main()
