"""Tier A - multi-agent orchestration tests (offline, no API).

Run from the repo root:  python -m unittest tests.test_multiagent -v
"""
import tempfile
import types
import unittest
from pathlib import Path

from agent.multiagent import SPECIALISTS, supervise


class FakeLLM:
    def __init__(self, content):
        self.content = content
        self.cost_usd = 0.001

    def complete(self, **kw):
        return types.SimpleNamespace(
            choices=[types.SimpleNamespace(message=types.SimpleNamespace(content=self.content))])


class TestSupervise(unittest.TestCase):
    def test_routes_to_named_specialist(self):
        spec, strat, cost = supervise(
            "decode this XOR file", FakeLLM('{"specialist":"crypto","strategy":"brute the byte key"}'))
        self.assertEqual(spec, "crypto")
        self.assertEqual(strat, "brute the byte key")
        self.assertEqual(cost, 0.001)

    def test_unknown_specialist_falls_back(self):
        spec, _, _ = supervise("x", FakeLLM('{"specialist":"wizard"}'))
        self.assertEqual(spec, "recon")

    def test_bad_json_falls_back(self):
        spec, strat, _ = supervise("x", FakeLLM('no json here'))
        self.assertEqual(spec, "recon")
        self.assertEqual(strat, "")

    def test_specialists_nonempty(self):
        self.assertIn("crypto", SPECIALISTS)
        self.assertTrue(all(SPECIALISTS.values()))


class TestMultiAgentMode(unittest.TestCase):
    def test_mode_reaches_engagement(self):
        from eval import registry
        from eval.runner import LocalDockerRunner
        seen = {}

        def agent(eng, cfg, m, ri, ws, c, dk, to):
            seen.update(eng)
            (Path(ws) / "evidence").mkdir(parents=True, exist_ok=True)
            (Path(ws) / "evidence" / "flag.txt").write_text("x", encoding="utf-8")
            return {"steps": 3, "cost_usd": 0.01}

        man = registry.select(registry.load_manifests(), ids={"gen-xor-flag"})[0]
        r = LocalDockerRunner(workspace_root=tempfile.mkdtemp(), provision=lambda *a: None,
                              teardown=lambda *a: None, apply_firewall=lambda *a: None,
                              agent_runner=agent)
        r.run_trial(man, run_index=1, experiment_id="e",
                    config={"name": "multi-agent", "mode": "multi-agent"})
        self.assertEqual(seen.get("_mode"), "multi-agent")


if __name__ == "__main__":
    unittest.main()
