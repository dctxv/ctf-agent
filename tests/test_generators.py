"""Tier A - generated-challenge tests (offline, no Docker, no API).

Run from the repo root:  python -m unittest tests.test_generators -v
"""
import json
import tempfile
import unittest
from pathlib import Path

from eval import registry, verify
from eval import generators
from eval.generators import get_generator
from eval.runner import LocalDockerRunner


class TestGenerators(unittest.TestCase):
    def _gen(self, name, seed="s1"):
        d = tempfile.mkdtemp()
        res = get_generator(name).generate(d, seed)
        return d, res

    def test_all_produce_flag_and_file_only_engagement(self):
        for name in ("xor_flag", "layered_encoding", "buried_flag"):
            d, res = self._gen(name)
            self.assertTrue(res["key"].startswith("FLAG{"))
            eng = res["engagement"]
            self.assertEqual(eng["allowed_hosts"], [])          # file-only
            self.assertEqual(eng["evidence"]["path"], "evidence/flag.txt")
            self.assertTrue((Path(d) / "README.txt").exists())

    def test_xor_hides_flag_but_is_solvable(self):
        d, res = self._gen("xor_flag")
        blob = (Path(d) / "challenge.bin").read_bytes()
        self.assertNotIn(res["key"].encode(), blob)             # flag not in plaintext
        # solvable: brute single-byte XOR recovers the flag
        recovered = False
        for k in range(1, 256):
            if res["key"].encode() in bytes(b ^ k for b in blob):
                recovered = True
                break
        self.assertTrue(recovered)

    def test_reverse_hides_flag(self):
        d, res = self._gen("layered_encoding")
        self.assertNotIn(res["key"].encode(), (Path(d) / "encoded.txt").read_bytes())

    def test_forensics_embeds_flag(self):
        d, res = self._gen("buried_flag")
        self.assertIn(res["key"].encode(), (Path(d) / "artifact.dat").read_bytes())

    def test_determinism_and_variation(self):
        _, a = self._gen("xor_flag", "same")
        _, b = self._gen("xor_flag", "same")
        _, c = self._gen("xor_flag", "different")
        self.assertEqual(a["key"], b["key"])        # same seed -> same flag
        self.assertNotEqual(a["key"], c["key"])     # different seed -> different flag

    def test_unknown_generator_raises(self):
        with self.assertRaises(ValueError):
            get_generator("nope")


class TestFlagFromKeyVerifier(unittest.TestCase):
    def setUp(self):
        self.ws = tempfile.mkdtemp()
        (Path(self.ws) / "evidence").mkdir(parents=True, exist_ok=True)

    def _write(self, text):
        (Path(self.ws) / "evidence" / "flag.txt").write_text(text, encoding="utf-8")

    def test_match(self):
        self._write("recovered: FLAG{abc123}")
        oc, _, _ = verify.verify(
            {"path": "evidence/flag.txt", "type": "flag_from_key", "_expected": "FLAG{abc123}"}, self.ws)
        self.assertEqual(oc.value, "verified_success")

    def test_wrong(self):
        self._write("FLAG{nope}")
        oc, _, _ = verify.verify(
            {"path": "evidence/flag.txt", "type": "flag_from_key", "_expected": "FLAG{abc123}"}, self.ws)
        self.assertEqual(oc.value, "verified_failure")

    def test_missing_expected_is_inconclusive(self):
        self._write("FLAG{abc123}")
        oc, reason, _ = verify.verify(
            {"path": "evidence/flag.txt", "type": "flag_from_key"}, self.ws)
        self.assertEqual(oc.value, "inconclusive")


class TestRegistryWithGenerators(unittest.TestCase):
    def test_loads_generated(self):
        ms = registry.load_manifests()
        gen = registry.select(ms, datasets={"test"})
        self.assertEqual({m["id"] for m in gen},
                         {"gen-xor-flag", "gen-layered-encoding", "gen-buried-flag"})
        for m in gen:
            self.assertNotIn("challenge", m)       # generator manifests have no challenge file
            self.assertIn("generator", m)

    def test_categories_cover_three_beyond_web(self):
        cats = {m["category"] for m in registry.select(registry.load_manifests(), datasets={"test"})}
        self.assertEqual(cats, {"crypto", "reverse", "forensics"})


class TestRunnerGeneratorBranch(unittest.TestCase):
    """Generated challenge through LocalDockerRunner with injected side effects:
    proves generate -> host-side key -> oracle-isolated verify."""
    def _manifest(self):
        return registry.select(registry.load_manifests(), ids={"gen-xor-flag"})[0]

    def test_solve_via_hidden_key(self):
        tmp = tempfile.mkdtemp()

        def agent(eng, cfg, m, ri, ws, c, dk, to):
            # simulate a solve: read the host-side key the runner just wrote
            slug = Path(ws).name
            key = json.loads((Path("eval/keys") / f"{slug}.json").read_text())["key"]
            (Path(ws) / "evidence" / "flag.txt").write_text("recovered " + key, encoding="utf-8")
            return {"steps": 7, "cost_usd": 0.02}

        r = LocalDockerRunner(workspace_root=tmp, provision=lambda *a: None,
                              teardown=lambda *a: None, apply_firewall=lambda *a: None,
                              agent_runner=agent, firewall=False)
        res = r.run_trial(self._manifest(), run_index=1, experiment_id="t", config={"name": "flash"})
        self.assertEqual(res["outcome"], "verified_success")
        self.assertEqual(res["category"], "crypto")
        self.assertEqual(res["dataset"], "test")

    def test_wrong_answer_fails(self):
        tmp = tempfile.mkdtemp()

        def agent(eng, cfg, m, ri, ws, c, dk, to):
            (Path(ws) / "evidence" / "flag.txt").write_text("FLAG{totally-wrong}", encoding="utf-8")
            return {"steps": 3, "cost_usd": 0.01}

        r = LocalDockerRunner(workspace_root=tmp, provision=lambda *a: None,
                              teardown=lambda *a: None, apply_firewall=lambda *a: None,
                              agent_runner=agent, firewall=False)
        res = r.run_trial(self._manifest(), run_index=1, experiment_id="t", config={"name": "flash"})
        self.assertEqual(res["outcome"], "verified_failure")


if __name__ == "__main__":
    unittest.main()
