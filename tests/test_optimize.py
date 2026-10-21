"""Tier A - M8 policy-proposal tests (offline, pure functions over row dicts).

Run from the repo root:  python -m unittest tests.test_optimize -v
"""
import unittest

from agent import optimize


def _row(cfg, outcome, cost, cat="crypto", ds="test"):
    return {"config_name": cfg, "outcome": outcome, "cost_usd": cost, "category": cat,
            "dataset": ds, "steps": 5, "duration_s": 10, "failure_reason": "",
            "challenge_id": "x"}


class TestAnalyze(unittest.TestCase):
    def test_default_and_avoid(self):
        rows = [_row("cheap", "verified_success", 0.003), _row("cheap", "verified_success", 0.003),
                _row("pricey", "verified_success", 0.01), _row("pricey", "verified_success", 0.01)]
        titles = [p["title"] for p in optimize.analyze(rows)]
        self.assertTrue(any("Default policy: 'cheap'" in t for t in titles))
        self.assertTrue(any("Avoid 'pricey'" in t for t in titles))

    def test_capability_tradeoff_flagged(self):
        rows = [_row("full", "verified_success", 0.003), _row("full", "verified_success", 0.003),
                _row("weak", "verified_failure", 0.001), _row("weak", "verified_success", 0.001)]
        props = optimize.analyze(rows)
        self.assertTrue(any("trade-off" in p["title"] and p["gate"] == "needs-review" for p in props))

    def test_single_config_no_proposals(self):
        self.assertEqual(optimize.analyze([_row("only", "verified_success", 0.003)]), [])


class TestContamination(unittest.TestCase):
    def test_clean(self):
        self.assertTrue(optimize.contamination_check([{"detail": "passed 1 check(s)"}])["clean"])

    def test_flagged(self):
        r = optimize.contamination_check([{"detail": "recovered FLAG{secret}"}])
        self.assertFalse(r["clean"])
        self.assertEqual(r["n_flagged"], 1)


class TestRender(unittest.TestCase):
    def test_human_approval_header_always_present(self):
        md = optimize.render_proposals([], scope="x", contamination={"clean": True, "n_flagged": 0})
        self.assertIn("HUMAN APPROVAL REQUIRED", md)

    def test_proposals_rendered(self):
        rows = [_row("cheap", "verified_success", 0.003), _row("pricey", "verified_success", 0.01)]
        md = optimize.render_proposals(optimize.analyze(rows))
        self.assertIn("Default policy", md)
        self.assertIn("advisable", md)


if __name__ == "__main__":
    unittest.main()
