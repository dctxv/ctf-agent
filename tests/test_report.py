"""Tier A - report/analytics tests (offline, pure functions over row dicts).

Run from the repo root:  python -m unittest tests.test_report -v
"""
import unittest

from eval import report


def _row(outcome, challenge, category, cost=0.01, steps=5, dur=10.0,
         dataset="dev", fr="", config="flash"):
    return {"outcome": outcome, "challenge_id": challenge, "category": category,
            "cost_usd": cost, "steps": steps, "duration_s": dur, "dataset": dataset,
            "failure_reason": fr, "config_name": config}


class TestWilson(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(report.wilson(0, 0), (0.0, 0.0, 0.0))

    def test_half(self):
        p, lo, hi = report.wilson(5, 10)
        self.assertAlmostEqual(p, 0.5)
        self.assertTrue(0.0 <= lo < 0.5 < hi <= 1.0)

    def test_small_n_wide(self):
        _, lo1, hi1 = report.wilson(1, 2)
        _, lo2, hi2 = report.wilson(50, 100)
        self.assertGreater(hi1 - lo1, hi2 - lo2)  # smaller n => wider interval


class TestSummarize(unittest.TestCase):
    def setUp(self):
        self.rows = [
            _row("verified_success", "c01", "web"),
            _row("verified_failure", "c01", "web", fr="verification"),
            _row("verified_success", "c02", "web"),
            _row("infra_error", "c02", "web"),        # excluded from denominator
            _row("verified_success", "c09", "reverse"),
        ]

    def test_overall_excludes_infra(self):
        s = report.summarize(self.rows)
        self.assertEqual(s["overall"]["n"], 4)        # 5 rows - 1 infra
        self.assertEqual(s["overall"]["solved"], 3)
        self.assertEqual(s["overall"]["infra_errors"], 1)

    def test_by_category(self):
        s = report.summarize(self.rows)
        self.assertEqual(s["by_category"]["web"]["n"], 3)      # infra removed
        self.assertEqual(s["by_category"]["reverse"]["solved"], 1)

    def test_failure_reasons(self):
        s = report.summarize(self.rows)
        self.assertEqual(s["overall"]["failure_reasons"].get("verification"), 1)

    def test_dev_caveat_present(self):
        s = report.summarize(self.rows)
        self.assertTrue(any("dev-tier" in c for c in s["caveats"]))

    def test_single_category_caveat(self):
        rows = [_row("verified_success", "c01", "web"), _row("verified_failure", "c02", "web")]
        s = report.summarize(rows)
        self.assertTrue(any("single category" in c for c in s["caveats"]))


class TestRegression(unittest.TestCase):
    def test_delta(self):
        before = [_row("verified_failure", "c08", "forensics")]
        after = [_row("verified_success", "c08", "forensics")]
        reg = report.regression(before, after)
        self.assertEqual(reg["c08"]["delta"], 1)
        self.assertEqual(reg["c08"]["before"], 0)
        self.assertEqual(reg["c08"]["after"], 1)


class TestRenderMarkdown(unittest.TestCase):
    def test_contains_sections(self):
        rows = [_row("verified_success", "c01", "web"), _row("verified_failure", "c09", "reverse")]
        md = report.render_markdown(report.summarize(rows), title="T", experiment_id="e")
        self.assertIn("Verified solve rate", md)
        self.assertIn("By category", md)
        self.assertIn("By challenge", md)
        self.assertIn("Read with care", md)  # caveat block


class TestPareto(unittest.TestCase):
    def test_all_equal_success_cheapest_wins(self):
        byc = {"economy": {"mean_cost_usd": 0.003, "solve_rate": 1.0},
               "balanced": {"mean_cost_usd": 0.005, "solve_rate": 1.0},
               "maximum": {"mean_cost_usd": 0.02, "solve_rate": 1.0}}
        self.assertEqual(report.pareto_front(byc), ["economy"])

    def test_tradeoff_keeps_both(self):
        byc = {"cheap": {"mean_cost_usd": 0.001, "solve_rate": 0.5},
               "mid": {"mean_cost_usd": 0.005, "solve_rate": 0.9},
               "dominated": {"mean_cost_usd": 0.01, "solve_rate": 0.9}}
        self.assertEqual(set(report.pareto_front(byc)), {"cheap", "mid"})


if __name__ == "__main__":
    unittest.main()
