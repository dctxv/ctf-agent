"""Tier A - campaign budget ledger tests (offline).

Run from the repo root:  python -m unittest tests.test_campaign -v
"""
import tempfile
import unittest
from pathlib import Path

from eval.campaign import Campaign


class TestCampaign(unittest.TestCase):
    def _c(self, cap=1.0):
        return Campaign(Path(tempfile.mkdtemp()) / "c.json", cap_usd=cap)

    def test_add_remaining_cap(self):
        c = self._c(1.0)
        self.assertEqual(c.spent(), 0.0)
        self.assertFalse(c.over_cap())
        self.assertEqual(c.remaining(), 1.0)
        c.add(0.4)
        self.assertAlmostEqual(c.spent(), 0.4)
        self.assertAlmostEqual(c.remaining(), 0.6)
        self.assertFalse(c.over_cap())
        c.add(0.7)
        self.assertTrue(c.over_cap())           # 1.1 >= 1.0
        self.assertEqual(c.remaining(), 0.0)

    def test_persists_across_instances(self):
        p = Path(tempfile.mkdtemp()) / "c.json"
        Campaign(p, cap_usd=5).add(2.0)
        self.assertAlmostEqual(Campaign(p, cap_usd=5).spent(), 2.0)   # reloaded


if __name__ == "__main__":
    unittest.main()
