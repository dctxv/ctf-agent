"""Tier A - attack-map storyboard tests (offline, no API, no network).

Covers the event->storyboard extractor, the LLM narration pass (with a fake
client), the deterministic fallback, the player-template injection, and the
dashboard route functions (called directly, so no fastapi.testclient / httpx dep).

Run from the repo root:  python -m unittest tests.test_storyboard -v
"""
import json
import shutil
import tempfile
import types
import unittest
from pathlib import Path

from agent import storyboard

FIX = Path(__file__).parent / "fixtures" / "story_session"


def fake_client(content):
    """A stand-in LLMClient whose .complete() returns `content` as the message."""
    def complete(**kw):
        return types.SimpleNamespace(
            usage=types.SimpleNamespace(prompt_tokens=100, completion_tokens=50),
            choices=[types.SimpleNamespace(
                message=types.SimpleNamespace(content=content, tool_calls=None))])
    return types.SimpleNamespace(complete=complete, cost_usd=0.0012)


GOOD_JSON = json.dumps({
    "title": "UNION SQLi dump of users",
    "subtitle": "via the product search API",
    "target": "host.docker.internal:3000",
    "outcome": "success",
    "tldr": "The agent found a SQL injection in the search box and used it to read the user table.",
    "nodes": [
        {"id": "n0", "label": "Attacker", "kind": "attacker", "phase": None},
        {"id": "n1", "label": "Juice Shop", "kind": "target", "phase": "recon"},
        {"id": "n2", "label": "/rest/products/search", "kind": "endpoint", "phase": "discovery"},
        {"id": "n3", "label": "SQLi confirmed", "kind": "finding", "phase": "exploit", "severity": "critical"},
        {"id": "n4", "label": "Users table", "kind": "loot", "phase": "exfil"},
    ],
    "steps": [
        {"i": 1, "phase": "recon", "node": "n1", "edge": ["n0", "n1"],
         "headline": "Knocked on the door", "say": "Loaded the site to see what it was.", "action_idx": 0},
        {"i": 2, "phase": "discovery", "node": "n2", "edge": ["n1", "n2"],
         "headline": "Probed the search API", "say": "Poked the search box with a quote.", "action_idx": 1},
        {"i": 3, "phase": "exploit", "node": "n3", "edge": ["n2", "n3"],
         "headline": "Confirmed injection", "say": "The database leaked an error.", "action_idx": 2},
        {"i": 4, "phase": "exfil", "node": "n4", "edge": ["n3", "n4"],
         "headline": "Dumped the users", "say": "Read the user table out through the hole.", "action_idx": 2},
    ],
})


class TestExtract(unittest.TestCase):
    def test_scope_and_actions(self):
        ex = storyboard.extract(FIX)
        self.assertEqual(ex["session"], "story-fixture")
        self.assertIn("UNION", ex["goal"])
        self.assertIn("host.docker.internal", ex["targets"])
        self.assertEqual(ex["stats"]["steps"], 3)                 # three tool_call events
        self.assertEqual([a["tool"] for a in ex["actions"]], ["run_command"] * 3)
        self.assertEqual(ex["actions"][0]["i"], 0)                # ordered, 0-based
        self.assertIn("curl", ex["actions"][0]["detail"])

    def test_cost_and_duration(self):
        ex = storyboard.extract(FIX)
        self.assertAlmostEqual(ex["stats"]["cost_usd"], 0.0274, places=4)
        self.assertGreater(ex["stats"]["duration_s"], 0)

    def test_ctf_loot_token_missing_file(self):
        # the evidence file does not exist on disk -> present False, token not hit
        ex = storyboard.extract(FIX)
        self.assertEqual(ex["loot"]["kind"], "evidence")
        self.assertEqual(ex["loot"]["contains"], "admin@example.com")
        self.assertFalse(ex["loot"]["present"])


class TestNarrate(unittest.TestCase):
    def test_valid_json_normalized(self):
        ex = storyboard.extract(FIX)
        sb = storyboard.narrate(ex, client=fake_client(GOOD_JSON))
        self.assertEqual(sb["schema"], storyboard.SCHEMA)
        self.assertEqual(sb["outcome"], "success")
        self.assertEqual(sb["stats"], ex["stats"])               # stats are authoritative from events
        self.assertTrue(sb["nodes"] and sb["steps"])
        ids = {n["id"] for n in sb["nodes"]}
        for st in sb["steps"]:                                   # every step references a real node
            self.assertIn(st["node"], ids)
            if st["edge"]:
                self.assertTrue(all(x in ids for x in st["edge"]))
        self.assertEqual(sb["phases"], ["recon", "discovery", "exploit", "exfil"])

    def test_command_backfilled_from_action_idx(self):
        ex = storyboard.extract(FIX)
        sb = storyboard.narrate(ex, client=fake_client(GOOD_JSON))
        self.assertIn("curl", sb["steps"][0]["command"])         # pulled from actions[0]

    def test_fenced_json_is_parsed(self):
        ex = storyboard.extract(FIX)
        sb = storyboard.narrate(ex, client=fake_client("```json\n" + GOOD_JSON + "\n```"))
        self.assertNotIn("fallback", sb["model"])
        self.assertEqual(len(sb["steps"]), 4)

    def test_dangling_node_ref_is_repaired(self):
        ex = storyboard.extract(FIX)
        bad = json.loads(GOOD_JSON)
        bad["steps"][0]["node"] = "does-not-exist"
        sb = storyboard.narrate(ex, client=fake_client(json.dumps(bad)))
        ids = {n["id"] for n in sb["nodes"]}
        self.assertIn(sb["steps"][0]["node"], ids)               # repaired, not crashed

    def test_bad_json_falls_back_to_skeleton(self):
        ex = storyboard.extract(FIX)
        sb = storyboard.narrate(ex, client=fake_client("sorry, here is your map!"))
        self.assertIn("fallback", sb["model"])
        self.assertTrue(sb["steps"])
        self.assertEqual(sb["nodes"][0]["id"], "n0")
        self.assertEqual(sb["nodes"][0]["kind"], "attacker")


class TestBuildAndRender(unittest.TestCase):
    def test_build_writes_and_caches(self):
        with tempfile.TemporaryDirectory() as d:
            sess = Path(d) / "sess"
            sess.mkdir()
            shutil.copy(FIX / "events.json", sess / "events.json")
            r1 = storyboard.build_storyboard(sess, client=fake_client(GOOD_JSON))
            self.assertFalse(r1["cached"])
            self.assertTrue((sess / "storyboard.json").is_file())
            # a second call must NOT regenerate (no cost), it reads the cache
            r2 = storyboard.build_storyboard(sess, client=fake_client("WOULD CRASH IF CALLED"))
            self.assertTrue(r2["cached"])
            self.assertEqual(r2["cost_usd"], 0.0)
            self.assertEqual(r2["storyboard"]["title"], r1["storyboard"]["title"])

    def test_render_html_injects_and_removes_placeholder(self):
        sb = storyboard.narrate(storyboard.extract(FIX), client=fake_client(GOOD_JSON))
        with tempfile.TemporaryDirectory() as d:
            tpl = Path(d) / "player.html"
            tpl.write_text("<html><script id=sb>__STORYBOARD__</script></html>", encoding="utf-8")
            html = storyboard.render_html(sb, template_path=tpl)
        self.assertNotIn("__STORYBOARD__", html)
        self.assertIn('"UNION SQLi dump of users"', html)
        self.assertNotIn("</script>", html.split("<script id=sb>")[1].split("</html>")[0][:-0] or "")


class TestServerRoutes(unittest.TestCase):
    """Call the dashboard route functions directly against a fixture session dir
    (no server, no httpx). Patches SESSIONS to a temp dir."""

    def setUp(self):
        from dashboard import server
        self.server = server
        self._orig = server.SESSIONS
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        (base / "story-fixture").mkdir()
        shutil.copy(FIX / "events.json", base / "story-fixture" / "events.json")
        server.SESSIONS = base.resolve()

    def tearDown(self):
        self.server.SESSIONS = self._orig
        self.tmp.cleanup()

    def test_storyboard_endpoint_ungenerated(self):
        out = self.server.api_storyboard("story-fixture")
        body = json.loads(out.body) if hasattr(out, "body") else out
        self.assertFalse(body["generated"])

    def test_replay_requires_generation(self):
        # no storyboard.json yet -> replay should 404 rather than silently build (costs money)
        from fastapi import HTTPException
        with self.assertRaises(HTTPException):
            self.server.api_replay("story-fixture")


if __name__ == "__main__":
    unittest.main()
