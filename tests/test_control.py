"""Tier A - session control + dashboard auth tests (offline, no API).

Run from the repo root:  python -m unittest tests.test_control -v
"""
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from agent.agent import read_control


class TestReadControl(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def test_default_running(self):
        self.assertEqual(read_control(self.d), "running")
        self.assertEqual(read_control(None), "running")

    def test_states(self):
        for s in ("paused", "cancelled", "running"):
            (self.d / "control.json").write_text(json.dumps({"state": s}), encoding="utf-8")
            self.assertEqual(read_control(self.d), s)

    def test_bad_value_is_running(self):
        (self.d / "control.json").write_text(json.dumps({"state": "bogus"}), encoding="utf-8")
        self.assertEqual(read_control(self.d), "running")

    def test_corrupt_is_running(self):
        (self.d / "control.json").write_text("not json", encoding="utf-8")
        self.assertEqual(read_control(self.d), "running")


def _load_server():
    spec = importlib.util.spec_from_file_location("dash", "dashboard/server.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestDashboardControlAuth(unittest.TestCase):
    def setUp(self):
        try:
            from fastapi.testclient import TestClient
        except Exception as e:                      # httpx/starlette TestClient missing
            self.skipTest(f"TestClient unavailable: {e}")
        self.m = _load_server()
        try:
            self.client = TestClient(self.m.app)
        except Exception as e:
            self.skipTest(f"TestClient init failed: {e}")
        self.sid = "__test_ctrl__"
        self.sdir = self.m.SESSIONS / self.sid
        self.sdir.mkdir(parents=True, exist_ok=True)
        (self.sdir / "events.json").write_text("[]", encoding="utf-8")

    def tearDown(self):
        if getattr(self, "sdir", None):
            shutil.rmtree(self.sdir, ignore_errors=True)

    def test_control_writes_file(self):
        r = self.client.post(f"/api/sessions/{self.sid}/control", json={"action": "cancel"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(json.loads((self.sdir / "control.json").read_text())["state"], "cancelled")

    def test_bad_action_400(self):
        r = self.client.post(f"/api/sessions/{self.sid}/control", json={"action": "nope"})
        self.assertEqual(r.status_code, 400)

    def test_auth_enforced_when_token_set(self):
        self.m.DASH_TOKEN = "secret"
        try:
            self.assertEqual(self.client.get("/api/sessions").status_code, 401)
            ok = self.client.get("/api/sessions", headers={"X-Dashboard-Token": "secret"})
            self.assertEqual(ok.status_code, 200)
        finally:
            self.m.DASH_TOKEN = ""


if __name__ == "__main__":
    unittest.main()
