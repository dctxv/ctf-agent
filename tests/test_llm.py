"""Tier A - LLMClient tests (offline, no API). Uses a fake OpenAI-compatible
client injected into LLMClient.

Run from the repo root:  python -m unittest tests.test_llm -v
"""
import types
import unittest

from agent.llm import LLMClient


class _Completions:
    def __init__(self, parent):
        self.parent = parent

    def create(self, **kw):
        self.parent.calls.append(kw)
        if self.parent.fail_thinking and "extra_body" in kw:
            raise RuntimeError("thinking rejected by API")
        return types.SimpleNamespace(
            usage=types.SimpleNamespace(prompt_tokens=100, completion_tokens=50),
            choices=[types.SimpleNamespace(
                message=types.SimpleNamespace(content="ok", tool_calls=None))])


class _Chat:
    def __init__(self, parent):
        self.completions = _Completions(parent)


class FakeClient:
    def __init__(self, fail_thinking=False):
        self.calls = []
        self.fail_thinking = fail_thinking
        self.chat = _Chat(self)


class TestLLMClient(unittest.TestCase):
    def test_role_routing(self):
        c = LLMClient(client=FakeClient())
        self.assertEqual(c.model_for("loop"), "deepseek-flash")
        self.assertEqual(c.model_for("escalate"), "deepseek-v4-pro")
        self.assertEqual(c.model_for("unknown"), "deepseek-flash")

    def test_strips_reasoning_content(self):
        fake = FakeClient()
        c = LLMClient(client=fake)
        msgs = [{"role": "assistant", "content": "x", "reasoning_content": "secret chain"}]
        c.complete(messages=msgs, role="loop")
        self.assertNotIn("reasoning_content", msgs[0])
        sent = fake.calls[0]["messages"]
        self.assertNotIn("reasoning_content", sent[0])

    def test_cost_tracked(self):
        c = LLMClient(client=FakeClient())
        c.complete(messages=[{"role": "user", "content": "hi"}], model="deepseek-flash")
        # (100 * 0.14 + 50 * 0.28) / 1e6
        self.assertAlmostEqual(c.cost_usd, (100 * 0.14 + 50 * 0.28) / 1e6, places=10)

    def test_thinking_fallback_retries_without_extras(self):
        fake = FakeClient(fail_thinking=True)
        c = LLMClient(client=fake)
        c.complete(messages=[{"role": "user", "content": "hi"}], role="escalate", thinking=True)
        self.assertEqual(len(fake.calls), 2)              # failed once, retried
        self.assertIn("extra_body", fake.calls[0])        # first try had thinking
        self.assertNotIn("extra_body", fake.calls[1])     # retry dropped it

    def test_tools_passed_through(self):
        fake = FakeClient()
        c = LLMClient(client=fake)
        c.complete(messages=[{"role": "user", "content": "hi"}],
                   tools=[{"type": "function"}], model="deepseek-flash")
        self.assertIn("tools", fake.calls[0])

    def test_price_fallback(self):
        c = LLMClient(client=FakeClient())
        self.assertEqual(c.price("some-unknown-model"), c.prices["deepseek-flash"])


if __name__ == "__main__":
    unittest.main()
