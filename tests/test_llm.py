"""Tier A - LLMClient tests (offline, no API). Uses a fake OpenAI-compatible
client injected into LLMClient.

Run from the repo root:  python -m unittest tests.test_llm -v
"""
import json
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


class FakeAnthropic:
    """Stands in for anthropic.Anthropic(); .messages.create(**kw) returns a fake Message."""
    def __init__(self, content_blocks, stop_reason="end_turn", stop_details=None, usage=None):
        self._content = content_blocks
        self._sr = stop_reason
        self._sd = stop_details
        self._usage = usage
        self.calls = []
        self.messages = self

    def create(self, **kw):
        self.calls.append(kw)
        usage = self._usage or types.SimpleNamespace(
            input_tokens=100, output_tokens=50,
            cache_read_input_tokens=0, cache_creation_input_tokens=0)
        return types.SimpleNamespace(content=self._content, stop_reason=self._sr,
                                     stop_details=self._sd, usage=usage)


def _blk(**kw):
    return types.SimpleNamespace(**kw)


class TestAnthropicRouting(unittest.TestCase):
    def test_provider_of(self):
        from agent.llm import provider_of
        self.assertEqual(provider_of("claude-haiku-5-5"), "anthropic")
        self.assertEqual(provider_of("deepseek-flash"), "deepseek")

    def test_tool_translation(self):
        from agent.llm import to_anthropic_tools
        t = to_anthropic_tools([{"type": "function", "function": {
            "name": "run_command", "description": "d",
            "parameters": {"type": "object", "properties": {"command": {"type": "string"}}}}}])
        self.assertEqual(t[0]["name"], "run_command")
        self.assertIn("input_schema", t[0])

    def test_message_translation_groups_tool_results(self):
        from agent.llm import to_anthropic_messages
        msgs = [{"role": "system", "content": "S"},
                {"role": "user", "content": "U"},
                {"role": "assistant", "content": "think",
                 "tool_calls": [{"id": "t1", "function": {"name": "run_command",
                                                          "arguments": '{"command":"ls"}'}}]},
                {"role": "tool", "tool_call_id": "t1", "content": "out"}]
        system, am = to_anthropic_messages(msgs)
        self.assertEqual(system, "S")
        self.assertEqual(am[0], {"role": "user", "content": "U"})
        self.assertTrue(any(b["type"] == "tool_use" and b["name"] == "run_command"
                            for b in am[1]["content"]))
        self.assertEqual(am[2]["content"][0]["type"], "tool_result")
        self.assertEqual(am[2]["content"][0]["tool_use_id"], "t1")


TOOL = [{"type": "function", "function": {"name": "run_command", "description": "d",
         "parameters": {"type": "object", "properties": {"command": {"type": "string"}}}}}]


class TestAnthropicComplete(unittest.TestCase):
    def test_normalizes_response_and_shapes_request(self):
        fake = FakeAnthropic([_blk(type="text", text="let me look"),
                              _blk(type="tool_use", id="tu1", name="run_command",
                                   input={"command": "ls"})])
        c = LLMClient(anthropic_client=fake)
        resp = c.complete(messages=[{"role": "system", "content": "sys"},
                                    {"role": "user", "content": "go"}],
                          model="claude-haiku-5-5", tools=TOOL)
        self.assertEqual(resp.choices[0].message.content, "let me look")
        tc = resp.choices[0].message.tool_calls[0]
        self.assertEqual(tc.function.name, "run_command")
        self.assertEqual(json.loads(tc.function.arguments), {"command": "ls"})
        self.assertEqual(resp.choices[0].message.model_dump()["tool_calls"][0]["id"], "tu1")
        kw = fake.calls[0]
        self.assertEqual(kw["system"], "sys")
        self.assertEqual(kw["cache_control"], {"type": "ephemeral"})
        self.assertEqual(kw["tools"][0]["name"], "run_command")
        self.assertGreater(c.cost_usd, 0)

    def test_cost_includes_cache_tokens(self):
        usage = types.SimpleNamespace(input_tokens=1_000_000, output_tokens=0,
                                      cache_read_input_tokens=0, cache_creation_input_tokens=0)
        fake = FakeAnthropic([_blk(type="text", text="x")], usage=usage)
        c = LLMClient(anthropic_client=fake)
        c.complete(messages=[{"role": "user", "content": "hi"}], model="claude-haiku-5-5")
        self.assertAlmostEqual(c.cost_usd, 0.10, places=9)   # 1M input * $0.10/MTok

    def test_refusal_detected_and_counted(self):
        fake = FakeAnthropic([], stop_reason="refusal",
                             stop_details=types.SimpleNamespace(category="cyber"))
        c = LLMClient(anthropic_client=fake)
        resp = c.complete(messages=[{"role": "user", "content": "x"}], model="claude-haiku-5-5")
        self.assertEqual(resp.refusal_category, "cyber")
        self.assertEqual(c.refusals, 1)
        self.assertIn("refusal:cyber", resp.choices[0].message.content)


if __name__ == "__main__":
    unittest.main()
