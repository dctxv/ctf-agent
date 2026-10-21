"""Model-provider layer. DeepSeek is the provider (OpenAI-compatible wire
format). This centralizes what the agent, court, and learn modules each used to
hard-code: client construction, role -> model routing, pricing/cost tracking,
the thinking-mode parameter, and the graceful fallback when the API rejects it.

It is an interface, not three copies, so swapping or adding a provider later is a
contained change - but there is intentionally no second provider today; the
project runs on the DeepSeek API only.
"""
import os

from openai import OpenAI

# $ per 1M tokens. Update when DeepSeek pricing changes.
PRICES = {"deepseek-flash":  {"in": 0.14,  "out": 0.28},
          "deepseek-v4-pro": {"in": 0.435, "out": 0.87}}

# Role -> model. The agent loop uses the cheap model and escalates to the
# reasoning model; verify/summarize are cheap single calls.
DEFAULT_ROLES = {
    "loop": "deepseek-flash",
    "escalate": "deepseek-v4-pro",
    "verify": "deepseek-flash",
    "summarize": "deepseek-flash",
}

BASE_URL = "https://api.deepseek.com"


def _strip_reasoning(messages):
    """Remove reasoning_content from history before sending.

    The reasoning model returns a `reasoning_content` field; echoing it back on a
    later turn makes the API reject the request (a BadRequestError observed in a
    baseline run). It is never needed as input, so drop it everywhere.
    """
    for m in messages or []:
        if isinstance(m, dict) and "reasoning_content" in m:
            del m["reasoning_content"]
    return messages


class LLMClient:
    def __init__(self, roles=None, prices=None, api_key=None, base_url=BASE_URL, client=None):
        self.roles = dict(DEFAULT_ROLES, **(roles or {}))
        self.prices = dict(PRICES, **(prices or {}))
        self._client = client or OpenAI(
            api_key=api_key or os.environ["DEEPSEEK_API_KEY"], base_url=base_url)
        self.cost_usd = 0.0
        self.last_usage = None

    def model_for(self, role):
        return self.roles.get(role, self.roles["loop"])

    def price(self, model):
        return self.prices.get(model) or self.prices[self.roles["loop"]]

    def complete(self, *, messages, model=None, role=None, tools=None,
                 temperature=0.3, thinking=False, timeout=180):
        """One chat completion. Routes by role unless `model` is given, strips
        stale reasoning_content, and on a thinking-mode rejection retries once
        without the thinking extras. Returns the raw response."""
        model = model or self.model_for(role or "loop")
        _strip_reasoning(messages)
        kwargs = dict(model=model, messages=messages, temperature=temperature, timeout=timeout)
        if tools:
            kwargs["tools"] = tools
        if thinking:
            kwargs["extra_body"] = {"thinking": {"type": "enabled"}}
        try:
            resp = self._client.chat.completions.create(**kwargs)
        except Exception:
            if thinking:
                kwargs.pop("extra_body", None)
                kwargs.pop("temperature", None)
                resp = self._client.chat.completions.create(**kwargs)
            else:
                raise
        if getattr(resp, "usage", None):
            self._track(model, resp.usage)
        return resp

    def _track(self, model, usage):
        p = self.price(model)
        self.cost_usd += (usage.prompt_tokens * p["in"] + usage.completion_tokens * p["out"]) / 1e6
        self.last_usage = usage
