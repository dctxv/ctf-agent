"""Model-provider layer: DeepSeek (default) and Anthropic (optional).

DeepSeek uses the OpenAI-compatible wire format; Anthropic uses the Messages API
(different shape entirely). To keep the agent loop unchanged, the Anthropic path
TRANSLATES our OpenAI-style messages/tools into Anthropic blocks on the way in,
and NORMALIZES the Anthropic response back into the OpenAI shape the agent reads
(`resp.choices[0].message.content` / `.tool_calls`, `resp.usage.prompt_tokens`...).
Routing is by model id: `claude-*` -> Anthropic, everything else -> DeepSeek.

Cost: per-provider pricing incl. Anthropic cache-read/cache-write tokens (the
cache prices are estimates - app-side accounting, never the authoritative bill).
Prompt caching is enabled on the Anthropic path (our append-only transcript is an
ideal cache prefix). Refusals (`stop_reason == "refusal"`) are surfaced so the
eval can record them as a distinct policy outcome, not a solve failure.

DeepSeek stays the default provider; Anthropic is opt-in by choosing a claude-* model.
"""
import json
import os

# $ per 1M tokens. cache_read / cache_write default to 0 where a provider has no
# cache tiering. Anthropic cache prices are estimates; the dashboard is authoritative.
PRICES = {
    "deepseek-flash":  {"in": 0.14,  "out": 0.28},
    "deepseek-v4-pro": {"in": 0.435, "out": 0.87},
    "claude-haiku-5-5":  {"in": 0.10, "out": 0.50, "cache_read": 0.01, "cache_write": 0.125},
    "claude-sonnet-5-5": {"in": 2.00, "out": 10.00, "cache_read": 0.20, "cache_write": 2.50},
    "claude-opus-5-5":   {"in": 4.00, "out": 20.00, "cache_read": 0.20, "cache_write": 5.00},
}

DEFAULT_ROLES = {
    "loop": "deepseek-flash",
    "escalate": "deepseek-v4-pro",
    "verify": "deepseek-flash",
    "summarize": "deepseek-flash",
}

BASE_URL = "https://api.deepseek.com"
ANTHROPIC_MAX_TOKENS = 8192


def provider_of(model):
    return "anthropic" if str(model).startswith("claude") else "deepseek"


def _strip_reasoning(messages):
    """Drop stale reasoning_content from history (DeepSeek reasoner gotcha)."""
    for m in messages or []:
        if isinstance(m, dict) and "reasoning_content" in m:
            del m["reasoning_content"]
    return messages


# ---------------- OpenAI-shaped mimics for the normalized Anthropic response ----------------

class _Fn:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments


class _ToolCall:
    def __init__(self, id, name, arguments):
        self.id = id
        self.type = "function"
        self.function = _Fn(name, arguments)

    def model_dump(self):
        return {"id": self.id, "type": "function",
                "function": {"name": self.function.name, "arguments": self.function.arguments}}


class _Msg:
    def __init__(self, content, tool_calls):
        self.role = "assistant"
        self.content = content
        self.tool_calls = tool_calls or None

    def model_dump(self):
        d = {"role": "assistant", "content": self.content or ""}
        if self.tool_calls:
            d["tool_calls"] = [tc.model_dump() for tc in self.tool_calls]
        return d


class _Choice:
    def __init__(self, msg):
        self.message = msg


class _Usage:
    def __init__(self, prompt_tokens, completion_tokens):
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens


class _Resp:
    def __init__(self, msg, usage, refusal_category=None):
        self.choices = [_Choice(msg)]
        self.usage = usage
        self.refusal_category = refusal_category


# ---------------- translation: our OpenAI-style messages/tools -> Anthropic ----------------

def to_anthropic_tools(tools):
    out = []
    for t in tools or []:
        f = t.get("function", t)
        out.append({"name": f["name"], "description": f.get("description", ""),
                    "input_schema": f.get("parameters", {"type": "object", "properties": {}})})
    return out


def to_anthropic_messages(messages):
    """Return (system_text, anthropic_messages). Consecutive tool results are
    grouped into one user message, as the Messages API requires."""
    system_parts = []
    out = []
    pending_tool_results = []

    def flush_tools():
        nonlocal pending_tool_results
        if pending_tool_results:
            out.append({"role": "user", "content": pending_tool_results})
            pending_tool_results = []

    for m in messages or []:
        role = m.get("role")
        if role == "system":
            if m.get("content"):
                system_parts.append(m["content"])
            continue
        if role == "tool":
            pending_tool_results.append({
                "type": "tool_result", "tool_use_id": m.get("tool_call_id"),
                "content": str(m.get("content", ""))})
            continue
        flush_tools()
        if role == "assistant":
            blocks = []
            if m.get("content"):
                blocks.append({"type": "text", "text": m["content"]})
            for tc in (m.get("tool_calls") or []):
                fn = tc.get("function", {})
                try:
                    inp = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    inp = {}
                blocks.append({"type": "tool_use", "id": tc.get("id"),
                               "name": fn.get("name"), "input": inp})
            out.append({"role": "assistant", "content": blocks or (m.get("content") or "")})
        else:  # user
            out.append({"role": "user", "content": m.get("content", "")})
    flush_tools()
    return ("\n\n".join(system_parts), out)


def from_anthropic_response(resp):
    """Normalize an Anthropic Message into the OpenAI-shaped _Resp the agent reads."""
    text_parts, tool_calls = [], []
    for block in getattr(resp, "content", []) or []:
        btype = getattr(block, "type", None)
        if btype == "text":
            text_parts.append(getattr(block, "text", "") or "")
        elif btype == "tool_use":
            tool_calls.append(_ToolCall(getattr(block, "id", ""), getattr(block, "name", ""),
                                        json.dumps(getattr(block, "input", {}) or {})))
    refusal = None
    if getattr(resp, "stop_reason", None) == "refusal":
        sd = getattr(resp, "stop_details", None)
        refusal = (getattr(sd, "category", None) or "unspecified") if sd else "unspecified"
        if not text_parts:
            text_parts.append(f"[refusal:{refusal}] the model declined this request.")
    u = getattr(resp, "usage", None)
    usage = _Usage(getattr(u, "input_tokens", 0) if u else 0,
                   getattr(u, "output_tokens", 0) if u else 0)
    usage.cache_read = getattr(u, "cache_read_input_tokens", 0) if u else 0
    usage.cache_write = getattr(u, "cache_creation_input_tokens", 0) if u else 0
    msg = _Msg("".join(text_parts), tool_calls)
    return _Resp(msg, usage, refusal)


class LLMClient:
    def __init__(self, roles=None, prices=None, api_key=None, base_url=BASE_URL,
                 client=None, anthropic_client=None):
        self.roles = dict(DEFAULT_ROLES, **(roles or {}))
        self.prices = dict(PRICES, **(prices or {}))
        self._api_key = api_key
        self._base_url = base_url
        self._client = client            # DeepSeek (lazy if None)
        self._anthropic = anthropic_client  # Anthropic (lazy if None)
        self.cost_usd = 0.0
        self.refusals = 0
        self.last_usage = None

    def _ds(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(api_key=self._api_key or os.environ["DEEPSEEK_API_KEY"],
                                  base_url=self._base_url)
        return self._client

    def _ac(self):
        if self._anthropic is None:
            import anthropic
            self._anthropic = anthropic.Anthropic()
        return self._anthropic

    def model_for(self, role):
        return self.roles.get(role, self.roles["loop"])

    def price(self, model):
        return self.prices.get(model) or self.prices[self.roles["loop"]]

    def complete(self, *, messages, model=None, role=None, tools=None,
                 temperature=0.3, thinking=False, timeout=180):
        model = model or self.model_for(role or "loop")
        if provider_of(model) == "anthropic":
            return self._complete_anthropic(model, messages, tools, timeout)
        return self._complete_deepseek(model, messages, tools, temperature, thinking, timeout)

    def _complete_deepseek(self, model, messages, tools, temperature, thinking, timeout):
        _strip_reasoning(messages)
        kwargs = dict(model=model, messages=messages, temperature=temperature, timeout=timeout)
        if tools:
            kwargs["tools"] = tools
        if thinking:
            kwargs["extra_body"] = {"thinking": {"type": "enabled"}}
        try:
            resp = self._ds().chat.completions.create(**kwargs)
        except Exception:
            if thinking:
                kwargs.pop("extra_body", None)
                kwargs.pop("temperature", None)
                resp = self._ds().chat.completions.create(**kwargs)
            else:
                raise
        if getattr(resp, "usage", None):
            self._track(model, resp.usage)
        return resp

    def _complete_anthropic(self, model, messages, tools, timeout):
        system, amsgs = to_anthropic_messages(messages)
        kwargs = dict(model=model, max_tokens=ANTHROPIC_MAX_TOKENS, messages=amsgs,
                      cache_control={"type": "ephemeral"})   # cache the stable prefix
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = to_anthropic_tools(tools)
        raw = self._ac().messages.create(**kwargs)
        resp = from_anthropic_response(raw)
        if resp.refusal_category:
            self.refusals += 1
        self._track(model, resp.usage)
        return resp

    def _track(self, model, usage):
        p = self.price(model)
        cost = (getattr(usage, "prompt_tokens", 0) * p["in"]
                + getattr(usage, "completion_tokens", 0) * p["out"]
                + getattr(usage, "cache_read", 0) * p.get("cache_read", 0)
                + getattr(usage, "cache_write", 0) * p.get("cache_write", 0)) / 1e6
        self.cost_usd += cost
        self.last_usage = usage
        return cost
