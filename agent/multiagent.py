"""Multi-agent orchestration (M7): a supervisor routes an engagement to the best
specialist, which then runs the normal tool loop with its expertise.

This is deliberately bounded - one supervisor call plus one specialist session,
not an open-ended swarm - so its cost is a small, measurable delta over the single
agent. Whether the orchestration actually helps is an empirical question answered
by an A/B on the held-out set, gated the same way memory and scaling were: it must
beat the single agent cost-adjusted, or it is reported as not worthwhile.

The specialists are system-prompt specializations of the same AgentSession; the
supervisor is a single routing call. No tool, scope, or verification path changes.
"""
import json
import re

from agent.agent import AgentSession
from agent.llm import LLMClient

SPECIALISTS = {
    "crypto": "You are a cryptography specialist: classical ciphers, XOR, base64/hex layers, "
              "hashing, and small RSA. Identify the scheme and decode methodically.",
    "reverse": "You are a reverse-engineering and decoding specialist: peel layered encodings, "
               "disassemble and decompile, recover logic.",
    "forensics": "You are a forensics specialist: extract hidden data from files - printable "
                 "strings, metadata, embedded or carved content.",
    "web": "You are a web application security specialist: enumerate endpoints, then test for "
           "injection, broken auth, and access-control flaws, and exploit methodically.",
    "recon": "You are a reconnaissance specialist: map the attack surface carefully before "
             "attempting exploitation.",
    "code-audit": "You are a source-code audit specialist: read code for vulnerable sinks and "
                  "trace untrusted data flow to them.",
}

_SUPERVISOR = """You are the supervisor of a team of security specialists. Given the engagement
goal, choose the ONE specialist best suited to it and give a one-sentence strategy.
Specialists: {names}.

Goal: {goal}

Respond with ONLY a JSON object: {{"specialist": "<one of the names>", "strategy": "<one sentence>"}}"""


def supervise(goal, llm=None):
    """One routing call. Returns (specialist_name, strategy, supervisor_cost_usd).
    Falls back to 'recon' on any parse problem or unknown specialist."""
    llm = llm or LLMClient()
    prompt = _SUPERVISOR.format(names=", ".join(SPECIALISTS), goal=(goal or "")[:1000])
    resp = llm.complete(messages=[{"role": "user", "content": prompt}], role="loop", temperature=0.0)
    text = resp.choices[0].message.content or ""
    spec, strat = "recon", ""
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            d = json.loads(m.group(0))
            spec = str(d.get("specialist", "recon"))
            strat = str(d.get("strategy", ""))
        except Exception:
            pass
    if spec not in SPECIALISTS:
        spec = "recon"
    return spec, strat, round(getattr(llm, "cost_usd", 0.0), 4)


def run_multiagent(engagement, human_fn):
    """Supervisor routes, then the chosen specialist runs the tool loop. Returns
    {session, specialist, strategy, supervisor_cost}."""
    llm = LLMClient()
    spec, strat, sup_cost = supervise(engagement.get("goal", ""), llm)
    eng = dict(engagement)
    eng["goal"] = (f"[Specialist: {spec}] {SPECIALISTS[spec]}\n"
                   f"[Supervisor strategy] {strat}\n\n" + eng.get("goal", ""))
    session = AgentSession(eng, human_fn)
    session.run()
    return {"session": session, "specialist": spec, "strategy": strat,
            "supervisor_cost": sup_cost}
