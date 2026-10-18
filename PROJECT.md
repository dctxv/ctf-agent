# AI CTF & Pentest Copilot

*A Windows-hosted, human-in-the-loop AI agent for penetration testing, CTF challenges, and security auditing.*

**Status:** v1.2, eval baseline complete (3x; 9/10 solved) · **3x baseline spend:** $1.05 · **Author:** [you], cybersecurity student

---

## 1. What This Project Is

An autonomous-in-the-small security agent: a Python orchestrator drives an LLM (DeepSeek V4-Flash via API) through a tool-calling loop, where every tool interaction is scoped, logged, and cost-tracked. The agent plans attacks, runs real pentest tools inside a sandboxed Linux container, reads the output, decides the next step, writes and executes proof-of-concept exploits, and finishes with a report - while a human operator supervises and answers questions when the agent asks.

Three target types are (or will be) supported:

1. **Web applications** (live hosts - current focus, proven working)
2. **CTF platforms** (HTB, picoCTF, PortSwigger - Phase 2)
3. **Local codebases** (source-code audit - Phase 2.5; already runnable informally)

The design philosophy: **the model is the brain, the human is the operator, the tools are the hands, and the allowlist is the cage.** The agent never decides what it's *allowed* to touch - that's enforced in code.

**Why it exists:** (a) as a force multiplier for a student still building experience - the agent does the grind, explains its reasoning, and demands verification skills of its operator; (b) as a portfolio project demonstrating agent architecture, security-scoped automation, and measured evaluation; (c) as a base platform for later privacy-preserving client work and model fine-tuning experiments.

---

## 2. What It Can Currently Do (verified)

### Eval baseline (3x, git `a3d3e74`)
The 10-challenge suite run 3 times each (30 runs), target pinned by digest, evidence content-asserted so a "could not do it" file can never score:

| Challenge | Solved | Steps (mean +/- sd) | Cost (mean +/- sd) |
|---|---|---|---|
| c01 version leak | 3/3 | 6.0 +/- 1.0 | $0.0043 +/- 0.0007 |
| c02 ftp bypass | 3/3 | 9.3 +/- 2.5 | $0.0065 +/- 0.0034 |
| c03 sqli admin | 3/3 | 10.0 +/- 3.0 | $0.0075 +/- 0.0038 |
| c04 find scoreboard | 3/3 | 9.0 +/- 1.7 | $0.0083 +/- 0.0026 |
| c05 sqli union dump | 3/3 | 16.7 +/- 11.6 | $0.0325 +/- 0.0413 |
| c06 error disclosure | 3/3 | 9.0 +/- 0.0 | $0.0108 +/- 0.0021 |
| c07 admin no injection | 3/3 | 17.3 +/- 6.8 | $0.0436 +/- 0.0424 |
| c08 kdbx crack | 0/3 | 35.0 (step budget) | $0.1229 +/- 0.0253 |
| c09 pyc reverse | 3/3 | 19.0 +/- 5.2 | $0.0271 +/- 0.0123 |
| c10 announcement decrypt | 3/3 | 27.0 +/- 8.2 | $0.0878 +/- 0.0322 |

**Suite: 9/10 challenges solved on every run (27/30 runs), 0 crashes, total $1.05, ~55 min wall.** The escalation tier fired in real runs for the first time (c07, c09, c10; one run each) and `ask_human` fired once (c10 run 2). The nine solvable challenges cost $0.69 total (mean $0.025/run); c08 alone is 35% of the spend: three full-budget runs that extract the KeePass hash and exhaust rockyou (with best64/best66 rules) without finding the master password, a wordlist gap rather than a tool gap (see section 3). High variance clusters on the multi-step challenges (c05, c07, c10); c01 and c06 are near-deterministic.

### Proven behaviors
- **Self-debugging PoCs:** when its exploit script hit a syntax error, the agent ran `ast.parse`, diagnosed it, rewrote the file using a heredoc pattern, and re-verified - zero human input [run 2].
- **Methodology quality:** it reconnoiters first (robots.txt, JS bundle route extraction, version leak), forms test-failure differentials (403 vs 200, 401 vs 200) before claiming findings, and enumerates before exploiting (column count probing).
- **Scope discipline:** agents attempt creative out-of-scope commands; the allowlist blocks them and the agent recovers within 1-2 steps.
- **Cost transparency:** every session produces `transcript.json`, `events.json`, `cost.txt`.

### Architecture (v1.2)
```
Windows host                                Docker container "agent-box" (Kali)
────────────────────────                    ─────────────────────────────────────
Python orchestrator  ──── API ───▶         nmap · sqlmap · ffuf · nuclei
  ├─ DeepSeek Flash    (tier-1 loop)        dirsearch · gobuster · nikto
  ├─ DeepSeek V4-Pro   (escalation tier)   semgrep · ripgrep · gdb
  ├─ Tavily            (web_search tool)    pwntools · python3
  ├─ Allowlist enforcement (pre-exec)       /workspace ◀──shared──▶ C:\...\workspace
  └─ Event emitter     (dashboard-ready)    + targets roam: Juice Shop, HTB VPN, etc.
```

**Tool surface:** `run_command` (allowlist-checked docker exec), `read_file` / `write_file` / `list_files` (workspace-sandboxed, LF-safe), `web_search`, `ask_human`, `finish`.

**Engineering discipline:** append-only transcripts (preserves prompt-prefix cache pricing - cached input is ~50× cheaper), byte-stable tool schemas, UTF-8 end-to-end (cp1252 crash class eliminated), path normalization (both `/workspace/x` and `x` resolve), preflight validation (9 checks including live key + balance), secrets in `.env` (never in repo or image), N-run eval harness with per-run artifact isolation and git provenance on every row.

---

## 3. What It Cannot Do (yet) - and Why

| Gap | Reason it exists |
|---|---|
| **No browser interaction** | Not built yet (Phase 2). Today everything is CLI/HTTP - the agent can't click through a web UI, fill forms, or read the CTF challenge page you're looking at. Playwright integration is designed but unbuilt. |
| **No platform integration (HTB/picoCTF)** | Phase 2. Challenge data must currently be hand-configured in `engagement.json`. No API adapters exist yet. |
| **Weak on pro-tier CTF / pwn categories** | Model-scale reality: DeepSeek-class models score ~40% on Cybench vs ~73.5% for frontier models. Binary exploitation is the weakest category for *all* current agents. Mitigation: pwntools are in the container, escalation tier is wired - but this is a known ceiling, not a bug. |
| **Can't crack the c08 KeePass DB** | The master password is not in rockyou: across all 3 baseline runs the agent extracted the `$keepass$` hash and ran john and hashcat (`-m 13400`) with best64/best66 rules to exhaustion, 0/1 recovered each time. The toolbox ships john, hashcat and a decompressed rockyou, so this is a wordlist/knowledge gap, not tooling. Solving it would need a targeted wordlist or an app-sourced hint, which is the agent's discovery problem. |
| **Escalation/ask_human tiers only lightly exercised** | They fired in 4 of 30 baseline runs (escalation on c07/c09/c10, ask_human on c10), the first firings in real runs. But every challenge that escalated still solved, and c08 (the one failure) never escalated, so the tiers are proven to *fire*, not yet proven to *change an outcome*. |
| **Hallucination risk on findings** | LLMs invent plausible-sounding vulnerabilities. Currently mitigated by the mandatory PoC-execute-before-claim rule and human review - not eliminated. This is why "verified" appears so often in §2. |
| **Not client-ready (privacy/authorization)** | All prompt data transits DeepSeek's API (servers in China; data may be used for training by default). Fine for labs; for client engagements the plan requires either target anonymization or the Phase-5 local model. |
| **No cross-session memory** | Each session starts fresh (findings files persist on disk, but the agent doesn't read prior sessions automatically). Deliberate for now: keeps eval runs scientifically clean. |
| **No learning outputs** | The writeup/flashcard generation (the student-differentiator feature) is Phase 3 - designed, not built. |
| **No dashboard/UI** | Phase 4. Console-only today. The event-emitter architecture exists precisely so this is additive, not a rewrite. |
| **Single-user, single-agent** | No concurrency, no multi-agent. Right for a solo operator; not an aim yet. |
| **`web_search` now functional (not yet re-evaluated)** | The 3× baseline hit it 23 times (c08/c10) but every call failed: Tavily returned HTTP 401 and the old code swallowed non-200 responses as "No results found", so the model never saw real web data. Code now surfaces HTTP errors and preflight fails on a bad key; the Tavily key has been replaced and web_search returns real results (preflight PASS). It has not yet been exercised in a fresh eval run — next baseline will measure its real effect. |

**Hardware context:** the operator's PC (Ryzen 5 5600, RTX 5060 Ti 16GB, 16GB DDR4) runs the API-first stack easily *because* inference is remote. The Phase-5 local model swap (Qwen3-Coder-30B-A3B, fits 16GB VRAM) is validated on paper but untested here - and 16GB system RAM is the constraint to watch.

---

## 4. Roadmap

| Phase | Contents | Why |
|---|---|---|
| **1.5 (next)** | Run 3× baseline of the 10-challenge eval suite; produces the reference numbers every future change is judged against | Turns "it worked once" into measured capability; catches regressions; exercises escalation/ask_human/web_search tiers for the first time |
| **2** | Playwright browser tools (`browser_open/click/type/download`, DOM-trimmed, persistent logged-in profile, headed for supervision); platform adapters (HTB, CTFd/picoCTF, PortSwigger); allowlist auto-population from spawned machine IPs | The agent's most-used mode: read the challenge you're on, attack it, submit the flag; future-proofs client web-app work too |
| **2.5** | Formalize code-audit mode (folder-target engagements; dependency CVE hunt → semgrep → LLM triage → PoC filter → report) | Cheapest, most client-sellable mode; legal unlimited practice targets (open source); already ~90% supported by the current engine |
| **3** | Learning layer: post-session writeups, concept extraction, flashcards; client-style report templating | The student differentiator - turns every session into retained knowledge |
| **4 (MVP)** | FastAPI backend streaming events over SSE + web dashboard (built against the API contract, mocked first) | The "app" form factor; visibility into live sessions; the demo people remember |
| **5** | Local model tier (Qwen3-Coder-30B-A3B via Ollama, config-swap), privacy mode for client work; later: fine-tune a model on self-collected successful trajectories | Closes the privacy gap; the fine-tune is the novel-contribution portfolio piece |

---

## 5. Key Design Decisions and Their Rationale

1. **API-first, local-model-later.** Starting with DeepSeek's API kept the PC free, bought frontier-class capability immediately, and taught us the workload's real token economics (~$0.05-0.07/engagement). Because the model layer is abstracted (a `MODELS` dict + OpenAI-compatible client), the local Qwen swap later is a config change. Cost: prompt data leaves the machine - acceptable for lab targets, deliberately deferred for client work.

2. **DeepSeek specifically as the backbone.** It's the cost king (5-30× cheaper than Western frontier APIs), the most refusal-resistant major API on offensive-security tasks (~5-7% refusal vs up to ~40% for some alternatives), near-frontier on code, and open-weights (future self-hosting/fine-tuning stays open). Frontier models (Claude/GPT-5) remain an optional, config-flagged "rescue" tier - used only when a hard problem justifies 10× cost.

3. **Human-in-the-loop, not full-auto.** Benchmark reality: small models derail in long autonomous chains (~10% solve on university CTFs solo). HITL - the human supervises, the agent grinds - beats 94% of human teams at picoCTF-tier in published research and matches how real pentest work is supervised anyway. Also the correct liability posture for client work, and the correct learning posture for a student: every `ask_human` is a lesson.

4. **The model never enforces scope.** Authorization is a *code* property: every `run_command` has hosts extracted and checked against the engagement allowlist before exec. Belt (system prompt: "authorization is managed by the operator") and suspenders (mechanical allowlist). Even a prompt-injected or hallucinating agent cannot reach an out-of-scope host. This is a liability feature first, an agent feature second.

5. **Docker toolbox container despite "Windows-native" as a requirement.** Three reasons: (a) pwntools/GDB - the pwn category - essentially don't exist on native Windows; (b) agents benchmark ~9.5pp better in Kali-style environments (and the model's training data is overwhelmingly bash/Linux-shaped); (c) it's a containment cage: prompt-injection damage dies inside a disposable container. The operator still never touches Linux - from the chair, it's all Windows + one `docker exec` away.

6. **Verification-before-claim.** The system prompt requires writing a PoC, saving it, *executing it*, and only then claiming a finding. This is the hallucination firewall - an LLM's confident narrative is not evidence; a 403→200 differential is. Run 2 validated the design when the agent debugged its own broken PoC rather than shipping it.

7. **Cost discipline as architecture, not afterthought.** Append-only transcripts + byte-stable tool schemas preserve prompt-prefix caching (~50× input discount); tiers are Flash (loop) → Pro-on-triggers (2 consecutive failures) → optional rescue; budgets (`max_steps`, `max_cost_usd`) abort runaway sessions with a forced summary. Result: full engagements cost less than a candy bar.

8. **Evidence-not-assertion engagement framing.** Refusals on legitimate security work are a real, documented LLM failure mode - and *over*-justifying ("I'm authorized, trust me") makes it worse by pattern-matching to jailbreak preambles. The prompts therefore describe engagement reality (scope, context) and assign authorization to the human operator's role, rather than pleading. Consequence: near-zero refusal rate in practice.

9. **Event-emitter architecture from day one.** The agent loop emits typed events (`tool_call`, `cost_update`, `ask_human`, …). The Phase-4 dashboard subscribes to the same stream the console prints today - UI arrives as an additive layer, not a rewrite.

10. **Measured evolution.** The eval harness (10 fixed challenges, N runs, content-asserted evidence so a "sorry, failed" file can't score, git-SHA provenance per row) exists so that prompt tweaks, model swaps, and Dockerfile changes are judged by numbers. If the numbers don't move, the change didn't happen.

---

## 6. Honesty Notes

- The agent is now measured across the full 10-challenge eval set (3x, 30 runs), but it is still **one application family** (Juice Shop). The suite widens coverage within that family; it does not widen beyond it.
- Both successful runs used a model that almost certainly **knows Juice Shop from training data** - solution knowledge, if not memorized, is at least heavily primed. Challenges like the scoreboard hunt and "admin without injection" exist in the eval set precisely to test discovery over recall.
- Per-challenge cost spans two orders of magnitude: $0.004 (c01, flash, one clear endpoint) to $0.12 (c08, three full-budget runs). The older $0.05-0.07 figure was per full multi-finding engagement; single-goal challenges are cheaper, but the hard ones (c10 $0.088, c08 $0.123) confirm that long chains and escalation run several times the easy cases. Still cheap; just less candy-bar.
- Nothing here is a license substitute: pointing this at any system requires the operator's authorization to be real. The tooling assumes a disciplined operator.

---

*Repository conventions: `git tag` per version; results in `results.csv` are append-only with provenance; secrets live in `.env` (git-ignored); the eval harness deletes stale evidence per run and pins the target image by digest.*
