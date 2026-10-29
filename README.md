# AI CTF & Pentest Agent

A Windows-hosted, human-in-the-loop AI agent for penetration testing, CTF challenges,
and source-code auditing. A Python orchestrator drives an LLM through a tool-calling
loop; every tool interaction is scope-checked, logged, and cost-tracked. The agent
plans, runs real tools inside a sandboxed Kali container, reads the output, writes and
executes proof-of-concept exploits, and finishes with a report, while a human operator
supervises.

**Model-agnostic.** The default tier-1 loop runs on DeepSeek (cheap); any `claude-*`
model (Haiku / Sonnet / Opus) is a drop-in alternative via the Anthropic Messages API,
with prompt caching. See [Results](#results) for a head-to-head.

**Status:** working, actively developed. Benchmarked on three external suites
(InterCode-CTF, NYU CTF Bench, plus leak-controlled generated challenges) and proven
end-to-end on OWASP Juice Shop and real open-source repos. Read the
[honest limitations](#what-it-does-not-have-yet-honestly) before pointing it at anything.

---

## 60-second demo

The code-audit path needs no API key and no agent loop in `--dry-run` mode — it runs the
same static scanners the agent uses and prints a triaged summary. Point it at any local
checkout:

```bash
python run_audit.py path/to/some/repo --dry-run
# clones nothing, executes nothing: semgrep + osv-scanner + pip-audit over the source,
# grouped by severity. ~10-30s. This is the free tier of the full LLM-triaged audit.
```

For the full agent (needs `DEEPSEEK_API_KEY` and the toolbox image), the leak-controlled
eval is the fastest honest proof it works:

```bash
python run_experiment.py --dataset test --runs 1 --experiment demo
# generated crypto/forensics/reverse challenges with RANDOM flags (cannot be memorized);
# each runs in its own container, flag verified host-side by exact match. ~1-2 min, ~$0.01.
```

Watch any run live at `http://localhost:8900` (`python dashboard/server.py`) - and replay any
finished run as an animated attack map with a plain-English story (`python build_storyboard.py <session> --export map.html --open`).

## What it is

- **The model is the brain, the human is the operator, the tools are the hands, and the
  scope boundary is the cage.** The agent never decides what it is *allowed* to touch.
  Scope is enforced in two layers (see [Scope & containment](#scope--containment)): a
  command-layer allowlist on every engagement, and a kernel-level egress firewall on
  evaluation trial containers.
- **Provider-agnostic model layer** (`agent/llm.py`). DeepSeek (OpenAI-compatible wire
  format) is the default; `claude-*` ids route to the Anthropic Messages API, translated
  in and normalized back so the agent loop is unchanged. Tier-1 loop runs a cheap model
  and escalates to a stronger reasoning model after repeated command failures. Refusals
  are surfaced as a distinct outcome, never silently scored as a capability failure.
- **Per-engagement budgets** (`max_steps`, `max_cost_usd`) abort runaway sessions with a
  forced summary. Everything the agent does is emitted as typed events, saved per session
  (`transcript.json`, `events.json`, `cost.txt`), and streamable to a dashboard.

## What it can do (built and tested)

- **Web/network engagements.** Recon, analyze, exploit, and verify against an in-scope
  target. Writes a PoC, saves it, *runs* it, and only then claims a finding. Verified
  end to end on OWASP Juice Shop.
- **Toolbox.** A Kali container with nmap, sqlmap, ffuf, nuclei, dirsearch, gobuster,
  nikto, ripgrep, gdb, pwntools, semgrep, john/hashcat (+ wordlists), decompilers, plus
  the extras below. The operator stays on Windows; the agent reaches tools via
  `docker exec`.
- **Headless browser tools.** Playwright-driven Chromium (`browser_open`,
  `browser_interact`, `browser_screenshot`) so the agent can render and act on JS single-
  page apps that `curl` cannot. Every URL is scope-checked like any command.
- **Code-audit mode (`run_audit.py`).** Point it at a local source folder, or a GitHub repo
  with `--github <url>` (shallow-cloned host-side and scanned statically, never executed); it
  builds a file-only engagement (no network in scope) and runs semgrep plus dependency-CVE
  scanners (osv-scanner, pip-audit), triages the results, writes PoCs, and produces a
  prioritized report plus a structured `findings.json`.
- **Experience memory (`agent/memory.py`).** An opt-in, namespaced store of *procedural*
  lessons from past engagements — category, outcome, and an approach sketch, with flags and
  evidence scrubbed so a held-out answer cannot leak back to the agent. Retrieval is keyword
  + category overlap with recency decay (no embedding model). It is the mechanism, gated by an
  A/B on held-out challenges; see the honest "no net benefit yet on tractable sets" finding in
  [BENCHMARK.md](docs/BENCHMARK.md).
- **Multi-agent orchestration (`agent/multiagent.py`).** A supervisor routes an engagement to
  the single best specialist (crypto, reverse, forensics, web, recon, code-audit), which then
  runs the normal tool loop with a focused system prompt. Deliberately bounded — one supervisor
  call plus one specialist, not an open-ended swarm — and eval-gated: it must beat the single
  agent cost-adjusted or it is reported as not worthwhile (on easy sets it is pure overhead).
- **Responsible-disclosure export (`run_disclose.py`).** Turns an audit's `findings.json` into a
  GitHub Security Advisory-style Markdown plus issue drafts, and can auto-file GitHub issues, but
  only on repos you have push/admin access to. Third-party repos are refused and get the advisory
  for coordinated, private disclosure.
- **Findings court (`run_court.py`).** An adversarial second pass that re-reads the cited code
  and confirms or refutes each finding (verdict + grounded reason), to catch hallucinations.
  Refuted findings are dropped from disclosure. On a labeled test (real vulns + planted fakes)
  it leaked zero fakes.
- **Vuln-regression (`run_retest.py`).** Diffs two audit runs into new / fixed / still-open, so
  you can confirm a fix landed.
- **Bug-bounty scope mode (`run_bugbounty.py`).** Parses a program's scope into a *proposed*
  engagement (allowlist from the in-scope assets) for you to review and launch — never
  auto-applied or auto-run; warns on out-of-scope hosts that fall under an in-scope wildcard.
- **CTFd platform adapter (`run_ctfd.py`).** Pulls a challenge from a CTFd instance via its API,
  builds an engagement, downloads files, and can submit the flag. Scope stays operator-controlled
  (empty by default). Validated against a mock and a real local CTFd 3.7.7 instance.
- **Learning layer (`run_learn.py`).** Turns a finished session into a Markdown writeup,
  key-concept notes, and flashcards, and optionally a client-style pentest report.
- **Dashboard (`dashboard/`).** A FastAPI + SSE web view: a session list and a live event feed.
  A running engagement streams its events in real time; finished sessions replay. An "Audit" tab
  launches a GitHub repo audit from the browser and renders severity-sorted finding cards.
- **Attack-map replay (`agent/storyboard.py`, `dashboard/player.html`).** Turns a finished run into
  an animated attack-path graph with an LLM-written, plain-English story of how it broke in - target
  to endpoint to "SQLi confirmed" to loot, revealed step by step. Watch it in the dashboard's "Replay"
  view, or export a single self-contained HTML file anyone can open offline, no server needed. The
  story is one cheap LLM call, cached, and generated only on explicit request.
- **Privacy mode (`--privacy`).** Anonymizes target hostnames, IPs, and emails before anything
  reaches the model API, and restores them before tools run (and before the scope check, so
  scope is always enforced on real values).
- **Evaluation harness (`run_eval.py`, `run_experiment.py`, `compare_runs.py`).** Fixed and
  *generated* (random-flag) challenge sets, N runs each, content-asserted evidence (a "could not
  do it" file cannot score), target pinned by digest, oracle-isolated exact-flag verification,
  git-SHA provenance on every result row, Wilson-interval solve rates, and per-challenge
  regression diffs. External suites (InterCode-CTF, NYU CTF Bench) import into the same harness.

## Results

Full methodology, caveats, and per-category tables in **[docs/BENCHMARK.md](docs/BENCHMARK.md)**.
Headlines (single attempt / pass@1 unless noted):

| Suite | Result | Notes |
|---|---|---|
| Generated (leak-controlled) | **9/9** crypto/forensics/reverse | random flags, cannot be memorized |
| InterCode-CTF (100 picoCTF tasks) | **83/100** (CI 74-89%) | DeepSeek-flash, ~$0.014/task |
| NYU CTF Bench (clean 56, CSAW) | Haiku **69%** · flash **70%** | indistinguishable (McNemar p=1.00); Haiku ~5x cheaper/solve |
| NYU — Haiku→flash→Sonnet cascade | **48/56 = 86%** | coverage play; ~$0.20/solve |

The honest counterweights live in BENCHMARK.md: public-benchmark recall vs discovery, the
pwn/binary ceiling for this model class, memory and multi-agent showing *no* net benefit on
tractable sets, and the pass@k analysis separating a real budget effect from run-to-run noise.

## Scope & containment

Two layers, with different strength, documented honestly because they are not equivalent:

1. **Command-layer scope check** (`agent/tools.py`) — applies to **every** engagement,
   including the operator's long-lived `agent-box`. A best-effort allowlist checked before every
   command and URL: it normalizes decimal/hex/IPv6 IP encodings, catches `user@host` and
   `nc host port`, **fails closed** for a network tool whose destination can't be resolved to an
   in-scope host or is built at runtime (shell variable / substitution), and hard-denies commands
   that reconfigure the network stack or firewall (`iptables`, `nft`, `ip ... add/set/...`). This
   is defense in depth, not a sandbox — static inspection of shell strings is inherently
   best-effort, and a sufficiently novel command shape could evade it.
2. **Kernel-level egress firewall** (`agent/net.py`) — the **authoritative** boundary, applied
   **only to ephemeral evaluation trial containers**, *not* to the long-lived `agent-box`. A
   default-drop nftables/iptables ruleset permits outbound traffic only to the resolved in-scope
   IPs (plus loopback, established flows, and DNS). The trial container runs **without**
   `NET_ADMIN`; the rules are installed by a short-lived sibling container that joins the trial's
   network namespace, holds `NET_ADMIN` just long enough to write them, and exits — so the agent
   inside the trial cannot flush or relax its own egress rules.

**What this means in practice:** for ordinary engagements in the `agent-box`, the boundary you
are relying on is command inspection (layer 1, best-effort). The kernel-level firewall is a
property of the evaluation harness, not of a general engagement. Pointing this at any system
still requires real authorization and a disciplined operator; the tooling assumes both.

## Architecture

```
Windows host                               Kali container "agent-box"
----------------------------               -----------------------------------
Python orchestrator  --- API --->          nmap sqlmap ffuf nuclei dirsearch
  model layer (llm.py):                     gobuster nikto semgrep ripgrep gdb
    DeepSeek  (default, tier-1 + escalate)  pwntools john hashcat wordlists
    Anthropic (claude-* opt-in, cached)     osv-scanner pip-audit decompilers
  Tavily           (web_search)             nftables/iptables (eval firewall)
  scope check      (pre-exec, layer 1)      playwright + chromium
  event emitter    (dashboard feed)         /workspace  <-- shared -->  host workspace

Evaluation trial: ephemeral container (NO NET_ADMIN) + NET_ADMIN firewall sibling (layer 2)
```

Tool surface: `run_command`, `read_file` / `write_file` / `list_files`, `web_search`,
`browser_open` / `browser_interact` / `browser_screenshot`, `ask_human`, `finish`.

## Repo layout

| Path | What it is |
|------|-----------|
| `agent/agent.py` | the event-emitting agent loop (`AgentSession`) |
| `agent/llm.py` | provider-agnostic model layer (DeepSeek + Anthropic) |
| `agent/tools.py` | tool implementations + command-layer scope enforcement |
| `agent/net.py` | kernel-level egress firewall for eval trial containers |
| `agent/memory.py` | opt-in, namespaced experience memory (procedural, flag-scrubbed) |
| `agent/multiagent.py` | supervisor + specialist orchestration |
| `agent/adapters.py` | CTFd adapter + code-audit engagement builder |
| `agent/learn.py` / `court.py` / `disclosure.py` / `regression.py` / `bugbounty.py` | post-session, findings court, disclosure, retest, bug-bounty scope |
| `agent/privacy.py` | target anonymization for `--privacy` |
| `main.py` | interactive single-engagement runner |
| `eval/` | evaluation subsystem (runner, registry, verifier, report, generators) |
| `run_eval.py` / `run_experiment.py` / `compare_runs.py` | eval harness + experiments + regression diff |
| `run_ctfd.py` / `run_audit.py` / `run_learn.py` | CTFd / code-audit / learning runners |
| `run_import_nyu.py` / `run_import_intercode.py` | external-benchmark importers |
| `dashboard/` | FastAPI + SSE dashboard + attack-map replay (`server.py`, `index.html`, `player.html`) |
| `agent/storyboard.py` / `build_storyboard.py` | run -> animated attack-map storyboard (one LLM call, cached) + standalone export |
| `tests/` | offline test suite (scope, eval, llm, memory, multiagent, …) |
| `Dockerfile` / `Dockerfile.firewall` | Kali toolbox image + nftables/iptables overlay |
| `docs/BENCHMARK.md` | reproducible benchmark results |
| `PROJECT.md` / `CHANGELOG.md` | design notes and change history |

## Setup

Prerequisites: **Docker Desktop**, **Python 3.12**, and the toolbox image. `preflight.py`
checks the whole environment and prints the exact fix for anything missing.

```bash
# 1. secrets — copy the example and fill in your own keys (.env is git-ignored)
cp .env.example .env         # DEEPSEEK_API_KEY required; ANTHROPIC_API_KEY/TAVILY_API_KEY optional

# 2. build the toolbox image (the .firewall overlay adds nftables/iptables for the eval firewall)
docker build -t pentest-tools .
docker build -f Dockerfile.firewall -t pentest-tools:latest .

# 3. long-lived agent-box for interactive engagements
docker run -dit --name agent-box -v C:\projects\ctf-agent\workspace:/workspace pentest-tools bash

# 4. verify everything
python preflight.py
```

## Running it

```bash
# interactive engagement
python main.py engagement.json [--privacy]

# evaluation / experiments
python run_experiment.py --dataset test --runs 3 --experiment demo
python run_eval.py --runs 3

# run the eval on a claude-* model instead of DeepSeek
python run_experiment.py --dataset test --runs 1 --model claude-haiku-5-5

# audit a codebase (local folder or --github <url>)
python run_audit.py path/to/source --dry-run        # scanners only, no API cost
python run_audit.py path/to/source --unattended
python run_audit.py --github https://github.com/owner/repo --dry-run

# CTFd challenge (needs CTFD_URL + CTFD_TOKEN in .env)
python run_ctfd.py --list
python run_ctfd.py <challenge_id> --allowed-hosts <target>

# study aid / client report from a finished session
python run_learn.py <session-name> --client

# dashboard
python dashboard/server.py   # http://localhost:8900

# attack-map replay: animated, plain-English story of a finished run (standalone, shareable)
python build_storyboard.py c05-sqli-union-dump/run_01 --export map.html --open

# offline test suite (no Docker, no API)
python -m pytest tests/ -q
```

## What it does NOT have (yet), honestly

- **No local model.** It talks to hosted APIs (DeepSeek by default, Anthropic optionally), so
  prompt data leaves the machine. `--privacy` sends only placeholders for target identifiers, but
  the rest of the prompt still transits the API. A local-model tier (Qwen via Ollama) is designed
  but **not built**.
- **Privacy is best-effort.** It scrubs the known in-scope hosts plus anything that looks like an
  IP or email; it will not catch every sensitive token. It reduces risk; it is not a guarantee.
- **The agent-box relies on command inspection.** Its scope boundary is layer 1 above
  (best-effort static inspection), not the kernel firewall — that is eval-only. See
  [Scope & containment](#scope--containment).
- **Only one platform adapter.** CTFd works; there is **no** Hack The Box, PortSwigger, or picoCTF
  adapter.
- **Scope is manual.** The allowlist must be set by the operator; there is no auto-population from
  a spawned machine's IP.
- **Browser is headless only.** No headed/supervised browser mode.
- **Narrow web testing.** Most web testing has been against one application family (Juice Shop),
  which the models likely know from training data, so some results reflect recall more than
  discovery. The same caveat applies to the public CTF benchmarks.
- **Hard categories hit a ceiling.** These model classes are weak on pwn/binary and
  knowledge-gated challenges; the NYU offline set excludes pwn/web entirely (their flags need a
  live target), so it says nothing about that ability.
- **Hallucination is mitigated, not eliminated.** The run-the-PoC-before-claiming rule, the
  findings court, and human review catch most invented findings, not all.
- **Memory and multi-agent are mechanisms, not proven wins.** Both are eval-gated and show no net
  benefit yet on the tractable sets tested; whether they help on harder, decomposable work is
  untested and future work.
- **Dashboard is read-only and unauthenticated.** It binds to localhost and shows saved sessions;
  it is not a multi-user or hardened service.
- **Not a license substitute.** Pointing this at any system requires real authorization.

## Safety

Targets must be systems you own or are explicitly authorized to test. The scope allowlist is a
code-enforced boundary, not a suggestion: commands and URLs touching anything out of scope are
blocked before they run, privacy mode restores real values only after that check, and the agent
cannot modify the scope boundary itself. Understand the difference between the two containment
layers above before relying on either.

## License

[MIT](LICENSE) © 2026 dctxv. Provided "as is", without warranty; you are responsible for using
it only against systems you are authorized to test.
