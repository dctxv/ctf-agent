# AI CTF & Pentest Agent

A Windows-hosted, human-in-the-loop AI agent for penetration testing, CTF challenges,
and source-code auditing. A Python orchestrator drives an LLM (DeepSeek) through a
tool-calling loop; every tool interaction is scope-checked, logged, and cost-tracked.
The agent plans, runs real tools inside a sandboxed Kali container, reads the output,
writes and executes proof-of-concept exploits, and finishes with a report, while a
human operator supervises.

**Status:** working, actively developed. Proven against OWASP Juice Shop and one real
open-source app; see the honest limitations below before pointing it at anything.

---

## What it is

- **The model is the brain, the human is the operator, the tools are the hands, and the
  allowlist is the cage.** The agent never decides what it is *allowed* to touch; that is
  enforced in code (an allowlist checked before every command and URL).
- Tier-1 loop runs on DeepSeek Flash (cheap); it escalates to a stronger reasoning model
  after two consecutive command failures. Per-engagement budgets (`max_steps`,
  `max_cost_usd`) abort runaway sessions with a forced summary.
- Everything the agent does is emitted as typed events, saved per session
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
  prioritized report plus a structured `findings.json`. Demoed on a real OSS app (`dvpwa`):
  14 findings including SQLi, broken access control, stored XSS, weak hashing, and vulnerable
  dependencies.
- **Responsible-disclosure export (`run_disclose.py`).** Turns an audit's `findings.json` into a
  GitHub Security Advisory-style Markdown plus issue drafts, and can auto-file GitHub issues, but
  only on repos you have push/admin access to. Third-party repos are refused and get the advisory
  for coordinated, private disclosure.
- **Findings court (`run_court.py`).** An adversarial second pass that re-reads the cited code
  and confirms or refutes each finding (verdict + grounded reason), to catch hallucinations.
  Verdicts show on the dashboard cards, and refuted findings are dropped from disclosure. On a
  labeled test (real vulns + planted fakes) it leaked zero fakes.
- **CTFd platform adapter (`run_ctfd.py`).** Pulls a challenge from a CTFd instance via
  its API, builds an engagement, downloads files, and can submit the flag. Scope stays
  operator-controlled (empty by default). Validated against a mock and a real local CTFd
  3.7.7 instance.
- **Learning layer (`run_learn.py`).** Turns a finished session into a Markdown writeup,
  key-concept notes, and flashcards, and optionally a client-style pentest report. Runs
  automatically at the end of real engagements.
- **Dashboard (`dashboard/`).** A FastAPI + SSE web view: a session list and a live event
  feed. A running engagement streams its events in real time; finished sessions replay. A
  "Repos" tab launches a GitHub repo audit from the browser and renders severity-sorted
  finding cards from `findings.json`.
- **Privacy mode (`--privacy`).** Anonymizes target hostnames, IPs, and emails before
  anything reaches the model API, and restores them before tools run (and before the
  allowlist check, so scope is always enforced on real values).
- **Evaluation harness (`run_eval.py`, `compare_runs.py`).** 10 fixed challenges, N runs
  each, content-asserted evidence (a "could not do it" file cannot score), target pinned
  by digest, git-SHA provenance on every result row, and a per-challenge regression diff.
  Current baseline: **9 of 10 solved** on every run.

## What it does NOT have (yet), honestly

- **No local model.** It only talks to DeepSeek's hosted API, so all prompt data leaves
  the machine (servers in China; may be used for training by default). `--privacy` sends
  only placeholders for target identifiers, but the rest of the prompt still transits the
  API. A local-model tier (Qwen via Ollama) is designed but **not built**.
- **Privacy is best-effort.** It scrubs the known in-scope hosts plus anything that looks
  like an IP or email. It will not catch every sensitive token (an unusual hostname, or a
  secret that shows up in tool output). It reduces risk; it is not a guarantee.
- **Only one platform adapter.** CTFd works (not yet run against a real operator-owned
  instance); there is **no** Hack The Box, PortSwigger, or picoCTF adapter, and
  `play.picoctf.org` uses a different API than standard CTFd.
- **Scope is manual.** The allowlist must be set by the operator; there is no automatic
  population from a spawned machine's IP.
- **Browser is headless only.** No headed/supervised browser mode.
- **Narrow testing.** Almost all web testing has been against one application family
  (Juice Shop), which the model likely knows from training data, so some results reflect
  recall more than discovery. Code-audit has been exercised on one real repo plus a
  fixture.
- **Hard categories hit a ceiling.** DeepSeek-class models are weak on pwn/binary and
  knowledge-gated challenges. Example: the KeePass challenge fails not for lack of tools
  but because the master password is not in the wordlist.
- **Hallucination is mitigated, not eliminated.** The run-the-PoC-before-claiming rule and
  human review catch most invented findings, not all.
- **No cross-session memory.** Each run starts fresh; the learning layer is after the fact.
- **Single user, single agent.** No concurrency, no multi-agent orchestration.
- **Dashboard is read-only and unauthenticated.** It binds to localhost and shows saved
  sessions; it is not a multi-user or hardened service.
- **No fine-tuning.** Training a model on collected successful trajectories is a goal, not
  a feature.
- **Not a license substitute.** Pointing this at any system requires real authorization;
  the tooling assumes a disciplined operator and keeps the scope allowlist as its one hard
  safety boundary.

## Architecture

```
Windows host                               Kali container "agent-box"
----------------------------               -----------------------------------
Python orchestrator  --- API --->          nmap sqlmap ffuf nuclei dirsearch
  DeepSeek Flash   (tier-1 loop)            gobuster nikto semgrep ripgrep gdb
  DeepSeek (reasoning, on escalation)       pwntools john hashcat wordlists
  Tavily           (web_search)             osv-scanner pip-audit decompilers
  allowlist check  (pre-exec)               playwright + chromium
  event emitter    (dashboard feed)         /workspace  <-- shared -->  host workspace
```

Tool surface: `run_command`, `read_file` / `write_file` / `list_files`, `web_search`,
`browser_open` / `browser_interact` / `browser_screenshot`, `ask_human`, `finish`.

## Repo layout

| Path | What it is |
|------|-----------|
| `agent/agent.py` | the event-emitting agent loop (`AgentSession`) |
| `agent/tools.py` | tool implementations + allowlist/scope enforcement |
| `agent/adapters.py` | CTFd adapter + code-audit engagement builder |
| `agent/learn.py` | post-session writeups, flashcards, client report |
| `agent/privacy.py` | target anonymization for `--privacy` |
| `main.py` | interactive single-engagement runner |
| `run_eval.py` / `compare_runs.py` | eval harness + regression diff |
| `run_ctfd.py` / `run_audit.py` / `run_learn.py` | CTFd / code-audit / learning runners |
| `dashboard/` | FastAPI + SSE dashboard (`server.py`, `index.html`) |
| `challenges/` | the 10 eval challenge configs |
| `Dockerfile` | the Kali toolbox image |
| `PROJECT.md` / `CHANGELOG.md` | design notes and change history |

## Running it

Secrets live in `.env` (git-ignored; copy `.env.example` and fill in your own keys).
Prerequisites: Docker Desktop with the `agent-box` toolbox image and the pinned Juice
Shop image for the eval. `preflight.py` checks the environment.

```bash
# interactive engagement
python main.py engagement.json [--privacy]

# evaluation suite (baseline)
python run_eval.py --runs 3

# audit a local codebase
python run_audit.py path/to/source --dry-run        # scanners only, no API cost
python run_audit.py path/to/source --unattended

# CTFd challenge (needs CTFD_URL + CTFD_TOKEN in .env)
python run_ctfd.py --list
python run_ctfd.py <challenge_id> --allowed-hosts <target>

# study aid / client report from a finished session
python run_learn.py <session-name> --client

# dashboard
python dashboard/server.py   # http://localhost:8900
```

## Safety

Targets must be systems you own or are explicitly authorized to test. The allowlist is a
code-enforced boundary, not a suggestion: commands and URLs touching anything out of
scope are blocked before they run, and privacy mode restores real values only after that
check. Keep it that way.
