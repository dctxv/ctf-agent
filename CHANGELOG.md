# Changelog

All notable changes to the AI CTF & Pentest Copilot.

## [Unreleased]
- Phase 2 platform adapters: `agent/adapters.py` adds a `PlatformAdapter` base and
  a `CTFdAdapter` (CTFd v1 REST API) that lists challenges, builds engagement dicts
  from a challenge, downloads files, and submits flags. Safety contract: the adapter
  never sets `allowed_hosts` from platform data - scope defaults to empty (nothing
  runnable) unless the operator passes it; hosts parsed from challenge text are
  offered only as `_suggested_hosts` for review. Token read from `CTFD_TOKEN` env.
  Verified against a faithful mock (12/12) and a throwaway real CTFd 3.7.7 instance
  (7/7: token auth, endpoints, response shapes, flag submission all confirmed).
  `run_ctfd.py` builds and runs an engagement from a challenge id (`--list`,
  `--dry-run`, optional `--submit`). A live run against the operator's own instance
  is still pending their URL + token.
- Phase 2 browser tools: Playwright headless Chromium runs inside agent-box via a
  new `agent/browser_driver.py`, exposed as `browser_open`, `browser_interact`
  (fill/click/press/wait/goto, optional force) and `browser_screenshot`. Every URL
  is scope-checked against the engagement allowlist, exactly like `run_command`.
  Renders JS SPAs that curl cannot (verified vs Juice Shop: product list, hidden
  score-board route, login flow, PNG screenshot). Dockerfile installs Playwright +
  Chromium via `--with-deps`.
- Fixed `web_search` silently masking failures: it POSTed to Tavily with no HTTP
  status check, so an auth failure collapsed to "No results found." The 3× baseline
  made 23 web_search calls (c08/c10) that all failed this way — Tavily returns HTTP
  401. It now switches to the current `Authorization: Bearer <key>` auth form and
  surfaces non-200 responses as `web_search error: HTTP <code> ...`. Preflight's
  Tavily check now does a real 1-result search and PASSes only on HTTP 200 with a
  non-empty results array, so a bad/expired key fails preflight. The
  `TAVILY_API_KEY` in `.env` has since been replaced; web_search now returns real
  results and preflight's Tavily check PASSes. Re-evaluated at git `0d0f571` (same
  3× suite): web_search fired 12 times across c08/c10 with zero errors and real
  writeup content (fix verified live), but outcomes were identical to the a3d3e74
  baseline (9/10 challenges, 27/30 runs; c08 still 0/3, c10 still 3/3) — working
  web_search is outcome-neutral on this suite, and c08 remains a wordlist gap, not a
  discovery gap. (New rows appended to `results.csv` under sha `0d0f571`.)
- Eval harness (`run_eval.py`): 10 fixed challenges, N runs each, content-asserted
  evidence (a non-empty file must also satisfy the challenge's `contains`/`matches`
  assertion, so a "could not do it" file can never score), target pinned by digest,
  per-run artifact isolation (`sessions/<name>/run_NN/`), 14-column `results.csv`
  with a git SHA on every row for provenance.
- First 3x baseline recorded at git `a3d3e74`: 9/10 challenges solved on every run
  (27/30 runs), 0 crashes, $1.05 total, ~55 min. Escalation tier fired in real runs
  for the first time (c07, c09, c10); `ask_human` fired once (c10). c08 (KeePass
  crack) is an expected failure, but not for the reason first assumed: the agent
  extracts the hash and runs john/hashcat against rockyou to exhaustion on all three
  runs because the master password is not in the wordlist. A wordlist/knowledge gap,
  not a tool gap.
- Toolbox image (`Dockerfile`) reconciled with the container the baseline actually
  ran on: added john, hashcat, wordlists, OpenCL (ocl-icd + pocl), gcc and dev
  headers via apt, and pykeepass/pycryptodomex/uncompyle6/decompyle3/pyotp via pip,
  and decompress rockyou at build time. The committed image now reproduces the
  baseline environment; previously these were hand-installed in the running
  container only.

## [1.2] - 2026-10-17
- UTF-8 end-to-end subprocess decode (eliminates the cp1252 crash class)
- Path normalization: both `/workspace/x` and `x` resolve to the same file
- Tool-aware failure tracking: file writes are no longer counted as command failures
- No-CRLF file writes: model-written scripts survive the Windows to Linux round trip
- Escalation loop fix: escalation no longer kills the session or skips artifacts

## [1.1]
- Tool-aware failure tracking (initial)
- Fixed the escalation loop

## [1.0]
- Initial agent: DeepSeek tool-calling loop, Dockerised Kali toolbox, allowlist scope
  enforcement, event-emitter architecture, preflight checks

## Bugs defeated on the road to v1.2
A record of the real bugs diagnosed and fixed during development:
1. Docker daemon pipe error
2. Kali dropped semgrep from apt (moved to pip)
3. Python 3.14 unicorn wheel gap
4. Placeholder API key passing preflight
5. "arm" typo in preflight
6. False escalations after write_file
7. Escalation return nuking sessions
8. chmod breaking on subdirectories
9. CRLF corruption (Windows/Linux line endings)
10. cp1252 UnicodeDecodeError mid-session
11. /workspace/workspace/ path nesting
12. PowerShell quote-mangling (twice: sed, python -c)
