# Changelog

All notable changes to the AI CTF & Pentest Copilot.

## [Unreleased]
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
