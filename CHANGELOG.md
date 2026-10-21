# Changelog

All notable changes to the AI CTF & Pentest Copilot.

## [Unreleased]
- Roadmap v2 (`docs/ROADMAP-v2.md`): consolidates the assessment, the foundational evaluation
  subsystem, and milestones M0-M8. DeepSeek stays the primary provider.
- M0 scope hardening: `agent/tools.py` `extract_hosts` now normalizes decimal/hex/IPv6 IP
  encodings and parses `user@host` and `nc/telnet HOST PORT`; `run_command` fails closed for a
  network tool whose destination is unresolvable or built at runtime - closing the scheme-less
  `curl example.com`, decimal-IP, and `$VAR`/`$()` allowlist bypasses. New `agent/net.py` adds a
  default-drop egress firewall (nftables, iptables fallback) for evaluation trial containers,
  live-verified to drop out-of-scope traffic while allowing loopback; `Dockerfile` gains
  nftables/iptables. `tests/test_scope.py`: 32 Tier A safety tests.
- M5 dashboard evaluation view: `dashboard/server.py` gains read-only `/api/eval/experiments`,
  `/api/eval/report`, and `/api/eval/regression` over the eval store, and `dashboard/index.html`
  gains an Eval tab that renders verified solve-rate with Wilson confidence intervals,
  per-category / per-challenge tables, and the honesty caveats - straight from the structured
  store. Localhost, read-only. `.claude/launch.json` added so the dashboard starts with one
  command. Verified live in the browser against the smoke experiments.
- M4 experience memory (`agent/memory.py`): a lightweight, namespaced store of procedural
  lessons (category, outcome, tool/approach sketch, goal keywords) - never flags or evidence
  (both scrubbed), so a held-out answer cannot leak into memory. Retrieval is keyword + category
  scoring with recency decay (no embedding model, keeping it DeepSeek-only and dependency-free).
  Namespaces isolate unrelated engagements/clients. Wired into the eval runner (opt-in via
  `run_experiment.py --memory`): it retrieves relevant past lessons and injects them into the
  goal, then records the authoritative verified outcome after the trial - memory is host-side,
  never in the agent's container. Whether it helps is measured by a memory-off vs memory-on A/B
  on the held-out generated set (reported honestly in `docs/BENCHMARK.md`, including null/negative).
  `tests/test_memory.py`: 8 tests (isolation, no-flag-leak, scoring, dedup, the runner loop).
  A/B result: no measurable benefit on the generated set (9/9 both arms; mean steps 5.8 off vs 6.8
  on, within noise at n=9) - an honest null, since the model already solves these; a test with
  headroom (harder or recurring-trick challenges) is future work.
- M3 generated challenges (`eval/generators/`): randomized, auto-verifiable, leak-controlled
  challenges in three new categories beyond web - crypto (single-byte XOR), reverse (layered
  base64/hex), forensics (flag buried in a binary blob). Each instance's FLAG is random (seeded
  by experiment:challenge:run), so the model cannot have memorized it - true generalization
  probes, not recall. The answer key is written host-side (`eval/keys/`, gitignored) and injected
  into the verifier only at check time, never into the agent's container (oracle isolation). The
  registry accepts generator manifests (no static challenge file); the runner stages the instance,
  records the key, and verifies by exact match. `tests/test_generators.py`: 13 tests. First
  generalization run (`docs/BENCHMARK.md`): 9/9 (100%, 95% CI 70-100%) across the three
  categories, 3 runs each, $0.033 total. Baseline ablations added (`run_experiment.py --baselines`):
  a no-tools raw-model arm (one model call, file contents inline, no container, no tool loop) and a
  single-step arm, run as separate configs and compared per config. Result: agent-full 6/6 (100%)
  vs single-step 0/6 (the loop is needed for the read-process-write shape) vs no-tools raw-model
  5/6 (83%) - on these easy challenges the bare model already does most of the work; the agent's
  edge should widen on code-requiring challenges (future work). See `docs/BENCHMARK.md`. Still
  pending in M3: integrating code-audit repos as dev/validation challenges.
- M2 model-provider layer (`agent/llm.py`): a single `LLMClient` centralizes the DeepSeek
  (OpenAI-compatible) client, role -> model routing (loop/escalate/verify/summarize), pricing,
  and the thinking-mode handling that `agent.py`, `court.py`, and `learn.py` each hard-coded -
  now all three route through it. Fixes a thinking-mode HTTP 400 by stripping stale
  `reasoning_content` from history before each call. DeepSeek stays the only provider (local
  inference is out of scope); the interface keeps a future provider a contained change. Live
  smoke: c01 solved via the refactored path at $0.0053, no regression. `tests/test_llm.py`: 6 tests.
- Evaluation reporting layer (`eval/report.py` + `run_report.py`): turns the structured store
  into verified solve-rates with Wilson-score confidence intervals (so small-n results show
  honestly wide bounds), per-category / per-challenge / per-config breakdowns, cost/step/latency
  aggregates, failure-reason distributions, and a per-challenge regression diff between two
  experiments. Emits a human `BENCHMARK.md` and a machine-readable JSON. Infra errors are
  excluded from solve-rate denominators; the report auto-flags dev-only or single-category
  coverage so a number is never mistaken for generalization. `tests/test_report.py`: 10 tests.
- M1 evaluation subsystem (`eval/`): versioned, schema-validated challenge manifests
  (`eval/manifests/`), orthogonal Outcome + FailureReason taxonomies, independent verifiers
  (stronger than substring: JWT-claim checks, min-count, failure-phrase rejection), a
  schema-versioned SQLite store with full provenance plus legacy `results.csv` export, and an
  isolated `LocalDockerRunner` (per-trial container/workspace/egress-firewall/budget) driven by a
  resumable, cost-capped controller. New CLI `run_experiment.py`; legacy `run_eval.py` unchanged.
  `tests/test_eval.py`: 20 Tier A tests. The 10 Juice Shop challenges are migrated as dev-tier
  manifests (not held-out).
- Vuln-regression (`run_retest.py`): diffs two audit sessions' findings into new / fixed /
  still-open (matched by file+CWE), writing retest.md - confirm which issues a later commit fixed.
- Bug-bounty scope mode (`run_bugbounty.py` + `agent/bugbounty.py`): parses a program's
  structured scope (HackerOne API via `H1_API_*` env, or `--scope-file`) into a PROPOSED
  engagement written to `workspace/engagements/` (allowed_hosts from the in-scope assets) -
  never auto-applied or auto-run; the operator reviews and launches it. Warns when an
  out-of-scope host falls under an in-scope wildcard.
- CI audit-on-push (`.github/workflows/audit.yml`): a report-only GitHub Action that runs
  semgrep + osv-scanner on push/PR and posts a job summary (no agent-box, no API key, no cost);
  the LLM-triaged audit stays on-demand.
- GitHub-mode validation (`validate_github.py` + `challenges/github_validation.json`): measures
  the auditor's recall against repos with known issue classes and appends `ghval-` rows to
  results.csv. dvpwa: 4/4.
- Findings court (second-pass verifier): `run_court.py` + `agent/court.py` re-read the cited
  source for each finding and adversarially confirm/refute it (verdict + grounded reason),
  merged back into findings.json. Eval-verifiable: on a labeled set (4 real fixture vulns + 3
  planted fakes) it confirmed all reals and refuted all fakes - 0 hallucinations leaked. On the
  dvpwa audit: 11 confirmed, 3 refuted (it pushed back on over-stated LOW/MEDIUM items). The
  dashboard shows the verdict on each finding card, and `run_disclose.py` drops refuted findings
  from disclosure.
- Responsible-disclosure export: `run_disclose.py` + `agent/disclosure.py` turn an audit's
  findings.json into a GitHub Security Advisory-style `disclosure.md` (summary, severity table,
  per-finding details) plus per-finding issue drafts. `--file-issues` auto-files GitHub issues
  ONLY when the `GITHUB_TOKEN` has push/admin on the target repo (checked via the API); every
  other case (no token, no write access, third-party repo) is refused and gets the advisory for
  manual, coordinated disclosure. Verified: renders 14 dvpwa findings and refuses to file
  without a token. Fail-closed by design; live filing needs `GITHUB_TOKEN` set and should be run
  on your own repos.
- GitHub repo audit: `run_audit.py --github https://github.com/owner/repo` shallow-clones the
  repo host-side (github.com never enters the allowlist; the code is scanned statically, never
  run) and audits it via the existing file-only flow. Audits now also emit a structured
  `findings.json` (id/title/severity/file/line/cwe/confidence/poc/description/remediation),
  written incrementally so it survives the step budget, with a tolerant `agent/findings.py`
  loader. Verified on dvpwa: 14 findings (SQLi, XSS, broken access control, weak hashing,
  vulnerable deps, etc.) for ~$0.21. Includes a Windows-safe clone overwrite (git read-only
  `.git` packs broke `shutil.rmtree`).
- Dashboard "Repos" tab: paste a github.com URL to launch a file-only audit from the browser.
  `POST /api/github/audit` clones host-side + spawns `run_audit.py --github` as a subprocess;
  the agent's live `events.jsonl` means the existing `/stream` shows progress with no new
  streaming code; `GET /.../findings` + `agent/findings.py` render severity-sorted finding
  cards. Clears a prior same-id run so the UI follows the fresh one, not a stale finished
  session. Localhost/single-operator; the URL is validated to github.com/owner/repo.
- Phase 5 privacy mode (target anonymization): `agent/privacy.py` replaces real hostnames,
  IPs and emails with stable placeholders before anything reaches the model API, and restores
  them before tools run - crucially BEFORE the allowlist check, so scope is enforced on real
  values and privacy never widens it. Wired into `AgentSession` and the runners (`--privacy` on
  main.py/run_ctfd.py/run_audit.py); local artifacts (events, reports) keep real values.
  Verified E2E on c01 with privacy on: the message history sent to the API held only
  placeholders (no real host), yet the agent still determined version 20.3.0 - $0.008, 7 steps.
- Phase 4 dashboard (MVP): a FastAPI backend (`dashboard/server.py`) over the agent's saved
  sessions - `GET /api/sessions`, `/api/sessions/{id}/events`, and an SSE
  `/api/sessions/{id}/stream` that replays a session's events to mock a live feed - plus a
  minimal single-page frontend (`dashboard/index.html`): session list (status, events, cost,
  goal) and a color-coded live event feed via EventSource. Read-only, path-traversal guarded.
  Verified in-browser: streamed a full SQLi session end to end.
- Phase 4 live streaming: `AgentSession` now appends each event to `events.jsonl` as it runs
  and `/stream` TAILS that log, so a running engagement shows as `running` (sorted to the top
  of the list) and its events appear in the feed in real time - verified in-browser watching a
  running audit stream its semgrep/osv-scanner/pip-audit calls live. Finished/old sessions
  without a live log fall back to replay.
- Phase 3 extras: the learning layer now auto-runs at session end - opt-in `auto_learn` on
  `AgentSession`, enabled in the real runners (`main.py`, `run_ctfd.py`, `run_audit.py`) and
  OFF for the eval so baselines stay clean/cheap - emitting a `learning_saved` event.
  Added a client-style report template: `generate_client_report` / `run_learn.py --client`
  produces a formal pentest report (executive summary, scope, per-finding
  severity/impact/remediation, risk table, appendix). Demoed: dvpwa -> a 15 KB, 12-finding report.
- Phase 3 learning layer: `agent/learn.py` + `run_learn.py` turn a finished session's
  events.json (goal + tool-call methodology + final summary) into a study aid - a Markdown
  writeup, key concepts, and 6-10 flashcards (JSON) - via one cheap LLM call, written next
  to the session. Handles eval runs under `run_NN/`. Demoed on the dvpwa audit and a c03
  SQLi run: accurate, concrete writeups (payloads, endpoints, file:line) and 10 flashcards each.
- Phase 2.5 polish + scale demo: `run_audit.py` and `run_ctfd.py` force UTF-8 stdout so a
  cp1252 Windows console no longer crashes on tool output; the audit goal now writes the
  report incrementally so partial progress survives the step budget. Demoed the auditor at
  scale on a real OSS app (`dvpwa`): a 20 KB, 12-finding prioritized report (SQLi, broken
  access control, stored XSS, MD5 passwords, vulnerable deps, unauth->compromise chain,
  plus examined false positives) for $0.22 / 34 steps.
- Phase 2.5 code-audit mode (folder-target engagements): `build_code_audit_engagement`
  (`agent/adapters.py`) stages a local source tree into the workspace and builds a
  file-only engagement (empty allowed_hosts = no network in scope) directing the agent
  to run semgrep, triage, PoC, and write a prioritized report. `run_audit.py` runner
  with `--dry-run` (semgrep only, no API cost) and `--unattended`. Demoed on a
  deliberately-insecure fixture (`tests/fixtures/vuln_sample`): the agent found all 4
  injection flaws - semgrep auto caught 3 and missed `os.system`, which the agent
  found by reading the code and then wrote a custom semgrep rule for - producing PoCs
  and a 255-line report for $0.019 / 14 steps.
- Phase 2.5 dependency-CVE hunt: the toolbox image now ships osv-scanner (multi-ecosystem,
  pinned v2.7.0 binary) and pip-audit (Python; needs python3-venv, now installed). Wired
  into the audit goal and `run_audit.py --dry-run`. Demoed on a vulnerable `requirements.txt`
  (jinja2/pyyaml/requests/urllib3): osv-scanner reports the full OSV advisory set and
  pip-audit lists per-package CVEs with fixed versions.
- `compare_runs.py`: diffs two eval runs in `results.csv` by git SHA (per-challenge
  solve rate, mean steps, mean cost) and flags solve-rate drops or material
  step/cost increases, so a change is judged against a reference baseline.
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
  made 23 web_search calls (c08/c10) that all failed this way - Tavily returns HTTP
  401. It now switches to the current `Authorization: Bearer <key>` auth form and
  surfaces non-200 responses as `web_search error: HTTP <code> ...`. Preflight's
  Tavily check now does a real 1-result search and PASSes only on HTTP 200 with a
  non-empty results array, so a bad/expired key fails preflight. The
  `TAVILY_API_KEY` in `.env` has since been replaced; web_search now returns real
  results and preflight's Tavily check PASSes. Re-evaluated at git `0d0f571` (same
  3× suite): web_search fired 12 times across c08/c10 with zero errors and real
  writeup content (fix verified live), but outcomes were identical to the a3d3e74
  baseline (9/10 challenges, 27/30 runs; c08 still 0/3, c10 still 3/3) - working
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
