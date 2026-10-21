# AI CTF & Pentest Agent - Roadmap v2

Consolidated architecture, objectives, and milestone plan. This document supersedes the
Phase 1-5 roadmap in `PROJECT.md` section 4 as the forward plan. It does not change any
code. Implementation of each milestone is gated on explicit operator approval.

**Primary model provider remains DeepSeek.** The provider abstraction below adds optionality
(a local privacy tier, a model-comparison axis for evaluation); it is not a migration away
from DeepSeek.

**Guiding constraint:** reliable single-machine first; design interfaces that permit scale
later without building distributed or generative infrastructure prematurely. Preserve existing
working functionality; avoid unnecessary rewrites.

---

## 0. Status of this document

- Direction approved by the operator, including evaluation as a foundational subsystem.
- Four final architectural considerations incorporated: challenge generation, failure
  diagnostics, parallel isolation, benchmark integrity.
- Saved as a plan only. No milestone is started. No application code is modified.

---

## 1. Current state assessment (verified against source)

The repository is a tight, honest, single-agent tool-calling loop: ~2,755 lines of Python,
one agent class, no automated test suite. The engineering discipline is real (append-only
transcripts for prompt caching, byte-stable tool schemas, UTF-8/LF correctness, git-SHA
provenance per eval row, safe-by-default empty allowlists in adapters). The weaknesses below
are specific and verified, not stylistic.

### Core components
- `agent/agent.py:51` - one `AgentSession` while-loop (`agent.py:102`). Seeds `self.messages`
  with the system prompt and a "Begin." message, runs tools until `finish` or a budget stop.
  This is the entire agent.
- `agent/tools.py` - nine tools: `run_command` (docker exec into `agent-box`), file
  read/write/list (workspace-sandboxed), `web_search` (Tavily), three Playwright browser
  tools, `ask_human`, `finish`.
- `agent/adapters.py` - CTFd adapter and the code-audit / GitHub-audit engagement builders.
  The safety contract (an adapter never auto-populates `allowed_hosts`; empty allowlist blocks
  everything) is well designed.
- `agent/court.py`, `learn.py`, `regression.py`, `bugbounty.py`, `disclosure.py`,
  `findings.py` - single-shot LLM helpers and deterministic utilities, not agents.
- `dashboard/server.py` (201 lines) - FastAPI + SSE, read-only over `workspace/sessions/`,
  plus one `POST /api/github/audit` that spawns `run_audit.py`.

### Verified weaknesses and technical debt
1. **The scope "cage" leaks (most serious).** `run_command` (`tools.py:61-67`) extracts hosts
   with two regexes (`tools.py:13-20`): http(s) URL hosts and dotted-quad IPv4 only. If nothing
   parses, `bad == []` and the command is allowed. So `curl example.com` (no scheme),
   `nc evil.com 4444`, `ssh user@evil.com`, decimal/hex/IPv6 IP encodings, and any
   shell-constructed host (`H=evil.com; curl http://$H/`) reach the network unchecked. Unlike
   `_scope_check_url` (`tools.py:154-155`), `run_command` has no "no host parsed" guard.
   Enforcement is a static string scan, not a network boundary, so runtime-constructed targets
   defeat it regardless. This contradicts the project's central claim that "the allowlist is
   the cage."
2. **No automated test suite.** `tests/` contains only `fixtures/`. Zero `test_*.py`.
3. **Provider lock-in is triplicated.** `OpenAI(..., base_url="https://api.deepseek.com")` is
   hard-coded in `agent.py:67`, `court.py`, and `learn.py`. `PROJECT.md:105`'s "the model layer
   is abstracted" overstates a two-entry `MODELS` dict (`agent.py:14`).
4. **Latent eval bug.** `run_eval.py` globs `challenges/*.json`, which now includes
   `github_validation.json` (a JSON array with no `workspace`), so an unfiltered run raises
   `TypeError` at `run_eval.py:186`.
5. **A real escalation fault in the data.** `results.csv` row 57 carries a `BadRequestError`
   about `reasoning_content` in thinking mode (the `extra_body={"thinking":...}` path at
   `agent.py:128`) in the same `error` column as genuine outcomes - infrastructure noise
   currently indistinguishable from agent failure.
6. **Dashboard POST is unauthenticated** and spawns subprocesses (`server.py:154-177`). Fine
   for localhost-solo; a liability if ever exposed.
7. **Shared execution substrate blocks parallelism.** `tools.py:8-9` hard-codes a single
   `WORKSPACE_HOST` and `CONTAINER = "agent-box"`. All trials share one container and one
   workspace; concurrent trials would collide. (Addressed in section 3.3.)

### Evaluation reality (verified against `results.csv`, not the docs)
- 83 data rows: **75 solved / 8 failed, and all 8 failures are `c08-kdbx-crack`.** The README's
  "9/10 on every run" holds as a per-challenge statement.
- "Solved" (`run_eval.py:34-54`, `check_evidence`) asserts only that the evidence file exists,
  is non-empty, and contains a substring / matches a regex. It never validates correctness
  (e.g. c03 only checks for the JWT prefix `"eyJ"`).
- The whole suite is one application family (Juice Shop), which the model very likely knows
  from pretraining. This measures recall, not discovery - the project already admits this
  (`README.md:96`).
- There is no persistent, cross-session, embedding, vector, or retrieval memory anywhere. The
  learning layer (`learn.py`) writes `learning.md` / `flashcards.json` and is never read back.

---

## 2. Approved objectives

1. **Persistent, experience-driven intelligence** - episodic/semantic/procedural memory with
   hybrid retrieval, confidence, provenance, decay, per-engagement privacy boundaries, and a
   clean no-memory evaluation mode. Memory must be *proven* to help, or reported as null.
2. **Intelligent multi-agent collaboration** - supervisor plus specialists, activated only when
   useful, gated behind measured improvement net of token cost.
3. **Advanced visual research dashboard** - timelines, decision/evidence inspection, approval
   and pause/resume/cancel, memory inspection, cost/benchmark analytics. Maintainable over
   impressive.
4. **Evidence-driven self-improvement** - offline trajectory/failure analysis, human-reviewed
   policy proposals, benchmark-gated with regression detection and rollback.
5. **General-purpose cybersecurity research platform** - CTF, authorized pentest, local vuln
   research, static code audit, defensive analysis, reproduction/remediation, education,
   coordinated disclosure. Network-level scope enforcement, isolation, auditability, human
   control as architectural requirements.
6. **Model-provider layer (DeepSeek only)** - a single provider interface with role-based
   routing (loop / escalate / verify / summarize), accurate cost tracking, caching, context
   management. Per operator direction the project runs on the DeepSeek API only; local
   inference is out of scope (the interface keeps a future provider a contained change, but
   none is built).
7. **Research credibility and open-source adoption** - reproducible, leak-controlled, diverse,
   baseline-compared benchmarks with honest failure analysis.
8. **Robust, scalable evaluation infrastructure (foundational)** - the first-class subsystem in
   section 3, on which objectives 1, 2, 4, and 6 depend for honest claims.

---

## 3. Evaluation subsystem (foundational)

Evaluation is promoted from a supporting script to a first-class subsystem. It is structurally
separate from the agent under test: the dependency arrow points one way only. `eval/` imports
`agent/` behind an interface; `agent/` never imports `eval/`. The thing being measured cannot
see the ruler.

### 3.1 Module architecture

```
eval/
  registry/        versioned challenge manifests (*.manifest.json) + JSON-Schema validator
  adapters/        per-category provisioning: web, ctfd, crypto, rev, pwn, forensics, code_audit
  generators/      (future) parameterized challenge generators -> manifests + keys
  runner/          Runner interface; LocalDockerRunner now, DistributedRunner later
  controller.py    experiment matrix {profiles} x {challenge sets} x {trials}: order, budgets, resume
  verify/          independent verifiers + outcome taxonomy + failure-reason taxonomy
  keys/            trusted answer keys / oracles - NEVER mounted into agent-box (gitignored)
  store/           schema-versioned structured results (SQLite primary; results.csv as export)
  report/          BENCHMARK.md, Pareto analysis, bootstrap CIs, regression detection
```

**Challenge registry.** Each manifest carries `schema_version`, `challenge_id`, `version`,
`category`, `tier` (A-E), `dataset` (dev|validation|test), `adapter`, `environment_digest`,
`budget`, a `verifier` spec, a `generator` spec (optional), and provenance. Every manifest is
schema-validated before a run; an invalid manifest never runs. This also removes the current
`run_eval.py` glob/`TypeError` bug because shape is validated, not assumed.

**Runner abstraction.** One interface:
`provision() -> reset() -> run_agent() -> collect_artifacts() -> verify() -> teardown()`.
`LocalDockerRunner` implements it first. The interface is the only seam a future queue-backed
`DistributedRunner` needs - designed for, not built now.

### 3.2 Outcome taxonomy and failure-reason diagnostics

Two orthogonal dimensions are recorded per trial.

**Outcome state** (one of seven):
`VERIFIED_SUCCESS`, `VERIFIED_FAILURE`, `PARTIAL`, `TIMEOUT`, `AGENT_ERROR`, `INFRA_ERROR`,
`INCONCLUSIVE`. Partial progress is a diagnostic metric, never summed into success.
`INFRA_ERROR` triggers a bounded retry and is never charged against the agent - this fixes the
existing confusion in `results.csv` where a thinking-mode HTTP 400 sits beside genuine outcomes.

**Failure reason** (structured, orthogonal to outcome; present for any non-success):
- `model_reasoning` - the model chose a wrong or incoherent approach, hallucinated, or looped.
- `tool_execution` - a tool or command failed, crashed, or produced unusable output.
- `orchestration` - escalation/routing/turn-management logic misbehaved.
- `configuration` - engagement/manifest/profile misconfigured (bad scope, wrong budget, etc.).
- `infrastructure` - container/network/provider/runner fault (maps to retries; not agent fault).
- `budget_exhaustion` - step or cost budget hit before completion.
- `verification` - the verifier could not confirm, or the claimed result failed its check.

A trial may carry one primary reason plus optional secondary tags. This dimension powers failure
-category analytics (Adaptive Intelligence evaluation, section 3.8) and the decision-mining step
of the optimization loop (M8).

### 3.3 Parallel isolation (fixing the shared container and workspace)

The current substrate is single-tenant by construction: `tools.py:8-9` hard-codes one
`WORKSPACE_HOST` and `CONTAINER = "agent-box"`. Concurrent trials would share a container, a
workspace, a network view, and have no independent budget enforcement. The runner must therefore
own per-trial isolation. Each concurrent trial gets:

- **Its own container.** An ephemeral `docker run` (or a per-worker named container
  `agent-box-{worker_id}`) from the pinned toolbox image, torn down at trial end. The runner
  passes the container name to the agent via the engagement/env rather than editing `tools.py`
  core logic (parameterize `CONTAINER`, keep behavior).
- **Its own workspace.** A per-trial host directory (`WORKSPACE_HOST` override), mounted into
  that container only. No cross-trial file visibility. Artifacts (`events.jsonl`, transcript,
  PoCs, screenshots) are collected per trial.
- **Its own network controls.** The network-level egress policy (M0) is applied per container:
  default-deny, allowlisted egress resolved from that trial's `allowed_hosts`. One trial cannot
  reach another trial's target or the host beyond its scope.
- **Reliably enforced cost and resource budgets.** The existing `max_cost_usd` is a soft,
  per-session, post-hoc summary. The controller adds: a hard per-trial cap that terminates the
  worker when exceeded, a per-experiment cap, and a global cap across the whole run. Plus wall
  -clock timeouts and container resource quotas (CPU/memory limits via docker flags). A trial
  that trips a hard cap is recorded as `TIMEOUT` or `budget_exhaustion`, not `VERIFIED_FAILURE`.

Worker count is bounded by RAM (section 3.10), not CPU. The runner enforces the configured worker
limit and never oversubscribes memory.

### 3.4 Trustworthy scoring and verifier isolation

Scoring never relies solely on file existence, substring match, or the agent's own claims.
Verification is independent and appropriate to the challenge:
- exact flag validation,
- hidden-state assertions,
- reproducible-exploit checks (run the PoC against a known oracle state),
- labeled-finding recall for code audits.

Trusted answer keys and oracles live in `eval/keys/`, never on any path the agent's workspace or
`agent-box` can read or mount. The existing `check_evidence` substring check is retained as the
*default weak* verifier for back-compat; per-challenge strong verifiers are added alongside
(e.g. c03 should confirm the token decodes to an admin claim, not merely that `"eyJ"` appears).

### 3.5 Benchmark tiers

- **Tier A - unit and safety tests (offline, ~free):** scope enforcement, tools, parsers,
  adapters, memory boundaries, orchestration behavior, oracle isolation. Ships with M0.
- **Tier B - smoke benchmarks (3-5 full challenges, cheap):** fast regression gate.
- **Tier C - development benchmarks (diverse):** feature comparison, prompt tuning, escalation
  policy development. The *only* set adaptation decisions are made on.
- **Tier D - held-out benchmarks (sealed):** generalization only, never optimized against.
- **Tier E - release evaluations (repeated trials):** published methodology, uncertainty
  estimates, reproducibility info, historical comparison.

### 3.6 Benchmark integrity

- **Three-way dataset separation.** Every manifest is tagged `dev`, `validation`, or `test`.
  Development (Tier C) is where tuning happens. Validation (Tier D) confirms generalization.
  Final test (Tier E / sealed held-out) produces headline numbers and is touched rarely.
- **Prevent repeated adaptation to held-out results.** The store tracks a held-out "usage
  budget": each evaluation against validation/test is logged, because each peek erodes validity.
  Adaptation decisions reference only dev results; a report flags if held-out sets have been
  queried more than a configured threshold.
- **Verifier isolation preserved** (section 3.4): keys never reach the agent, enforced by a
  Tier-A test, not convention.
- **Nondeterministic model behavior.** Reproducibility is statistical, not bit-exact. DeepSeek
  sampling is stochastic (temperature 0.3 in the loop). Reports therefore state trial counts,
  temperature, any seeds, and bootstrap confidence intervals, and claim reproducibility as
  "within CI on re-run of experiment id X", never as identical outputs.

### 3.7 Challenge generation (future capability, design for now)

An extensible generation layer (`eval/generators/`) produces randomized, isolated, automatically
verifiable challenges so generalization can be tested on instances that cannot have been in
training data. Design principles, built later (M6+):
- **Parameterized templates per category.** Example seeds: SQLi over a randomized schema and
  flag, a crypto challenge with randomized keys/nonces, a reversing binary with a randomized
  secret, a code-audit tree with synthetically injected, labeled vulnerabilities.
- **Each generated instance emits a manifest plus its own trusted key**, written to `eval/keys/`
  out of the agent's reach. Verification is automatic by construction (the generator knows the
  answer it planted).
- **Deterministic from a seed** for reproducibility; the seed is part of provenance.
- **Feeds Tier D** primarily: a freshly generated, never-published instance is the cleanest
  possible generalization probe.
- Interfaces are defined now (generator spec in the manifest schema); no generator is built
  until the static benchmark (M1-M3) is in place.

### 3.8 Adaptive Intelligence evaluation

Because the controller already varies configuration as an axis, comparing operating modes is
just populating that axis - no separate engine. Compared configurations:
- single DeepSeek Flash,
- Flash + retrieval memory,
- Flash + specialist collaboration,
- Flash + reasoning escalation,
- full Adaptive Intelligence Scaling,
- Economy / Balanced / Maximum profiles,
- different escalation thresholds and policies.

Protocol: matched challenge sets, equal hard budgets where appropriate, randomized run order,
repeated trials, controlled configs. Metrics: solve rate, API cost, tokens, latency, tool use,
escalation frequency, failure categories (section 3.2). Analyses include cost-versus-success
trade-offs and Pareto-efficient configurations. No configuration is assumed to be an improvement
without evidence; null and negative results are reported as findings.

### 3.9 Integration with the existing harness (reuse, do not rewrite)

| Existing | Becomes |
|---|---|
| `run_eval.py` loop | thin CLI wrapper over `eval/controller.py` + `LocalDockerRunner` |
| `reset_juice()` | the web adapter's `reset()` |
| `check_evidence()` substring check | the default weak verifier; strong per-challenge verifiers added |
| `results.csv` | an export view of the structured store (back-compat preserved) |
| `compare_runs.py`, `regression.py` | read the structured store; keep their CLIs |
| `events.jsonl` | captured by the runner as per-trial artifacts |
| `challenges/*.json` | migrated to validated manifests via a shim |

No existing command breaks. The subsystem wraps the harness; it does not replace it.

### 3.10 Hardware, cost, scaling

Target machine: Ryzen 5 5600 (6c/12t), RTX 5060 Ti 16 GB, 16 GB system RAM.
- **RAM is the binding constraint, not CPU.** Each live-web worker is a container plus often a
  target container plus Playwright. Realistic parallelism: 2-3 workers for web/CTF trials, 1 if
  a local model is loaded (VRAM and RAM contention). Offline/deterministic trials (code audit,
  fixed-input crypto, parser/adapter tests) cost about $0 and parallelize freely, so Tiers A and
  B should be dominated by those to keep the fast loop cheap and RAM-light.
- **Cost control:** tier discipline (A/B cheap and frequent, C occasional, D/E rare and
  deliberate); hard global, per-experiment, and per-trial budgets; provider rate-limiting and
  throttling in the LLM client; dev iteration on Flash with small subsets; Tier-E repeated-trial
  runs gated behind explicit opt-in. Prompt-prefix caching (already preserved) continues to help.
- **Scaling:** the `Runner` interface is the only seam that changes for distribution. A future
  `DistributedRunner` has workers pull trials from a queue and push results to the shared store.
  Not built until a benchmark is large enough to justify it.

### 3.11 Trustworthiness acceptance criteria

The framework is trustworthy only when all of these pass:
- **Oracle isolation:** a Tier-A test proves no answer key is reachable from the agent workspace
  or `agent-box`.
- **Taxonomy integrity:** an injected infrastructure fault yields `INFRA_ERROR` plus retry, never
  `VERIFIED_FAILURE`.
- **Isolation integrity:** two concurrent trials cannot read each other's workspace or reach each
  other's target; each has an independently enforced hard budget.
- **Contamination control:** held-out ids are hash-tracked; a test fails if one appears in memory
  or dev config; held-out usage budget is logged.
- **Full provenance:** every result carries challenge version, environment digest, agent commit,
  model id and configuration, orchestration policy, prompt version, memory-snapshot id, and
  verifier version (section 6).
- **Reproducibility:** re-running an experiment id reproduces results within the stated CI.
- **Honesty guardrail:** reports state trial counts and application-family coverage, and refuse
  to headline a number drawn from few trials or one family.

---

## 4. Architecture proposal (system-wide seams)

**Keep unchanged:** the `AgentSession` event-emitter design, the tool schemas (byte-stability
matters for caching), the adapter safety contract, the workspace sandbox concept, the git-SHA
provenance habit.

**New seams, minimal and additive:**
- `agent/llm.py` - an `LLMClient` interface (M2) with role routing. `agent.py` / `court.py` /
  `learn.py` depend on it instead of constructing `OpenAI` directly; the three duplicated clients
  collapse to one. DeepSeek stays the default backend.
- `agent/net.py` + per-container Docker network config - network-level egress enforcement (M0).
  `run_command` / browser keep a fast pre-check for UX, but the kernel/network is the boundary.
- `agent/memory.py` - a `MemoryStore` with `retrieve(context)` / `record(outcome)` (M4). Two hook
  points in `AgentSession.run()` (inject at start, record at finish); nothing else touches it.
- a `control` flag on `AgentSession`, checked at the top of the loop, for pause/cancel (M5
  dashboard).
- the `eval/` package (section 3), parameterizing `CONTAINER` and `WORKSPACE_HOST` per trial via
  the engagement/env so the runner can isolate trials without rewriting `tools.py` logic.

**Refactor only when touched:** the triplicated client (M2 fixes it), the `run_eval.py` glob bug
(M1 registry fixes it), the thinking-mode 400 (M2 client handles it).

**Explicitly resist:** rewriting the loop for multi-agent speculatively (compose the M7 supervisor
around the existing `AgentSession`); building distributed or generative infrastructure before a
benchmark needs it.

---

## 5. Milestone roadmap

| Order | Milestone | Acceptance criteria |
|---|---|---|
| **M0** | Close the scope cage + Tier A bootstrap | Network-level egress: `curl example.com`, decimal/hex/IPv6 IPs, and `H=evil.com; curl http://$H/` all fail at the network layer for a narrow allowlist, proven by `tests/test_scope.py`. First Tier-A safety tests exist. DONE (32 tests; firewall live-verified; command-layer live today, kernel firewall engages for eval trial containers after the image rebuild that adds nftables). |
| **M1** | Eval subsystem skeleton (foundational) | Manifest registry + schema validation; outcome + failure-reason taxonomies; structured store with provenance; `LocalDockerRunner` with per-trial isolation; controller with trials/budget/resume; the 10 Juice Shop challenges migrated with strengthened verifiers; Tier B smoke set. `run_eval.py` left working unchanged; a `results.csv`-format export is produced. DONE (20 tests; live-validated end to end on c01). |
| **M2** | Provider layer (DeepSeek only) | One `LLMClient` with role routing; the three duplicated clients collapse; thinking-mode 400 fixed (stale reasoning_content stripped); DeepSeek stays the only provider (no local inference); a cheap live smoke confirms no regression. DONE. |
| **M3** | Diverse Tier C/D challenges + baseline ablations | Challenges across >=3 categories beyond Juice Shop, split dev/validation/test; independent verifiers; baselines (raw model no-tools, single-tool-call) measured; a reproducible `BENCHMARK.md` with held-out generalization numbers. GENERALIZATION SET DONE: 3 generated held-out categories (crypto/reverse/forensics), randomized + oracle-isolated + exact-match verified, 9/9 at 100% (95% CI 70-100%), $0.033 - published in `docs/BENCHMARK.md`. BASELINES DONE: agent-full 6/6 (100%) vs single-step 0/6 vs no-tools raw-model 5/6 (83%) - the loop is needed for the read-process-write shape, but the bare model already solves most easy instances; the agent's edge should widen on code-requiring challenges (future work). Still pending: integrating code-audit repos as dev/validation challenges. |
| **M4** | Experience memory, proven on Tier D | Episodic store + hybrid retrieval; per-engagement privacy namespaces; `--no-memory` mode; an A/B on the held-out set showing memory-on vs memory-off deltas (reported honestly, including null/negative). MECHANISM DONE: namespaced, leak-controlled (procedural notes only, flags scrubbed), keyword+category retrieval, wired into the runner as opt-in `--memory`; 8 tests. A/B on the held-out generated set: NO measurable benefit (9/9 both arms; +1 step with memory, within noise at n=9) - honest null, the model already solves these; a headroom test (harder/recurring challenges) is future work. Still pending: AgentSession-level memory for interactive runs, and embedding-based retrieval. |
| **M5** | Eval + agent dashboard upgrade | Experiments/worker status, historical results, per-category solve rates with uncertainty, cost/latency comparisons, strategy comparisons, escalation effects, regression detection, config provenance, exportable + machine-readable reports; pause/resume/cancel; minimal auth before any exposure. Eval analytics view DONE (experiments list, verified solve-rate with Wilson CIs, per-category/challenge tables, caveats, regression endpoint, browser-verified); pause/resume/cancel of running sessions (via a `control.json` the agent checks between steps) + optional token auth (`DASHBOARD_TOKEN`) DONE and browser-verified. |
| **M6** | Adaptive Intelligence Scaling + challenge generation | Economy/Balanced/Maximum profiles and escalation thresholds compared as a config axis with Pareto analysis; first parameterized challenge generators feeding Tier D (randomized, isolated, auto-verified). |
| **M7** | Multi-agent, gated by eval | Supervisor + 2-3 specialists with bounded parallelism; must beat single-agent on the held-out set cost-adjusted, or be reported as not worthwhile. |
| **M8** | Offline policy-optimization loop | Collect validated trajectories -> mine failed/inefficient decisions -> generate candidate policies -> test on Tier C -> reject on safety/reliability/cost gates -> validate on Tier D -> human approval before deploy. Held-out solutions and verifier internals structurally barred from memory. |

**First to build (on approval): M0, then M1.** M0 because the one hard safety claim is currently
false and the fix is small; it also seeds Tier A. M1 because every later claim must be measured
against it. M2 pairs naturally with M1-M3 (model-comparison axis) while keeping DeepSeek primary.

---

## 6. Provenance and research-quality requirements

Every evaluation result must be traceable to:
challenge version, environment digest, agent commit, model identifier, model configuration,
orchestration policy, prompt version, memory snapshot id, and verifier version.

Handling rules:
- **Hidden tests:** keys isolated from the agent; verified by a Tier-A test.
- **Contamination controls:** dev/validation/test tags; held-out usage budget logged; a test
  fails on held-out id leakage into memory or dev config.
- **Failed infrastructure runs:** classified `INFRA_ERROR`, retried, never counted as agent
  failure.
- **Stochastic model behavior:** statistical reproducibility with trial counts and confidence
  intervals; never claimed as identical outputs.
- **Benchmark version changes:** a challenge version bump starts a new comparison series; results
  across versions are not silently pooled.
- **Small-sample / single-family honesty:** reports state trial counts and application-family
  coverage and refuse to overstate from few trials or one family.

---

## 7. Engineering principles and non-goals

- Preserve existing working functionality; avoid unnecessary rewrites.
- Modular interfaces and explicit contracts; the agent never imports the evaluator.
- Correctness, reproducibility, observability first.
- Keep dependencies and infrastructure complexity minimal; single-machine first, interfaces for
  later.
- DeepSeek remains the primary provider; abstraction adds optionality, not a migration.
- Security boundaries (network-level scope, isolation, oracle isolation) and human oversight are
  architectural requirements, not features.
- Prefer a small demonstrated breakthrough (trustworthy evaluation + a correctly enforced cage)
  over many unfinished features.
- Distinguish verified capability from assumption in every claim.

**Non-goals for now:** distributed evaluation infrastructure, a challenge-generation engine ahead
of a working static benchmark, multi-agent or memory features asserted as improvements without
held-out evidence, and any model fine-tuning before the evaluation subsystem can gate it.

---

*No application code is changed by this document. Implementation of each milestone is gated on
explicit operator approval, starting with M0.*
