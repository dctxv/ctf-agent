# CTF-Agent Benchmark

Reproducible evaluation results from the `eval/` subsystem. Generated 2026-10-21 at agent commit `cefb3b1`, model `deepseek-flash`.

## Methodology

- **Leak control.** The challenges below are *generated*: each instance's `FLAG{...}`
  is random, seeded by `experiment:challenge:run`, so the model cannot have seen the
  answer in training. These measure generalization, not recall. (The Juice Shop set,
  by contrast, is dev-only and almost certainly in pretraining - it is not reported here.)
- **Oracle isolation.** The answer key is written host-side (`eval/keys/`, never mounted
  into the agent's container) and injected into the verifier only at check time. Scoring
  is exact-match on the recovered flag - not substring, not the agent's own claim.
- **Isolation.** Each trial runs in its own ephemeral container and workspace; these
  challenges are file-only (empty allowlist, no network in scope).
- **Uncertainty.** Solve rate is reported with a 95% Wilson score interval, so small-n
  results show honestly wide bounds.

Reproduce:

```bash
python run_experiment.py --dataset test --runs 3 --no-reset --experiment m3-generated-test
python run_report.py --experiment m3-generated-test --out-md docs/BENCHMARK.md
```

## What this does and does not show

It shows the agent reliably solves randomized crypto/reverse/forensics instances it
cannot have memorized, cheaply. It does **not** show performance on hard or adversarial
challenges - these three categories are deliberately tractable starter probes. Harder
generated challenges and more categories are future work; numbers here should not be
read as a general capability claim.

---

# Generalization benchmark (generated challenges)

Experiment: `m3-generated-test`
Datasets: test | Categories: crypto, forensics, reverse

## Overall

- Verified solve rate: **9/9 (100%, 95% CI 70%-100%)**
- Infra errors (excluded from the rate): 0
- Mean cost $0.0037 | mean steps 6.7778 | mean duration 19.2433s

### By category

| key | solve rate | mean $ | mean steps | infra |
|---|---|---|---|---|
| crypto | 3/3 (100%, 95% CI 44%-100%) | 0.0042 | 7.3333 | 0 |
| forensics | 3/3 (100%, 95% CI 44%-100%) | 0.0021 | 5.6667 | 0 |
| reverse | 3/3 (100%, 95% CI 44%-100%) | 0.0047 | 7.3333 | 0 |

### By challenge

| key | solve rate | mean $ | mean steps | infra |
|---|---|---|---|---|
| gen-buried-flag | 3/3 (100%, 95% CI 44%-100%) | 0.0021 | 5.6667 | 0 |
| gen-layered-encoding | 3/3 (100%, 95% CI 44%-100%) | 0.0047 | 7.3333 | 0 |
| gen-xor-flag | 3/3 (100%, 95% CI 44%-100%) | 0.0042 | 7.3333 | 0 |


---

## Memory A/B (M4): does experience memory help here?

Same held-out generated set, memory-off vs memory-on, 3 runs per category each (n=9 per arm).

| arm | solved | mean steps | mean $ | mean s |
|---|---|---|---|---|
| memory-off | 9/9 (100%) | 5.78 | 0.002 | 15.3 |
| memory-on  | 9/9 (100%) | 6.78 | 0.003 | 17.4 |

Per-category mean steps (off -> on): crypto 6.33 -> 7.33, forensics 5.33 -> 6.67, reverse 5.67 -> 6.33.

**Finding: no measurable benefit on this set, and a slight overhead.** Solve rate is already at
its ceiling - these challenges are tractable and the model knows the techniques - so memory has
no headroom to raise it, and the injected "prior experience" hints add a little prompt cost and
about one extra step. At n=9 per arm that step difference is within noise, not a real regression.

This is the honest answer the A/B exists to give: on easy challenges the model already solves,
stored experience does not help. Whether memory helps where it should - harder challenges, or a
non-obvious trick that recurs across instances - is untested here and is future work. M4 delivers
the mechanism and the measurement, not a capability claim.

---

## Baseline ablations (M3): how much is the agent vs the model?

Same held-out generated set, three configs, 2 runs per challenge each (n=6 per config).

| config | solved | mean steps | mean $ | what it is |
|---|---|---|---|---|
| agent-full | 6/6 (100%) | 6.8 | 0.003 | the full agentic tool loop |
| agent-1step | 0/6 (0%) | 1.0 | 0.001 | a one-step budget (single tool call) |
| raw-model (no tools) | 5/6 (83%) | 1 call | 0.003 | the bare model, file contents handed in inline, no code execution |

raw-model by category: crypto 2/2, forensics 2/2, reverse 1/2.

**Findings.**
- The multi-step loop is necessary for the task shape: a one-step budget solves nothing - you
  cannot read the file, process it, and write the answer in a single action.
- But the no-tools model, given the raw data in one call, already solves 5/6. On these tractable,
  self-contained challenges much of the success is the model's own reasoning, not the agent
  scaffolding; the loop adds reliability (100% vs 83%) and recovers one case the bare model missed.
- This is the honest value of a baseline: it stops us over-crediting the harness on easy problems.
  The agent's advantage should widen on challenges that genuinely require running code - large
  inputs, brute force, real exploitation - rather than one-shot reasoning, which these are not.
  Measuring that is future work.

---

## Adaptive scaling (M6): cost vs success across profiles

Same held-out generated set, three profiles, 2 runs per challenge each (n=6 per profile).

| profile | solved | mean $ | mean steps | escalations | what it is |
|---|---|---|---|---|---|
| economy | 6/6 (100%) | 0.0027 | 6.3 | 0 | flash only, no escalation, tight budget |
| balanced | 6/6 (100%) | 0.0043 | 7.7 | 2 | flash + escalate to the reasoning model after 2 failures |
| maximum | 6/6 (100%) | 0.0090 | 6.8 | 6 | reasoning model in the loop, escalate on first failure |

**Pareto-efficient: economy.** All three profiles solve 100%, so the cheapest wins outright -
balanced costs 1.6x and maximum 3.3x economy for identical success. Escalation did fire (2 and 6
times), but on challenges with no headroom it only adds cost; the reasoning model and aggressive
escalation earn their keep only where the cheap model genuinely fails and a stronger model
recovers the case - which these easy challenges are not. Expect the Pareto front to move toward
balanced/maximum on harder, code-requiring challenges; measuring that is future work.

---

## Multi-agent (M7): does a supervisor + specialists beat the single agent?

Same held-out generated set, single-agent vs multi-agent, 2 runs per challenge each (n=6 per arm).

| config | solved | mean $ | mean steps | mean s |
|---|---|---|---|---|
| single-agent | 6/6 (100%) | 0.0031 | 6.5 | 16.5 |
| multi-agent  | 6/6 (100%) | 0.0043 | 7.5 | 21.0 |

The supervisor routed correctly (e.g. the XOR challenge to the crypto specialist, confirmed in the
trial transcripts). But both arms solve 100%, and multi-agent costs ~1.4x more - the supervisor
call plus a longer specialist framing - for no gain.

**Eval-gate verdict: not worthwhile here.** Multi-agent must beat the single agent cost-adjusted to
earn its place; on these self-contained, single-flag challenges the orchestration is pure overhead.
Its value should appear on genuinely decomposable, multi-step engagements where a specialist's
focus (or parallel subtasks) changes the outcome - untested here and future work. This matches the
published literature, where multi-agent setups frequently lose on cost-adjusted outcome for
smaller models.

---

## Memory on harder challenges (two cycles)

Harder generated set (multi-byte XOR, mixed encode chain) - both require writing and running code.
Three arms, 2 runs per challenge each (n=2 per challenge per arm; small - read as directional).

| arm | solved | mean $ | mean steps | mean s |
|---|---|---|---|---|
| control (memory off) | 4/4 | 0.0050 | 7.25 | 24.7 |
| cycle 1 (memory on, cold) | 4/4 | 0.0079 | 8.50 | 27.7 |
| cycle 2 (memory on, warm) | 4/4 | 0.0053 | 7.00 | 20.9 |

Per challenge, warm cycle 2: gen-xor-multibyte $0.0050 / 6.5 steps / 19.5s; gen-chained-decode
$0.0057 / 7.5 steps / 22.3s. (The memory note now stores the agent's approach, not just tool
names - e.g. "Recovered the repeating multi-byte XOR key and the flag; Method ...".)

**Verdict: memory works mechanically but shows no clear net benefit, even with headroom.** Warm
memory (cycle 2) recovered the cold-cycle overhead and matched the no-memory control (7.0 vs 7.25
steps, $0.0053 vs $0.0050); it beat the cold cycle but not the control. The agent already solves
these competently, so a retrieved hint saves little - the same conclusion as the easy set. A clear
win would need challenges where the cheap model genuinely FAILS without guidance (success headroom,
so a hint can flip fail->solve), or far more trials to separate a small effect from noise. n=2 is
noisy; treat as directional.
