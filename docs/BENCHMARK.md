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

---

## InterCode-CTF (external benchmark): 83/100

[InterCode-CTF](https://github.com/princeton-nlp/intercode) is 100 picoCTF tasks across six
categories, imported and run through our eval subsystem (one attempt each, DeepSeek-flash,
oracle-isolated exact-flag verification - the task's solution/ folder is never shown to the agent).

**Overall: 83/100 = 83% (95% CI 74-89%), $1.42 total (~$0.014/task), ~53s/task, 0 infra errors.**

| category | solved | rate (95% CI) | cost |
|---|---|---|---|
| general | 31/33 | 94% (80-98%) | $0.34 |
| reverse | 21/27 | 78% (59-89%) | $0.27 |
| forensics | 12/15 | 80% (55-93%) | $0.30 |
| crypto | 14/19 | 74% (51-88%) | $0.30 |
| pwn | 3/4 | 75% (30-95%) | $0.15 |
| web | 2/2 | 100% (34-100%) | $0.06 |

**Context.** InterCode-CTF is considered easy and near-saturated - published agents reach ~95% with
stronger models and multiple attempts. 83% from a single cheap model (DeepSeek-flash), single
attempt (pass@1), at ~1.4 cents per task is a strong, comparable result. Binary exploitation is the
known ceiling for this model class (only 4 pwn tasks here, so that 75% is high-variance).

**Honest caveats.** picoCTF challenges and writeups are public, so this measures recall as much as
discovery (the same caveat as Juice Shop). Single attempt; multi-attempt would score higher. The
flag is exact-match verified against the dataset's gold flag, injected host-side.

## NYU CTF Bench (external, university-level): Haiku, and a Sonnet recovery pass

[NYU CTF Bench](https://github.com/NYU-LLM-CTF/nyuctf_agents) is CSAW (2017-2023) university-level
CTF. We imported the test/ split and ran it through the eval subsystem, one attempt each,
oracle-isolated exact-flag verification. This set is much harder than InterCode. **The offline
benchmark is 56 challenges: 70 were imported, then 14 excluded** as not fairly solvable in a
file-only, no-network harness (recorded with reasons in `_excluded.json`): **6 empty_handout**
(NYU hosts the binaries outside git, so they stage as empty shells), **7 service** (pwn/web/nc
challenges whose flag lives on a remote endpoint - all pwn and all web fall here), and **1
synthetic_flag** (an NYU validation placeholder not derivable from the content). All numbers below are
over the clean 56 (categories: reverse 27, crypto 12, forensics 11, misc 6).

**Claude Haiku 5.5 - standalone: 37/54 = 69% (95% CI 55-79%), $1.00 total (~$0.027/solve), 0 refusals.**
(56 challenges, 2 excluded as infra errors.) Prompt caching makes Haiku cheaper per challenge than
DeepSeek-flash in the agent loop.

**Sonnet 5.5 recovery pass.** We then ran Claude Sonnet 5.5 on the challenges Haiku failed - a
"does a stronger model recover them?" probe. **Sonnet recovered 8/17 = 47% (95% CI 26-69%), ~$0.77
per recovery.** Of the 9 it did not solve, **4 were policy refusals** (Sonnet declined on safety
grounds) and 5 were genuine attempts that failed verification. Haiku refused **0**. Separating the
refusals, Sonnet solved **8/13 = 62% of the challenges it actually attempted**.

| category | recovered | refused | attempted-failed | Haiku failed |
|---|---|---|---|---|
| forensics | 4 | 0 | 1 | 5 |
| reverse | 2 | 3 | 3 | 8 |
| crypto | 1 | 1 | 1 | 3 |
| misc | 1 | 0 | 0 | 1 |
| **total** | **8** | **4** | **5** | **17** |

**Refusals, in the offline set and beyond.** Within these 56, Sonnet refused 4 (3 reverse, 1 crypto)
where Haiku attempted all of them - so a "refusal" is a distinct outcome from a capability failure,
and the refusal-as-outcome tracking is what surfaces it. The pattern is sharper in the *excluded*
service set: **every excluded pwn and web challenge was also a Sonnet refusal** - the stronger,
more safety-tuned model declines offensive-exploitation framing that the smaller models simply try.

**Cascade (Haiku first, Sonnet on the residual): 45/56 = 80%, ~$7.13 total (~$0.158/solve).** Running
the cheap model first and escalating only its failures to Sonnet solves 80% of the offline set.

**DeepSeek-flash head-to-head.** flash solved **39/56 = 70% (95% CI 57-80%)** at **$5.25 total
($0.135/solve)**, 0 refusals - level with Haiku's 69%, and the paired comparison confirms no real
gap. Of the 54 paired challenges: both solved 32, both failed 11, flash-only 6, Haiku-only 5 (McNemar
exact two-sided **p = 1.00**). The two cheap models are statistically indistinguishable on solve rate
here - but **Haiku is ~5x cheaper per solve** ($0.027 vs $0.135), because prompt caching and shorter
loops make it far cheaper per challenge. (An earlier flash attempt stalled at `402 Insufficient
Balance` ~10 challenges in; those trials were recorded as infra errors and excluded until the balance
was restored and they were re-run - the classifier fix below kept the outage from scoring as losses.)

**Honest caveats.** CSAW challenges and writeups are public (recall as much as discovery) - several
excluded challenges (des2bites, and the three web services) were "solved" only by reproducing the
public flag verbatim with no usable local files, a pure-recall artifact, which is one reason they are
excluded. Single attempt (pass@1); multi-attempt would score higher. The offline benchmark is
crypto/forensics/reverse/misc only - pwn and web are excluded because their flags require a live
target, so this says nothing about pwn/web ability. One run per challenge, so per-category splits are
high-variance. **Import validation** (`run_import_nyu.py`) excludes challenges with missing/empty
handouts, a remote-only flag, or a synthetic validation flag (14 of 70 here), with a runtime
`infra_error` backstop; and the flag-format hint now states each challenge's real wrapper
(flag{...}, csawctf{...}, ...) instead of hardcoding flag{...}, which previously misled the agent on
15 of the challenges. A trial where the model made no successful API call (0 tokens, $0) is likewise
`infra_error` and excluded, so a provider outage never silently deflates a score.

## Cascade economics: does stacking models pay off?

Joining all three models (Haiku, DeepSeek-flash, Sonnet) by challenge id over the clean 56, using the
recorded per-challenge costs. Sonnet was run only on Haiku's failures, which is exactly where a
Haiku -> flash -> Sonnet cascade would invoke it.

**Sonnet's 8 recoveries are only half additive.** 4 of the 8 were challenges **flash had already
solved** (misc-leaked-flag, rev-parallel-vm, rev-realism, forensics-br3akth3vau1t) - so in a cascade
that tries flash first, Sonnet adds nothing there. The genuinely additive 4 (challenges **both** Haiku
and flash failed) are **3 forensics** (floating-points, whyos, emoji) and **1 crypto** (m-ster-0f-prn9).

| strategy | solved | rate | total $ | $/solve |
|---|---|---|---|---|
| Haiku alone | 37/56 | 66% | $1.00 | **$0.027** |
| flash alone | 39/56 | 70% | $5.25 | $0.135 |
| Haiku -> Sonnet (2-stage) | 45/56 | 80% | $7.13 | $0.158 |
| **Haiku -> flash -> Sonnet (3-stage)** | **48/56** | **86%** | $9.62 | $0.200 |

(Haiku alone is 37/56 = 66% as coverage over the full set; its fair standalone rate excluding its 2
infra errors is 69%.) The 3-stage cascade reaches the highest coverage (86%): flash adds 7 unique
solves as the middle stage, Sonnet adds the final 4. But each stage buys coverage at a worse marginal
rate - Haiku alone is ~7.4x cheaper per solve than the full cascade. Stacking models is a coverage
play, not an efficiency one.

**Which categories benefit from adding a model** (incremental solves over Haiku alone; pwn/web are
excluded from the offline set, so this is crypto/forensics/reverse/misc):

| category | n | Haiku | +flash | +Sonnet | final | unsolved |
|---|---|---|---|---|---|---|
| forensics | 11 | 5 | +2 | **+3** | 10 | 1 |
| reverse | 27 | 19 | **+4** | 0 | 23 | 4 |
| crypto | 12 | 9 | 0 | +1 | 10 | 2 |
| misc | 6 | 4 | +1 | 0 | 5 | 1 |

- **forensics** is the category that benefits most from a stronger model: **Sonnet** is uniquely
  additive here (+3), nearly doubling Haiku's 5 to 10, plus flash +2.
- **reverse** gains most in absolute count from **flash** (+4); Sonnet adds nothing - the hardest
  reversing (bananascript, steady-counting, halfpike) defeats all three.
- **crypto / misc** gain little from stacking - Haiku already gets most of what is reachable offline.

## Capability experiment: does more step budget help reverse?

Diagnosing the unsolved reverse challenges showed the failing agents used sensible tools (gdb,
objdump, and decompilers - r2/ghidra appear in ~half the transcripts) but **hit the 50-step budget**:
on bananascript, steady-counting, halfpike, bdos and free-as-in-freedom, flash exhausted the budget
(`budget_hits=1`, did not finish naturally). So the single lever we tested is the **step/cost budget**
(50 -> 90 steps), on flash (the model that actually hits the ceiling), A/B'd against the flash@50
baseline over all 27 reverse challenges - the budget-hit failures are the design target, the other ~22
are the held-out no-regression set.

**Result: flash@50 21/27 -> flash@90 24/27 ($2.78 -> $4.85), but only +2 are attributable to budget.**
Decomposing the delta honestly:

| challenge | @90 | steps | budget-attributable? |
|---|---|---|---|
| steady-counting | solved | 59 | **yes** - needs >50, impossible under the old cap |
| halfpike | solved | 57 | **yes** - needs >50 |
| free-as-in-freedom | solved | 42 | no - 42 < 50, a lucky stochastic run |
| beleaf | solved | - | no - its @50 failure was an anomalous 2-step give-up |
| realism | **regressed** | - | no - solved @50, flipped @90 (noise) |
| bananascript | failed | 90 (hit cap) | no - **genuine reasoning ceiling** (custom interpreter) |

**The clean effect of the lever is +2** (steady-counting, halfpike both *finish naturally* at 57-59
steps - provably unreachable at 50). The rest of the net +3 is single-run noise: flash is stochastic,
and at one run per challenge the variance (1 regression, 2 flukey gains) is the **same magnitude as
the real effect**. bananascript hitting 90 and still failing confirms a reasoning ceiling that budget
does not address.

**Transfer:** the +2 were not hand-tuned, and only 1/21 baseline solves flipped (noise, not systematic
regression) - so raising the reverse budget to ~90 genuinely helps any challenge that needs 51-90
steps, at ~75% more cost. **Takeaway:** a real but modest win; the honest next step to separate the
signal from flash's run-to-run noise is multiple runs per challenge (pass@k), and the ceiling
challenges (custom VMs/interpreters) need reasoning depth - a stronger model or a decompiler scaffold -
not more steps. The `--max-steps`/`--max-cost` flags added here make that budget a one-line knob.
