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

