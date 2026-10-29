# Phase 18 — reproducible historical initialization ablation

**Status: complete exploratory replay of the two previously exposed Li.Fi and Revest incidents. No newly independent external cases.** This branch is based on immutable Phase16 commit [e720697](https://github.com/KuznetsovKarazin/blockchain-analytics-lab/commit/e720697bc3986dd291a7047c580cf973ae6e5567).

## Scientific question

With the fixed transaction observations, same-token gross-outflow rank thresholds, transaction-level grouping and daily notification policies unchanged, does retaining earlier positive history increase eligible scores, raw triggers, actual notifications and matches to previously verified exploit executions?

- History variants: independent daily reset (frozen control), 7-day strictly past lookback inside the existing capture, cumulative strictly past history inside the existing 30-day window.
- Main rank threshold 1/20; sensitivity 1/10; 19 preceding same-token positive outflows required; history cap 128.
- Greedy, paced-cumulative and token-bucket policies with daily limits 1/5/20. Policies and grouping **still reset each UTC day**.
- **Two cases, not 108 independent experiments.** Every new intervention is *exploratory*, chosen after the original incident outcomes were known. Not independent prospective validation; no pre-window warm state is claimed.
- The original 948 semantic-method and 8,532 notification-admission rows were matched exactly to the frozen baseline; 14 synthetic test cases passed.

## Reproduce (Python 3.10+, standard library)

Use the published 4,706,961-byte [sealed evidence ZIP from Phase16](https://github.com/KuznetsovKarazin/blockchain-analytics-lab/blob/e720697bc3986dd291a7047c580cf973ae6e5567/papers/monitoring_jss/phase16/public_evidence/sealed_evidence.zip). Expected SHA-256:

```
56f19a262c36f5438d11d19cbb8434ea3dcb731b1cbdae34f479f667ec9997e2
```

From this directory:

```sh
python initialization_full_replay.py --evidence-zip /path/to/sealed_evidence.zip --out ./phase18_results
python -m unittest -v test_initialization_full_replay.py
```

To reproduce the three figures and token-day summaries (matplotlib required):

```sh
python make_phase18_figures.py --evidence-zip /path/to/sealed_evidence.zip --results ./phase18_results --out ./phase18_results
```

Outputs include exact transaction-level and per-case/method/policy/budget decision tables, 108 summary cells and independently checked frozen-control equality. Source evidence and full raw-chain archive were **not** recollected. Do not run `scripts/run_all.sh`.

## Principal observations

| Case | Initialization | Eligible transactions | Greedy B=5 rank 1/20 notifications | Exact known-execution hits |
|---|---|---:|---:|---:|
| Li.Fi | Daily reset | 0 / 280 | 0 | 0 / 1 |
| Li.Fi | 7-day lookback | 20 / 280 | 0 | 0 / 1 |
| Li.Fi | Cumulative in-window | 59 / 280 | 2 | 0 / 1 |
| Revest | Daily reset | 24 / 194 | 0 | 0 / 2 |
| Revest | 7-day lookback | 64 / 194 | 2 | 0 / 2 |
| Revest | Cumulative in-window | 71 / 194 | 1 | 0 / 2 |

The new notifications have unknown truth status; they are not labelled false positives. History improves score computability, but neither offered budget nor improved history recovers the three identified exploit executions. Li.Fi is particularly unsuitable for a core-sender gross-outflow rule because the documented approval-drain path is user-to-attacker `transferFrom`.

## Publication and figures

- [English scientific findings](PHASE18_FINDINGS_EN.md)
- [Article 2 revised V2 manuscript](Article2_Manuscript_V2_2026-10-29.md)
- [Prospective new-cohort screening protocol](EXTERNAL_COHORT_PROTOCOL.md)
- [Source-grounded candidate triage](PHASE19_SOURCE_TRIAGE.md)
- [Phase19 corpus-source and provenance audit](PHASE19_CORPUS_SOURCES.md)
- [Fig. 1 — token-day applicability](phase18_results/fig1_token_day_gate.svg)
- [Fig. 2 — eligibility vs history retention](phase18_results/fig2_history_eligibility.svg)
- [Fig. 3 — raw and emitted notifications](phase18_results/fig3_raw_vs_notifications.svg)

This is a scientific-interpretation and reproducibility artifact, not a software release or submitted article. **Never replace the frozen Phase16 results or companion pin.**
