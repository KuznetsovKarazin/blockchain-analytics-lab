# Phase 21 — Independent label-free selected-transaction feasibility audit

**Status:** completed source-level count audit; no new incident was admitted to the detection-performance cohort. Executed 29 October 2026, based on fixed Phase20 60-day S3 source identities. Immutable Phase16 and exploratory Phase18 decision records are unchanged.

## Scientific question

For a fixed history-dependent rule requiring **19 strictly prior positive same-token outflow observations** after each independent UTC-day reset, how often is there even a sufficient number of **distinct transactions**, regardless of their log volume, to make an eligible score possible?

Each selected transaction can add at most one positive gross-outflow observation **per token**. A necessary condition to produce any eligible score in a given token/day is thus **20 selected transactions involving that token**. Consequently, a day with fewer than 20 total core-selected transactions is mathematically ineligible for all tokens, even before transfer decoding. This necessary condition is not a sufficient test.

## Inputs and independent checks

- Phase20 accepted evidence: `papers/monitoring_jss/phase20/source_evidence/core_traffic.json` and `daily_core_log_counts.csv`; 60 days in exactly the same source and address boundaries.
- Original AWS log Parquet columns read: `address`, `block_number`, `transaction_index` from every row group, using capped ranged HTTP reads with source ETags. Distinct transaction identity is the pair (block number, transaction index) **within the canonical fixed-day Ethereum source**, not a count of event logs.
- Exact address normalization to lowercase was required for mixed-case Rari addresses. The first incomplete run correctly halted on an independent Phase20 count mismatch and remains preserved; code was fixed and synthetic tests updated before the successful rerun.
- Final [successful workflow run](https://github.com/KuznetsovKarazin/blockchain-analytics-lab/actions/runs/40861738915) contains **two successful case jobs**. Both reproduce every day/core emitted-log count exactly against the Phase20 accepted table. Combined final source projection: **558 HTTP ranges** and **503,904,867 response bytes**, excluding listing overhead. Total previously verified underlying log rows: **120,747,757**. No missing days or inferred zero-source days.
- The signed/secure historical receipt root is not independently verified. No all-emitter bundles or complete transaction status were retrieved for this experiment. No rank scores or attack labels were needed.

## New population-level results

| Separate nominated view | Core log events / 30 days | Distinct selected TX / 30 days | Median distinct TX / day | Days with fewer than 20 distinct TX |
|---|---:|---:|---:|---:|
| Bacon proxy | 746 | **256** | 7 | **28/30 (93.3%)** |
| Rari Pool 127 fETH | 331 | **132** | 4 | **30/30 (100%)** |
| Rari Pool 127 fUSDC | 426 | **159** | 2 | **28/30 (93.3%)** |
| Rari Pool 127 Comptroller | 146 | **133** | 3.5 | **29/30 (96.7%)** |

The three Rari components are **alternative emitter-specific observations**, not pooled detector implementations. As a descriptive diagnostic only, their union contains 411 distinct transaction-day observations across 30 days, and 24/30 days have fewer than 20 union-selected transactions. A pooled protocol core has not been historically nominated/admitted for detector evaluation and must not be retrospectively chosen to maximize reference coverage.

**Attack-day diagnostic, not a post-join detector result.** Bacon on 5 March 2022: 66 core logs in 23 selected transactions. Rari fETH on 30 April 2022: 54 core logs in **19** selected transactions. The latter remains ineligible under daily resets even if all 19 fETH-selected transactions contained positive outflows of one token: reaching 19 previous observations requires the 20th one. Other candidate Rari components have 48 (fUSDC) and 24 (Comptroller) distinct selected transactions on that day; their histories and roles require additional assessment.

The source-level results strengthen the originally weaker bound based on **log counts**: Bacon's count of impossible days rises from 15/30 based on logs to at least 28/30 based on distinct transactions, and Rari fETH rises from 26/30 to 30/30. These are necessary conditions for **any scored rank under the tested daily-reset and component-scope assumptions**, not measurements of actual eligible-token counts, raw detector alerts, or verified execution hits.

## Reproducibility and limitations

- Source and bounded workflow: [Phase21 audit code](selected_tx_audit.py), [tests](test_selected_tx_audit.py), [protocol](PHASE21_SELECTED_TX_PROTOCOL.md), [GitHub Actions workflow](../../../.github/workflows/monitoring_phase21_selected_tx_audit.yml).
- Machine-readable [daily count table](selected_tx_daily_counts.csv) contains per-component events, selected transactions, alternative union counts and independent Phase20 matching status.
- Original attack transactions themselves are not used to select events or calculate these source counts; historical core addresses were incident-informed, and the experimental change is **exploratory** relative to exposed prior cases.
- **Do not** infer actual 30-day token-outflow rank eligibility on days with 20 or more selected transactions, entire Rari protocol recall, precision/FPR, loss reduction or prevention. Do not equate the 558 ranges with 558 independent observations.
- Next decision gate: freeze independently justified component sets, acquire complete selected transaction bundles and status at the same source tier, perform token-specific history and exact execution join, and only then call Bacon/Rari external detection-performance cases.

**Accepted performance cohort remains Li.Fi and Revest (two incident families).** Bacon and Rari remain source-only candidate analyses.
