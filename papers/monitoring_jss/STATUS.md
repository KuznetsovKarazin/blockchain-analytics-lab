# Article 2 status — 25 October 2026

**Header and Euler event-log feasibility pilots completed. Delayed-feedback
scheduling and temporal calibration bookkeeping verified. The full scientific
comparison remains draft; no independent attack-detection result is claimed.**

Repository: KuznetsovKarazin/blockchain-analytics-lab; branch: paper/monitoring-jss.
First pilot published at aa5886d20866579eb8855bca36cfad54ac76dee8.
Companion dependency remains dc1ba8876f3f163c27c48f3a39292fc47f71bf18.
Historical book scripts and results are unchanged.

## Completed evidence

- Header pilot: 7,167 blocks, 12 cells and 44,802 decisions; see `SESSION_REPORT.md`.
- Euler acquisition: complete address scan of 2,416,676 rows; all 1,247 matching
  core logs from 218 transactions, linked to 215 blocks. All 7,118 daily headers,
  7,117 parent links and 37 downloaded ranges checked independently.
- Euler replay: six processes, 7,482 decisions; each emits 5 notifications from
  146 raw workload triggers, with equal semantics across speeds and repetitions.
  Measured local costs and modeled FIFO queues are reported separately.
- Delayed feedback: delays 0/1/2/4, predict-before-release, disjoint temporal
  calibration, whole-model/threshold fallback and stale-update protection.
  No estimator has been fitted by this new utility.
- Candidate exposure: Euler and Beanstalk occurred in earlier catalog/curation
  sources, but were not K4 positive cases in the audited scope. BSC has no match
  in the checked sources. All three remain candidates, not eligible tests.
- Full monitoring test suite: 58 passed and 23 subtests passed. Independent
  reviews additionally check acquisition, label scheduling and written logs.

The current detailed report is `SESSION_2_REPORT_RU.md`. Protocol extensions
are `EVENT_LOG_CONTRACT.md` and `DELAYED_FEEDBACK_CONTRACT.md`.

## Accepted and excluded runs

| Evidence | Path |
|---|---|
| Accepted header replay | `runs/pilot_20261025T081404_015172Z/` |
| Accepted Euler acquisition | `runs/protocol_logs_20261025T083346_282558Z/` |
| Accepted Euler log replay | `runs/event_logs_20261025T084327_927529Z/` |
| Earlier header run, excluded | `runs/pilot_20261025T081159_554384Z/` |

The excluded header run has one truncated gzip decision log and hash mismatch.
Original bytes and failed integrity results are preserved. The cause is not
established; its timing results are not used. Later accepted runs are checked
on their written files rather than relying on process success alone.

Raw data, downloaded ranges and per-record logs are preserved privately.
Git contains code, exact executed snapshots, aggregate results and audit hashes.
No raw upstream redistribution license is inferred from a software license.

## Work packages

| Package | Actual state | Remaining |
|---|---|---|
| P2.01 | Header and real protocol-event replay, ordering and provenance verified | Receipts/traces, deployed semantic ABI, cross-chain availability |
| P2.02 | Hard budget and delayed-label/calibration state contracts verified | Fitted models, class minima, threshold objective, full temporal experiment |
| P2.03 | Three candidates, exposure audit, two population definitions, one full Euler day | Eligible labelled cases and 30–60-day continuous populations |
| P2.04 | Measured source extraction and local replay; modeled queueing | More source/population workloads and declared live/finality scope |
| P2.05 | Duplicate/late delivery and orderly snapshot continuation | Durable outbox, arbitrary crashes, delivery and recovery timing |
| P2.06 | Two reproducible exploratory reports with independent checks | Independent scientific comparisons and uncertainty |

## Next bounded research step

Complete eligible-case and monitored-population definitions, including exact
attack transaction labels and historical deployment evidence where semantic
features require it. Plan continuous windows with the measured extraction
volume, retain prior-exposure categories, and fix the multi-day budget clock.
For Elliptic, freeze actual estimator, calibration class minima, seeds and
threshold objective before an exploratory rerun of already studied steps.
These are evidence/design requirements, not a request for further permission.
Article 1 and the book retain their agreed priority.
