# Article 2 status — 25 October 2026

**Bounded feasibility pilot completed and independently checked. The full research
protocol remains draft; the article is not ready for submission.**

Repository: KuznetsovKarazin/blockchain-analytics-lab; branch: paper/monitoring-jss.
Starting HEAD: bb80caac70f8a289e719ec5b88dafa3767c1ef79.
Companion dependency unchanged: dc1ba8876f3f163c27c48f3a39292fc47f71bf18.

## Completed

- Reviewed the supplied plan and handoff, M1/M2 source, stored summaries,
  data indexes, dependency and actual historical manifests (`source_audit.json`).
- Added the draft operational contract, machine-readable schemas, a causal
  finalized-header replay core, acquisition/runner and verification scripts.
- Downloaded the indexed Ethereum block-header partition for 2024-03-04;
  checked 7,167 blocks and 7,166 parent links. Selected the busiest hour, 17 UTC,
  by input workload only: 300 blocks from the same day.
- Executed 12 small cells: two periods, two virtual arrival schedules, three
  independent worker repetitions. No model training or full research grid.
- Passed 14 unit tests, 8 real-input QA checks and schema validation of all
  44,802 final-run decisions. Independent reviewer recomputed FIFO queues,
  counts and budgets from logs. All 24 final compressed logs match saved hashes.
- Assembled three incident candidates and probed real BSC RPC availability.
  No candidate yet passes independent-test eligibility.

## Accepted evidence

Use `runs/pilot_20261025T081404_015172Z/` and `qa/verify_20261025T081539_946082Z/verification.json`.
See `SESSION_REPORT.md` for the measured results, interpretation and commands.
Per-record logs and raw data are retained privately; Git contains code, source
snapshots, aggregate results and verification hashes.

The earlier run `pilot_20261025T081159_554384Z` is **quarantined/superseded**:
independent validation found one truncated compressed decision log with a hash
mismatch. Its original bytes/metadata are preserved, its integrity audit records
failure, and none of its timing results are used in the session report. The cause
of the truncation is not established. The accepted run independently passes the
same integrity checks. An initial runtime success flag is not sufficient evidence.

## Work packages

| Package | Actual state | Remaining |
|---|---|---|
| P2.01 | Header event/decision schema and causal replay verified | Receipts/logs/traces; cross-chain availability and watermark |
| P2.02 | Fixed rule, causal cooldown, hard notification admission | Calibration, model-compatible fallback, temporal retraining, label queue |
| P2.03 | Three candidates; one BSC attack receipt actually obtained | Prior-exposure audit, full attack labels, 30–60-day continuous populations |
| P2.04 | Measured local header stages, RAM/disk; modeled FIFO queues | Real data-extraction pipeline and live/finality timing scope |
| P2.05 | Duplicate/late/orderly snapshot continuation verified | Durable outbox, crash injection, delivery and recovery timing |
| P2.06 | Reproducible exploratory pilot report | Independent scientific comparisons, uncertainty and transferable result |

## Next executable task

Audit prior exposure of Euler, Beanstalk and BSC Token Hub across the book and K4.
For the first eligible mechanism, fix historical contracts/ABI/event population
and test receipt/log availability for one full day before committing to a 45-day
window. Keep label adjudication separate from detector settings. Build the new
Elliptic label-availability queue and temporal calibration only after its phase
convention is fixed. Article 1/book priorities remain unchanged.
