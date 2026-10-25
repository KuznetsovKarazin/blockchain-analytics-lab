# Article 2: first working session

25 October 2026 · Oleksandr Kuznetsov

The operational contract and real-header feasibility pilot are implemented.
The accepted run is `pilot_20261025T081404_015172Z`. It establishes correctness
and local processing feasibility within the bounded header-only scope; it does
not establish attack-detection accuracy or a publishable engineering finding.

## What changed

The paper branch now contains causal event and decision schemas, a fixed-rule
monitor, explicit grouping and hard-budget admission, data acquisition,
measured-stage replay with virtual FIFO schedules, a full source snapshot,
checksums and independent verification. Historical scripts, results and the
companion dependency were preserved.

The input is the complete indexed Ethereum header partition for 4 March 2024:
7,167 records with consecutive numbers, unique hashes, strictly increasing times
and 7,166 verified parent links. The selected intensive hour, 17 UTC, contains
300 of these blocks. It is a workload slice, not another independent case.

The rule is transaction_count > 300, with a 300-second event-time cooldown
anchored on the last emitted notification, and five notifications per playback
UTC day. This arbitrary fixed rule exercises the implementation; it is not a
validated security detector. Grouped and budget-rejected signals do not extend
the cooldown. Historical observation times remain unknown.

## Measurements

Each row below summarizes three separate worker repetitions. Ranges describe
measurement variation, not confidence intervals across independent incidents.
Time is measured locally; queue waits use a virtual schedule and are not
historically observed. No 24-hour wall-clock experiment was conducted.

| Period | Playback speed | Events / raw triggers / notifications | Local loop, s | p99 local service, ms | Peak RSS, MB | Max virtual queue wait, s |
|---|---:|---:|---:|---:|---:|---:|
| intensive_hour | 1 | 300 / 25 / 5 | 0.011–0.017 | 0.252–0.361 | 20.6–20.6 | 0.000–0.000 |
| intensive_hour | 1,000,000 | 300 / 25 / 5 | 0.013–0.016 | 0.281–0.343 | 20.6–20.6 | 0.009–0.011 |
| ordinary_day | 1 | 7,167 / 438 / 5 | 0.306–0.333 | 0.336–0.384 | 28.3–28.6 | 0.000–0.000 |
| ordinary_day | 1,000,000 | 7,167 / 438 / 5 | 0.282–0.346 | 0.282–0.395 | 28.7–28.8 | 0.190–0.252 |

All cells respected the budget, and semantic decisions were identical across
speeds and repeats. Full-day p99 service time was below 0.4 ms in this machine
and scope. These values exclude receipts, traces, RPC, consensus confirmation,
durable delivery and reaction. The fastest schedule compresses one historical
day to about 0.086 seconds; queue growth under this artificial input schedule
is an engineering stress check, not an estimate of production congestion.
The queue is calculated algebraically: RSS does not include a materialized
arrival buffer. It includes interpreter, state and timing buffers up to the end
of replay, before summary aggregation.

The final raw source download took 4.55 s and Parquet decoding/normalization
0.40 s. These are separate one-off preparation measurements with uncontrolled
network/cache conditions, not per-event or historical RPC latency. Download size
was 6,206,807 bytes. The final run occupies about 9.81 MB including its full
logs and source snapshot before packaging. Local disk artifacts are not the
same as peak RAM.

## Verification

- 14 unit tests passed.
- Eight checks using the real 7,167-block input passed: prefix invariance,
  label irrelevance for this fixed rule, 57 duplicate deliveries, deterministic
  snapshot continuation, one late-delivery injection, budget, unknown observation
  times and final-run schema validation.
- All 44,802 persisted decisions validate against the captured JSON Schema.
- A separate implementation recomputed FIFO queue lengths and timing recurrence.
- All 24 final gzip logs fully decompress and match their stored SHA-256 values.
- Executed source files and configuration match the run's captured snapshot.
  The acquisition command is preserved retrospectively from the execution
  journal in supplementary_provenance_audit.json; it was not part of the
  original input manifest.

Snapshot continuation is not arbitrary-crash exactly-once delivery. An atomic
outbox or idempotent external sink and crash-injection tests remain necessary
before such a claim. Fixed-rule label invariance does not test learned adaptation.

The earlier run `pilot_20261025T081159_554384Z` is quarantined: one compressed
log was truncated and failed its saved checksum. Its original bytes and failure
audit are preserved. The cause is unknown; no result in this report uses that
run. The final run passed independent integrity checks of every log.

## Historical corrections and external evidence

The M1 total includes warm-up; evaluation is 7,605,805 blocks over 1,065 days.
M2's old delay formula does not support setting DELAY=0, and retraining uses
in-sample calibration. Its budget precision 255/258 is conditional on labelled
alerts, while 418 additional budget alerts have unknown labels. These facts are
recorded in source_audit.json; historical numbers were not overwritten.

The candidate register contains Euler, Beanstalk and BSC Token Hub, with **zero
eligible independent test cases so far**. A real BSC attack receipt, transaction
and block were obtained. That endpoint rejected the tested log request and lacked
state for historical tracing. Complete 45-day histories, exact populations,
label checks and prior-use checks remain open. Source reports are linked in the
registry; candidate status does not establish new independent evidence.

XChainWatcher already evaluates fact extraction, including extra RPC/tracing,
and model execution. BridgeGuard WWW 2025 evaluates execution-graph detection.
Our candidate contribution concerns jointly controlled availability, notification
budgets, delayed feedback and reliability. Its novelty and value must still be
established empirically, beyond this pilot. See the related-work note.

## Reproduce

From the repository root, using Python 3.12:

```bash
python -m pip install pyarrow==26.0.0 pytest==9.1.1 jsonschema==4.26.0
python papers/monitoring_jss/fetch_pilot.py --out data/raw/monitoring_jss/2024-03-04_parent_checked
python papers/monitoring_jss/run_pilot.py --inputs data/raw/monitoring_jss/2024-03-04_parent_checked
python -m pytest -q papers/monitoring_jss/tests
python papers/monitoring_jss/verify_pilot.py --input data/raw/monitoring_jss/2024-03-04_parent_checked/ordinary_day.jsonl --run papers/monitoring_jss/runs/<new_run_id>
python papers/monitoring_jss/make_pilot_table.py papers/monitoring_jss/runs/<new_run_id>
```

The runner assigns a unique directory and refuses overwrites. Timing will vary
across machines. Raw inputs and per-record logs are private evidence; the Git
branch contains acquisition code, full source snapshots, hashes, summaries and
QA records. No new paper release, DOI or submission was made.

## Next executable step

Check prior use of the three candidate incidents across K4 and the book, then
fix the first eligible protocol's historical contracts/ABI/event population.
Acquire one full day of receipts/logs and verify completeness before committing
to a continuous 45-day corpus. In parallel, specify the Elliptic label-release
queue and model-specific temporal calibration; the full comparison grid remains
unexecuted. Article 1 and book priorities are unchanged.
