# Article 2 status — 25 October 2026

**Phase 5 local resource measurement is complete and independently verified:
30 timing workers, 24 fresh-prefix memory probes and 150 modeled FIFO scenarios
per series. A fully identical technical repeat followed a documented concurrent
audit in the original series; both remain preserved. Independent incident
validation and the full scientific comparison remain incomplete.**

Repository: KuznetsovKarazin/blockchain-analytics-lab; branch: paper/monitoring-jss.
Companion pin unchanged: dc1ba8876f3f163c27c48f3a39292fc47f71bf18.
Historical book scripts/results are unchanged. Current report:
[SESSION_5_REPORT_RU.md](SESSION_5_REPORT_RU.md). Prior continuous-window report:
[SESSION_4_REPORT_RU.md](SESSION_4_REPORT_RU.md). Previous stage:
[SESSION_3_REPORT_RU.md](SESSION_3_REPORT_RU.md).

## New findings

- Resource repeat `resource_20261025T135508_936231Z`: all 725,400 decisions equal
  the accepted phase4 B5 semantics; all 24 prefix states independently reconstructed.
  The five-run median instrumented-loop throughput is about 11.1–12.1k records/s;
  per-run p95 service medians span166–199microseconds across the six cells.
- B5 bounds notifications, not processing volume or retained identities. Every
  accepted event adds one seen and one order-key entry. Full greedy checkpoints
  are4,506,512bytes (Euler) and6,692,443bytes (Beanstalk); memory is not indefinitely bounded.
- Queue results are lossless finite-trace simulations, not historical/live latency.
  RSS is a whole-process OS estimate sampled before checkpoint serialization.
- Initial resource series is semantically valid but has known concurrent reference
  audit activity; identical sources/jobs were fully repeated with known local tasks held.
  Shared-platform interference remains uncontrolled; no causal policy-speed superiority.
- Full suite:165tests+92subtests. Both sealed runs and150scenarios per run independently PASS.
- Renewed Git publication was blocked by automatic risk review on content/destination
  authorization. No commit/ref update; remote remains23129bd. Local history retained in bundle.


- A shared continuous window, March19–April17 2022, contains 19,425 Euler core
  and 28,935 Beanstalk Diamond logs. All 30 source partitions and 192,391
  consecutive headers were independently verified. This is an incident-conditioned
  window, not random background or an independent attack test.
- Eighteen cells compare greedy, paced cumulative and token-bucket admission
  at daily caps 1/5/20. All 435,240 decisions, 540 daily and 12,960 hourly
  aggregates match an independent oracle; no hard-cap exceedances.
- At cap five, Euler notifications are 119/105/71 and Beanstalk 49/47/42.
  Paced admission covers more raw-trigger-active hours here, but this is a
  workload metric and does not establish better attack detection.
- All nine Beanstalk cells issue zero notifications on the six logs of the
  reported exploit execution. Three raw triggers are rejected by the hard daily
  cap, unreleased quota or unavailable token. Unused daily allowance does not
  guarantee immediate admission. This L2 case is now a development diagnostic.
- The first comparison run failed final integrity checks on five decision gzip
  files and is excluded. A retry using identical computation in isolated staging
  was sealed before export and passed independent integrity and semantic checks.
  The corruption cause remains unknown.
- Current full suite: 146 tests and 73 subtests pass. Pre-execution independent
  checks cover 390,888 synthetic decisions and 744 checkpoint continuations.

- Elliptic: 10 cells, 100 fitted estimators and 675,040 decisions on a declared
  direct18 subset. At 328 notifications per cell, fixed LightGBM found 73 known
  positives; retraining at delays 0/1/2/4 found 42/46/52/68. All 150 batches filled
  the cap, so this result reflects ranking and does not demonstrate a threshold-
  calibration benefit. Most LightGBM alerts have unknown labels.
- Primary-source review found future address history within the purported local
  Elliptic features. The reduced subset is still a retrospective supplied-feature
  benchmark with global normalization/dependence caveats, not an online repair.
- Euler March13: unchanged workload rule used all five daily notifications before
  the first of six reported exploit executions. Their 196 raw triggers were all
  budget-suppressed. These six executions comprise one L2 incident; after viewing
  this outcome, Euler is a development diagnostic, not a future untouched test.
- Process crashes: 12 actual terminations and resumes plus three uninterrupted
  cells recover identical 1,247 decisions and five unique local sink effects.
  After sink commit/before ack, six delivery attempts produce five effects under
  the specified idempotent sink contract. No general network exactly-once claim.
- Full test suite: 82 passed and 39 subtests passed. Independent checks include
  actual models/scores, fitting/calibration cohorts, compressed logs, SQLite
  states, preserved crash snapshots and sealed evidence archives.

## Evidence status

| Evidence | Run | Status |
|---|---|---|
| Header pilot | pilot_20261025T081404_015172Z | accepted |
| Original header attempt | pilot_20261025T081159_554384Z | excluded: truncated gzip |
| Euler March1 acquisition/replay | protocol_logs_20261025T083346_282558Z / event_logs_20261025T084327_927529Z | accepted |
| Elliptic acquisition | elliptic_data_20261025T090822_439609Z | accepted original v1 |
| Elliptic actual-model experiment | elliptic_prequential_20261025T091655_598646Z | accepted, exploratory |
| Euler March13 acquisition/replay | protocol_logs_20261025T091457_496507Z / event_logs_attack_20261025T092349_917377Z | accepted, descriptive |
| First durability attempt | durable_20261025T090940_001269Z | excluded: changed/corrupt DB artifacts and stale sidecars |
| Replacement durability experiment | durable_20261025T092104_711695Z | accepted after independent sealed-archive verification |
| Continuous 30-day acquisition | protocol_window_20261025T123312_675327Z | accepted; both selected emitters |
| First allocation comparison | budget_policy_20261025T124444_450736Z | excluded: five changed/truncated gzip artifacts |
| Sealed allocation retry | budget_policy_20261025T125143_314640Z | accepted; identical code/config/inputs |
| Beanstalk post-decision label join | budget_policy_label_join_20261025T125414_524570Z | accepted, one L2 diagnostic only |

All paths are under `runs/`. All excluded attempts retain original reports and
observed bytes. Their causes are unestablished; their timing results are not
used as accepted evidence. Hardening the artifact handoff is not presented as
proof of the original corruption cause.

Raw datasets, exact cohorts, models, decisions and database evidence are retained
privately. Git contains code, frozen configs/source snapshots, aggregate results
and hashes. Source distribution terms are not inferred from a code license.

## Remaining work

| Package | Completed bounded work | Still required for broader claims |
|---|---|---|
| P2.01 | Header/core-log ingestion, order, provenance | Semantic ABI/deployment evidence, receipts/traces and cross-chain availability where needed |
| P2.02 | Actual fit/calibrate/release experiment; 18-cell causal budget allocation | Wider predeclared model comparisons; distinguish threshold, ranking and admission effects |
| P2.03 | Exposure/label audit; complete 30-day two-emitter population and one-day diagnostics | Independent eligible cases, additional windows and adjudication of unknown alerts |
| P2.04 | Extraction, prepared-feature modeling, local replay and persistence measurements | Controlled performance study, live/finality scope and more workloads |
| P2.05 | Real local process crashes with conditional idempotent sink | Other fault positions, remote delivery, kernel/power-loss only if claimed |
| P2.06 | Reproducible negative findings; learned-model and continuous-window tables/figures | Independent scientific comparisons and justified uncertainty |

Next, obtain eligible independent cases and label evidence, define semantic
features before their outcomes, and separate workload coverage from incident
quality. Do not tune on Euler or Beanstalk and reuse them as untouched tests.
Already studied Elliptic steps remain exploratory. Article 1 and the book retain
their agreed priority; submission and correspondence are not authorized here.

The prior GitHub publication was rejected without a reason. The last verified
remote head is 23129bdcff24508bb690a6747c3c4900d8ae8dbd; later work is local and
preserved in portable evidence bundles. Thirty source archives were durably saved
and verified local cache copies reclaimed; their exact location/SHA index is
retained privately. Do not interpret absent local source ZIPs as failed acquisition.
