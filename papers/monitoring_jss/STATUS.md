# Article 2 status — 25 October 2026

**Stages 3–5 are published. Phase 6 completes bounded Revest metadata,
historical-source and source-listing checks. No new independent attack case
is admitted.** Latest report: [SESSION_6_REPORT_RU.md](SESSION_6_REPORT_RU.md).
Protocol: `protocol.json` v0.7, still draft for the full scientific comparison.

Repository: KuznetsovKarazin/blockchain-analytics-lab, branch paper/monitoring-jss.
Companion pin unchanged: dc1ba8876f3f163c27c48f3a39292fc47f71bf18.
Book source/results and scripts/run_all.sh are untouched.

## Current findings

- Exact old/current K4 metadata loaders both omit the targeted pinned Revest
  fixture in both modes: the required literal `flash` is absent. The S2 row
  establishes scoped historical L1 catalogue exposure. This does not establish
  actual K4 contamination, global non-exposure or a blind test.
- A historical SDK registry differs from current documentation. Source-level
  registry setters can change bindings without dedicated mapping-change events.
  Historical creation, deployed-code equivalence and routing intervals remain
  unverified; a complete protocol population is not yet established.
- The proposed 30-day window [2022-02-26,2022-03-28) has 60 complete nonempty daily
  source listings, one object per logs/blocks day. Only 40,620 XML bytes were received;
  listed payload size 6,404,872,951 bytes was not downloaded. This is metadata
  availability, not data completeness. Independent listing audit PASS.
- Metadata audit, twelve eligibility gates and deployment review:
  `incidents/phase6_revest/`. Frozen listing protocol, code, 5 tests + 11 subtests and
  actual independent verification: `incidents/source_availability_phase6/`.
  No new candidate event payload, detector scores, fitted rule or positive-label
  join. Revest remains `candidate_not_eligible`.

## Accepted work from previous stages

| Evidence | Main result | Scientific scope |
|---|---|---|
| Header and Euler event pilots | Ordered ingestion, prefix/duplicate/restart checks | Bounded feasibility; no independent attack evaluation |
| Elliptic direct18 actual estimator study | 10 cells, 100 fits, 675040 decisions; fixed LGBM 73 known TP versus adaptive 42/46/52/68 at 328 notifications | One seed; supplied globally normalized features; already studied steps; all 150 batch thresholds nonbinding |
| Euler and Beanstalk joins | Zero emitted notifications within reported exploit executions under studied settings | Two development diagnostics; executions/policy cells are not independent incidents |
| Continuous two-emitter budget study | 30 days, 18 cells, 435240 decisions; no cap exceedance | Incident-conditioned window; workload coverage is not detection quality |
| Local process-crash recovery | 12 actual terminations plus 3 baselines; 5 unique effects under specified idempotent SQLite sink | Conditional local reliability, not arbitrary-network exactly-once |
| Resource measurement | Two 54-worker series, 150 modeled queues each; repeat median loop throughput about 11–12k events/s | Shared host/warm cache descriptive measurements, not live throughput or latency |
| State growth | seen/order_keys each N; full greedy state 4,506,512 and 6,692,443 bytes | Notification cap does not bound retained identities or all processing |

The resource initial series is valid with known concurrent audit activity and
was retained alongside an identical technical repeat; it is not a corrupt or
excluded run. Full production suite at phase 5: 165 tests + 92 subtests. Phase 6 changes
no measured decoder/policy/resource source. See SESSION_3/4/5_REPORT_RU.md and
result_ledger.json for exact runs, counts, evidence and limitations.

Excluded original header, durability and budget-comparison attempts remain
preserved with unchanged failure records. Their corruption causes are unknown.
Do not repair expected hashes or substitute them for accepted sealed retries.

## Publication and evidence

Stages 3–5 were published as 09fa5825b4e27dc35e1d43b2f46e14ba1fa13a02,
parent 23129bdcff24508bb690a6747c3c4900d8ae8dbd. Its tree
3ef6b10f4ae3674cefa2e5025db648d6c4736717 exactly equals local snapshot 1fedf551.
The API snapshot commit and preserved local ancestry have different commit IDs.
The lease-protected non-force update and fresh ref/tree fetch passed. The prior
publication rejection was resolved by the user's explicit content/destination
permission. See qa/publication_success_20261025_phase6.json; old rejection
receipts and old reports describe their historical state, not a current block.

Git contains owned code, configs, aggregate results and provenance. Raw datasets,
models and per-record evidence are in previously saved private packages. Thirty
phase4 source archives are durable; reclaimed local ZIP caches are not missing
acquisitions. The phase6 package adds metadata evidence and retrieval instructions,
not the full third-party PoC or older large experiment archives.

## Remaining work

Resolve historical deployment/registry provenance; design semantic features on
declared development cases; freeze the candidate frame, population, windows,
methods and exclusion/stopping rules before acquiring evaluation-stream payloads.
Historical creation/state evidence can be gathered separately as provenance.
Revest alone does not meet 2–4 incidents across at least 2 families. Euler/Beanstalk
cannot become untouched tests after their outcomes have informed development.
BSC remains reserved pending complete chain data and positive-transaction evidence.
Unknown alerts are not negatives; false-alarm estimation needs adjudication.

Full scientific comparisons, controlled live/remote measurements and justified
uncertainty remain open. Keep the agreed priority of Article 1 and the book.
No manuscript submission, release or external correspondence is authorized here.
