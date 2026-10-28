# Article 2 status — 28 October 2026

**Phase16 is complete: two fixed external cases, independently checked decisions,
and bounded post-decision reference adjudication.** The current entrypoint is
[Phase16 results and public evidence](phase16/README.md). The primary semantic
method's previously observed development advantage was not reproduced in these
external cases.

At an offered daily budget of five notifications, all three policies yield
Li.Fi count 1/1 versus semantic 0/1, and Revest 0/2 for both methods. Realized
30-day notification loads are 1 versus 0 for Li.Fi and 2 versus 0 for Revest.
Both denominators are verified known subsets. No-hit cells do not establish a
complete incident miss. All three semantic references fail the minimum-history
gate; token histories have zero or one earlier positive observation within the
UTC day, below the required 19.

The [full results](phase16/manuscript/EXTERNAL_CASE_RESULTS.md) retain all policies,
budgets and sensitivity thresholds. The operational code and
[public evidence package](phase16/public_evidence/README.md) support inspection
and offline verification from the selected observations and sealed decisions.
Fresh raw-source replication still requires the separate accepted source bodies
and original whole objects. Original frozen code and scientific parameters are
unchanged; portability is handled by a separate hash-checking path map.

The cohort contains two incident families over 60 case-days and 37 calendar
dates. The 12,798 decision rows and 1,620 daily cells do not increase the number
of independent incidents. The scientific result is a measured applicability
limit of the daily-reset semantic configuration, not evidence of general
superiority, precision/FPR or live protection. A warm-start comparison and
validation on additional incidents remain future work under a separate protocol.

Repository: KuznetsovKarazin/blockchain-analytics-lab, branch paper/monitoring-jss.
Companion pin remains dc1ba8876f3f163c27c48f3a39292fc47f71bf18.

## Historical Phase7 status — 26 October 2026

The following record describes the earlier stage and is retained for context;
its candidate dispositions and remaining-work list are not the current Phase16
status.

**Phase 7 adds Revest creation/initial-binding provenance and a frozen
ten-transaction Euler development sample for source-bound Transfer observations.
No new independent attack case is admitted.** Latest report:
[SESSION_7_REPORT_RU.md](SESSION_7_REPORT_RU.md).
Protocol: `protocol.json` v0.8, still draft for the full scientific comparison.

Repository: KuznetsovKarazin/blockchain-analytics-lab, branch paper/monitoring-jss.
Companion pin unchanged: dc1ba8876f3f163c27c48f3a39292fc47f71bf18.
Book source/results and scripts/run_all.sh are untouched.

### Current findings

- Revest: five successful creations on 24 September 2021 and registry
  initialization at block 13290609 link four historical components at explorer
  evidence level. Twenty direct registry transactions are enumerated, but internal
  calls, mutable component pointers and continuous window activation remain
  unresolved. Review and independent PASS receipt: `incidents/phase7_revest/`.
- Exact old/current K4 metadata loaders still omit the pinned Revest fixture
  because literal `flash` is absent. Scoped catalogue exposure and incidental
  phase 7 search-snippet exposure are disclosed; global blindness is not claimed.
- Proposed Revest window [2022-02-26,2022-03-28) retains 60 complete source
  listings and 6,404,872,951 listed payload bytes, not an acquired evaluation
  stream or frozen scientific cohort. Revest remains `candidate_not_eligible`.
- The new pure observation boundary checks original metadata and every provider
  log page, distinguishes ERC20/721-shaped events, and computes separate per-token
  raw integer flow strings. Thirty offline tests and an independent arithmetic
  oracle over 100 synthetic bundles / 2,020 logs passed before acquisition.
- First ten transactions in the previously accepted Euler-core stream on
  1 March 2023 were frozen before requests. All ten produced accepted observations
  in 21 calls: 192 provider logs, all 58 archived core payloads matched, 84
  ERC20-shaped events, 16 involving the monitored core. No retries/replacements.
  Independent actual-response/flow audit PASS: `qa/phase7_transfer_actual_independent_review.json`.
  Core-emitter logs contain zero ERC20-shaped events; the 16 come from other
  emitters across 11 tokens. This demonstrates source scope, not detection quality.
  Pagination exhaustion is not independent full-receipt completeness; event sums
  are not proven balance changes. No detector, labels, thresholds or policy change.

### Accepted work from previous stages

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
excluded run. Full production suite at phase 5: 165 tests + 92 subtests. Phases 6–7 change
no existing measured decoder/policy/resource source. The old suite was not rerun
in phase 7; the new standalone adapter and its acquisition code have separate
tests. See SESSION_3/4/5_REPORT_RU.md and
result_ledger.json for exact runs, counts, evidence and limitations.

Excluded original header, durability and budget-comparison attempts remain
preserved with unchanged failure records. Their corruption causes are unknown.
Do not repair expected hashes or substitute them for accepted sealed retries.

### Publication and evidence

Stages 3–5 were published as 09fa5825b4e27dc35e1d43b2f46e14ba1fa13a02,
parent 23129bdcff24508bb690a6747c3c4900d8ae8dbd. Its tree
3ef6b10f4ae3674cefa2e5025db648d6c4736717 exactly equals local snapshot 1fedf551.
The API snapshot commit and preserved local ancestry have different commit IDs.
The lease-protected non-force update and fresh ref/tree fetch passed. The prior
publication rejection was resolved by the user's explicit content/destination
permission. See qa/publication_success_20261025_phase6.json; old rejection
receipts and old reports describe their historical state, not a current block.

Phase 6 is published as ef6271631e14c5c1d5afb14d98f3cfa5d8c5389e,
tree b8efd0a8b383987a2d76f80bb58a97170257d7ad; phase 7 starts from that
freshly restored remote head.

Git contains owned code, configs, aggregate results and provenance. Raw datasets,
models and per-record evidence are in previously saved private packages. Thirty
phase4 source archives are durable; reclaimed local ZIP caches are not missing
acquisitions. The phase6 package adds metadata evidence and retrieval instructions,
not the full third-party PoC or older large experiment archives.

### Remaining work

Resolve continuous historical registry/component routing and independent runtime
provenance; develop semantic rules only on declared development cases; freeze
the candidate frame, population, windows,
methods and exclusion/stopping rules before acquiring evaluation-stream payloads.
Historical creation/state evidence can be gathered separately as provenance.
Revest alone does not meet 2–4 incidents across at least 2 families. Euler/Beanstalk
cannot become untouched tests after their outcomes have informed development.
BSC remains reserved pending complete chain data and positive-transaction evidence.
Unknown alerts are not negatives; false-alarm estimation needs adjudication.

Full scientific comparisons, controlled live/remote measurements and justified
uncertainty remain open. Keep the agreed priority of Article 1 and the book.
No manuscript submission, release or external correspondence is authorized here.
