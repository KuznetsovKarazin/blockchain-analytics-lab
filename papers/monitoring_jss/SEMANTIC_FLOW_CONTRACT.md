# Causal positive outflow rank rule

26 October 2026. This contract defines a development baseline on validated
transaction observations. It asks whether one token's current gross external
outflow is unusually large relative to that token's preceding positive outflows.
It does not classify attacks, estimate balances or economic losses, or establish
a new independent incident result. The frozen study must preserve every declared
configuration, cold-start observation and failed source attempt.

## Observation and source boundary

The new study consumes `archive_transfer_observation_v1` records produced from
all-emitter daily archive logs for the predeclared selected transactions.
Each record must contain actual `dataset_execution_status=1`, checked against
the archive's transaction metadata, and `status=observed_success`. Logs alone
must not be presented as a receipt or used to invent execution status.

The transaction fields are chain ID, block number/hash, transaction hash/index
and exact integer `event_time_ns`. `population_addresses`, `counts`,
`token_flows` and `raw_amount_encoding=base10_integer_string` follow the
phase 7 transfer-observation contract. `archived_core_log_count` records the
matching core-emitter subset for the count control. Its value is nonnegative
and cannot exceed the transaction's total archive log count.

Required archive evidence uses tier
`enumerated_daily_partition_and_transaction_metadata_checked`, with an external
`source_audit_manifest_sha256` and `selection_manifest_sha256`. Raw RPC receipt,
receipt-root verification, independent full-chain completeness, historical ABI
equivalence and token-standard compliance remain false. Historical
`observed_time` remains null. The source audit must establish the selected
transaction population, complete enumerated partition scan, exact core subset,
header/status joins and observation membership before accepted replay.

The pure monitor is constructed with the expected audited source-manifest digest
and a nonempty `source_scope` description. Every `observe` call supplies the
expected canonical observation SHA-256 from the separately retained observation
manifest. Source digests anchor the retained bytes; their presence does not prove
provider truth or audit correctness. The replay controller and independent audit
remain responsible for reading those manifests and verifying their membership.
The monitor independently checks the digest, chain/population, status, counts,
unique sorted token rows and all raw flow arithmetic.

Legacy `transfer_observation_v1` records from phase 7 are accepted for compatibility
tests under their distinct provider-pagination tier. A single monitor cannot mix
the archive and provider schemas. This does not retroactively change the phase 7
contract or its immutable results.

## Fixed rule and configurations

For token emitter a in transaction t, let x be its sum of **gross external-out**
amounts in that complete observation, in raw token units. Consider only x>0.
Maintain the last W=128 strictly preceding positive x values for that same token,
chain and fixed monitored population. If there are n retained values, compute

`tail_rank = (1 + number of retained values greater than or equal to x) / (n + 1)`.

The numerator and denominator are retained as exact integers; comparisons use
cross multiplication. No floating-point approximation or cross-token raw sum is
used. Ties are conservative because equal past values count in the numerator.
The current value is scored first and appended only after the entire transaction
has passed validation and all token scores have been calculated.

| Parameter | Fixed value for this bounded study |
|---|---|
| History window | Last 128 positive external-out observations per token |
| Minimum preceding history | 19 positive observations per token |
| Primary raw-trigger threshold | `tail_rank <= 1/20` |
| Descriptive sensitivity | `tail_rank <= 1/10`, retained separately |
| Grouping interval | 300 seconds of replay event time |
| Maximum stored tokens | 4,096; exceeding capacity halts replay |

The first 19 positive observations for a token are explicitly cold start, not
scored negatives. A valid observation with no positive external outflow still
advances the transaction watermark but adds no reference value. Zero amounts,
incoming-only flows, internal transfers and zero-address mint/burn patterns do
not enter this positive-outflow reference. Report cold-start and eligible-token
coverage; do not silently remove cold-start transactions from result denominators.

Each token is evaluated separately. A transaction triggers when any eligible
token meets the threshold, with all triggering token addresses and exact ranks
retained. The number of tested and eligible tokens is reported. The minimum rank
across many token tests is not a transaction false-alarm probability. The two
thresholds are predeclared configurations, not a choice of the better result
after inspection.

The tail fraction is a descriptive empirical rank, **not a calibrated p-value**.
No exchangeability, stationarity or false-positive-rate guarantee is established
for these dependent historical transactions. The window is counted in positive
observations, so its elapsed time differs by token; each score retains the oldest
and newest reference event times. Updating the reference with every valid
positive value can absorb a sustained change or adversarial contamination. No
robustness against that effect is claimed. Large gross outflow can coexist with
equal same-transaction incoming flow, so incoming/net context is retained and a
trigger must not be called a drain.

## Candidate grouping before budget admission

All token signals in a transaction form one raw trigger. A raw trigger becomes
an upstream group candidate if there is no earlier candidate or at least 300
seconds have elapsed since the last candidate. At exactly 300 seconds, it is
eligible. Suppressed triggers do not move the anchor. A candidate moves the
anchor **before and independently of any downstream budget decision**.

Every budget policy receives the same closed candidate sequence for a given
detector configuration. Budget rejection cannot alter scores, references or
future candidate grouping. A budget-rejected candidate can still suppress later
raw triggers within its grouping interval; this is an explicit cost of the fixed
grouping definition. It differs from the historical phase 4 grouping anchored on
actually emitted notifications, so phase 4 output counts are not an unchanged
baseline for this new comparison. The count control must use the new declared
grouping and observation timing too.

The monitor emits no notification and contains no budget policy. Reference
updates occur for every valid positive token observation, including cold-start,
nontriggering, grouped and subsequently budget-rejected observations.

## Ordering, missing data and bounded state

Input transactions must increase strictly in `(block_number, transaction_index)`;
event time cannot decrease. Transactions within one block must have the same
block hash and timestamp. Duplicates, conflicting context, invalid amounts,
unknown status, unavailable source observations and capacity overflow raise
`SemanticFlowError` without changing any monitor state. The accepted replay
must halt on such a failure, retain the failure, and never skip it as zero flow.
Structural ordering alone cannot detect an entirely absent transaction; complete
selection/coverage is a required source-audit check outside this pure component.

Only the current order watermark is retained, not an unbounded set of all prior
transaction IDs. Canonical uniqueness and source identity are checked by the
upstream selection/audit; this component does not promise global identity conflict
detection for fabricated old hashes reused at later positions. Replaying an old
position is rejected, rather than accepted as an idempotent redelivery.

At most 4,096 token histories contain at most 128 records each. Each record stores
the amount string, time/order and observation digest. No token eviction occurs.
This is a bound on retained records, not an exact RAM bound: Python object size,
integer/string length and cumulative counter representation also matter. The
decision records report the number of tokens and history records retained.

## Interface and restart

`SemanticFlowMonitor(config, *, source_audit_sha256, source_scope)` accepts a
plain dict with exactly these keys: `schema_version=semantic_flow_monitor_config_v1`,
`chain_id`, sorted unique `population_addresses`, `history_size`, `min_history`,
`threshold_numerator`, `threshold_denominator`, `grouping_ns`, and `max_tokens`.

`observe(observation, *, expected_observation_sha256)` returns a
`semantic_flow_decision_v1` object: transaction identity, source/config digests,
per-token ranks and reference counts/times, positive/eligible/cold-start token
counts, triggering tokens, `raw_trigger`, `group_candidate`, grouping reason,
the preceding candidate anchor and retained-state counts. Raw amounts remain
decimal strings. `historical_observed_time` is null.

The shared pure `validate_observation(observation, *, expected_observation_sha256,
config, source_audit_sha256, source_scope)` validates the same source envelope
for the count control without updating a semantic monitor.

`snapshot()` returns detached JSON-safe state. Restore with
`SemanticFlowMonitor.from_snapshot(snapshot, *, expected_snapshot_sha256)`.
The snapshot binds configuration, audited source identity/scope, observation
schema, reference values and their provenance, order watermark and grouping
anchor. Restoration verifies the external digest and structural consistency;
it is not proof that arbitrary self-authored history happened. The enclosing run
must additionally bind executable source hashes and the accepted snapshot bytes.
Checkpoint/restart equivalence here is deterministic local state equivalence,
not a new durable-delivery or arbitrary-network exactly-once guarantee.

## Offline validation

Run `python3 papers/monitoring_jss/tests/test_semantic_flow_monitor.py`.
The 23 tests cover warmup and threshold boundaries, conservative ties,
strictly-past sliding references, grouping independent of downstream decisions,
token separation, gross/net distinction, omitted zero-only references, exact
large integers, future-prefix invariance, checkpoint/restart parity, detached
outputs/configuration, invalid source/status/arithmetic, atomic multi-token
failure, capacity, duplicate/time/block conflicts and checkpoint context checks.
These are synthetic implementation tests; actual development replay and its
independent oracle are separate retained evidence.
