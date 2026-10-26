# Transaction final semantic flow development comparison

26 October 2026. This bounded experiment compares three methods on two already
exposed Euler development days. It is a deterministic functional comparison,
not an independent attack evaluation. All methods, source expansion, thresholds,
grouping, policy formulas and stopping rules must be frozen before acquiring
the new archive payload or inspecting semantic outcomes.

## Population and observation boundary

Use all 218 transactions in the previously accepted 1 March 2023 Euler core
stream (1,247 core logs) and all 676 transactions in the accepted 13 March 2023
stream (3,283 core logs). For these fixed transaction identities, collect every
matching log from the complete enumerated daily archive object, with projected
transaction execution metadata and matching block headers. The source adapter
checks every archived core payload exactly and retains original source objects.
This establishes consistency within enumerated dataset objects, not independent
receipt-root completeness or the absence of omissions by the dataset provider.

The input is one successful, source-validated transaction observation with
`archived_core_log_count`, exact identity/order/time, shape counts and separate
per-token integer event-flow aggregates. An observation manifest binds every
JSONL byte and row digest, plus the actual source-audit manifest. Its digest is
supplied externally to the runner before execution. Missing or unavailable
observations are failures; they never become zero flows or excluded rows.

All comparison arms receive the same complete transaction bundle and make one
decision at its end. The replay clock uses the exact historical block timestamp
and canonical transaction order. Actual historical observation and feature-ready
times remain unknown. Notification time is logical event time, not measured
network latency, and a post-transaction observation cannot prevent that atomic
transaction. Records sharing a block timestamp remain ordered by transaction
index without invented subsecond times.

Each day starts from empty history and grouping state. The budget starts at
zero used permissions; token bucket starts with one token. No state crosses the
unobserved 2–12 March interval. These are two separate day streams, not two
independent scientific cases, and the ordinary-calendar day is not adjudicated
attack-free traffic.

## Fixed methods and common grouping

The primary semantic method considers each token's strictly positive gross
external-out event-amount sum. Compare it with at most 128 preceding positive
values for the same token and monitored population. With current value `x` and
`n` prior values, the tail rank is `(1 + count(previous >= x)) / (n + 1)`.
Require at least 19 prior values. The primary threshold is 1/20; the separately
declared descriptive sensitivity threshold is 1/10. Both use exact integer
cross-multiplication. Current values update the reference only after scoring,
regardless of trigger, grouping or notification admission. Zero and absent
outflows do not enter this conditional positive-magnitude reference.

One transaction triggers when any eligible token crosses the threshold. Tokens
remain separate; their raw amounts are never added across assets. This rank is
not a calibrated p-value, false-alarm probability or economic loss measure.
The union across tokens has no multiple-testing error guarantee. The reference
is limited to 128 records per token and 4,096 token histories; capacity overflow
fails closed without eviction. This record bound is not an exact RAM guarantee.

The count control sums core-emitter logs in the open-left interval `(t−60s,t]`.
All core logs from the current transaction enter together, then the count is
tested against 10. This is a new transaction-final baseline. It differs from
the old per-log baseline in decision granularity and must not be represented
as an unchanged replay of that earlier rule.

For every method, a raw trigger becomes a candidate only when at least 300
seconds have elapsed since the previous candidate. A candidate always updates
the grouping anchor, even when all budget cells reject it. Grouped raw triggers
do not move the anchor. Scoring and grouping run once per method/day; the exact
same candidate stream is then passed to all nine policy/budget cells. This
removes the previous coupling where admission determined the grouping anchor.

## Exact admission policies and matrix

The complete matrix is two day streams × three methods × three policies ×
three daily caps, giving 54 cells. Caps are 1, 5 and 20 notifications; 5 is
primary. There is one deterministic run, not a timing benchmark or stochastic
replication. No cell is selected for reporting based on its outcome.

For one day of `T=86,400,000,000,000` nanoseconds:

- Greedy admits the first `B` candidates.
- Paced cumulative releases `min(B, 1+floor(B*t/T))` permissions by elapsed
  time `t`, with zero permissions when `B=0`.
- Token bucket has capacity one, starts with one token, refills at `B/T` per
  nanosecond and spends one per admission. Integer credit units use one token
  equal to `T`, with refill `elapsed_ns * B`. A separate daily hard cap applies.

Rejected candidates are dropped. There is no queue, retry, retroactive
top-selection or threshold adjustment. All policies process every observation
to advance their logical clocks; only shared group candidates can emit.

## Outputs and interpretation

Private method logs retain scores, reference eligibility, raw triggers, grouping,
source digests and token-specific raw values. Private cell logs retain every
admission and rejection reason. Public aggregates may report counts and hashes,
but not individual raw token amounts. Preserve all outputs and final states,
including failed runs, without overwriting previously accepted artifacts.

Report total transactions, positive token observations, eligible token scores,
cold-start token scores, transactions with positive outflow and with any eligible
score, raw triggers, candidates, grouping suppressions, notifications, actual
load, unused slots, rejection reasons and first/last event-time notification.
Zero triggers without eligible history must be distinguishable from evaluated
non-triggering observations. Verify equal candidates across every policy/cap
cell and zero hard-cap exceedance.

No labels enter the runner. A separate specification may join the six already
reported Euler execution hashes only after outputs are closed, with the label
set frozen beforehand. Such a join remains a development diagnostic for one
known incident. Unlabelled notifications are not false positives; reporting
overall precision or general attack recall would require additional evidence.

## Verification and freeze

Run the standalone semantic-monitor and replay unit suites before the freeze.
They cover exact rank history, cold start, conservative ties, causal grouping,
transaction-final count boundaries, exact budget arithmetic, no invalid-input
mutation and independent day resets. An independent reviewer reconstructs
scores/candidates/admissions from retained inputs without using production
policy routines for expected values.

The design freeze binds code, tests, protocol and configuration before new
payload/outcomes. After acquisition, bind the completed input manifest before
the runner starts. The runner verifies frozen sources before and after replay,
rejects incomplete inputs and records a failure receipt if processing aborts.
Its executable never acquires network data or imports attack labels. Frozen
phase 7 sources and previous measured policy implementations remain unchanged.
