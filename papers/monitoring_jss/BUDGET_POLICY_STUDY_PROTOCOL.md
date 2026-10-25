# Continuous-window alert-budget study

This is an exploratory operational comparison, defined after the Euler March
2023 diagnostic showed that a greedy daily allowance could be exhausted before
reported exploit executions. It does not validate an attack detector or provide
an untouched external test. The rule and all allocation parameters are fixed
before the newly selected stream is acquired or compared.

## Population and selection

Use exactly 30 full UTC days, `[2022-03-19, 2022-04-18)`, for both Euler V1 core
and the historical Beanstalk Diamond. These are separate emitter populations,
each with its own budget. Select every matching log regardless of topic,
transaction identity, label or score. Underlying token/proxy logs and internal
traces outside these emitters are excluded; the streams are not complete
protocol activity.

This interval ends on the known Beanstalk incident day. It was selected using
that date and acquisition constraints, not randomly. Initially considered
separate Euler March 2023 and Beanstalk April 2022 windows would duplicate daily
source acquisition and exceed safe local storage. Metadata inspection showed
that the shared interval needs 7,141,246,236 bytes of full Ethereum logs and
headers. The resource-motivated revision precedes new payload acquisition and
all policy outcomes. Both protocols share chain days; neither 30 days nor the
18 execution cells are independent incident replications.

Require all 30 enumerated daily pairs. Validate whole-object identity and
hashes, every address row, payload/header consistency, timestamp bounds and
uninterrupted parent links within and across days. A verified day with no
matching log is an empty population; a failed or missing partition is not.
Do not shorten, replace or discard days based on policy performance.

Full upstream objects are retained in private, checked daily archives. Loose
download copies may be removed only after every archive member has been read
back and its size, CRC and SHA-256 verified. Selected inputs remain available
separately. Preserve all failures and attempted-run metadata.

## Rule, clock and state

The unchanged workload rule triggers when at least 10 accepted emitter logs
occur in `(t-60 seconds,t]`, including the current log. It is not fitted as an
attack classifier. The same parameters apply to both emitters despite their
different activity distributions.

Use original integer block-event nanoseconds as the **logical simulation
clock**. They are not measured historical observation or arrival times. Daily
allocation follows this clock in UTC and cannot change with playback speed,
CPU scheduling or file boundaries. This convention is deliberately separate
from the earlier single-day playback-clock engineering pilot; results must not
be pooled as if both budget clocks were identical.

Start once at the beginning of the interval with an empty rolling window and
no grouping anchor. Preserve features, canonical watermark, duplicate ledger,
grouping state and token balance across midnight and all daily files. No
pre-window warmup is provided. Retaining the duplicate ledger for this finite
window does not establish bounded production state for indefinite operation.

Group triggers within 300 event-time seconds of the last notification actually
admitted in that cell. Neither grouping nor allocation rejection extends the
anchor. Consequently the three policies share raw trigger streams but can have
different group-candidate streams. This is an end-to-end admission comparison,
not allocation applied to a common pre-grouped candidate list.

## Fixed allocation policies

All policies enforce an additional hard cap of `B` notifications per emitter
per UTC day. Compare `B=1,5,20`; five is primary and the other two are declared
sensitivity cases from the earlier protocol. There are 18 deterministic cells:
two emitters, three policies and three caps. No stochastic seeds or performance
repetitions are needed for this functional comparison.

1. **Greedy:** all daily credits are available at midnight; admit the earliest
   ungrouped triggers until the cap is reached.
2. **Paced cumulative:** release a credit at elapsed offsets `j*T/B`, for
   `j=0,...,B-1`, where `T` is one day. At integer nanosecond offset `t`, the
   released quota is `min(B,1+floor(B*t/T))` for positive `B`. Unused released
   credits accumulate within the day and expire at its end.
3. **Token bucket:** capacity one token, initially one at the study start,
   continuously replenished at `B/T` tokens per nanosecond. It carries across
   midnight without a reset or extra midnight token. Only the separate hard
   daily counter resets. Use integer units with one token equal to `T`, so no
   floating-point rounding determines admission.

All candidates rejected by allocation are dropped immediately; none are queued
for later delivery. Zero budget is tested as an implementation boundary but is
not an added study cell. Exact redelivery and late records cannot spend or
refill credits. Invalid conflicts fail rather than silently selecting a copy.

## Outcomes and interpretation

Report daily and hourly notifications, raw triggers, candidates, each
suppression reason, unused slots, days at the cap, first/last notification
times, overlap of actual notification sets and capture of hours containing raw
triggers. Include verified empty days and expose denominators. A zero hard-cap
exceedance count is a required invariant, not evidence of detector quality.
More spread-out notifications are not automatically more useful notifications.

Join the existing Beanstalk label manifest only after all decisions are closed.
The single reported exploit transaction is a descriptive positive seed with
prior L2 exposure. Proposal transactions remain context, not theft labels or
negatives. Unlabelled notifications remain unknown; no precision, false-positive
rate, independent incident recall or prevented-loss estimate is licensed.
An alert on finalized atomic exploit logs does not show that the transaction
could have been interrupted. Full receipt completeness, deployed facet ABI,
live observation time and operational label delay remain unresolved.

Freeze exact code/config/input/label hashes before replay, verify them again
afterwards, and independently recompute admissions from saved input. Essential
checks cover causal prefix invariance, exact release/refill boundaries,
midnight and file continuity, gaps and empty days, identical timestamps,
duplicate/conflict handling, snapshot continuation and each hard daily cap.
Report every planned cell regardless of its outcome; do not retune parameters
or select a winner using the known incident.
