# Delayed feedback and temporal calibration contract

Implementation status: scheduling and provenance utilities implemented and unit
tested. A separate bounded actual-model experiment is now documented in
`ELLIPTIC_PILOT_PROTOCOL.md` and `SESSION_3_REPORT_RU.md`; this utility itself
does not fit an estimator.

## Release phase

For a transaction in source step s and declared delay d, its label is released
after predictions and decisions for step s+d have been recorded. It may first
affect prediction at s+d+1. The supported draft delays are 0, 1, 2 and 4.
The contract uses step indices, never seconds.

| Source step | Declared delay | Release after prediction at | First usable prediction at |
|---:|---:|---:|---:|
| 35 | 0 | 35 | 36 |
| 35 | 1 | 36 | 37 |
| 35 | 2 | 37 | 38 |
| 35 | 4 | 39 | 40 |

Historical M2 `DELAY=2` first uses step-35 labels at prediction step 37, which
matches d=1 in this newly explicit phase convention. Do not relabel historical
results or treat equal parameter numerals as equal availability assumptions.

`DelayedLabelQueue` provides immutable views at `begin_step(t)` and releases
labels at `end_step(t)`. The caller must persist predictions before calling
`end_step`. Initial historical labels are separately declared available before
the first evaluation step; they are not silently shifted by d. A missing label
is `None`, never an assumed negative. The base experiment assumes the historical
known labels become available independently of whether an alert was issued.
Selective investigation-only feedback is not implemented.

The API may preload source labels in private queue state for offline replay.
Prediction code must use the returned availability view only. This is a
sequencing contract, not a process sandbox that prevents Python introspection.

## Temporal partition and fallback

Immediately before a proposed model update, `plan_retraining` takes the latest
four available source steps containing known labels as the calibration window.
All earlier known rows form the fitting set. Unknown-only steps do not fill the
window; record the actual calibration steps and elapsed step span. This is an
expanding training history with a moving, disjoint temporal calibration cohort.

The fitting set must contain both classes. Minimum positive and negative counts
for calibration must be supplied explicitly by the experiment configuration.
The unit tests use small fixture minima solely to test branches. Statistical
minimum counts for the full study are still to be fixed; tests do not establish
their sufficiency.

When a plan is ineligible, skip the update and retain the existing model and its
threshold together. A newly fitted model must produce scores for the complete
planned calibration cohort, with matching model identity. Missing, non-finite,
duplicated or old-model scores cause the same fallback. The registry validates
the partition, its hash, class counts and score provenance before replacing the
active pair. Reusing an old model's threshold after installing a new model is
not an allowed fallback.

Successful activation steps must increase strictly. A late-arriving candidate
from an older or already activated prediction step retains the whole active
pair. Failed later candidates do not advance this clock. The optional
`initial_activation_step` declares the existing pair's history; when omitted,
the first successful candidate establishes the clock without inventing an
initial activation time. This guard validates declared steps, not the actual
time when an estimator was fitted.

Threshold optimization and model fitting remain separate procedures. Merely
tagging scores with a model version does not prove they came from that estimator;
the separate bounded runner now saves estimator/config hashes, fitting indices
and calibration-score artifacts for independent verification. The registry is in memory, not a transactional
checkpoint/outbox. Durable crash recovery remains a separate task.

## Validation and remaining work

Tests cover every delay, prediction-before-reveal, future-label prefix
invariance, unknown labels, explicit initial-history availability, disjoint
calibration, insufficient classes, scoring failure, wrong-model scores and
atomic fallback. No detection metric is reported from these fixtures.

The bounded Elliptic pilot froze its estimator configurations and reported one
seed; before the wider study, fix the remaining estimator configurations,
minimum class counts, seeds, threshold objective, stable-ID ties and completed-
batch budget rounding. Use a score cache keyed by model version. Publish known-
label coverage beside precision/recall and report unknown alerted rows. Keep
the previously studied steps 35–49 exploratory rather than newly independent.
