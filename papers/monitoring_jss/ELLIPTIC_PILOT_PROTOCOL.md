# Elliptic: bounded retrospective delayed-feedback experiment

This experiment evaluates a declared feedback policy on prepared benchmark
vectors. It does not measure historical investigation delays, live feature
extraction or performance on previously untouched entities. Steps 35–49 were
already studied in the book and remain exploratory. Parameters are fixed
before fitting; this is not a search for the best reported result.

## Input and availability

Use the official Elliptic Kaggle release, version 1, with original CSV hashes
and exact transaction-ID alignment recorded in the acquisition manifest.
Unknown labels stay in the monitored population and budget denominator, but
never become negative examples in fitting, calibration or evaluation.

The original 94-feature local count includes the time step, leaving 93 local
predictors. Excluding the 72 neighboring-transaction aggregates does not by
itself establish historical availability. Šafář et al. (2026) report that
address-derived local features use a fixed later block and identify global
preprocessing and shared-address dependence. Their reconstructed mapping,
not a provider correction, motivates the restricted subset. See DOI
10.1016/j.fsidi.2026.302124 and qa/elliptic_primary_source_availability_review.json.

Select original zero-based CSV positions
[2,3,5,6,7,9,10,11,12,13,14,15,17,18,19,20,21,22]. Exclude ID, time,
undefined columns 4/8/16, address-derived columns 23–94 and neighbor aggregates
95–166. Record float32 conversion. These 18 supplied features remain globally
normalized. This work does not reconstruct raw Bitcoin features or eliminate
all benchmark dependence. The subset is not called a repaired dataset.

## Fitting, calibration and feedback

Known labels for steps 1–34 are explicitly declared available before prediction
35. Fit on known rows from steps 1–30; calibrate on 31–34. The logistic-regression
scaler is fitted on fitting rows only. Use the exact parameters, single seed
and thread limits in elliptic_pilot_config.json; no hyperparameter search or
early stopping. The pre-fit review and source/config hashes precede execution.

Compare a fixed model/threshold pair with an expanding retrained pair at delays
0, 1, 2 and 4. Compute the fixed reference once per model family. Labels from
step s are exposed after prediction s+d, first usable at s+d+1. Initial history
is an explicit exception to this scenario rule, not an observed historical fact.

Each candidate uses the latest four available steps containing known labels
for calibration, excluding those rows from fitting. Both fitting classes must
exist; calibration requires at least ten positives and ten negatives. These
are feasibility guards, not optimized or statistically established minima.
Refit only when the available known-label cohort changes.

Choose the threshold maximizing F1 on that candidate's calibration scores.
Evaluate complete tied-score groups with score >= threshold; the largest
threshold wins a tie. Insufficient classes, fitting/calibration failure,
nonconvergence or rejected provenance retain the entire preceding model and
threshold. A failed initial model prevents an accepted run.

## Budget and evaluation

After each complete batch, permit at most floor(N_all / 200) notifications.
Apply the calibrated threshold, then admit the highest qualifying scores,
with numeric transaction ID ascending as tie-breaker. There is no forced
minimum and no filling unused capacity with below-threshold rows. ID order
is not claimed to be historical arrival order.

Write decisions before the step's label-release call. Gzip flush establishes
logical sequencing, not durable outbox delivery. Evaluate after the entire
decision log is closed. Report all/known/unknown alerts, true positives on
known labels, known-positive recall, precision conditional on known alerted
labels, F1, coverage and unused budget. Unknown alerts are not false positives.
Undefined ratios remain null.

Average precision uses known labels only. Pooled adaptive scores can come
from different model versions, so pooled AP is descriptive rather than the
primary budget comparison. No confidence interval assumes that transactions
or repeated steps are independent incidents.

## Reproducibility and cost

Workers execute captured source and run-local configuration. Preserve model
artifacts, exact fitting/calibration cohorts, calibration scores, update
records and decisions privately, with hashes in public manifests. Independent
checks validate actual files and predictions, not just process success flags.

Measure fitting, calibration prediction, threshold selection, batch prediction
and admission separately. The modeling loop includes artifact/decision writing
but excludes initial CSV loading and queue preparation. Worker RSS includes
preparation and later evaluation buffers. Steps are not converted to seconds;
scoring prepared vectors is not end-to-end blockchain-processing latency.
