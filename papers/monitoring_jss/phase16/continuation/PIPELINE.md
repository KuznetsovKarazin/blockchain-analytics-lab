# Candidate continuation pipeline

This module is a prospective operational continuation candidate. Its presence and passing synthetic tests do not authorize real requests or make an incomplete first attempt usable for measurement.

`continue_pipeline.py` requires one exact, current root amendment covering both cases. The amendment validator checks closure of the original attempt, a sealed report of prior source exposure, both original acceptances, the original plan, new execution bindings and the absolute cumulative deadline. The original case windows, population addresses, methods, thresholds, source inventory and dependency versions remain unchanged. The original source plan and its acceptances are not rewritten or relabeled.

The new collection uses a fresh directory and cache. The separate continuation collector authenticates the original receipts and bytes before copying accepted ranges. Its cumulative budget includes every original GET and retained response byte; its only permitted additional retry is one exact, prospectively declared manual reacquisition. The pipeline invokes that operation explicitly only when the accepted amendment contains its descriptor. No automated retry or second continuation is implemented.

The pipeline hash-checks and imports the original preparation implementation. It rebuilds all 39 header days and 37 study days, including both boundary-only block objects. Every original completed day's sealed selection and exact cases/bundles payload must match. A core selection already sealed for the next incomplete day is also preserved and compared. Source sidecars accurately reflect new transport provenance and may have different hashes. A scientific-payload difference fails the continuation before decoding or scoring.

The new `collection_result.json` identifies the actual continuation plan and amendment, separately records the original plan, and binds the reproduction comparison report. Its completion status only permits independent review. A new transport audit must authenticate multi-attempt provenance; the unchanged independent source-row auditor can then check the new plan and output. Transfer decoding and detector replay require the separate continuation-aware pre-replay authorization.

```bash
python papers/monitoring_jss/phase16/continuation/continue_pipeline.py collect \
  --amendment /absolute/prospective_amendment.json \
  --expected-amendment-sha256 AMENDMENT_SHA \
  --expected-protocol-sha256 PROTOCOL_CODE_SHA \
  --dependencies /absolute/pinned_pyarrow_site \
  --wheel /absolute/pinned_pyarrow.whl \
  --reuse-map /absolute/original_verified_reuse_map.json \
  --output /absolute/new_continuation_collection
```

The original whole-object reuse expectations still control every optional reuse-map entry. Runtime local paths may vary; source key, size, ETag, full-object digest and retained archive/member identity may not.

The synthetic pipeline tests exercise 113 fabricated Parquet sources across the exact 37-day union, both 30-day selections, complete and partial prior-day preservation, immutable science fields, tampered prior evidence, unsafe bindings and failure on changed selected payload. They never acquire or read archive rows.

After independent amended transport and source reviews both pass, assemble both cases without scoring:

```bash
python papers/monitoring_jss/phase16/continuation/continue_pipeline.py assemble \
  --amendment /absolute/prospective_amendment.json \
  --expected-amendment-sha256 AMENDMENT_SHA \
  --expected-protocol-sha256 PROTOCOL_CODE_SHA \
  --transport-audit /absolute/transport_audit.json \
  --expected-transport-audit-sha256 TRANSPORT_SHA \
  --source-review /absolute/source_review.json \
  --expected-source-review-sha256 SOURCE_SHA \
  --multiattempt-ledger /absolute/multiattempt_ledger.json \
  --expected-multiattempt-ledger-sha256 LEDGER_SHA \
  --collection /absolute/accepted_continuation_collection \
  --output /absolute/new_assembled_observations
```

This gate invokes the unchanged original assembler only after the amended reviews are bound. `assembly_result.json` contains exact two-field `{path,sha256}` input-manifest bindings for the root's subsequent pre-replay receipt. Assembly creates no detector scores. The fixed continuation output destination is part of the prospective amendment, preventing another acquisition run at a different output with the same accepted gate.

The current report contains 14 passing synthetic checks. The assembly compatibility check uses explicitly synthetic source-audit fixtures and a stubbed source-ready gate inside the test; it verifies both real frozen driver input validators, not actual archive coverage.

The final collector integration additionally checks that the accepted original input-plan SHA is passed explicitly even when runtime JSON serialization has a different file SHA. The earlier 13-check suite was retained; only this focused check and the acquisition-gate rejection check were run after the one-argument integration change.
