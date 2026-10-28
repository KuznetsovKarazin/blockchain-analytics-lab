# Candidate: one prospective source-only continuation

These files are candidate implementation, not acceptance or permission to stop,
modify, extend or restart the current attempt. A1 continues under its original
bound plan. Root may activate this route only after an eligible natural closure
and a separately recorded prospective acceptance. No frozen original file or
measurement receipt is rewritten.

The frozen `measurement_protocol.json` permits an implementation amendment after
source reads when the original attempt and exposure are preserved. This route
keeps both nominated cases, all 113 source identities, both complete 30-day
windows, core-emitter selection, methods, thresholds, grouping, histories,
admission policies, budgets and daily resets unchanged. No detector result or
new reference may be examined before full source audit and frozen replay.

## Fixed operational delta

- One A2 continuation in one prospectively pinned, initially absent output
  directory outside the immutable A1 directory.
- The absolute deadline is **A1 start UTC + 14,400 seconds**. Amendment drafting,
  downtime and gate checks do not reset it. Acceptance itself must precede it.
- Cumulative limits remain **5,000 GET attempts and 17,179,869,184 charged
  response bytes**, counting A1 and A2 and explicitly reacquired bytes. Exact
  retained bytes remain a separate unchanged counter. Every failed/pending GET
  is conservatively charged its full requested range: add requested length minus
  retained partial bytes as a reservation. This covers potentially consumed but
  unreturned HTTP-read bytes; it is not complete wire-byte measurement. Other
  original limits and concurrency 1 remain unchanged.
- Zero automatic retries. At most one separately declared manual reacquisition
  of the exact final eligible A1 failed GET, with the same source key/start/length.
  It consumes another GET and all received bytes. A failed response is never
  promoted to accepted source evidence by omitting its failure record.
- All successful original ranges used in A2 require original-byte verification.
  The full failed/cumulative ledger and the accepted-range evidence view are
  separate, bound artifacts. A1 receipts and sparse files remain untouched.

Eligible A1 closure is a proven `FAILED` wall guard, the narrow deadline-associated
timeout described below, or producer
`COMPLETE` with a separately proven total-wall violation while every accepted
GET completed inside A1's original 7,200-second deadline and source validity is
independently established. The latter is recorded literally as **producer
COMPLETE; original wall contract FAILED**. Earlier/general network failures,
identity/schema/source-validation failures, capacity errors and ambiguous
request-cap failures are ineligible. A live or pending attempt cannot be sealed.

The narrow timeout branch recognizes only four exact outer class/message pairs:
`TimeoutError: timed out`, `TimeoutError: The read operation timed out`,
`URLError: <urlopen error timed out>`, and
`URLError: <urlopen error The read operation timed out>`. The receipt and outer
failure must preserve that exact same type/message. There must be exactly one
failed final GET, started in `[A1start+7140s,A1start+7200s)`, completed at or after
the original deadline, with final session monotonic elapsed at least 7200s,
ordered UTC times and UTC/monotonic closure difference at most 2s. Every earlier
accepted GET must finish within the original deadline. If any response-header
field exists, the complete status206/URL/ETag/range/length/identity-encoding tuple
must validate; if none exists, retained body bytes must be zero. A nonnull exact
manual-reacquisition descriptor is mandatory. DNS, SSL/handshake/certificate and
other URLError messages are excluded.

This branch is `DEADLINE_ASSOCIATED_TIMEOUT_CAUSALITY_UNRESOLVED`. The original
collector used a remaining-wall-limited timeout, but did not record the actual
argument for that request; association does not prove the wall timer caused the
failure. Neither the exception nor that causal uncertainty is rewritten.

## Exact schemas and binding bases

Unless stated otherwise, a binding is `{ "path": "...", "sha256": "..." }`;
artifact paths may be absolute or relative to the JSON containing the binding.
Execution-code paths are repository-relative, unique and cannot contain `..`.
Only real computed hashes belong in an accepted record.

### Continuation plan

Copy every field/value from the original full source plan, change only
`schema_version` to `article2_phase16_continuation_source_plan_v1`, and add:

```json
{
  "original_plan_binding": "BINDING_TO_UNCHANGED_ORIGINAL_FULL_PLAN",
  "continuation_transport": {
    "absolute_deadline_seconds_from_a1_start": 14400,
    "cumulative_get_limit": 5000,
    "cumulative_response_byte_limit": 17179869184,
    "automatic_retries": 0,
    "maximum_explicit_manual_reacquisitions": 1,
    "failed_get_byte_charge": "FULL_DECLARED_RANGE_LENGTH"
  },
  "continuation_execution_bindings": []
}
```

The original `collector` object, including its original 7,200-second field, is
preserved exactly as baseline evidence. The explicit continuation envelope
governs the new absolute deadline; this is not a renamed original plan. The new
plan has a different actual hash. Required new code bindings include
`continuation/protocol.py`, `collector.py`, `continue_pipeline.py`,
`independent_transport_audit.py` and `audit_sources.py`; bind any additional new
execution dependency too. Original helper code remains bound by the original
plan and measurement acceptance.

### First-attempt closure seal

After A1 closes, the future root command is:

```bash
python papers/monitoring_jss/phase16/continuation/protocol.py seal-first-attempt \
  --parent-root /retained/A1 \
  --original-plan /retained/original_source_plan.json \
  --expected-original-plan-sha256 ACTUAL_ORIGINAL_PLAN_SHA256 \
  --output /retained/continuation_gate/first_attempt_seal.json
```

This refuses an active/ineligible A1 and writes outside its directory. It does
not authorize A2. The seal has:

- `schema_version: article2_phase16_first_attempt_closure_seal_v1`
- `status: CLOSED_ORIGINAL_ATTEMPT_PRESERVED`
- `parent_root` (absolute), `original_plan_sha256`, `attempt_id`, `started_utc`,
  `closed_utc` (final original session `updated_utc`), `sealed_utc`
- `closure_class: WALL_LIMIT_FAILED`,
  `DEADLINE_ASSOCIATED_TIMEOUT_CAUSALITY_UNRESOLVED`, or
  `COMPLETE_OVER_ORIGINAL_WALL_LIMIT`
- `producer_status: FAILED` or `COMPLETE`,
  `original_wall_contract_status: FAILED`,
  `original_attempt_compliant_completion: false`
- `original_request_count`, `original_response_bytes`,
  `original_wall_seconds_elapsed`
- `timeout_causality_unresolved`: true exactly for the narrow timeout branch
- `reserved_parent_failed_response_bytes`: failed length minus retained partial
  bytes; `inherited_charged_response_bytes`: original retained bytes plus that
  reservation. Original A1 counters are not changed.
- `parent_evidence_bindings`: relative-A1-path to SHA string, or null for an
  explicitly absent required artifact. This exhaustively binds every existing
  A1 `*.json` file, including range receipts and preparation sidecars.
- `completed_days`: ordered records `{day_utc, prepared: binding,
  core_selection: binding}`. These binding paths are relative to `parent_root`.
- `partial_core_selection_seals`: zero or one `{day_utc, core_selection:
  binding}` for an incomplete next day whose core selection was already sealed.

Required parent-evidence names are `frozen_plan.json`, `runtime_acceptances.json`,
`transport/plan.json`, `transport/session.json`, `transport/requests.json`,
`runtime_source_paths.json`, `failure.json`, and `collection_result.json`.
Required absent files use explicit null. The validator compares the current
exhaustive JSON file inventory and every bound byte hash. It also compares all
completed and partial core-selection filenames/SHAs, so the final incomplete
day's already exposed membership cannot silently change during continuation.

### Root exposure report

This is a truthful root review of exposure, not an automatically inferred claim
that no information was seen. Required fields are:

```json
{
  "schema_version": "article2_phase16_source_only_exposure_report_v1",
  "status": "ROOT_REVIEWED_SOURCE_ONLY_EXPOSURE",
  "first_attempt_seal_sha256": "ACTUAL_SEAL_SHA256",
  "reviewed_utc": "ACTUAL_UTC_TIME_AFTER_SEAL",
  "reviewer": "ROOT_REVIEWER_IDENTITY",
  "exposure_description": "Concrete retained/source-decoded and inspected material",
  "source_payload_exposed": true,
  "detector_scoring_started": false,
  "new_reference_acquisition_started": false,
  "performance_or_reference_results_examined": false,
  "completed_days": [],
  "partial_core_selection_days": []
}
```

The date lists must exactly match the closure seal. Existing incident-informed
nominations remain acknowledged; this report does not transform the cohort into
a globally blind sample. If any stated negative is false, this gate is ineligible.

### COMPLETE-overwall eligibility review

Only that branch additionally requires an independent artifact with schema
`article2_phase16_complete_overwall_eligibility_review_v1`, status
`PASS_SOURCE_VALIDITY_ONLY_ORIGINAL_WALL_CONTRACT_FAILED`, and:

- `first_attempt_seal_sha256`, `original_plan_sha256`,
  `original_collection_result_sha256`, `reviewed_utc`, nonempty `reviewer`
- `producer_status: COMPLETE`, `original_wall_contract_status: FAILED`
- `all_http_gets_within_original_deadline: true`
- `all_source_parts_and_projection_integrity_valid: true`
- `selection_and_prepared_bundles_valid: true`
- `source_identity_schema_validation_errors: false`
- `source_objects: 113`, `study_days: 37`
- nonempty `evidence_bindings`, resolved relative to this review artifact.

Review follows the closure seal and precedes amendment acceptance. It is not a
forged ordinary transport PASS: the original total-wall failure stays explicit.

### Prospective amendment acceptance

Root creates this only after actual eligibility/exposure review, at the actual
current time. Required fields:

```json
{
  "schema_version": "article2_phase16_source_continuation_acceptance_v1",
  "status": "ACCEPTED_BEFORE_CONTINUATION_ONLY",
  "accepted_utc": "ACTUAL_CURRENT_UTC_TIME",
  "continuation_output_root": "/retained/fixed_fresh_A2_directory",
  "continuation_plan": "BINDING",
  "first_attempt_seal": "BINDING",
  "exposure_report": "BINDING",
  "complete_overwall_source_validity_review": null,
  "original_measurement_acceptances": {
    "lifi_20220320": "ORIGINAL_UNCHANGED_ACCEPTANCE_BINDING",
    "revest_20220327": "ORIGINAL_UNCHANGED_ACCEPTANCE_BINDING"
  },
  "parent_evidence_bindings": {},
  "manual_reacquisition": null,
  "accepted_before_continuation_requests": true,
  "source_payload_previously_exposed": true
}
```

Replace schematic binding strings with actual objects. Copy the exact parent
evidence map from the sealed A1 report and exact original acceptance mapping
from A1 `runtime_acceptances.json`. For COMPLETE-overwall replace the null
validity-review field with its binding. For one permitted manual GET use exactly
`{parent_request_ordinal, source_key, start, length}` from the final explicit
wall-failed original record, or the sole qualifying deadline-associated timeout.
The timeout branch requires that exact nonnull descriptor. Otherwise keep it null
unless explicitly accepting the permitted final wall-guard reacquisition.

There is deliberately **no** new `accepted_before_affected_payload` assertion;
the validator rejects that field. Both original measurement acceptances retain
their actual old timestamps, original plan hash and true historical meaning.
Never feed a new plan to the old acceptance builder or force equality to the
old plan SHA. Acceptance order must be A1 close ≤ closure seal ≤ exposure review
≤ new acceptance < absolute deadline. The continuation launcher independently
checks the protocol file hash before importing it, then checks all bound code.

## Shared implementation API

`validate_amendment(path, expected_sha256, *, now_utc=None,
for_execution=True)` returns the validated amendment, new/original plans,
`plan_path`, `plan_sha256`, `first_attempt_seal`, exposure, `parent_root`,
`parent_bindings`, `manual_reacquisition`, `continuation_output_root`,
`absolute_deadline_utc` (JSON UTC string) and `original_acceptances`.
Execution mode requires the fixed A2 directory still absent and the absolute
deadline not expired. Later read-only audit mode uses `for_execution=False`;
it still checks prospective acceptance ordering and immutable A1 evidence.

The new collector API is
`ContinuationSession(original_plan['collector'], new_output/'transport',
parent_root, parent_bindings=..., continuation_plan_sha256=...,
manual_reacquisition=...)`. The cumulative ledger must retain every failed and
partial original/new request. A2 does not resume the failed A1 session or erase
its terminal status.

## Audit, assembly, replay and reference stages

After A2 closes, the independent transport audit must report
`PASS_CONTINUATION_TRANSPORT_ORIGINAL_BYTES`, exact `plan_sha256`,
`continuation_amendment_sha256`, `multiattempt_ledger_sha256`, and its pinned
`auditor_sha256`. The full ledger counts all costs/failures; the accepted source
range view is separately derived and bound. The continuation source adapter
then produces `PASS_SOURCE_SELECTION_AND_RAW_BUNDLES` with the unchanged
`phase16_independent_actual_source_review_v1` schema plus amendment/original-plan
lineage, its new `reviewer_sha256`, and `original_row_auditor_sha256` for the
unchanged original row-validation implementation. Both 30-day source audits
must pass; no missing day is converted to zero or dropped.

`validate_amended_source_ready(amendment_path, expected_amendment_sha256, *,
transport_audit, source_review, multiattempt_ledger, binding_parent,
now_utc=None)` verifies this chain before **assembly**. It returns context plus
`transport_audit`, `source_review` and `multiattempt_ledger_path`. Binding
arguments are exact `{path,sha256}` objects. Original `assemble_case` may then
build both common input manifests without computing detector scores.

Only after those manifests exist does root sign a pre-replay receipt:

```json
{
  "schema_version": "article2_phase16_continuation_pre_replay_authorization_v1",
  "status": "ACCEPTED_FOR_FROZEN_REPLAY_AFTER_AMENDED_SOURCE_AUDIT",
  "accepted_utc": "ACTUAL_CURRENT_UTC_TIME",
  "accepted_before_replay": true,
  "detector_scoring_started": false,
  "new_reference_acquisition_started": false,
  "continuation_amendment": "BINDING",
  "transport_audit": "BINDING",
  "source_review": "BINDING",
  "multiattempt_ledger": "BINDING",
  "input_manifests": {
    "lifi_20220320": "BINDING",
    "revest_20220327": "BINDING"
  }
}
```

`validate_pre_replay_authorization(path, expected_sha256, now_utc=...)` verifies
the lineage, both complete manifests and their source-audit/config bindings.
The unchanged frozen driver then receives its **original** measurement
acceptance and the new, fully audited input manifest. The supplemental receipt
explains why that amended source execution is accepted; it does not pretend the
driver's old schema itself understood the new transport plan.

Seal both full replay results before references. The final study seal must bind
the continuation amendment, full multi-attempt ledger and pre-replay receipt in
addition to both original acceptances and exact final run/input hashes. The
original archive-reference auditor correctly rejects mismatched old/new source
plan lineage; a separately named continuation-aware wrapper is needed before
the final study/reference stage. Do not relabel an amended plan as the original
or feed only successful requests while hiding the full failed/cost ledger.

## Scientific interpretation and candidate verification

The comparison remains a fixed-method, incident-informed, source-limited
two-case measurement if these gates hold. Report the transport amendment after
source-only exposure and before any scores/new references. Report A1's original
cap failure and the cumulative amended cost. Do not claim completion under the
original 7,200-second plan or two independent experiments. The continuation
changes operational feasibility evidence; it does not add incidents, alter
coverage denominators or justify causal/prevention claims.

`python papers/monitoring_jss/phase16/continuation/protocol.py self-test` exercises
new synthetic gate fixtures only. All 28 focused checks pass, including narrow
timeout association, full failed-range reservation, live/noneligible closure
rejection, exact single manual reacquisition, unchanged science/cumulative caps,
and preservation of partially exposed core selection. A separate temporary-only
synthetic chain exercised original acceptance → A1 seal → exposure → amendment →
source-ready gates and adversarial mutations: 45 checks passed against protocol
SHA `7afb6398fcf4f10f0db6f92bc18a8f1949e13b411f19241443c86d8d0d811fff`.
Its report SHA is
`8fd7a12c7d2df5b110ff23a6f3250758cd3a47da075bf8c5f27de4450aacf89f`.
These checks inspect no real A1 capture, perform no acquisition, run no old suite
and grant no root continuation acceptance. They remain separate from an actual
eligibility decision and actual transport/source audits.
