# Frozen replay and post-decision reference workflow

These new wrappers use the storage-recovery lineage. They do not activate the unused wall-continuation implementation. `protocol.py` remains pinned to `3b5003147d59cfd13f28adf614bb2859f8d6d1c6a3923ccd3c77e34944d261e0`; the original Phase15 driver, two case configurations, exact-reference join and archive source-fact engine remain unchanged. Importing either wrapper or running `--help` performs no replay, source scan or reference acquisition.

## 1. Source admission, assembly and root pre-replay receipt

Complete A2 and obtain its independently passed transport audit/full multiattempt ledger and source review. The source review must bind the new transport audit, unchanged case scope, full source projections and exact A1 prepared-day/selection comparisons. Run the new pipeline's gated `assemble` subcommand to produce both final input manifests. No detector scores are admitted before these steps.

Root creates a new JSON pre-replay authorization. Every `binding` below is an actual `{ "path": "ABSOLUTE_RETAINED_PATH", "sha256": "ACTUAL_FILE_SHA256" }`; placeholders are not usable hashes. Do not edit or reissue the original measurement acceptances.

| Field | Required value |
|---|---|
| `schema_version` | `article2_phase16_storage_recovery_pre_replay_authorization_v1` |
| `status` | `ACCEPTED_FOR_FROZEN_REPLAY_AFTER_AMENDED_SOURCE_AUDIT` |
| `accepted_utc` | Actual current UTC after source review completes and before replay |
| `accepted_before_replay` | `true` |
| `detector_scoring_started` | `false` |
| `new_reference_acquisition_started` | `false` |
| `storage_recovery_amendment` | Exact accepted storage amendment binding |
| `transport_audit` | Passed `PASS_STORAGE_RECOVERY_TRANSPORT_ORIGINAL_BYTES` report binding |
| `source_review` | Passed `PASS_SOURCE_SELECTION_AND_RAW_BUNDLES` report binding |
| `multiattempt_ledger` | Exact complete ledger binding used by those audits |
| `input_manifests` | Dictionary with exactly `lifi_20220320` and `revest_20220327`, each bound to its assembled manifest |
| `replay_launcher_sha256` | Actual final byte hash of this directory's `run_replays.py` |
| `replay_output_root` | Absolute, fresh root chosen for this single replay attempt |
| `reference_archive_auditor` | Actual final binding to this directory's `archive_reference_audit.py` |
| `reference_compact_reader` | Binding to this directory's `independent_compact_reader.py`, already frozen in the storage plan |
| `reference_archive_source_engine_sha256` | `347bf76e162cf995e0b3c30ce6a3e72a75a1e78008d120ce8d51137667409955` |

The new receipt must not contain `accepted_before_affected_payload`. Original payload exposure and ENOSPC history are preserved through the amendment chain.

```sh
python papers/monitoring_jss/phase16/storage_recovery/run_replays.py \
  --pre-replay-authorization ROOT_PRE_REPLAY_RECEIPT \
  --expected-authorization-sha256 ACTUAL_RECEIPT_SHA \
  --output EXACT_AUTHORIZED_REPLAY_OUTPUT_ROOT
```

The launcher verifies the pinned storage protocol and receipt, both original acceptances and input manifests, its own code and the future archive auditor/reader bindings. It invokes the unchanged driver once for LiFi and once for Revest. It validates each completed run with the unchanged exact join's seal verifier; validation does not recompute detector scores. First-case failure prevents a second invocation. Any failure preserves partial files and writes a failure record where possible; the used output directory cannot be retried automatically.

Only after both valid runs, it writes `replay_launcher_receipt.json` and `decision_study_seal.json`. The latter retains the ordinary `article2_phase16_decision_study_seal_v1` / `BOTH_CASE_DECISION_STAGES_CLOSED` schema and exact two case bindings accepted by the frozen join, plus storage amendment, pre-replay authorization, full cost ledger, launcher receipt and archive/reader code pins. Do not initiate primary reference retrieval until this file exists and its exact hash has been recorded. Partial outputs and a launcher failure record do not authorize reference acquisition.

## 2. Primary reference acquisition and candidate inventory

Only after both sealed decisions, root may use the separately frozen primary-report/reference acquisition procedure and journal. This wrapper performs no network requests. Preserve primary document bytes, URL, location, retrieval timing, hashes and role conflicts; candidate hashes must come from primary reports, not notifications or score ranks. Existing limits remain: primary-document query/item/document/wall caps; at most 64 canonically ordered execution candidates per case; bounded execution audit/fallback requests and bytes. Archive execution time is charged before any permitted provider fallback, not reset.

Create a candidate inventory with exact schema:

```json
{
  "schema_version": "article2_phase16_primary_candidate_inventory_v1",
  "status": "PRIMARY_CANDIDATES_EXTRACTED_NOT_ADJUDICATED",
  "decision_study_sha256": "ACTUAL_STUDY_SEAL_SHA",
  "created_utc": "ACTUAL_UTC_AT_OR_AFTER_STUDY_SEAL",
  "cases": [
    {"case_id": "lifi_20220320", "candidates": []},
    {"case_id": "revest_20220327", "candidates": []}
  ]
}
```

Each candidate has integer `chain_id:1`, a real primary-reported canonical lowercase `transaction_hash`, `primary_source_locations_and_hashes` (each `{artifact:binding,url,location}`), and nonempty `reported_role`. Resolve duplicate case/hash entries by retaining every source location and conflict. Unresolved chain identity must not be silently assigned to Ethereum. Empty lists are allowed. No example attack hash is supplied here. The wrapper sorts only audit order by `(chain_id, transaction_hash)`; all candidates beyond rank64 remain in the output with unavailable coverage.

## 3. Exact archive source facts

```sh
python papers/monitoring_jss/phase16/storage_recovery/archive_reference_audit.py \
  --study-manifest REPLAY_OUTPUT_ROOT/decision_study_seal.json \
  --expected-study-sha256 ACTUAL_STUDY_SEAL_SHA \
  --candidates PRIMARY_CANDIDATE_INVENTORY \
  --expected-candidates-sha256 ACTUAL_CANDIDATE_SHA \
  --collection /tmp/article2_phase16_runtime_159bf77d8682/attempt2 \
  --transport-audit PASSED_TRANSPORT_REPORT \
  --expected-transport-audit-sha256 ACTUAL_TRANSPORT_SHA \
  --source-review PASSED_SOURCE_REVIEW \
  --expected-source-review-sha256 ACTUAL_SOURCE_REVIEW_SHA \
  --recovery-receipt ORIGINAL_OBJECT_RECOVERY_RECEIPT \
  --expected-recovery-receipt-sha256 ACTUAL_ORIGINAL_RECOVERY_RECEIPT_SHA \
  --dependencies /workspace/scratch/159bf77d8682/phase16_dependencies/site \
  --output FRESH_REFERENCE_ARCHIVE_OUTPUT
```

The wrapper verifies both decision seals and launcher lineage before source scanning. It retains all inherited requests, including the unresolved parent GET, and independently rechecks known/null/reserved/cumulative accounting through the already frozen independent transport auditor. The accepted byte view must equal every successful exact receipt and origin, without the pending parent range.

For compact sources, each blob is matched to its exact original response hash, range and origin, then rehashed by the independent strict reader before footer/row decoding. Coverage holes cannot be synthesized as zeros. For the 18 reused whole objects, the original recovery receipt and frozen public manifest/independent acquisition expectations establish prior provenance; current canonical whole bytes are hashed again. Relocated paths may resolve through the historical symlink. **No deleted temporary ZIP is reopened and no fresh ZIP verification is claimed.**

The unchanged source-fact engine checks all 39 header days, complete transaction identity/status projections over the 37-day union, and complete log identity/address projections on candidate days. Nonselected topics/data and transfer semantics are not decoded. An applicable no-core conclusion requires the complete corresponding log scan and agreement with sealed selection. A missing hash remains unavailable; it does not establish nonexistence or an outside-window date.

The shared archive execution budget is 1,200 seconds for both cases. The wrapper adds per-chunk deadline checks to the same complete SHA calculation in its private reader import, without changing the frozen reader file; it restores the original hash function after construction. Checks also surround every projection read and validation. If reached, `CLOSED_UNAVAILABLE_TIME_CAP` discards partial matches as accepted evidence. Record `execution_wall_seconds` and charge it to each affected case before any provider fallback. No automatic repeat or fresh 20-minute allowance is provided by this wrapper.

## 4. Outputs and exact join schema

`projection_evidence.json` and `archive_reference_result.json` use new storage-recovery report schemas, retain the full multiattempt ledger binding and all unknown cost distinctions, and state that attack roles were not adjudicated. Each per-candidate file uses the unchanged schema required by `exact_reference_join.py`:

| Field | Allowed value |
|---|---|
| `schema_version` | `article2_phase16_reference_source_audit_v1` |
| `case_id`, `chain_id`, `transaction_hash` | Exact candidate identity |
| `identity_status` | `VERIFIED` or `UNAVAILABLE` |
| `success_status` | `SUCCESS`, `FAILED`, `UNAVAILABLE` |
| `core_selection_status` | `SELECTED`, `OBSERVED_NO_CORE_EMITTER`, `UNAVAILABLE` |
| `core_log_count` | Verified integer count; otherwise null |
| `full_core_scan_or_terminal_logs_complete` | Boolean supported by complete scan evidence |
| `identity_evidence`, `selection_evidence` | Lists of exact retained file bindings |
| `evidence_tier` | `ENUMERATED_SOURCE_ARCHIVE` or `UNAVAILABLE` here |
| `rationale` | Concrete bounded evidence explanation |

From the exact matching case/hash fact, copy `actual_identity_or_unavailable`, `success_status_or_unavailable`, `in_fixed_window` and `source_coverage_audit_binding` into the separately adjudicated reference inventory. Full identity has exactly `chain_id`, `block_number`, `block_hash`, `transaction_hash`, `transaction_index`, `event_time_ns`. Keep missing fields unavailable; do not invent provider metadata.

The final inventory retains schema `article2_phase16_reference_inventory_v1`, status `SEALED_AFTER_DECISIONS_INDEPENDENTLY_ADJUDICATED`, `decision_study_sha256`, `reference_acquisition_started_utc`, `sealed_utc`, nonempty `prepared_by`, an `independent_review` binding, and both ordered `cases`. Each case has `case_id`, `execution_inventory_status`, `completeness_rationale`, `completeness_evidence`, and all deduplicated `references`. Status alternatives are `KNOWN_SUBSET_ONLY` (default), `COMPLETE_WITH_POSITIVE_CLOSURE_EVIDENCE`, `UNRESOLVED_CONFLICT`, `NO_VERIFIED_EXECUTION_UNDER_CAP`. Completeness requires positive closure evidence; finding no further references is insufficient.

Each reference retains its exact identity, primary locations, role, source facts, audit binding, nonempty `reviewer_rationale`, and `adjudication_status`: `VERIFIED_APPLICABLE_EXECUTION`, `VERIFIED_OUTSIDE_WINDOW`, `NOT_ATTACK_EXECUTION`, `UNRESOLVED`, or `UNVERIFIED_DUE_TO_CAP`. A positive execution requires exact verified successful identity, within-window timestamp and independently supported `reported_role:SUCCESSFUL_UNAUTHORIZED_EXECUTION`.

The separate review schema is `article2_phase16_reference_review_v1`, status `APPROVED_FOR_EXACT_REFERENCE_JOIN`, with `decision_study_sha256`, `reference_cases_sha256` equal to `semantic_flow_replay.digest(inventory["cases"])`, a nonempty `reviewer` distinct from `prepared_by`, `reviewed_utc`, and true `primary_roles_checked`, `identity_status_window_checked`, `source_coverage_checked`, `inventory_completeness_checked`. Acquisition starts after the study seal; review follows acquisition start and precedes inventory seal. Detailed unchanged rules remain in `phase16/reference/README.md`.

```sh
python papers/monitoring_jss/phase16/reference/exact_reference_join.py \
  --study-manifest REPLAY_OUTPUT_ROOT/decision_study_seal.json \
  --expected-study-sha256 ACTUAL_STUDY_SEAL_SHA \
  --reference-inventory SEALED_ADJUDICATED_INVENTORY \
  --expected-reference-sha256 ACTUAL_INVENTORY_SHA \
  --output FRESH_EXACT_JOIN_OUTPUT
```

Interpret only exact `(chain_id, transaction_hash)` notification matches as execution hits. Unknown notifications are not false positives; incomplete inventories support known-subset coverage and bounds, not global incident recall. Missing evidence is not a measured zero. These wrappers make no causal, prevention, full-chain-completeness or receipt-root claim.
