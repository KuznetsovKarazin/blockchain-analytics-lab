# Archive-only source evidence for post-decision references

`archive_reference_audit.py` constructs source-side evidence records accepted by
the frozen exact-reference join. It establishes exact transaction identity,
success/failure status, fixed-window applicability and core-emitter selection
coverage from already retained sources. It never decides whether a transaction
was an attack execution. Primary attribution, role conflicts and inventory
completeness still require separate independent adjudication.

The CLI performs **no network requests** and leaves the frozen join, protocol,
detector inputs and decisions untouched. It reads only block headers, transaction
metadata/status and log identity/address projections. Nonselected topics/data
and transfer semantics are not decoded or inferred.

```bash
python papers/monitoring_jss/phase16/reference/archive_reference_audit.py \
  --study-manifest /retained/decision_study.json \
  --expected-study-sha256 ACTUAL_ROOT_STUDY_SHA256 \
  --candidates /retained/references/primary_candidates.json \
  --expected-candidates-sha256 ACTUAL_CANDIDATE_FILE_SHA256 \
  --collection /retained/phase16_collection \
  --transport-audit /retained/transport_audit.json \
  --expected-transport-audit-sha256 ACTUAL_TRANSPORT_AUDIT_SHA256 \
  --source-review /retained/source_review/source_review.json \
  --expected-source-review-sha256 ACTUAL_SOURCE_REVIEW_SHA256 \
  --dependencies /retained/phase16_dependencies/site \
  --output /retained/references/archive_audit
```

All paths are concrete retained artifacts; all SHA values must be computed, not
invented. `--output` must not exist. This route requires both complete, sealed
Phase15 driver runs and both source audits passing for the full fixed windows.
Before reference acquisition, the same root `decision_study.json` must additionally
pin `reference_archive_auditor_sha256` to the final byte hash of
`archive_reference_audit.py`. The frozen join accepts this additional study field;
its own `reference_join_code_sha256` binding remains required and unchanged.
An incomplete source stage cannot authorize absence/no-core conclusions through
this CLI. The separately frozen provider fallback remains a later operation.

The execution scan uses a fixed shared 1,200-second wall budget for both cases,
which is conservative relative to the frozen 20-minute per-case cap. The timer
starts after integrity-gate validation and before authenticating/reading source
bytes. Deadline checks occur within byte hashing and around each row-group
decode/validation. If it is reached, the route closes as
`CLOSED_UNAVAILABLE_TIME_CAP`; partial scan matches are not promoted to accepted
source facts, and all candidates retain unavailable identities/coverage.
Elapsed execution time is recorded and must be charged to each case before any
provider fallback; a later HTTP step must not reset this frozen audit budget.

## Candidate input

Construct this file only after the two-case decision-study seal. Preserve
primary-document order and source locations during extraction; the auditor sorts
only the audit order by `(chain_id, transaction_hash)` and audits at most the
first 64 unique candidates per case. It does not use notification results to
choose candidates. Every additional candidate remains in the output as
`UNVERIFIED_DUE_TO_CAP` with unknown identity/status/coverage, even if another
case's permitted audit happened to encounter the same hash.

```json
{
  "schema_version": "article2_phase16_primary_candidate_inventory_v1",
  "status": "PRIMARY_CANDIDATES_EXTRACTED_NOT_ADJUDICATED",
  "decision_study_sha256": "ACTUAL_ROOT_STUDY_SHA256",
  "created_utc": "UTC_TIMESTAMP_AFTER_STUDY_SEAL",
  "cases": [
    {
      "case_id": "lifi_20220320",
      "candidates": [
        {
          "chain_id": 1,
          "transaction_hash": "ACTUAL_PRIMARY_REPORTED_CANONICAL_HASH",
          "primary_source_locations_and_hashes": [],
          "reported_role": "RETAIN_THE_PRIMARY_REPORT_ROLE_OR_UNKNOWN"
        }
      ]
    },
    {"case_id": "revest_20220327", "candidates": []}
  ]
}
```

The placeholders above are intentionally not valid example attack hashes.
Empty candidate lists are allowed. Within each case duplicate identities must
first be merged while preserving all source roles/conflicts. This archive route
requires independently justified Ethereum chain context (`chain_id: 1`);
unresolved chain context cannot silently be assigned to Ethereum. Extra primary
extraction fields are retained in the pinned input but are not adjudicated by
this program.

## What is independently checked

1. The frozen join verifies both decision-stage seals, root acceptances, full
   input/selection/source manifests and every selected method/admission row.
2. The new auditor verifies both source-plan wrappers and execution-code
   bindings, exact passed transport/source review hashes, all 113 source
   identities, the retained path map, request/session seals and the source
   reviews used by the scored runs.
3. Before any source footer or row decode, its currently retained original
   ranges are rehashed against the audited acquisition receipts, or its whole
   object is rehashed against the verified reused-source SHA. Footer evidence is
   checked separately. A sparse file is never authenticated by hashing its holes.
4. The independent offline reader checks that every requested column extent is
   inside verified original ranges. All 39 declared header days, including the
   two exterior controls, are checked for consecutive links. All transaction
   identity/status projections across the 37-day union are scanned and matched
   to headers and independently reviewed row totals.
5. On each day containing a bounded candidate, all declared log identity/address
   row groups are reread, checked against the audited full row count and TX
   identities, and used to reconstruct core-emitter membership/counts. Those
   memberships must match the sealed selected observations. Only then can an
   applicable nonselected candidate receive `OBSERVED_NO_CORE_EMITTER`.

This uses the independent source auditor's offline reader and normalization
primitives, not the collection producer's selection code. It supports a scoped
dataset-source assertion, not receipt-root authentication or proof that the
archive equals the complete canonical chain.

## Outputs and assembly into the reference inventory

`projection_evidence.json` records the exact study/candidate/context seals,
current code hashes, all scanned row groups, candidate identity matches and the
scoped completeness evidence. Per-candidate JSON files under each case directory
contain the exact `article2_phase16_reference_source_audit_v1` schema required by
`exact_reference_join.py`.

`archive_reference_result.json` contains per-case source facts. Copy these fields
from the exact matching case/hash into the separately adjudicated inventory:

| Output fact | Inventory field |
|---|---|
| `chain_id`, `transaction_hash` | Same exact identity |
| `actual_identity_or_unavailable` | Same field, including null |
| `success_status_or_unavailable` | Same field: SUCCESS, FAILED or UNAVAILABLE |
| `in_fixed_window` | Same field, including null |
| `source_coverage_audit_binding` | Same binding to the generated candidate audit |

Retain `primary_source_locations_and_hashes` and `reported_role` from the primary
candidate inventory. A separate reviewer sets `adjudication_status`,
`reviewer_rationale`, the case inventory status and positive closure evidence,
then signs the review schema described in `README.md`. Successful execution by
itself does not establish an attack label. Failed, deployment, financing,
preparatory and remedial transactions must retain their appropriate dispositions.

An exact candidate found outside a case window gets verified identity/status and
`in_fixed_window: false`, with no within-window selection outcome. A candidate
not located in the declared union keeps null identity/date and UNAVAILABLE
status; this does not prove the transaction never existed or was outside the
window. These cases may require the already frozen provider fallback or remain
unresolved. Merely being absent from selected JSONL cannot produce zero core
logs or a measured miss.

## Synthetic verification

`test_archive_reference_audit.py` uses generated tiny Arrow/Parquet sources,
invented identities and explicit synthetic evidence only. It checks source-byte
mutation before decode, sparse projection holes, complete-day counts, exact
selected/no-core membership, failed status, outside/absent/cap-unknown handling,
and that topics/data are not requested. The focused test report is
`archive_reference_synthetic_report.json`. No real reference lookup or historical
payload scan is part of those tests.
