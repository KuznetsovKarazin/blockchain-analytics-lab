# Exact post-decision reference join

`exact_reference_join.py` implements the already frozen Phase16 label/denominator
procedure. It performs no network access, reference search, source acquisition,
replay, parameter fitting or attack-role inference. The protocol files remain
unchanged. The full fixed window is 30 days per case: 810 daily cells become 27
method/policy/budget aggregates per case, across two intended incidents.

```bash
python papers/monitoring_jss/phase16/reference/exact_reference_join.py \
  --study-manifest /retained/decision_study.json \
  --expected-study-sha256 SHA256_FROM_ROOT_RECEIPT \
  --reference-inventory /retained/references/inventory.json \
  --expected-reference-sha256 SHA256_FROM_ADJUDICATION_RECEIPT \
  --output /retained/reference_join
```

The output directory must be new. All validation precedes output creation.
No detector metrics are produced when a purported COMPLETE run is corrupt or
missing any selected decision; this is an integrity failure, not zero coverage.
A deliberately closed unavailable source stage can instead be declared before
reference acquisition, preserving its null load and unknown coverage.

## Input bindings and ordering

Every `binding` below is `{ "path": "...", "sha256": "..." }`.
Reference/study bindings resolve relative to the containing JSON file, or may
use an absolute retained path. Original driver input and gate bindings retain
their original stricter relative-path rules. Digests bind bytes and audit
assertions; independent adjudication establishes their scientific meaning.

The root seals `decision_study.json` **after both cases have closed and before
new reference acquisition**:

```json
{
  "schema_version": "article2_phase16_decision_study_seal_v1",
  "status": "BOTH_CASE_DECISION_STAGES_CLOSED",
  "sealed_utc": "UTC_TIMESTAMP",
  "reference_join_code_sha256": "FINAL_EXACT_REFERENCE_JOIN_PY_SHA256",
  "cases": [
    {
      "case_id": "lifi_20220320",
      "status": "COMPLETE",
      "config": "BINDING",
      "measurement_acceptance": "BINDING",
      "input_manifest": "BINDING",
      "run_manifest": "BINDING"
    },
    {
      "case_id": "revest_20220327",
      "status": "COMPLETE",
      "config": "BINDING",
      "measurement_acceptance": "BINDING",
      "input_manifest": "BINDING",
      "run_manifest": "BINDING"
    }
  ]
}
```

This is schematic JSON: replace every `BINDING` string with an actual binding
object and supply only real computed hashes. Case order is fixed. Configs must
match the two immutable Phase16 configs. Existing driver validators verify the
root acceptance and the entire input/selection/source-audit manifest. The join
then verifies all 1,020 output artifact hashes per complete run, all selected
observation-to-method-to-admission row bindings, and recomputes method/cell
summaries from sealed decisions. It does not rescore any transaction.

For a closed source failure use `status: "UNAVAILABLE"`, null `input_manifest`
and `run_manifest`, and a `failure_report` binding. The report must contain:

```json
{
  "schema_version": "article2_phase16_closed_source_failure_v1",
  "status": "SOURCE_STAGE_CLOSED_UNAVAILABLE",
  "case_id": "CASE_ID",
  "config_sha256": "ACTUAL_CONFIG_SHA256",
  "closed_utc": "UTC_TIMESTAMP",
  "reason": "Concrete bounded-source failure",
  "detector_metrics_available": false
}
```

## Separately adjudicated reference inventory

`inventory.json` contains:

- `schema_version: "article2_phase16_reference_inventory_v1"`
- `status: "SEALED_AFTER_DECISIONS_INDEPENDENTLY_ADJUDICATED"`
- `decision_study_sha256`, `reference_acquisition_started_utc`, `sealed_utc`
- `prepared_by`: a nonempty preparer identity
- `independent_review`: binding to the review below
- `cases`: LiFi then Revest, including cases with no verified references.

Each case has `case_id`, `execution_inventory_status`, nonempty
`completeness_rationale`, `completeness_evidence` (list of bindings), and
`references` (all found deduplicated candidates, not only detector-selected or
notified transactions). Allowed inventory statuses are the frozen
`COMPLETE_WITH_POSITIVE_CLOSURE_EVIDENCE`, `KNOWN_SUBSET_ONLY`,
`UNRESOLVED_CONFLICT`, and `NO_VERIFIED_EXECUTION_UNDER_CAP`.
The default scientific interpretation is KNOWN_SUBSET_ONLY. COMPLETE requires
nonempty positive closure evidence, at least one applicable verified execution,
and no unresolved or cap-unverified candidate.

Each reference has these fields (case ID and inventory status are inherited
from its enclosing case):

| Field | Contract |
|---|---|
| `chain_id`, `transaction_hash` | Ethereum 1, canonical lowercase 32-byte hash; unique within case |
| `primary_source_locations_and_hashes` | List of `{artifact: binding, url: string, location: string}`; primary evidence, not search snippets |
| `reported_role` | Nonempty retained role; positives require `SUCCESSFUL_UNAUTHORIZED_EXECUTION` |
| `actual_identity_or_unavailable` | Full driver transaction identity object or null |
| `success_status_or_unavailable` | `SUCCESS`, `FAILED` or `UNAVAILABLE` |
| `in_fixed_window` | Boolean checked from exact timestamp, or null with unavailable identity |
| `adjudication_status` | `VERIFIED_APPLICABLE_EXECUTION`, `VERIFIED_OUTSIDE_WINDOW`, `NOT_ATTACK_EXECUTION`, `UNRESOLVED` or `UNVERIFIED_DUE_TO_CAP` |
| `reviewer_rationale` | Nonempty disposition explanation |
| `source_coverage_audit_binding` | Binding to the independent exact-identity evidence audit below |

A complete transaction identity contains exactly `chain_id`, `block_number`,
`block_hash`, `transaction_hash`, `transaction_index`, `event_time_ns`. Do not
invent missing provider fields; use null identity and an unresolved disposition.
Successful identity and primary attack role are both required for positives.

Each reference source audit contains:

```json
{
  "schema_version": "article2_phase16_reference_source_audit_v1",
  "case_id": "CASE_ID",
  "chain_id": 1,
  "transaction_hash": "REAL_CANDIDATE_HASH",
  "identity_status": "VERIFIED_OR_UNAVAILABLE",
  "success_status": "SUCCESS_FAILED_OR_UNAVAILABLE",
  "core_selection_status": "SELECTED_OBSERVED_NO_CORE_EMITTER_OR_UNAVAILABLE",
  "core_log_count": null,
  "full_core_scan_or_terminal_logs_complete": false,
  "identity_evidence": [],
  "selection_evidence": [],
  "evidence_tier": "ENUMERATED_SOURCE_ARCHIVE_OR_BLOCKSCOUT_INDEXER_OR_UNAVAILABLE",
  "rationale": "Concrete provenance and bounded-coverage explanation"
}
```

The `*_OR_*` strings above describe alternatives; choose one exact alternative.
Evidence lists contain file bindings relative to the audit file. Verified
identity requires nonempty identity evidence. SELECTED requires a matching
complete selected observation, its positive core count and selection evidence.
OBSERVED_NO_CORE_EMITTER requires verified identity, zero core count, no selected
record, a true complete-scan/terminal-log flag, and retained selection evidence.
The reviewer must inspect that evidence: the flag alone is not proof. A retained
complete fixed-window address/hash scan at the declared dataset tier suffices;
no receipt-root or full-chain proof is claimed. Merely failing to find the hash
in an observation JSONL file does not suffice. UNAVAILABLE requires null core
count. An already validated selected input supplies source evidence even if an
additional reference audit is unavailable; an unselected identity never obtains
that inference from absence alone.

The independent review file contains:

```json
{
  "schema_version": "article2_phase16_reference_review_v1",
  "status": "APPROVED_FOR_EXACT_REFERENCE_JOIN",
  "decision_study_sha256": "ACTUAL_STUDY_SHA256",
  "reference_cases_sha256": "SHA256_OF_CANONICAL_INVENTORY_CASES_ARRAY",
  "reviewer": "Identity distinct from prepared_by",
  "reviewed_utc": "UTC_TIMESTAMP",
  "primary_roles_checked": true,
  "identity_status_window_checked": true,
  "source_coverage_checked": true,
  "inventory_completeness_checked": true
}
```

`reference_cases_sha256` uses `semantic_flow_replay.digest(inventory["cases"])`
before adding any internal join fields. Review follows reference acquisition
start and precedes inventory seal. The reference acquisition start must be at
or after the both-case decision-study seal. This structure avoids a circular
inventory/review hash dependency.

## Output interpretation

- `coverage.json`: 27 aggregates per case, all 30 daily loads per aggregate,
  exact execution funnel, known/unknown denominator and bounds, and 27
  across-case incident comparisons over both intended cases.
- `reference_funnel.jsonl.gz`: every verified applicable execution in every
  method/policy/budget aggregate, including independently proved no-core
  executions outside the selected stream. Original suppression codes survive.
- `candidate_adjudications.jsonl.gz`: every candidate disposition, including
  unresolved metadata, outside-window roles, non-attacks and audit-cap overflow.
- `join_receipt.json`: output byte counts, file hashes and input/code seals.

Only an emitted notification with the exact same `(chain_id, transaction_hash)`
earns an execution hit. Count skips semantic outflow/history gates. Missing
unselected source evidence yields UNKNOWN and bounds, not a miss. Empty verified
denominators are undefined. No hit on an incomplete inventory is indeterminate.
A complete incident miss requires positive inventory closure and complete
observation evidence. A hit needs at least one exact verified notification.
Nonreference notifications remain UNKNOWN; this procedure estimates no precision
or false-positive rate and supports no prevention or causal claim.

## Focused synthetic checks

```bash
python papers/monitoring_jss/phase16/reference/test_exact_reference_join.py -v
```

This runs only the new join tests. It imports the earlier synthetic fixture
helpers without running their suite and constructs invented two-case 30-day
sealed streams. No HTTP request, primary reference, real attack hash, old suite
or historical experiment is executed. The test fixture assertions are explicitly
synthetic and do not establish empirical source completeness.
