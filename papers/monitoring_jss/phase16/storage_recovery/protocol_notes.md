# Prospective resource and storage recovery

This is a separate candidate for the externally observed ENOSPC termination of A1. It does not activate or broaden the unused wall-continuation candidate (`continuation/protocol.py`, SHA `7afb6398fcf4f10f0db6f92bc18a8f1949e13b411f19241443c86d8d0d811fff`). No code or test in this directory constitutes root acceptance.

The original checkpoint remains `OPEN_REQUEST_PENDING`. An external attestation supplies the observed exit code, verbatim ENOSPC error, terminal-tool provenance and the interval between the last running observation and first ended observation. It does not manufacture `failure.json`, an exact failure timestamp, a producer terminal status, or a wall-limit failure. Original metadata, the empty failed checkpoint and original measurement acceptances remain immutable.

The committed successful prefix is retained as known evidence. The final pending record's persisted zero is a placeholder: actual received and written bytes are unknown. It is never accepted as a source range. The full requested pending range is charged conservatively; a single explicitly accepted reacquisition of exactly the same source key, offset and length is charged again. All failed and pending A2 requests reserve their full declared lengths. Actual known retained bytes and conservative charged bytes remain separate; this is not a claim of complete wire-byte measurement.

The original cumulative 5,000 GET and 16 GiB limits remain. The single operational extension has an absolute deadline of A1 start plus 14,400 seconds, including forensic review, storage preparation and A2; it is not a fresh A2 duration. There are no automatic retries or repeated A2 destinations. Bulk storage is fixed to `/tmp/article2_phase16_runtime_159bf77d8682/attempt2`. Original A1 is preserved at sibling `attempt1`, with its historical logical path retained as a hash-checked symlink relocation.

The source layout changes to immutable authenticated range blobs exposed through a strict Arrow view. Only proven covered extents can be read; absent bytes cannot be supplied as zeros. Before import, the new gate must pass. The collector then rehashes every imported successful A1 range. Independent transport and source auditors check the compact representation and unchanged projections. All 113 source objects, both cases, full 30-day windows, method parameters, thresholds, grouping, budgets, daily resets, and reference rules remain byte-for-byte identical in the original plan fields. Already prepared days and any partial core-selection seals must compare exactly.

## Exact artifact chain

All bindings are `{path, sha256}`. Code bindings are repository-relative; forensic bindings use absolute paths. The helper performs metadata validation only: no HTTP, parquet payload import, row decoding, transfer decoding or replay.

1. `forensic_bindings.json` is a plain dictionary with exactly `metadata_inventory`, `allocation_review`, `path_relocation`, `external_resource_failure_attestation`, and `accepted_range_review`. The last binding identifies the root receipt that verified every committed successful range before auxiliary-file cleanup. The attestation binds these supporting reports and the runtime observer log.
2. `first_attempt_seal` uses schema `article2_phase16_external_resource_closure_seal_v1`, status `EXTERNALLY_CLOSED_ENOSPC_CHECKPOINT_PRESERVED`. It binds all existing JSON/checkpoint metadata and explicit absence of producer failure/result, the forensic dictionary, original plan, process-end bracket, known request/byte prefix, null pending received bytes, full pending reservation, and completed/partial daily seals. Its `parent_root` is the fixed relocated A1 path. It is external closure evidence, not scientific source admission or recovery acceptance.
3. `recovery_plan` uses schema `article2_phase16_storage_recovery_source_plan_v1`. It copies every original field unchanged except the schema and adds `original_plan_binding`, `storage_recovery_transport` equal to the helper's exact `LIMITS`, and six `storage_recovery_execution_bindings`: `protocol.py`, `compact_collector.py`, `pipeline.py`, `independent_transport_audit.py`, `independent_compact_reader.py`, `audit_sources.py`.
4. `exposure_report` retains schema `article2_phase16_source_only_exposure_report_v1`, status `ROOT_REVIEWED_SOURCE_ONLY_EXPOSURE`, `first_attempt_seal_sha256`, `reviewed_utc`, nonempty `reviewer` and `exposure_description`, the seal's complete/partial day names, `source_payload_exposed:true`, and false `detector_scoring_started`, `new_reference_acquisition_started`, `performance_or_reference_results_examined`.
5. The prospective amendment uses schema `article2_phase16_storage_recovery_acceptance_v1`, status `ACCEPTED_BEFORE_RECOVERY_IMPORT_AND_REQUESTS_ONLY`, current `accepted_utc`, `accepted_before_recovery_source_import:true`, `accepted_before_recovery_requests:true`, `source_payload_previously_exposed:true`, bindings `recovery_plan`, `first_attempt_seal`, `exposure_report`, and both `original_measurement_acceptances` keyed by case. It copies `parent_evidence_bindings` and `forensic_bindings` exactly from the seal, pins `recovery_output_root` to the fixed A2 path, and specifies `manual_reacquisition:{parent_request_ordinal,source_key,start,length}` exactly matching the pending request. The historical assertion `accepted_before_affected_payload` is prohibited here. Ordering is external termination → attestation → external seal → exposure review → amendment → A1 byte import/new HTTP.
6. Independent transport must return `PASS_STORAGE_RECOVERY_TRANSPORT_ORIGINAL_BYTES` and bind the full `multiattempt_ledger`, including the unresolved parent GET and conservative costs. Independent source review retains `PASS_SOURCE_SELECTION_AND_RAW_BUNDLES`, with `storage_recovery_amendment_sha256`, original/new plan identities, transport identity, current adapter and compact reader hashes, frozen original row-auditor hash, and independently checked prior-exposure equality. Only then may the pipeline assemble both input manifests.
7. A separate current pre-replay authorization uses schema `article2_phase16_storage_recovery_pre_replay_authorization_v1`, status `ACCEPTED_FOR_FROZEN_REPLAY_AFTER_AMENDED_SOURCE_AUDIT`, `accepted_before_replay:true`, false scoring/reference-started fields, and bindings `storage_recovery_amendment`, `transport_audit`, `source_review`, `multiattempt_ledger`, plus both `input_manifests`. It is accepted after completed source review. `validate_pre_replay_authorization` validates all inputs through the unchanged frozen driver before a separate launcher may score. Both decision stages must subsequently close and be sealed before reference acquisition.

## Commands for the root workflow

Run from the repository root. These commands create reviewable metadata only; none creates an acceptance automatically.

```sh
python papers/monitoring_jss/phase16/storage_recovery/protocol.py prepare-candidate-plan \
  --original-plan ORIGINAL_PLAN --expected-original-plan-sha256 ORIGINAL_SHA \
  --output NEW_CANDIDATE_PLAN

python papers/monitoring_jss/phase16/storage_recovery/protocol.py seal-external-resource-closure \
  --parent-root /tmp/article2_phase16_runtime_159bf77d8682/attempt1 \
  --original-plan ORIGINAL_PLAN --expected-original-plan-sha256 ORIGINAL_SHA \
  --forensic-bindings FORENSIC_BINDINGS --expected-forensic-bindings-sha256 FORENSIC_SHA \
  --output NEW_EXTERNAL_SEAL
```

Root then reviews exposure and writes the explicit prospective amendment. Existing acceptance files are not edited. Before the pipeline can construct a `ResourceSession` or read/import source bytes:

```sh
python papers/monitoring_jss/phase16/storage_recovery/protocol.py validate-amendment \
  --amendment NEW_AMENDMENT --expected-amendment-sha256 NEW_AMENDMENT_SHA
```

The pipeline separately pins the protocol SHA before import and repeats this validation. `--historical` validates an already used chain for auditing and never grants acquisition. The source-ready and pre-replay functions similarly revalidate the same prospective acceptance and exact bindings. All output files are exclusively created; no existing seal is overwritten.

This amendment changes operational source acquisition and representation after source-only exposure. It cannot support a claim that the new storage implementation was frozen before original payload exposure. The resulting study must retain A1 failure, exposed membership, this prospective amendment, both cost ledgers and all admission gates. Scientific results remain uncomputed until the complete source gate passes.
