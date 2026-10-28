# Storage-recovery pipeline candidate

This wrapper is isolated from the unused wall-continuation authorization. It requires the new prospective storage/time amendment before reading prior payloads, importing authenticated source ranges or making any new request. The externally sealed ENOSPC closure and pending request remain original evidence; the pipeline does not rewrite A1 as a successful or wall-failed attempt.

The original scientific source plan remains unchanged. A new envelope binds the resource recovery, six new implementation/auditor files, forensic closure and relocation evidence, and one fixed A2 destination. The original `prepare_day`, `selection_for_case` and `assemble_case` are imported only after checking their exact source hashes. The previous continuation module supplies only explicitly listed pure JSON/binding/reproduction helpers; its protocol and acquisition functions are never called.

All A2 source blobs, descriptors, transport records and assembled observations must remain under `/tmp/article2_phase16_runtime_159bf77d8682/attempt2`. The compact collector imports only authenticated successful A1 ranges into immutable response blobs. An unaccepted pending A1 range is excluded and conservatively charged at its full requested length. The wrapper invokes its one explicitly authorized exact reacquisition before preparation. Neither the original GET budget nor the byte budget resets; the absolute deadline remains A1 start plus 14,400 seconds.

`runtime_source_storage.json` maps every source key to `{storage_kind,path}`. The supported kinds are `compact_descriptor` and `verified_whole_object`. A compact descriptor is never represented as a Parquet file. The collector's interval reader supplies the original-offset view without writing a full-sized sparse file. `runtime_source_paths.json` is not produced. The typed map's exact SHA is included in the collection result.

Preparation still reads all 39 header days and all 37 study days, expands address-selected transactions to every emitter's logs, and uses the frozen validation functions. Every previously completed day's selection and exact cases/bundles payload must reproduce. Any core selection already sealed for the next incomplete day must also reproduce. Source manifests describe the new storage provenance; scientific-payload differences are fatal.

```bash
python papers/monitoring_jss/phase16/storage_recovery/pipeline.py collect \
  --amendment /absolute/storage_recovery_amendment.json \
  --expected-amendment-sha256 AMENDMENT_SHA \
  --expected-protocol-sha256 NEW_PROTOCOL_SHA \
  --dependencies /absolute/pinned_pyarrow_site \
  --wheel /absolute/pinned_pyarrow.whl \
  --reuse-map /absolute/original_verified_reuse_map.json \
  --output /tmp/article2_phase16_runtime_159bf77d8682/attempt2
```

`collection_result.json` uses `phase16_storage_recovery_collection_result_v1` and binds the actual new plan, storage amendment, original plan, typed source locations, all 113 source manifests, both selection manifests and prepared days. Producer completion still requires a new independent compact-storage transport audit and an independent source-row audit before transfer decoding.

```bash
python papers/monitoring_jss/phase16/storage_recovery/pipeline.py assemble \
  --amendment /absolute/storage_recovery_amendment.json \
  --expected-amendment-sha256 AMENDMENT_SHA \
  --expected-protocol-sha256 NEW_PROTOCOL_SHA \
  --transport-audit /absolute/transport_audit.json \
  --expected-transport-audit-sha256 TRANSPORT_SHA \
  --source-review /absolute/source_review.json \
  --expected-source-review-sha256 SOURCE_SHA \
  --multiattempt-ledger /absolute/multiattempt_ledger.json \
  --expected-multiattempt-ledger-sha256 LEDGER_SHA \
  --collection /tmp/article2_phase16_runtime_159bf77d8682/attempt2 \
  --output /tmp/article2_phase16_runtime_159bf77d8682/attempt2/observations
```

Assembly validates the new resource-aware source gate and then calls the unchanged original assembler for both cases. It emits exact `{path,sha256}` input-manifest bindings for the separate new pre-replay authorization. It never computes detector scores.

Seven focused synthetic pipeline checks cover explicit storage types, all 113 entries, preservation of 19 completed days plus a partial seal across the 37-day union, unchanged scientific fields, both new gates, fixed external storage, and correct forensic/accepted-plan/pending-request arguments at the collector boundary. No real A1/A2 payload is read by these tests. Low-level compact byte-view and transport checks belong to the separate collector and independent reader suites.
