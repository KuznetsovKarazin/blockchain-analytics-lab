# Phase16 projected source pipeline

`streaming_pipeline.py` prepares the declared 37-day Ethereum union for two exact 30-day fixed-address cases. It calls the Phase16 range collector and the unchanged public Phase15 retained observation core/driver. It never reads attack labels or runs detector scores.

All block headers (including February18 and March28 boundary-only days), transaction metadata and log identity/address/hash projections are scanned. Per-day Arrow arrays validate the full projected populations without converting millions of rows to Python dictionaries. Topics/data are materialized only from row groups containing selected logs, then only selected rows become dictionaries. The explicit source interface differs from Phase15's complete normalized-row adapter: nonselected topics/data are not validated. It does not claim receipt-root or full-chain proof.

Per day, selection by core-emitter address is sealed before all-emitter transaction expansion and before transfer decoding. `core_selection.json`, `scan.json`, `headers.json`, `source_parts.json` and `prepared.json` retain membership and coverage evidence. Empty selection is covered only after successful full scans; errors leave a failed preparation, never zero observations. `source_parts.json` binds the exact prepared cases/bundles digest. The independent auditor, not this producer, supplies the driver-shaped PASS audit.

`collect` verifies exact root acceptances, source-plan wrapper and nested plan, every execution binding, pinned source inventory, dependency versions and wheel digest. Whole-file reuse requires a frozen original source SHA/size/ETag and bound retained archive/member expectation; the runtime path alone may change. Range requests obey the single frozen collector attempt and caps. No retry is added by this pipeline.

```bash
python streaming_pipeline.py collect \
  --repo /absolute/repository \
  --plan /absolute/frozen_plan.json --expected-plan-sha256 PLAN_SHA \
  --dependencies /absolute/pyarrow/site --wheel /absolute/pinned.whl \
  --acceptances /absolute/runtime_acceptances.json \
  --reuse-map /absolute/runtime_reuse_map.json \
  --output /absolute/new_collection_directory
```

The acceptances runtime JSON maps each config case ID to `{path,sha256}` of its exact root receipt. The reuse runtime JSON maps each source key to `{path,source_key,sha256,size_bytes,etag_opaque}`. `--reuse-map` may be omitted. `source_plan_candidate.json` is a concrete metadata-only candidate for root review, not an acceptance or acquisition authorization.

The collector output includes all113 original source manifests in `transport_sources.json`, private source paths in `runtime_source_paths.json`,37 prepared day directories,39-day header chronology, both30-day selection manifests and `collection_result.json`. The independent auditor may reopen verified retained projections to reconstruct selection and selected bundles. Full address/hash projections remain available for later post-decision reference coverage checks.

After an independently authored audit is accepted:

```bash
python streaming_pipeline.py assemble \
  --config /absolute/accepted_config.json \
  --collection /absolute/collection_directory \
  --audit /absolute/source_audit.json --expected-audit-sha256 AUDIT_SHA \
  --output /absolute/new_observation_directory
```

Assembly verifies actual audited sidecar hashes and prepared payload digest before calling the exact retained transfer decoder. It emits30 observation JSONL files, selection/audit copies and a Phase15 input manifest, then loads the whole window through the unchanged driver. It does not score. Invoke the unchanged Phase15 driver separately with its root acceptance to apply the frozen methods and independent UTC-day reset.

Run the new synthetic tests with pinned PyArrow on `PYTHONPATH`:

```bash
python -m unittest discover -s papers/monitoring_jss/phase16/pipeline -p 'test_*.py' -v
```

The14 checks cover two-core membership, all-emitter expansion, complete scans, covered-empty selection, exact220-bit transfer amounts, invalid status/header counts/log gaps/null addresses/day boundary, 30-day driver compatibility, post-audit tampering, root execution wrappers and frozen reuse bindings. Synthetic source-audit fixtures are confined to tests and are not scientific evidence.
