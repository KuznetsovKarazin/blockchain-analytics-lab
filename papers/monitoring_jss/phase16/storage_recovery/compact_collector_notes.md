# Compact resource-recovery candidate

No real capture bytes or network requests were used while implementing this
candidate. The original collector, original A1 files and unused wall-continuation
candidate are unchanged. Real construction must follow the independent GO and
the separately validated, current resource/time amendment for both cases.

The candidate imports only receipt-validation helpers from the exact hash-bound
unused continuation module; it never constructs that module's wall session.

```python
session = ResourceSession(
    original_plan['collector'], runtime_root / 'transport', relocated_a1_root,
    parent_bindings=sealed_parent_bindings,
    recovery_plan_sha256=recovery_plan_sha,
    original_plan_sha256=accepted_original_plan_sha,
    forensic_bindings=validated_five_forensic_bindings,
    manual_reacquisition=exact_pending_descriptor,
    pinned_runtime_root=runtime_root,
    repo=repo,
)
session.reacquire_pending_range()  # Exactly one explicitly declared operation.
reader = CompactSourceReader(source, session, session.storage_dir, pa, pq, reuse=reuse)
reader.open()
```

Bulk output is restricted to
`/tmp/article2_phase16_runtime_159bf77d8682/attempt2`; the parent resolves to the
adjacent `attempt1`. The constructor authenticates every successful A1 range and
copies it into a compact immutable blob. It does not read or import the pending
range. These are payload operations, so the constructor is not a metadata-only
preflight. Existing verified whole-object reuses remain read-only original files.

No new full-size or sparse Parquet source files are created. Each response is
buffered up to the frozen256MiB range maximum, hashed, written once outside the
shared workspace, flushed/fsynced, checked for exact length/SHA256, renamed to its
content-addressed name and marked0444. A64MiB free-space margin is required before
a GET or blob write. Failed positive bodies are separately labelled forensic and
excluded from accepted intervals. If persistence itself fails, received bytes
known in memory and durable retained bytes remain separate; the full requested
range stays charged and the recovery fails closed.

Descriptors are `storage/SOURCE_ID/source_storage.json`, with
`storage_kind: compact_descriptor`, original source identity/logical size and
disjoint segments `{start,length,blob_path,blob_sha256,origin_attempt_id,
origin_ordinal,receipt_sha256}`. Blob paths are relative to the descriptor's
directory. `accepted_range_evidence.json` separately binds each unchanged receipt
to an exact runtime-root-relative blob. A1's complete original request ledger,
including the unresolved final request, is retained unchanged in
`inherited_requests.json`; `requests.json` contains only new global-ordinal GETs.

`StrictIntervalFile` permits only reads fully covered by verified intervals. It
rejects a hole before returning any prefix. PyArrow receives authenticated
original footer metadata with `pre_buffer=False`, `buffer_size=0` and single-thread
reads; footer parsing uses only the explicitly identified decoder envelope.
There are no synthetic gap bytes. Reader `.path` is honestly a descriptor path
for compact storage, or an actual Parquet path for verified whole-object reuse;
`.storage_descriptor()` returns this distinction for the runtime storage map.

The producer caches blob verification using path, expected SHA and
device/inode/size/mtime/ctime, then checks immutability before and after reads.
This avoids repeatedly hashing an entire source for each row group. Independent
transport/source auditors reauthenticate blobs separately. A fresh standalone
`StrictIntervalFile` hashes its blobs before use.

The original pending response is never interpreted as an actual zero-byte
outcome: `parent_pending_response_bytes` is null and
`actual_cumulative_response_bytes_complete` is false. Known retained bytes and
conservative resource charges are separate. The full pending length is charged,
as are the remaining declared bytes of any new failed/pending response. The
unchanged5,000GET/16GiB ceilings apply cumulatively; the absolute deadline is
the original A1 UTC start plus14,400seconds. There is no automatic retry or third
attempt. Exactly one explicit pending-range reacquisition is counted as a retry.

New source preparation still uses the frozen original footer/schema/column
validation and projection logic. Scientific windows, source identities, selected
columns, fixed cores, status rules and detector methods are not changed.

Focused synthetic checks use tiny temporary files, mocked HTTP and PyArrow26:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PINNED_PYARROW_SITE" \
  python -m unittest -v test_compact_collector.py
```

The final15 checks pass, including a real synthetic Parquet roundtrip without
creating any new Parquet file, unknown pending-byte exclusion, exact retry lineage,
conservative budgets, header rejection, forensic partial responses, immutable
blob/hash checks, no repeated hashing through the trusted cache, and hole rejection.
