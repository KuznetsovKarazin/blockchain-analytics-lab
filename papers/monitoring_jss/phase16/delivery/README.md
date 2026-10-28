# Phase16 original-range delivery

These helpers operate after acquisition and are outside the frozen measurement
code. They make no HTTP calls, decode no Parquet rows, and confer no scientific
acceptance. Run only against a quiescent, finalized capture.

`pack_range_capture.py` copies only recorded HTTP response bytes from their
original sparse-file offsets. Every copied body must match its recorded length
and SHA256. HTTP acceptance headers and source identity are checked again.
Archives use ZIP_STORED, fixed ZIP metadata, UTC source day then original request
ordinal order, and deterministic splitting between responses. The 500 MiB cap
includes ZIP headers, central directory, and receipt metadata; an individual
response that cannot fit is rejected. No sparse-hole bytes are stored or hashed
as original evidence, and whole reused objects are not duplicated.

The portable `index.json` is written last and binds archive names, sizes and
SHA256, original metadata files, source identities, unchanged request receipts,
and original ZIP/member provenance references for reused whole objects. The
original source-path map is hash-bound but kept only in the separate private
`OUTPUT.runtime.json`. Absolute paths, including paths embedded in exception
strings, are rejected in portable JSON metadata. Exact metadata is not redacted;
if such a path occurs, retain that capture privately and address its separate
delivery with the operator rather than publishing a modified original receipt.
Keep the final index SHA256 outside the pack. An interrupted pack without its
final index is incomplete. Packing does not delete or modify source evidence.

Complete capture:

```bash
python papers/monitoring_jss/phase16/delivery/pack_range_capture.py \
  --collection "$CAPTURE" --repo "$REPO" --output "$PACK" \
  --expected-plan-sha256 "$RUNTIME_FROZEN_PLAN_SHA" --accepted-plan "$ACCEPTED_INPUT_PLAN" \
  --expected-result-sha256 "$COLLECTION_RESULT_SHA" \
  --expected-transport-sources-sha256 "$TRANSPORT_SOURCES_SHA"
```

`--expected-plan-sha256` pins the exact runtime `frozen_plan.json` bytes.
`--accepted-plan` supplies the original accepted input bytes: their SHA256 must
match `collection_result.plan_sha256`, and their parsed canonical value must equal
the runtime plan. The index preserves both different digests and both exact files.
The argument can be omitted only when both byte serializations already match.
It is not used in failed mode.

Failed capture with finalized `failure.json`, `transport/session.json`, and
`transport/requests.json`:

```bash
python papers/monitoring_jss/phase16/delivery/pack_range_capture.py \
  --mode failed --collection "$CAPTURE" --repo "$REPO" --output "$PACK" \
  --expected-plan-sha256 "$RUNTIME_FROZEN_PLAN_SHA" --expected-result-sha256 "$FAILURE_SHA"
```

Failed mode retains every successful body plus any positive, recorded partial
`response_bytes` whose recorded SHA256 verifies. Partial or otherwise unaccepted
bodies are explicitly forensic, even when their byte count equals the requested
length. Zero-byte failed/pending attempts remain in original request metadata.
Unrecorded bytes after an abrupt process kill are never promoted to evidence.
When source opening failed before its runtime path was published, failed mode
resolves only the collector's canonical `cache/SOURCE_ID/source.parquet` path
from the frozen inventory and original request identity, then verifies each
recorded body. An entirely absent initial runtime path map is supported.
A missing finalized failure file must be addressed separately by the operator;
the helper does not invent a failure result or silently reset an attempt.

Restore:

```bash
python papers/monitoring_jss/phase16/delivery/restore_range_capture.py \
  --pack "$PACK" --output "$RESTORED" --expected-index-sha256 "$INDEX_SHA"
```

Restoration verifies all archive hashes before creating sparse source files,
then verifies each streamed member and writes only its recorded original offset.
It preserves original session/requests and writes collector-compatible
`cache/SOURCE_ID/ranges.json` containing successful receipts only. Failed captures
stay failed and cannot be resumed as a fresh attempt. Sparse holes remain
unavailable evidence, even though filesystem reads would return zeros.

Reused full objects remain unresolved provenance references unless an optional
`--reuse-map` supplies `{source_key: {path, source_key, size_bytes, etag_opaque,
sha256}}`. Each supplied object is hash-verified before attachment; no old ZIP or
whole object is copied. Original ZIPs must be preserved separately. Prepared
days, independent audits, selections, labels and scored results also require
separate preservation: this pack restores source-byte evidence only.

Disk planning must include both current sparse sources and new ZIPs: packing adds
approximately acquired response bytes plus small metadata/ZIP overhead. The
16 GiB transport cap is not an additional free-space guarantee for packaging.
RAM use for range copying is approximately one 1 MiB buffer plus metadata.

Focused offline checks:

```bash
cd papers/monitoring_jss/phase16/delivery
python -m unittest -v test_range_pack.py
```

Tests use tiny synthetic sparse files only. They cover deterministic splitting,
offset/hash round trips and untouched holes, complete/failed separation,
unaccepted partial bodies, old-object provenance and optional attachment,
tampered metadata/range/archive rejection, overlap rejection and archive limits.
