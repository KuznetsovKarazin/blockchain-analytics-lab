# Bounded original-byte Parquet collector

`range_collector.py` supplies the transport and sparse-file interface used by the Phase16 pipeline. It acquires no labels, performs no contract calls and changes no detector rule. The caller must first verify the separately accepted measurement/source plans and exact source inventory. Constructing a reader is not scientific admission.

The fixed source inventory has 111 study objects over the LiFi/Revest union, plus two block objects containing the immediately adjacent February18/March28 headers. Boundary objects support UTC/header checks and do not extend either study window.

## Interface

```python
session = RangeSession(collector_plan, new_capture_directory)
reader = SourceReader(source, session, cache_directory, pa, pq, reuse=None).open()
for row_group_index, table in reader.iter_row_groups(["address", "transaction_hash"]):
    # The caller records every scanned row group and applies the fixed predicate.
    pass
reader.ensure_columns(required_fields, row_groups=selected_row_group_indices)
manifest = reader.manifest()
session.close("COMPLETE")
```

The pipeline is the scientific command-line entry point; its acceptance, input and output bindings remain mandatory. `read_row_group(index, columns)` and `iter_row_groups(columns, row_groups=None)` ensure every requested field's leaf chunks before invoking PyArrow. Only columns listed in the accepted collector plan can be read. Row groups are explicit, sorted and unique. Reading the exposed local path directly would bypass this guard and is not the accepted API.

Each source record has `table`, `day_utc`, `key`, `size_bytes`, `etag_opaque` and an optional exact `url`. The endpoint and key layout are restricted to the named AWS Ethereum archive. Listing exhaustion and complete day/table membership are established upstream and independently audited; the collector cannot infer them from one file.

## Original bytes and transport limits

The collector reads the actual leading four `PAR1` bytes, the eight-byte trailer and the exact footer. The small in-memory footer decoder envelope is used only to inspect offsets/schema; actual sparse-file leading bytes are authenticated by the range response or a verified whole object. Footer statistics values are never accessed, exported or used for selection.

Every GET sends `If-Match` and an exact byte range. Acceptance requires the original URL, status206, identical opaque ETag, exact Content-Range and Content-Length, and no content encoding. Invalid headers are rejected before reading the body. Partial bodies are retained and counted, but never accepted as readable ranges. The deadline is checked after each read and after closing the response; a late final chunk is counted but not accepted. Any failed HTTP attempt prevents the same live session from starting another request or reporting completion. Redirects, automatic retries, HEAD requests and provider switching are disabled.

The proposed ceilings are 5,000 GETs, 16GiB of retained HTTP response bytes, 7,200 seconds for the original attempt, 60 seconds per request, 256MiB per range and 1MiB per footer. Individual objects are at most2GiB, with bounded rows, row groups and column counts. Exact values are frozen by the root source plan; the library validates their types and enforces them. A merged column span larger than the range limit is split deterministically. The byte ceiling is not a prediction of actual traffic.

Only needed columns are fetched. A pipeline can scan every address/transaction-hash row group, seal the fixed transaction set, then acquire the additional column chunks needed for complete selected bundles and real transaction statuses. It must never use transfer values or labels to expand the transaction set. Blocks and transaction identity/status columns may be projected without acquiring transaction input payloads.

Successful response bodies are stored once at their original offsets in `source.parquet`, with SHA256, original offset/length and HTTP metadata in the range receipts. This avoids duplicating large range bodies. Holes in sparse files are not acquired zeros and are not content-hashed as full original objects. The manifest records acquired chunks and every decoded projection separately. The independent audit must validate these ranges against retained receipts and the actual projection schedule.

## Reuse and resume

An explicit whole-object reuse entry contains `path`, `sha256`, `source_key`, `size_bytes` and `etag_opaque`. All must agree with the frozen original-member evidence and inventory. The collector hashes the complete local file and checks its size before reading. A ZIP checksum alone is insufficient. Whole-object reuse performs no HTTP request and remains separately accounted.

`RangeSession(..., resume=True)` can reopen only a clean `OPEN` checkpoint of the same plan and capture directory. It preserves the original UTC start/deadline, cumulative request count and retained response bytes. Pending or failed HTTP attempts cannot be resumed; a new source attempt requires a separately reviewed prospective decision. Every request is recorded as pending before it starts. Thus a process interruption cannot silently erase a possibly issued request and restart its budget.

Range cache receipts must be byte-for-byte identical to successful, already charged capture records in that same attempt; all cached response bytes are rehashed. A fresh attempt cannot consume another attempt's range cache and reset accounting. A clean capture checkpoint preceding the final cache-index write can recover its already charged successful response without requesting it again. Reuse of a complete original source object is a separate explicit provenance route.

The collector stores one Arrow row-group projection at a time; the caller's buffers and selected bundles determine additional memory use. Peak memory and full-window transfer time have not yet been measured. Source metadata totals and the earlier one-date projection costs must not be presented as measured full-window performance.

## Focused checks

The 21 distinct new producer tests use invented Parquet bytes and mocked HTTP responses only. They passed across three documented executions as review findings added guards; repeated executions are not additional distinct tests. They cover projected bytes and offsets, sparse-hole rejection, original magic, invalid status/ETag/range/encoding/redirect, partial-body accounting, request/byte limits, deterministic splitting, source-bound whole-object reuse, cumulative clean resume, pending/failure refusal, late reads and cache tampering. Existing test suites and real incident rows are not used. Independent transport checks are recorded separately under `phase16/qa`.
