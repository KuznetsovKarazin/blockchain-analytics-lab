# Phase 6: proposed source-partition metadata availability

The scope is a bounded feasibility check for the already proposed Revest window
[2022-02-26T00:00:00Z, 2022-03-28T00:00:00Z): 30 full UTC dates. This is not a
final scientific cohort, new label adjudication, or detector evaluation. The
proposal and exact date/table prefixes are fixed before any new network call.

Use only the existing AWS Public Blockchain Data S3 endpoint from
`acquire_protocol_logs.py`: `https://aws-public-blockchain.s3.us-east-2.amazonaws.com/`.
Request ListObjectsV2 metadata for `v1.0/eth/logs/date=DAY/` and
`v1.0/eth/blocks/date=DAY/`. Do not GET/HEAD any Parquet object, log payload, receipt,
trace or individual Revest transaction. Do not query other providers.

Each response is limited to 1 MiB and a 30-second network timeout. Four modest
metadata workers are allowed. Up to two pages per exact prefix are permitted:
at most 120 calls and 120 MiB response bytes, with no retries or redirects. A
provider, transport or validation failure stops unstarted requests; calls already
in flight may finish. A pagination cap or failed check produces an inconclusive
partition, never an inferred absence.

Require the expected S3 XML namespace, bucket name and exact returned Prefix.
Validate each returned key begins with the requested prefix, nonnegative integer
Size, opaque ETag, unique keys, exact KeyCount, and an explicit IsTruncated value.
A truncated page requires a non-repeated continuation token; listing completeness
requires a final IsTruncated=false page. Preserve all returned object keys,
including non-Parquet objects; do not silently filter entries.

Original response XML and request/header receipts remain private outside Git.
Public outputs retain complete key/size/ETag metadata and per-response SHA-256;
that digest describes the XML bytes only, not any unacquired source object.
Record command, timestamps, code/config/freeze digests, every partition outcome,
counts, and listed object sizes. ETags are not presented as content hashes.

Offline checks precede the freeze and live listing calls: valid and empty XML,
wrong prefixes, out-of-prefix and duplicate keys, negative/non-integer sizes,
missing continuation token, token loops, response caps, and cancellation.
The completed run must leave the frozen script and config bytes unchanged.

A nonempty complete listing supports metadata availability only. It establishes
neither readability of the object contents nor verified headers, source coverage
for a monitored emitter, attack labels, contract identity, or an independent test.
