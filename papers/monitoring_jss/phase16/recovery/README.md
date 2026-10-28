# Retained metadata and original-object recovery

`source_union.json` contains 111 study objects covering the 37 UTC dates from
2022-02-19 through 2022-03-27, plus block objects for the two surrounding dates.
The 113 objects total 21,481,727,176 declared whole-object bytes. These totals
describe source metadata; they are not download or row-processing totals.

`build_source_union.py` verifies six retained S3 listing XML digests, terminal
pagination and object identities, then cross-checks all 180 per-case inventory
records from Phase14 LiFi and Phase15 Revest. The two case inventories overlap
on 69 objects. Dates are ordered ascending, then blocks, logs and transactions.
ETags remain opaque source-version identifiers, including multipart suffixes.

`reuse_expectations.json` describes nine original Phase4 ZIP archives for
2022-03-19 through 2022-03-27. Prior producer and independent-audit metadata agree
on archive sizes/hashes and the 18 canonical raw block/log members. Their source
keys, sizes and ETags match the union inventory. Archive bytes total 2,367,074,342;
canonical raw source bytes total 1,942,523,039. These expectations do not claim
that the original bytes have been verified during Phase16. Archive locators and
runtime paths remain private. Earlier selected-emitter outputs are not reused.

`reuse_source_receipts/` retains 18 per-source expectation records with original
acquisition metadata and prior manifest/audit digests. The map in
`whole_object_reuse_expectations.json` is embedded unchanged in the common source
plan. Its `acquisition_receipt` bindings identify retained source expectations;
their status explicitly disclaims new acquisition or current byte verification.

`verify_recovered_archives.py` must run only after both real per-case root
measurement acceptances exist. It verifies their pinned receipt digests through
the frozen Phase15 driver, exact case IDs/populations/windows, a shared source
plan and its own execution-source binding. The shared plan must contain
`inventory_binding` and `reuse_expectations_binding`, each with the canonical
repository-relative metadata path and its exact `sha256`. These must match the
independently supplied command-line digests. It then verifies each complete ZIP
size and SHA256 before ZIP inspection, rejects unsafe/duplicate paths, and
extracts only root members `headers.parquet` and `logs.parquet`. Selected members
must match expected size, CRC and whole-object SHA256 and cannot be symlinks.
The archive is hashed and inspected through one open handle. Output must use a
fresh private directory; existing recovered sources are never overwritten.

Successful recovery writes a runtime-only `reuse_map.json` keyed by source key;
each value contains `path`, `sha256`, `source_key`, `size_bytes` and `etag_opaque`.
This matches the collector's reuse interface. A failure produces no accepted
reuse map; partial output and its failure receipt must not enter the collector.
The utility neither fetches network data nor decodes Parquet or scores detectors.

Example after the exact root acceptance freeze and authorized archive retrieval:

```bash
python papers/monitoring_jss/phase16/recovery/verify_recovered_archives.py \
  --acceptances PRIVATE_ACCEPTANCE_MAP.json \
  --reuse-expectations papers/monitoring_jss/phase16/recovery/reuse_expectations.json \
  --expected-reuse-sha256 ROOT_PINNED_EXPECTATIONS_SHA256 \
  --inventory papers/monitoring_jss/phase16/recovery/source_union.json \
  --expected-inventory-sha256 ROOT_PINNED_INVENTORY_SHA256 \
  --archive-paths PRIVATE_ARCHIVE_PATH_MAP.json \
  --output FRESH_PRIVATE_RECOVERY_DIRECTORY
```

The acceptance map has exactly `lifi` and `revest` entries, each containing
`config_path`, `acceptance_path` and `acceptance_sha256`. The archive-path map
contains exactly the nine expected UTC dates mapped to local original ZIPs.

The focused new checks use synthetic byte strings in temporary ZIPs and
temporary acceptance fixtures explicitly marked synthetic. They do not acquire
or consume real archive rows and never authorize actual recovery:

```bash
python -m unittest discover -s papers/monitoring_jss/phase16/recovery -p test_recovery.py -v
```

`preflight_status.json` records the metadata and synthetic checks at their
pre-acquisition checkpoint. Later acquisition receipts must report actual bytes
and rows separately; a metadata-ready status is not a scientific result.
