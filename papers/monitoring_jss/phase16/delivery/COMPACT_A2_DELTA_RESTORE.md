# Compact A2 delta restoration

`restore_compact_a2_delta.py` restores the byte artifacts described by a pinned
`phase16_compact_a2_delta_index_v1` index. It does not acquire data, decode rows,
calculate scores, rerun scientific audits, or replace the historical acceptance
receipts. A successful restore receipt explicitly says
`PASS_COMPACT_DELTA_BYTE_RESTORATION_NOT_NEW_SOURCE_AUDIT`.

Required inputs are the delta index and its ZIP files, the A1 forensic index,
either the original A1 ZIP directory or an already restored A1 directory, and a
JSON map from each expected whole-object source key to its existing local file.
The two index SHA256 values must come from the trusted delivery record. Whole
objects are verified in place and are not copied into the output.

```sh
python restore_compact_a2_delta.py \
  --index /downloaded/a2/a2_delta_index.json \
  --expected-index-sha256 <trusted_delta_index_sha256> \
  --a1-index /downloaded/a1/forensic_index.json \
  --expected-a1-index-sha256 <trusted_a1_index_sha256> \
  --a1-pack-root /downloaded/a1 \
  --whole-object-map /downloaded/whole_object_paths.json \
  --output /new/fresh_restore
```

Use `--a1-restored-root /restored/attempt1` instead of `--a1-pack-root` when the
canonical A1 files are already present. This directory must directly contain
`cache/<source_id>/source.parquet`; it is not the directory above `attempt1`.

The output contains `attempt2/` with exact archived metadata, observations and
new response blobs, and reconstructed inherited response blobs. External proofs
remain under `delivery_control/`. Only accepted inherited ordinals below 730
and new ordinals above 730 may become blobs. The unresolved parent ordinal 730
is excluded. Its later accepted reacquisition has its own new ordinal.

Restoration validates the exact accepted-receipt/descriptor/blob population,
source identities, disjoint intervals, durable dependency bindings, ZIP hashes,
member hashes and sizes. Each required A1 canonical image is streamed once,
including holes and bytes outside selected intervals; its complete artifact
hash must match before any reconstructed range from that image is committed.
Those artifact hashes preserve the local cache image and do not assert that
holes or unverified regions are accepted source evidence. The individual range
hashes independently bind the accepted bytes. Full A1 images are not recreated
when restoring directly from ZIPs.

All response blobs are verified again after writing and made read-only with
mode `0444`. Original JSON bytes, including historical absolute paths, remain
unchanged. `relocation_map.json` gives current descriptor and whole-object paths
separately. Its `external_artifact_paths` maps each recorded original absolute
external path to the restored `delivery_control/` artifact; duplicate original
paths are rejected. Older synthetic fixtures without external origin fields
remain valid and contribute no entries to this map. Consumers must explicitly use that map and must not treat historical
audits as newly rerun. A failure leaves `restore_failure.json` where possible and
never writes a successful restore receipt. Partial output must not be consumed.

The production packer enforces the real 729 inherited accepted responses,
113 source identities and complete audit prerequisites. The restorer supports
smaller synthetic fixtures while enforcing the same fixed pending ordinal and
byte/lineage rules. Its focused tests use invented bytes only:

```sh
python -m unittest -v test_restore_compact_a2_delta.py
```

The tests cover both A1 input modes, the producer's exact artifact grouping and
ZIP format, byte-identical metadata including empty observations, no whole-file
copy, read-only blobs, full-cache tampering outside accepted ranges, missing and
orphan evidence, pending-byte exclusion, overlap, traversal, bad archive/whole
hashes, and the required fresh output directory. No actual A2 restore has been
performed as part of this validation.
