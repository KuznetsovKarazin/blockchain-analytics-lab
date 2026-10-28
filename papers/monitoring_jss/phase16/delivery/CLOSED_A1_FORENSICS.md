# Closed A1 forensic archives

`pack_closed_a1_forensics.py` preserves the canonical files of the externally closed, incomplete A1 attempt without changing its original `OPEN_REQUEST_PENDING` producer status. It performs byte hashing and ZIP compression only. It does not parse Parquet rows, decode transfers, compute detector scores or inspect references.

The declared preservation set is 70 `cache/*/source.parquet` images, all 173 original JSON files, the empty `transport/requests.json.pending` file, and ten explicitly supplied external forensic files. Unrelated and noncanonical relocation working files are excluded. Logs and transactions receive individual archives; block images are grouped below the cap. Metadata and external evidence have a separate archive. Every final ZIP is hard-limited to 500 MiB, including ZIP overhead, and uses DEFLATE level 1 so sparse zero regions remain compact.

Every member has three checked hashes: canonical bytes streamed into the archive, bytes streamed back from the ZIP, and the original file reread after packing. File identity, size and modification/change timestamps are checked around these reads and again at completion. Each archive has its own SHA, bounded size and verification receipt. A renamed ZIP without a passing receipt and final complete index is not a completed preservation result.

A sparse-cache image SHA identifies the exact local forensic artifact. It is explicitly **not** a complete original archive-source SHA. Holes, zeros and other unverified regions do not become source evidence. The pending GET's received body length remains unknown; a recorded zero counter is not treated as proof that zero bytes arrived. Pending bytes remain unaccepted.

All bulk pack output belongs under `/tmp/article2_phase16_runtime_159bf77d8682/forensic_packs`. The packer makes no uploads. The final `forensic_archive_index.json` and per-pack receipts provide the ordered inventory for a separate durable-delivery step.

Restore only after independently obtaining the expected index SHA:

```bash
python papers/monitoring_jss/phase16/delivery/pack_closed_a1_forensics.py restore \
  --index /absolute/forensic_archive_index.json \
  --expected-index-sha256 EXPECTED_INDEX_SHA \
  --output /absolute/new_restore_directory
```

The restore helper verifies each ZIP hash and exact member inventory, rejects unsafe/duplicate paths, checks every uncompressed member hash and skips zero 4-KiB pages to retain a sparse logical image. It preserves exact logical bytes; it does not claim to reconstruct the original filesystem's physical extent allocation. Source acceptance still requires the original receipts and source checks.

Six focused synthetic tests cover sparse roundtrip and restore, unchanged original status/metadata, unknown pending length, source mutation rejection, hard ZIP byte caps, corrupted archives and unsafe member names. Independent static review found no blocker. No real payload is used by these tests.
