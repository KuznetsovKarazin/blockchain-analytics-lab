# Full retained observations for the Phase30 streams

This extension retains the raw event payloads that were absent from the V6.1
public observation bundles. The old bundles stored derived features and
all-emitter payload digests. The new evidence includes original HTTP response
bytes, normalized full event rows and indexed successful-execution metadata,
so an offline user can reproduce the payload-to-feature transformation.

The population is unchanged: the original AWS-selected transactions for Saddle
(`cohort28_07`, 44), XCarnival (`cohort28_11`, 43) and Audius
(`cohort28_14`, 38), for a total of **125**. The expected all-emitter log count is
**2,103**. Neither detector outputs nor attack-reference hashes select the
transactions. Original Phase28–30 files remain unchanged.

## Verified result (29 October 2026)

**PASS:** all 125 selected transactions and all 2,103 event rows. Every canonical
raw payload digest equals its V6.1 digest; every frozen feature field and every
independently reconstructed event count/token flow matches. Three altered-data
negative tests are rejected. The same result was obtained from a fresh temporary
extraction of `raw_observations.zip`, with zero verification network requests.

| Stream | Transactions | Event rows | Retained HTTP responses | HTTP response bytes |
|---|---:|---:|---:|---:|
| Saddle | 44 | 850 | 92 | 2,816,353 |
| XCarnival | 43 | 1,200 | 107 | 3,478,583 |
| Audius | 38 | 53 | 76 | 172,021 |
| Total | 125 | 2,103 | 275 | 6,466,957 |

The deterministic ZIP contains 409 files and is 1,307,523 bytes. Its SHA-256 is
`3e1a3de3454c886c7a051db6780a876f435d2a96011faf1854aa0f8b53d8d77d`.
The Git artifact stores this archive, source code, reports and checksums;
hundreds of uncompressed working files under `data/` are not tracked.

## Reproduce offline

From the repository root:

```bash
python papers/monitoring_jss/phase31/raw_payload_audit/verify_all.py --archive papers/monitoring_jss/phase31/raw_payload_audit/raw_observations.zip --integrity-tests
```

This safely extracts the archive into a fresh temporary directory, verifies all
three cases, and writes
`FULL_RAW_OBSERVATION_AUDIT.json`. A `PASS` requires all 125 transactions;
partial results are not described as complete observations. Without `--archive`,
the verifier uses `data/` if available, otherwise the same ZIP automatically.
Archive extraction rejects absolute or parent-traversing paths, symlinks,
duplicate normalized paths and excessive uncompressed sizes. The three negative
integrity checks use temporary copies and must reject a modified raw response,
a modified normalized event and modified execution-success metadata.

Each case's `offline_verification.json` reports exact per-transaction evidence:

1. Every captured HTTP body matches its recorded length and SHA-256, and every
   receipt extends the preceding receipt's hash chain.
2. Indexed transaction hash, success status, block number, transaction position
   and timestamp match the frozen selected identity.
3. Every logs endpoint and pagination cursor is retained through the terminal
   page; normalized log positions/counts and all transaction identities match
   the original AWS-selected population.
4. The canonical normalized all-emitter payload digest equals the exact digest
   published in V6.1 for that transaction.
5. Re-extraction reproduces every frozen scientific feature field and its
   observation digest. Transport-only pagination counts need not be identical
   if the indexer's pagination changes.
6. A separate decoder reconstructs every event-shape count, transfer category,
   token flow, raw amount and net event-flow field and compares them exactly.

`verify_all.py` verifies locally and makes no network requests. No attack
reference or detector-scoring module is imported by this collector/verifier.
The earlier 441-cell replay remains in `../replay_audit/`.

## Optional reacquisition and resume

Run one case per output directory. Cases can run concurrently because their
receipt chains and files are independent:

```bash
python papers/monitoring_jss/phase31/raw_payload_audit/collect_and_verify.py --case cohort28_07 --out papers/monitoring_jss/phase31/raw_payload_audit/data/cohort28_07
python papers/monitoring_jss/phase31/raw_payload_audit/collect_and_verify.py --case cohort28_11 --out papers/monitoring_jss/phase31/raw_payload_audit/data/cohort28_11
python papers/monitoring_jss/phase31/raw_payload_audit/collect_and_verify.py --case cohort28_14 --out papers/monitoring_jss/phase31/raw_payload_audit/data/cohort28_14
```

Existing per-transaction bundles are verified before reuse. A bundle is written
atomically only after all historical-digest and feature checks pass. HTTP bodies
and receipt entries are retained even when an attempt fails; duplicate requests
from a resumed acquisition remain visible. An interrupted first serial attempt
was resumed as independent case workers to reduce wall time; previously
verified evidence was reused without changing selection or scientific methods.

Defaults per worker are at most 1,200 requests, 100,000,000 cumulative response
bytes and 1,800 seconds per invocation, with up to three attempts for transient
failures and no automatic retry of HTTP403. An `INCOMPLETE` manifest records
failures or missing data. A `STOP` file inside an output directory requests a
cooperative pause before the next transaction; remove it before resuming.

## Files and limits

- `data/<case>/responses/`: exact gzip-compressed HTTP response bodies.
- `data/<case>/http_receipts.jsonl`: public endpoint URLs, statuses, retrieval
  times, byte lengths, body digests and chained receipt digests.
- `data/<case>/bundles/<case>/<tx>.json.gz`: normalized full logs, original
  transaction metadata, source identity and receipt pointers.
- `data/<case>/acquisition_manifest.json`: source pins and acquisition progress.
- `data/<case>/offline_verification.json`: independent offline verification.

The source tier remains **AWS-selected identities/counts plus Blockscout
payloads and status**. The additional retained bytes make the transformation
reproducible; they do not turn indexer observations into original AWS topics/data
or cryptographically authenticated Ethereum receipts. A hash chain detects
subsequent alterations relative to its published head; it does not authenticate
the historical correctness of the provider. This work does not resolve pending
attack-reference roles, complete incident inventories or economic-loss labels.
