# Proposed Revest window: source metadata result

The frozen listing-only check completed on 25 October 2026. All 60 requested
partitions in [2022-02-26, 2022-03-28) UTC returned HTTP 200 and one complete,
nonempty ListObjectsV2 page containing exactly one object. The 60 XML responses
total 40,620 bytes. There were no retries, redirects, alternate providers or
source-object payload requests.

| Table | Complete nonempty daily listings | Listed objects | Listed object bytes (metadata only) |
|---|---:|---:|---:|
| Ethereum logs | 30 | 30 | 6,242,470,841 |
| Ethereum blocks | 30 | 30 | 162,402,110 |
| Total | 60 | 60 | 6,404,872,951 |

These are listing existence and size metadata. No 6.4 GB source download was
performed. Opaque ETags, exact keys and XML response SHA-256 values are retained
in `run_20261025T145900Z/availability.json`; the compact partition table is in
`availability.csv`. Original XML and HTTP receipts are private evidence.

The design freeze predates all calls: 14:58:14.932958 UTC; the actual execution
ran from 14:58:27.989517 to 14:59:50.395890 UTC. The run-folder name is an identifier,
not an exact start-time assertion. Frozen script, configuration, protocol and
offline-check bytes remained unchanged. Offline tests: 5 passed and 11 subtests
passed. The post-run check rehashed all 60 original XML responses.

This closes only the proposed window's partition-listing feasibility check.
Object download and Parquet decoding, block continuity, emitter population,
contract identity, semantic features, incident labels and independent-cohort
eligibility are not established by these results. No detector outcomes or new
labels were requested.
