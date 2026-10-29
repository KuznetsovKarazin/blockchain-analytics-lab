# Phase31: review audit and reproducibility revision

This is the audit accompanying Article 2's V7 research revision. It preserves the
V6.1 baseline (`651daa926bb3803ad76227389a4fb35c1027da63`) and does not change its
source populations, original measurements, or release tag. The review response is
in [REVIEW_RESPONSE_RU.md](REVIEW_RESPONSE_RU.md).

## Evidence map

| Directory or file | Scope |
|---|---|
| `V6_1_INPUT_VERIFICATION.json` | Uploaded manuscript package against the published baseline |
| `V6_1_CI_VERIFICATION.json` | Previously completed baseline workflow runs |
| `reproduce_original.py` | Frozen execution joins, causal replay, 252 independent policy cells and original tables |
| `cohort_audit/` | Census denominators, all 67 source-file dispositions, and 16 contract-creation records |
| `replay_audit/` | Seven fixed streams, 441 policy cells, independent count-dispatch arithmetic and boundary checks |
| `three_cases/` | Detailed Saddle, XCarnival and Audius observations, expanded role ledger and Saddle rank decomposition |
| `raw_payload_audit/` | Retained indexed response bytes and full events for all 125 second-wave transactions |
| `nomad/` | Fixed higher-volume source extension, acquisition attempts, resource limits and label-blind replay |
| `nomad_independent/` | Separately implemented source, feature and policy verifier |
| `verify_release.py` | Fail-closed checks required before packaging the revision |

## Offline verification

Run from the repository root with Python 3.11 or later. These commands do not
require API keys or network access:

```bash
python papers/monitoring_jss/phase31/reproduce_original.py --out /tmp/original_reproduction.json
python papers/monitoring_jss/phase31/replay_audit/run_audit.py --out /tmp/seven_stream_audit
python papers/monitoring_jss/phase31/cohort_audit/recompute_census.py
python papers/monitoring_jss/phase31/cohort_audit/audit_catalogue.py
python papers/monitoring_jss/phase31/cohort_audit/deployment/audit_deployments.py
python papers/monitoring_jss/phase31/three_cases/observe_three_cases.py
python papers/monitoring_jss/phase31/three_cases/saddle_rank_decomposition.py --check
python papers/monitoring_jss/phase31/raw_payload_audit/verify_all.py --archive papers/monitoring_jss/phase31/raw_payload_audit/raw_observations.zip --integrity-tests --out /tmp/phase30_raw_audit.json
python papers/monitoring_jss/phase31/verify_release.py --out /tmp/v7_release_audit.json
```

The final command requires a complete, accepted 930-transaction Nomad population;
an incomplete acquisition checkpoint cannot satisfy it. It checks that the
independent implementation reproduces all 63 Nomad policy cells and that the
primary replay regenerates its retained result exactly.

## Source boundaries

The retained second-wave indexed response bytes were reacquired in this revision.
Their canonical normalized event-payload digests match the V6.1 digests; this does
not claim recovery of byte-identical historical HTTP responses. The 125-transaction
archive contains 2,103 events, and fresh-extraction verification rejects three
intentional integrity violations.

The Nomad acquisition preserves normalized full-event bundles, transaction status,
source listings, range receipts and attempt manifests. Sparse Parquet caches are
temporary extraction inputs and are not distributed. Accordingly, its offline
verification starts with retained normalized source rows; repeating the original
Parquet-byte extraction requires source access. No dataset here establishes
receipt-root authentication.

The source catalogue audit is retrospective. It documents eight Ethereum PoC
files without recorded original exclusion reasons instead of inventing an
exhaustive historical inclusion rule. Full third-party PoC source files are not
redistributed; immutable source identifiers and file digests are retained.

Exact identity joins, policy cells, and repeated source checks are distinct units.
They do not add independent incidents or establish population recall, benign
false-positive rates, or complete incident execution inventories.

The build and release procedure is specified in
`../../../.github/workflows/article2_v7_review_release.yml`. The official Elsevier
class is pinned externally; the manuscript package does not redistribute a
partial class installation. Journal submission has not been performed.
