# Data sources

All raw data live under `data/raw/` and `data/cache/`, which are git-ignored.
Nothing in this repository redistributes third-party labels; `results/` holds
aggregate metrics and figures only.

| Source | Revision | Used by | Licence / terms | How obtained |
|---|---|---|---|---|
| Elliptic Data Set (Weber et al. 2019) | Kaggle release `ellipticco/elliptic-data-set` | A1, D2, P2, M2, F1 | Kaggle terms; not redistributed | manual download into `data/raw/elliptic/` |
| DeFiHackLabs (SunWeb3Sec) | commit `23c7bd83ccb4524972a9493617fcc8764ab6269b` | S2 | repository licence | `scripts/00_fetch_data.py` |
| OFAC SDN digital-currency addresses (0xB10C, branch `lists`) | commit `6ae2472c439b9bb2788f8df662052ae31854aa97`; point-in-time snapshots `96f89d770659edad674fa2ea101a0d79a7f4c768` (2022-09-16) and `0650c71e7a7561dd0f97bdda49110eb56b59a7fa` (2024-02-21) read with `git show` | D1, P3 | public-domain source data (U.S. Treasury) | `scripts/00_fetch_data.py` |
| ethereum-lists (MyEtherWallet), darklist | commit `8f86cba9b58db79608ece8fa784775b3c41e2e26` | D1 | repository licence | `scripts/00_fetch_data.py` |
| ethereum-ponzi (blockchain-unica; Bartoletti et al.) | commit `e083ce720f934e17ea1fe9124b70ea874aa042bf` | P4 | GPL-3.0; used locally, not redistributed | `scripts/00_fetch_data.py` |
| AWS Public Blockchain Data | `s3://aws-public-blockchain/v1.0/{btc,eth}/…`, anonymous access, us-east-2 | D1, P1, P3, P4, M1 | AWS Open Data terms | `scripts/d0_cache_aws.py`; every fetched day is logged in `data/cache/cache_index.csv` |

## AWS cache specifications

See `SPECS` in `scripts/d0_cache_aws.py`: Ethereum and Bitcoin block headers
2023-01-01 to 2025-12-31; Ethereum transactions for the weeks 2022-07-25 to
2022-07-31 and 2024-03-04 to 2024-03-10; Ethereum contracts (deployed bytecode)
created 2015-07-30 to 2017-12-31. Only the listed columns are kept.

## Known encodings in the AWS Ethereum tables

* `to_address` of contract creations is the literal string `"None"`, not null.
* `value` is stored as floating point; values above 2^53 wei are inexact.
* Missed slots after the Merge appear as gaps in block timestamps (12 s grid).

These are audited by D1 (`results/data/d1_v1/audit.csv` and `blocks_hygiene.json`).
