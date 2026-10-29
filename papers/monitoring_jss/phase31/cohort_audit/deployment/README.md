# Indexed deployment-date sensitivity audit

This audit augments the frozen Phase28 census without changing its source counts or nominated addresses. It answers only which UTC dates precede the nominated address's indexed creation transaction; it is not detector-performance validation.

## Results

All 16 nominated core addresses have a successful indexed creation transaction. The 32 raw Blockscout responses (16 address records and 16 creation transactions) and request receipts are preserved in `raw/`; response SHA256 values are checked on every offline replay.

| Denominator | Days with <20 selected transactions | Fraction | Zero-transaction days |
|---|---:|---:|---:|
| Original calendar dates | 410/480 | 85.4% | 302 |
| Nonempty calendar dates | 108/178 | 60.7% | 0 by definition |
| Creation date and subsequent dates | 250/320 | 78.1% | 142 |
| Strictly after creation date | 243/312 | 77.9% | 141 |

Exactly 160 original dates strictly precede creation, and all have zero selected transactions. Eight dates contain creation and therefore have only partial exposure. Excluding both groups leaves 312 fully postdeployment calendar dates. The nonempty result and deployment-adjusted results answer different questions and must remain separately named: **108/178 is not a deployment-adjusted denominator**. For example, Auctus was created in 2020, so its entirely empty 2022 window is inactivity in the nominated emitter, not predeployment. These figures remain an upper-bound traffic screen for daily same-token rank readiness; >=20 selected transactions does not establish token-specific readiness.

## Per-case evidence

| ID | Family | Indexed creation block | UTC creation date | Predeployment dates | Partial creation dates | Full postdeployment dates |
|---|---|---:|---|---:|---:|---:|
| cohort28_01 | Compound cTUSD sweepToken | 11008385 | 2020-10-07 | 0 | 0 | 30 |
| cohort28_02 | Umbrella Network staking | 14385979 | 2022-03-14 | 23 | 1 | 6 |
| cohort28_03 | Ronin Bridge Ethereum withdrawal | 11724674 | 2021-01-25 | 0 | 0 | 30 |
| cohort28_04 | Auctus options writer | 10336437 | 2020-06-25 | 0 | 0 | 30 |
| cohort28_05 | Beanstalk governance | 12974075 | 2021-08-06 | 0 | 0 | 30 |
| cohort28_06 | Akutar NFT auction | 14636831 | 2022-04-22 | 29 | 1 | 0 |
| cohort28_07 | Saddle sUSD metapool | 13806669 | 2021-12-15 | 0 | 0 | 30 |
| cohort28_08 | ApeCoin airdrop claim | 14403861 | 2022-03-17 | 29 | 1 | 0 |
| cohort28_09 | Inverse Finance June lending | 14838270 | 2022-05-24 | 6 | 1 | 23 |
| cohort28_10 | Schnoodle ERC777 token | 12905190 | 2021-07-27 | 0 | 0 | 30 |
| cohort28_11 | XCarnival XNFT | 14909176 | 2022-06-05 | 8 | 1 | 21 |
| cohort28_12 | FlippazOne NFT auction | 15082870 | 2022-07-05 | 29 | 1 | 0 |
| cohort28_13 | Omni NFT lending | 14998212 | 2022-06-20 | 9 | 1 | 20 |
| cohort28_14 | Audius governance | 11103280 | 2020-10-22 | 0 | 0 | 30 |
| cohort28_15 | Nomad Bridge replica | 14629758 | 2022-04-21 | 0 | 0 | 30 |
| cohort28_16 | Bad Guys by RPF NFT | 15448210 | 2022-08-31 | 27 | 1 | 2 |

## Reproduction and limits

From the repository root, replay the saved responses without network access:

```sh
python papers/monitoring_jss/phase31/cohort_audit/deployment/audit_deployments.py
```

This rewrites `DEPLOYMENT_AUDIT.json` and `DEPLOYMENT_CASES.csv` deterministically. Optional explicit `--acquire` performs at most 32 HTTP requests with four workers, a 25-second per-request timeout and a 1 MB response cap; it updates raw metadata and receipts. No detector scores, labels, or source counts are acquired or altered.

The evidence tier is **Blockscout indexed creation metadata, not raw-chain or receipt-root authentication**. Address and transaction identities, successful status, UTC timestamps, integer block heights, response checksums, and the absence of emissions before the indexed creation date are validated. The address endpoint describes its indexed creation and is not a complete proof of all potential historical code incarnations. A UTC date containing creation is never treated as a fully exposed day. The original windows end on the full UTC date containing the PoC fork block; this sensitivity does not change them into strictly pre-attack histories or exact attack-time windows.
