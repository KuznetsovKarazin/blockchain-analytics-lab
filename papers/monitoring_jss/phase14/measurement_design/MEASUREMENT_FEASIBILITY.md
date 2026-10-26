# Fixed-core observation feasibility

This is an implementation audit and a proposed observation adapter. The prospective all-frame scope amendment was accepted in a [separate receipt](../scope_review/root_amendment_acceptance.json); that acceptance nominates no core address and admits no case. The proposed LiFi core remains subject to the same uniform row-nomination review and a separate measurement freeze. [The contract proposal](observation_contract_proposal.json) and [audit](feasibility_audit.json) bind the current code and document the remaining work. Neither document acquires detector inputs or computes scores.

## Practical data route

The existing AWS route can supply the required raw fields without reconstructing every facet activation. Its anonymous endpoint is `https://aws-public-blockchain.s3.us-east-2.amazonaws.com/`; the tables are `v1.0/eth/{logs,blocks,transactions}/date=YYYY-MM-DD/`. The [AWS registry](https://registry.opendata.aws/aws-public-blockchain/) confirms the public bucket, region and Ethereum path. The [AWS table schema](https://github.com/aws-solutions-library-samples/guidance-for-digital-assets-on-aws/blob/main/analytics/consumer/schema/eth.md) documents raw logs, transaction status and header fields. This establishes a documented route, not readability or completeness of the required historical objects.

Two complete March listings already exist locally: 31 log objects and 31 block objects, with `IsTruncated=false`. Phase6 metadata covers 23 of LiFi's 30 dates, February26–March20, for logs and blocks. The missing prior metadata is February19–25 for those tables and transaction objects for all 30 dates. The proposed inventory needs only four new monthly-prefix listings: February logs, February blocks, February transactions and March transactions. Original XML and acquisition counts remain distinct from reused metadata.

Prior QA records identify full March19 and March20 archives, but those original archive paths are absent from this workspace. The audit does not claim to reuse their payloads. Recover and verify durable originals before considering any duplicate download. Existing Euler/Beanstalk selected subsets do not establish the LiFi emitter stream.

The other documented routes are [Google Blockchain Analytics](https://docs.cloud.google.com/blockchain-analytics/docs/schema), using `bigquery-public-data.goog_blockchain_ethereum_mainnet_us`, and Allium's [`ethereum.raw.logs`](https://docs.allium.so/historical-data/supported-blockchains/evm/ethereum/raw/logs) with [`ethereum.raw.transactions`](https://docs.allium.so/historical-data/supported-blockchains/evm/ethereum/raw/transactions). Google exposes logs, receipts, transactions and blocks; Allium documents raw topic fields and integer receipt status. Neither route was queried. No corresponding query tool was available in this session, and account access, export limits and query cost were not inspected. AWS therefore has the clearest existing acquisition path.

## Observation contract

The proposed LiFi example uses the historically identified diamond `0x5a9fd7c39a6c488e715437d7b1f3c823d5596ed1` over `[2022-02-19,2022-03-21)` UTC. The known included block interval is 14,233,163–14,426,367. This remains a provisional implementation target until the uniform row-nomination review and separate measurement freeze accept it. Scope-amendment acceptance alone does not establish that nomination.

1. Enumerate every source part for every date. Scan every log-address column row group for the fixed core, without a topic or transfer filter. Preserve raw fields, exact row locations and source identities.
2. Freeze the selected transaction set as exactly the transactions containing at least one core-emitted log. Bind ordered transaction identities, core-log counts and payload hashes before transfer decoding, scoring or joining labels.
3. Expand those transactions to every emitted log in the accepted source partitions. Join unique transaction status metadata and the full header chain. Do not expand the transaction set or core addresses based on token transfers, victims or incident descriptions.

Canonical ordering is `(block_number,transaction_index,log_index)` for logs and `(block_number,transaction_index)` for transaction bundles. Reject conflicting block/transaction identities, duplicate logs, missing metadata and incompatible statuses. Require integer successful status1 for selected log-bearing transactions; do not fill unknown status with success. Match every original core log exactly inside the expanded bundle. Validate source log-index continuity, header parent links, increasing timestamps, cross-day links and accepted endpoint anchors.

These checks establish coverage within the listed source partitions. They do not independently verify receipt roots, source-index completeness or the absence of missing leading/trailing logs. Historical live observation and feature-ready times remain unknown. Block timestamps support logical replay only.

Reuse the existing transfer-shape decoder and integer arithmetic. `external_out_raw` requires an ERC20-shaped transfer with its sender in the fixed core and a nonzero external recipient. The token emitter's address, spender identity and victim ownership do not change this rule. Retain amounts as decimal integer strings. AWS's documented decoded-transfer amount uses a floating-point type, so it is unsuitable for replacing raw-byte amount decoding.

## Required adapter work

The generic semantic monitor already accepts a sorted fixed address set. The old acquisition and replay drivers contain Euler development assumptions that must remain unchanged in their accepted artifacts:

- `group_core` rejects an empty core day. A new adapter must accept an empty observation file when the whole day's source/header/address-scan coverage is verified. An unavailable day remains unavailable; it is not a zero day.
- The old acquisition requires exactly one object per daily partition and ten previously sealed Euler cross-source bundles. The reusable adapter must account for all enumerated parts; that development-specific bundle count is not a universal case requirement.
- `semantic_flow_replay.validate_config` hardcodes the Euler address, two dates, known counts and 54 comparison cells. A separately frozen driver should preserve the monitor, transaction-final count, grouping and budget behavior while accepting the new observation manifest.
- The generic book cache has automatic retries and writes projected Parquet files. It should not replace exact raw-range receipts in this workflow.

Preserve daily feature/grouping resets unless a separate prospective method amendment changes them. Continuous acquisition of 30 dates does not automatically mean carrying monitor state across midnight. Cold start, absent core outflow and no alerts are valid outcomes; none allows removing a case or adding addresses.

## Small next experiment

First complete the bounded metadata inventory. Then freeze a structural probe for the deterministic first date, **February19,2022**, with one logs, blocks and transactions object if the inventory contains exactly that structure. Read only each object's eight-byte Parquet trailer and its exact bounded footer: six range requests. If the structure differs or exceeds the cap, preserve that finding and redesign prospectively; do not choose a more favorable date.

The footer probe can establish the schema, row-group counts and exact compressed ranges for the required columns. Report the address/hash scan cost and the conservative full-column projection cost. The actual payload needed after predicate matching is not yet known, and one date cannot establish a 30-day total. No row data, token flows or detector scores should be decoded in that probe.

The documentation work used five web-tool calls: three searches, nine opens and two clicks. Backend HTTP counts and bytes are unknown. There were no dataset-row queries or SQL executions. [Documentation accounting](method_documentation.json) records the primary URLs and the private receipt hash.
