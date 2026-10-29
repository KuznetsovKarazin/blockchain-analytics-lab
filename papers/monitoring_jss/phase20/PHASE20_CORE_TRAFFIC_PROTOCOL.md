# Phase 20 — prospective label-free traffic eligibility upper-bound audit

**Protocol frozen before reading new 30-day address-column observations (29 October 2026).** This study uses the already identified historical exploit references for component nomination but does not use any detector result or positive label to select traffic rows. The new cases are **not yet admitted to the independent detector-performance cohort**.

## Declared populations and periods

- `bacon_20220305`: Ethereum mainnet, **2022-02-04 through 2022-03-05**, UTC inclusive (30 days), exactly one monitored emitter `0xb8919522331c59f5c16bdfaa6a121a6e03a91f62` (historical Bacon proxy).
- `rari_fuse_pool127_20220430`: Ethereum mainnet, **2022-04-01 through 2022-04-30**, UTC inclusive (30 days). **Primary single-emitter core**: fETH Pool127 `0x26267e41ceca7c8e0f143554af707336f27fa051`. Separately report fUSDC Pool127 `0xebe0d1cb6a0b8569929e062d67bfbC07608f0a47` and Comptroller `0x3f2d1bc6d02522dbcdb216b2e75edddafe04b16f`. These are distinct descriptive emitter views, **not** a retrospectively selected union that maximizes alert counts. Actual protocol-wide or pool-wide core completeness is not established.

Source: AWS public Ethereum Parquet, `s3://aws-public-blockchain/v1.0/eth/logs/date=YYYY-MM-DD/`. Require complete listing of each daily partition, exact source identity/ETag, validated Parquet footer and complete original byte-range acquisitions of every `address` column chunk used. A missing or failed day remains `UNAVAILABLE`, never zero. Do not download topics/data/transaction hashes as part of this eligibility ceiling calculation; do not run the frozen detector.

## Estimand and interpretation

For a proposed fixed emitter set `C`, let `L_{C,d}` count all log rows emitted by `C` in UTC day `d`. Because each selected transaction has at least one nominated core log, the number of selected transactions satisfies `T_{C,d} <= L_{C,d}`. In the existing semantic rule each token requires at least **19 strictly preceding positive token outflow observations within that same UTC day**, and each selected transaction can add at most one history observation *per token*.

Therefore **if `L_{C,d} < 20`, no selected transaction on day `d` can be history-eligible**. This is a necessary feasibility test, not an exact count of eligibility. If `L_{C,d} >= 20`, eligibility may still be zero; only all-emitter selected transaction observations, token-specific outflow, and exact transaction ordering can determine that.

Results shall include daily core log counts, the number of audited days with `L<20` (and `L>=20`), range request/byte budgets and source-failure dispositions. Separate fETH/fUSDC/Comptroller counts, not aggregated as an optimized core. No attack-label join, true/false alerts, recall, precision or incident hit conclusions. Source completeness is restricted to enumerated archived Parquet partitions, not receipt-root or chain-wide authentication.

## Operational cap

No more than 60 day objects, at most 450 original range GETs and 550 million retained response bytes, and 10 minutes wall time for the address-column pass. One worker, no automatic retries or alternate provider. Save only small derived counters and exact source/key/range-hash audit receipts; do not upload the source columns or copied third-party raw material. If caps are exceeded, preserve partial status without imputing missing dates. Original Phase16/Phase18 results and the companion pin remain unchanged.

This is a source-limited *pre-admission applicability bound*. Bacon and Rari may become full external evaluation cases only after further core nomination, transaction and full selected-bundle audit, complete 30-day source checks and independently adjudicated reference inventory.
