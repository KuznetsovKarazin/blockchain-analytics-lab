# Phase 21 — Label-free selected-transaction feasibility audit

Date: 2026-10-29. Exploratory source audit planned after Phase20 activity counts. The case nominations are incident-informed, the source and populations are not blind; attack outcomes do not enter this audit.

## Research objective

Refine the necessary feasibility bound `L(core,day) >= 20` based on the number `T(core,day)` of *distinct transactions* with at least one event emitted by the selected core, rather than the number of emitted logs. Since only one positive outflow sample per token and selected transaction may enter rank history, at least 20 qualifying selected transactions with same-token positive outflow per UTC day are necessary for a daily-reset rule with `min_history=19`. Consequently `T(core,day)<20` proves ineligibility on that emitter-day. `T>=20` does not prove eligibility. Treat the pre-existing multi-emitter Rari candidate group as a disclosed *candidate union*, never as an endorsed incident-wide observation boundary. All original separately nominated component results remain visible.

## Inputs

- Phase20 frozen 60-day address-column audit: `papers/monitoring_jss/phase20/source_evidence/core_traffic.json`, with exact 60 S3 object keys, ETags and row counts; prior tally must match.
- Bacon proxy `0xb8919522331c59f5c16bdfaa6a121a6e03a91f62`, 2022-02-04 through 2022-03-05 UTC inclusive.
- Rari Pool 127 candidate fETH, fUSDC, Comptroller as listed in original Phase20 protocol, 2022-04-01 through 2022-04-30 UTC inclusive.
- Immutable Phase16 source-range reader `phase16/collector/range_collector.py` in the published Git tree; pyarrow 19.0.1.
- All source rows are read for the projected `address`, `block_number` and `transaction_index` columns. Full-event and transaction-hash fields are NOT acquired; do not infer exact transaction identity across external systems.

## Measurements and acceptance

For every day (60, no omissions): check source byte-range identity and declared metadata; scan all Parquet row groups; validate row counts; count core logs exactly equal Phase20 accepted totals; compute per-core unique `(block_number, transaction_index)` pairs and the candidate Rari union. Persist source keys and per-day projections, hash receipt ledger and code SHA. Failed/missing days halt acceptance. Do not use labels, price, token amounts, attack-day reference identity or detector scores.

Primary descriptive measures: per-core selected TX/day, number of days with T<20, distribution summaries and difference between core log count and distinct selected TX count. An optional Rari multi-emitter *candidate union* remains methodologically separate from single-emitter results and shall not replace them without independent architecture evidence.

No coverage, precision, recall, incident hits or attack miss conclusions can be inferred from this phase. The existing two-family external detector-performance denominator remains unchanged. The new output will guide whether full transaction-level input reconstruction is feasible.