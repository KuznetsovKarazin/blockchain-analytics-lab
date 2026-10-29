# Phase30 — pre-score second wave from fixed Phase28 candidates

**Decision timestamp:** 29 October 2026, after the first four Phase29 cases were scored. This is an **exploratory extension**, not independent prospective case selection. The original frozen 16-case registry `phase28/CANDIDATE_FRAME.json` and Phase28 480-day source census are unchanged. Never replace a candidate based on trigger results.

## Fixed additional cases before detailed token-feature acquisition

| ID | Nominated fixed emitter | Phase28 30-day selected TX | Known reference-role uncertainty |
|---|---|---:|---|
| cohort28_07 | Saddle sUSD metapool proxy | 44 | One reported original successful historical transaction, but alternative pools and multi-transaction inventory unresolved |
| cohort28_11 | XCarnival XNFT proxy | 43 | Two candidate original transactions; one emits zero logs from this fixed core, retain as mechanism/boundary limitation |
| cohort28_14 | Audius governance proxy | 38 | Four distinct reported original stages (initialization, vote, governance, late swap); do not classify final sale as governance exploit |

These three cases are chosen on the *already exposed* source/readiness census and source-document evidence. They add threat/architecture diversity, not population representativeness. No method or reference family is allowed to be replaced after observing new scores.

## Frozen workflow and admission

1. Original 30-day source dates are the Phase28 fixed PoC-fork dates (Apr30, Jun26, Jul23); independent preflight confirms that the attack incident day is included for these candidates. For any reference later shown outside its window, mark unavailable and do not synthesize an extra day.
2. Original AWS S3 event log Parquet, all partitions and row groups, original `address`, `block_number`, `transaction_index`, then complete selected transaction `hash`, block, all-emitter log indices/times, with first and second pass across *all* row groups. Exact original object ETag, Content-Range and per-range SHA.
3. Full `topics`/`data` and success metadata from Blockscout only **after** validating original AWS IDs and all-emitter log counts. Never attribute an AWS-authenticated receipt root to indexer data.
4. Immutable feature definitions: per-token positive gross core outflow rank, history min 19, 128 cap, daily reset/7d lookback/30d cumulative, rank 1/20 and sensitivity 1/10, count10/60s, grouping300s, three policies, B=1/5/20. Reference join after completely label-blind method and policy decisions.
5. Exact role-adjudication and label completeness reported in source ledger and post-score join, with **no automatic case-performance admission**. Unknown emitted signals remain unknown.
6. If source or time/resource cap fails, preserve failed audit record and do not impute zero. The user-facing claim is source audit or exploratory outcome only.

A full 10–20-case independent external validation remains open beyond this second bounded pilot. The Phase29 independent algorithm QA must be applied to the combined published results before adding them to the scientific article.
