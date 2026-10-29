# Phase 29 — four additional source-bound monitoring streams

**Date:** 29 October 2026. **Status:** exploratory source/reference and frozen-method evaluation, not a representative independent case-performance estimate. The original Phase16 sealed and Phase18/22 observational results are unchanged.

## Evidence provenance

- Original fixed 16-case, nonrandom screening registry and 480 source days: [Phase28](../phase28/PROTOCOL.md), frozen root `fc25cd8c187e6c8b0afb9afae2072f78dc2d3c0e`.
- Original historical AWS: full address+block+transaction-index selection across all Parquet row groups; re-read selected transaction IDs, original hashes/block/timestamps and complete **counts and log indexes** across row groups. Each source response ETag/content-range/SHA is retained; all four 30-day inputs passed an offline independent identity verifier.
- Full selected all-emitter event `topics`/`data` and success status: Blockscout v2, cross-checked against AWS-pinned transaction identities, event counts, blocks and source-index timestamps. These are **mixed-source** observations. Original receipt-root authentication is NOT claimed.
- Complete selected source data, independent verification receipts, and method/policy output tables are permanently published under `phase29/data`, `phase29/indexed`, `phase29/results` for each case. The temporary Actions artifacts are secondary, not the sole source.
- Original Phase18 rank method, count threshold, grouping and dispatch applied unchanged; no training or case-specific tuning. Reference comparison is performed after the label-blind replay. The reference inventory remains incomplete for several incidents and no new population recall/precision/FPR estimate is admitted.

## Results (greedy, B=5 per UTC day, primary rank 1/20)

| Case / fixed emitter | Selected TX / 30d | Rank eligible TX (daily / 7d / 30d) | Rank notifications (daily / 7d / 30d) | Count notifications | Conditional exact hits for documented execution(s) |
|---|---:|---|---|---:|---|
| Umbrella staking | 92 | 0 / 0 / 0 | 0 / 0 / 0 | 0 | No independently closed exact reference set (not a miss measurement) |
| Inverse June yvCrv market | 71 | 20 / 20 / 20 | 3 / 3 / 3 | 2 | 0 matching independently reported execution TX |
| Schnoodle token proxy | 134 | 0 / 0 / 0 | 0 / 0 / 0 | **27** | **1 exact match by count** on independently reported historical execution TX |
| Omni NFT lending | 103 | 0 / 0 / 0 | 0 / 0 / 0 | 5 | 0 matching independently reported execution TX |

The original indexed references are an *incomplete known subset*; these numbers are not population incident recall, nor do unknown alerts imply false positives. A token-level score need not be eligible merely because the contract emitted enough logs. Even with an eligible token history, an alert needs an extreme raw outflow and successful passage through grouping/dispatch. Schnoodle is a useful example of the complementarity (and the cost): the count method marks the known incident TX, but emits 27 notifications over the window, whose other truth statuses remain unknown.

Each case contributes **63** method×initialization×policy×budget cells, for 252 total. The four streams contain 400 distinct selected transactions, NOT 252 independent experiments or 400 independent incidents.

## Independent scientific QA

1. Exact source identity/count replay and original-AWS audit checks pass for all four selected 30-day emitter populations. The first attempt was rejected because a transaction can span multiple Parquet row groups; the accepted version reconstructs complete selected bundles in two passes over all groups.
2. Blockscout event payload source was checked against AWS-pinned transaction identity/count for every selected transaction; two independent standard SHA formats are distinguished (raw 64-digit SHA vs `0x`-prefixed Ethereum hash).
3. Original method/policy replay run twice from clean directories with exact byte comparison for every case.
4. Additional **independent algorithmic implementation** `independent_policy_audit.py` reimplements per-token history (min 19, cap 128, 7d inclusive cutoff), count 10/60s, 300s candidate grouping, all three budget policies and hard caps. It matched **252/252** published cell results, checking raw triggers, eligible observations, grouping, notifications, and exact emitted transaction sequences. [CI run 40928208970](https://github.com/KuznetsovKarazin/blockchain-analytics-lab/actions/runs/40928208970): SUCCESS.
5. Scientific CSV `\r\n` emitted by a frozen Python writer is normalized to `\n` in *publication copies only*, **after** byte-exact scientific comparison, to pass GitHub `git diff --cached --check`. No row or value changes.
6. Offline reproducibility does NOT require new Ethereum downloads: use the published inputs and scripts; network remeasurement is separate from deterministic scientific replay.

## Selection and disclosure

The phase followed **nonrandom** early results from Li.Fi/Revest/Bacon/Rari. Wave 1 selected four source-manageable fixed-core emitter views out of the already frozen 16-case Phase28 register: Umbrella, Inverse, Schnoodle and Omni. All other 12 registrations, including PoC-only and differently timed/structured attacks, remain in the screening frame; they cannot be quietly replaced based on whether alerts occur.

One Beanstalk PoC fork block date is earlier than the historical exploit: its original Phase28 observation window must be **re-anchored** before historical execution analysis. Multi-stage Audius, Nomad, XCarnival likewise require distinct setup and execution roles and an independently justified emitter boundary.

## Remaining acceptance gates

- Independent closure of exact historical execution-reference inventories and ambiguity of original emitter selection, including multi-stage attacks; case-level certainty varies.
- Expand to additional independent *qualified* incidents (not merely extra core windows); report every exclusion and missing-source reason.
- Validate attack-relevant features across a more diverse and appropriately sampled emitter population; Phase26 comparison controls are not confirmed attack-free and its z/MAD/EWMA readiness describes **core-log counts**, not token outflows.
- Author-approved disclosures, full bibliographic and licensing QA, one immutable final release+archive DOI before JSS submission.

**This is a completed exploratory four-case extension. It is NOT a completed 10–20-case prospective external validation.**
