# Phase 20 — independent source checks and label-free history-feasibility bounds

**29 October 2026.** Status: **completed source-level audit of two additional *candidate* protocols, not a third or fourth independent detector-performance experiment.** No new incident has been admitted to the primary evaluation. Nothing in frozen Phase 16 or the Phase 18 counterfactual results was modified.

## 1. Question and prior design

The previously evaluated semantic monitor requires **19 strictly prior positive token-outflow observations for the same token in one UTC day**. Can a bounded, attacker-label-free inspection of the proposed core-emitter traffic show when that requirement is impossible *before* examining scores or reference labels?

The protocol and source windows were fixed before the 60-day address-column scan: [PHASE20_CORE_TRAFFIC_PROTOCOL.md](PHASE20_CORE_TRAFFIC_PROTOCOL.md).

- **Bacon Protocol:** Ethereum, 4 February–5 March 2022 inclusive, nominated historical proxy \`0xb8919522331c59f5c16bdfaa6a121a6e03a91f62\`.
- **Rari Fuse Pool 127:** Ethereum, 1–30 April 2022 inclusive, separately nominated fETH \`0x26267e41ceca7c8e0f143554af707336f27fa051\`, fUSDC \`0xebe0d1cb6a0b8569929e062d67bfbC07608f0a47\`, Comptroller \`0x3f2d1bc6d02522dbcdb216b2e75edddafe04b16f\`. These are **separate emitter-specific descriptive views**, not one optimized pooled core.

Component nomination was informed by known historical incidents and third-party reproduction code. Therefore the exercise is **not globally blind**. None of these addresses is certified as an exhaustive historical protocol-owning or pool-wide observation boundary. The labels of the known exploit executions were **not used** in the 60-day activity count.

## 2. Original source acquisition and independent checks

The metadata preflight enumerated all 180 expected S3 partition/table combinations (two cases × 30 UTC days × logs/transactions/blocks). Every partition was listed, with no missing listing. Their declared combined compressed object size was **36,102,387,652 bytes**; *listing is not a source-row integrity audit*.

The subsequent bounded pass inspected the \`address\` column in **all row groups of all 60 daily logs Parquet objects**, with verified byte-range 206 responses, matching S3 ETags, content ranges, recorded per-range SHA-256 values and no incomplete-day substitutions.

| Source criterion | Bacon | Rari Pool 127 |
|---|---:|---:|
| Audited UTC days | 30/30 | 30/30 |
| Log rows in inspected source files | 58,780,156 | 61,967,601 |
| Declared full log-object bytes | 6,180,247,225 | 7,320,699,457 |
| Verified range-response bytes | 204,236,593 | 177,023,982 |
| Original range GETs | 150 | 156 |

The study therefore inspected **120,747,757 source log rows**, with **306 range GETs and 381,260,575 transferred response bytes** (approximately 35.4× less transfer than downloading the combined 13.50 GB of original *logs* objects; not a wall-clock or cross-system performance benchmark). Columns \`topics\`, \`data\` and \`transaction_hash\` were *not* downloaded in the 60-day activity pass, so no semantic outflow, full transaction bundle or attack-label score was reconstructed there.

Evidence: [full-window metadata job](https://github.com/KuznetsovKarazin/blockchain-analytics-lab/actions/runs/40851131526), [frozen protocol](PHASE20_CORE_TRAFFIC_PROTOCOL.md), [60-day address-only audit job](https://github.com/KuznetsovKarazin/blockchain-analytics-lab/actions/runs/40852958094), [per-day derived counters](daily_core_log_counts.csv). The source collection's full compact audit receipt is attached to the corresponding workflow run; do not equate it with a raw Parquet archive or chain-level authentication.

The independent offline checker reconciled source keys, all 60 dates, daily source sizes against the earlier S3 listing, 306 response SHA-256 receipt formats and byte/count totals, emitter counts and the attack-day source lower bounds. It returned **PASS**. This is a verification of the *retained provenance and derived table*, not an independent re-download of every range.

## 3. Population applicability bound

Let \`L(C,d)\` be the number of logs emitted by the nominated component \`C\` on UTC day \`d\`, and \`T(C,d)\` the number of distinct transactions selected because they contained at least one such core log. Then \`T(C,d) ≤ L(C,d)\`. The monitor adds at most one positive history sample **per token per selected transaction**. Consequently, the 19-prior requirement cannot be met if \`L(C,d) < 20\`. Having 20 or more logs is **not sufficient**: they may belong to fewer transactions and may have no positive, token-matched outflows.

The source-derived results are:

| Nominated component | Total logs / 30 days | Conventional median daily logs | Days with \`L<20\` | Days with \`L≥20\` |
|---|---:|---:|---:|---:|
| Bacon proxy | 746 | 19 | **15/30** | 15/30 |
| Rari fETH | 331 | 8.5 | **26/30** | 4/30 |
| Rari fUSDC | 426 | 5 | **25/30** | 5/30 |
| Rari Comptroller | 146 | 3.5 | **29/30** | 1/30 |

For the **single-emitter** Bacon and fETH observation contracts, these data show that the frozen daily-reset semantic rule is incapable of achieving sufficient per-token history on at least **50.0%** and **86.7%**, respectively, of the thirty-day windows. The fUSDC and Comptroller results are *separate alternate emitter views*, not combined incidence rates. No inference is drawn about their union or a complete Rari-pool monitor.

**Median audit correction.** The initial machine-readable workflow field \`median_core_logs\` is actually the upper central order statistic for an even number of days, not the standard arithmetic median. The independently recomputed medians are 19 (not 20) for Bacon, 8.5 (not 9) for fETH, 5 for fUSDC and 3.5 (not 4) for Comptroller. Original source rows and daily counters were not changed; the table above uses the correct medians.

## 4. Exact reference evidence (separate, *post-label* diagnostic)

Original source log-identity checks were performed **only in the known exploit transactions**, independently of the 60-day label-free scan:

| Property | Bacon execution | Rari Fuse Pool 127 execution |
|---|---|---|
| Transaction hash | \`0x7d2296bcb936aa5e2397ddf8ccba59f54a178c3901666b49291d880369dbcf31\` | \`0xab486012f21be741c9e674ffda227e30518e8a1e37a5f1d58d0b0d41f6e76530\` |
| Ethereum block | 14,326,932 | 14,684,814 |
| All-emitter source log rows | 18 | 65 |
| Matched Blockscout indexer rows | 18 | 65 |
| Core-emitter logs | Bacon proxy 8 | fETH 7; fUSDC 12; Comptroller 10 |
| Original S3 range bytes read for exact reference | 35,385,379 | 144,340,431 |

S3 source and Blockscout indexed emitter distributions matched exactly in these two reference transactions. The checks are limited to the enumerated S3 Parquet source and indexed explorer, not independent receipt-root authentication or completeness of all attacker executions.

Correctly handling Blockscout's null-padded four-slot \`topics\` representation yields **11** positive ERC20-shaped Transfer logs for Bacon and **24** for Rari. An earlier indexer-only diagnostic incorrectly counted zero due to interpreting padded null slots as real topics; its Transfer-shape conclusions were explicitly superseded. Under the *candidate* core boundaries, 7 Bacon and 13 Rari ERC20-shaped positive transfers did not touch any nominated core address. This is relevant to construct validity but does not establish economic loss or native ETH transfer coverage.

Original third-party attack reproductions use *fork blocks one below* the actual execution blocks: Bacon fork block 14,326,931 and Rari fork block 14,684,813. Fork block heights are not original exploit transaction identities.

Primary context: [Bacon original postmortem](https://paragraph.com/@homecoinfinance/lend-exploit-post-mortem), [Rari original postmortem](https://medium.com/@JackLongarzo/fuse-exploit-post-mortem-76ce18d8974), [DeFiHackLabs pinned source](https://github.com/SunWeb3Sec/DeFiHackLabs/tree/0a9b9fd81c50767ff49f81089fbf8934f2f45b02/src/test). The Rari primary report identifies multiple affected Fuse pools; the single Pool 127 transaction must not be presented as a complete Rari incident inventory.

The exact original-source check and corrected ERC20-shape diagnostics are archived as [AWS reference audit](https://github.com/KuznetsovKarazin/blockchain-analytics-lab/actions/runs/40852527355) and [corrected reference log analysis](https://github.com/KuznetsovKarazin/blockchain-analytics-lab/actions/runs/40851989349).

## 5. What this means for the manuscript

The independent source-level observation extends the earlier **label-free applicability** argument beyond Li.Fi and Revest, while remaining below the evidential threshold for a new incident-detection performance assessment. It is valid to write:

> In a further source-limited pre-admission audit, we examined all 60 daily Ethereum log partitions for the candidate Bacon and Rari Fuse Pool 127 components. At the nominated single-emitter boundaries, fewer than 20 core logs occurred on 15/30 Bacon days and 26/30 Rari fETH days. Under the fixed daily-reset rule, these days could not possibly provide 19 strictly preceding positive per-token observations. The result is a necessary feature-computability bound derived without exploit labels; it does not quantify actual eligibility on the remaining days or new incident-detection performance.

It is **not** valid to claim from these counters that these additional attack executions were missed or detected; full selected all-emitter bundles, successful transaction statuses, token histories, exact reference inventories and independent case admission are still required.

## 6. Next research gate

1. Independently verify the historical core boundaries and reference inventory of Bacon and **all relevant Rari Pool 127** exploit executions; keep other Fuse pools separate.
2. For the 60-day source, freeze selective transaction-hash projections and obtain full all-emitter selected bundles plus execution metadata, without downloading unrelated multi-gigabyte transaction/source bodies. Audit token histories in exactly the same rules for each nominated component.
3. Only then perform frozen daily-reset/7-day/continuous score and notification replay, separately from the earlier exposed Li.Fi/Revest development evidence. Preserve no-hit, unavailable and unknown-alert outcomes.
4. Do not adjust the outflow rank or count thresholds after inspecting these candidates.

**The primary independent external detection cohort still comprises only Li.Fi and Revest (two families).** The present additional data are source-reproducibility and feature-applicability observations for two **prospective** cases, not new independent detection evaluations.
