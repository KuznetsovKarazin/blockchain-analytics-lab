# Phase 22 — Protocol for source-bounded external monitoring evaluation

**Frozen rules before full selected-bundle scoring** (29 October 2026).
Research branch: `research/monitoring-applicability-20261029`.
Original accepted method record: `e720697bc3986dd291a7047c580cf973ae6e5567` (Phase 16).
Phase 18 is exploratory diagnostic; Phase 20–21 are independent source/applicability controls.
No changes to original observations, original decisions, companion pin or `scripts/run_all.sh`.

## Cohort, intent and experimental unit

- **Bacon Protocol**: Ethereum mainnet; 30 complete UTC days `[2022-02-04,2022-03-06)`; sole nominated proxy emitter `0xb8919522331c59f5c16bdfaa6a121a6e03a91f62`; one independently cited successful exploit execution candidate `0x7d2296bcb936aa5e2397ddf8ccba59f54a178c3901666b49291d880369dbcf31`.
- **Rari Fuse, Pool 127**: Ethereum mainnet; `[2022-04-01,2022-05-01)`; separately report fETH `0x26267e41ceca7c8e0f143554af707336f27fa051`, fUSDC `0xebe0d1cb6a0b8569929e062d67bfbC07608f0a47` and Comptroller `0x3f2d1bc6d02522dbcdb216b2e75edddafe04b16f`. Do not pool them into one optimized core. One independently cited Pool 127 successful execution candidate `0xab486012f21be741c9e674ffda227e30518e8a1e37a5f1d58d0b0d41f6e76530`. The full Rari incident spans multiple Fuse pools and is not inventoried in this experiment.
- Cases and addresses were **incident-informed**, and this extension was started after Li.Fi/Revest results were known. Report it as an explicitly bounded additional evaluation, not prospectively blind random validation.
- Independent incident families, not transaction rows, token-day cells, software test counts or budget configurations, are the scientific sampling units.

## Two-layer source audit and authoritative boundaries

1. Original S3 Ethereum log partitions are enumerated and checked on 60 complete days (Phase 20); all original `address` row groups were covered. Phase 21 counted unique selected `(block_number, transaction_index)` pairs from the **original** Parquet `address`, `block_number`, `transaction_index` columns, with exact Phase 20 count reconciliation.
2. Phase 22 A uses **these frozen selected positions** and original S3 Parquet `transaction_hash`, `block_hash`, `block_timestamp`, `log_index` to recover exact identities and *complete emitted-log counts* (not the original token values). Selection is not changed by scores, reference identities, or later source failures. Every selected transaction must have a contiguous all-emitter log-index span.
3. Phase 22 B fetches `topics`, `data` and execution status via public **Blockscout API v2**, keyed exclusively by the previously recovered S3 transaction hashes. It requires the indexer's transaction/block/time/index, all-emitter log count, contiguous log indices and each nominated core-emitter count to agree with original S3 evidence. Missing, failed or mismatched records make that case **unavailable**, not normal, detected, or missed. Any bounded request failure is retained.
4. **Source-tier limitation:** Phase 22 B log topics/data and execution statuses are indexer-derived and are *not* original S3 topic/status bytes independently rehashed for all selected transactions. Do not re-label the inputs as the fully original-S3 Phase 16 evidence tier; results are strictly labelled as mixed-source indexed replay. Historic receipt roots and global chain completeness remain unverified.
5. Full source files and copyrighted third-party texts are not republished. Bounded source selection, hashes, derived token observations, exact list of selected transactions and requests/verification receipts are preserved.

## Fixed scoring and notification layers

For each distinct fixed-core observation view:

- Gross external ERC-20-shaped token outflow from the monitored core is a **positive raw token-unit amount**, aggregated per token, excluding incoming, internal, mint and burn values, using the unchanged published `transfer_observation` semantics.
- Rank `(1 + #{prior strictly earlier same-token positive amounts >= current}) / (n+1)`; most recent 128 positive amounts; minimum `n=19`; main threshold `1/20`; descriptive sensitivity `1/10`.
- Initialization: independent UTC-day reset **primary**, prior-seven-day and within-window continuous history **retrospective diagnostics**. For historical modes, only token-score histories persist; grouping and budgets independently reset each day. No pre-window history is assumed.
- Count control: 10 core-emitter logs in `(t-60 seconds,t]`, computed after the complete transaction, with independent day reset; independent of semantic token history.
- Grouping: 300 seconds after previous grouped candidate. Notification rules: greedy, paced cumulative and token bucket, separate daily caps `B ∈ {1,5,20}`; the primary descriptive allocation is greedy, `B=5`. Offered `B` and realized load are both reported.
- The score and all budget decisions are computed for *every* selected transaction, with no reference identity or exploit label in the input. Exact known-successful execution hashes are joined **after** all score streams and deterministic QA complete.

## Interpretation and acceptance gates

- Require 30/30 source-complete days and no missing selected transaction observation for each case; do not substitute zero records for missing source.
- Report population-level positive gross core-outflow transaction count, token-day activity, history eligibility, raw triggers, grouped candidates and emitted alerts *per distinct nominated view*. Put the known-subset execution hit count next to the realized notification load.
- A transaction is a hit only if its **exact hash** receives an emitted notification. Nearby or grouped transactions cannot substitute. A no-hit result is not proof of complete incident failure where the reference inventory is incomplete.
- Unadjudicated notifications are **unknown**, not false positives. Do not compute population recall, false-positive rates, precision, damage averted, live latency, or comparative statistical significance from the observed one-execution subsets.
- All negative, null, tied and source-unavailable outcomes stay visible, even if they weaken the original scientific hypothesis.
- Single-emitter Rari alternatives must not be combined after seeing their outcome. No new model or threshold may be tuned on Bacon/Rari and then retested as independent validation.

## Scientific reporting

These experiments extend the narrow Li.Fi/Revest applicability findings through a different, audited **mixed-source** 30-day replay. They do not supersede frozen Phase 16/18 results or prove universal detector superiority. Document differences of observation tier and reference completeness prominently. The original source audit and report manuscript must distinguish: *source metadata*, *selected identities*, *full event reconstruction*, *successful execution*, *raw trigger*, *emitted alert*, and *admitted known-reference hit*.