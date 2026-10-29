# Nomad fixed-core high-volume follow-up (Phase31)

Frozen before acquisition or detector scoring in this follow-up. This is a purposive sensitivity study prompted by review M1, not an independent random sample or retrospective preregistration.

- Choose Nomad, `cohort28_15`, because its already published Phase28 census has 930 selected transactions, more than any of the seven replay streams (38–134), and is tractable within a 3.6 GB acquisition cap. No detector result is used for selection.
- Preserve Phase28 core `0x5d94309e5a0090b165fa4181519701637b6daeba` (Replica proxy), the immutable 30-day window 2022-07-03 through 2022-08-01 inclusive, and the original AWS source identities/ETags. No core substitution after looking at results.
- The traffic is highly concentrated: 884 transactions on the final UTC day, 46 on the preceding days. Thus this tests a busy day/stream, not uniformly high daily traffic or an independently sampled population.
- Reuse the immutable Phase28 complete projected census for the 18 zero-selected days; do not download their payload columns. On each of the 12 nonempty days read every address/coordinate row group, seal selected coordinates, then read **all** row groups containing any selected coordinates. This preserves cross-row-group complete bundles.
- Acquire the selected transactions' complete original AWS event topics/data and original AWS transaction identities and `receipt_status`; no Blockscout data substitution. The direct Blockscout preflight returned HTTP403. Record source listing/body hashes and byte range receipts, not receipt-root authentication.
- Cap acquisition at 3,600,000,000 response bytes, 1,600 range requests and 1,800 wall seconds. A failed or truncated stream is INCOMPLETE, with no detector performance claims.
- Keep all original phases unchanged. Store normalized full selected log bundles and statuses so the scientific transformation and replay can be independently verified offline.
- Only after source acceptance, compute the existing fixed methods and policies without reference labels: positive same-token core-outflow ranks, warm-up19/window128, thresholds1/20 and1/10, daily/7d/cumulative initialization; count>=10 core-emitter logs/60s; group on previous candidate with gap>=300s; greedy/paced/token bucket B={1,5,20}.
- Seal label-blind replay before any optional exact reference join. Nomad's multi-actor inventory is incomplete; neither this stream nor any subset of cited executions estimates incident-wide recall.
