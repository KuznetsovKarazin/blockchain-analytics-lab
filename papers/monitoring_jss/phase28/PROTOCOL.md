# Phase 28 — frozen incident-derived source-readiness cohort

**Design date:** 2026-10-29; **catalogue:** DeFiHackLabs commit \`0a9b9fd81c50767ff49f81089fbf8934f2f45b02\`. The 16 source-derived entries and nominated emitter addresses are fixed in \`CANDIDATE_FRAME.json\` *before* any new S3 traffic measurement. This is an exploratory extension selected after the Li.Fi/Revest/Bacon/Rari results were known, **not** a pre-registered or statistically independent detection-performance test. Retain uncertain and non-realized PoCs in the disposition frame; never replace based on measured traffic or detector outcomes.

## Research question and unit

For each fixed candidate emitter, how frequently does the address emit events in fewer than 20 distinct Ethereum transactions over each UTC day in a 30-day window? The unit is a named emitter-window, with 30 dependent daily observations per case. The tested original daily-reset token-rank detector requires 19 **strictly prior positive outflows of the same token**; if the emitter appears in fewer than 20 selected transactions that day, the feature cannot be eligible. At 20 or more, eligibility is *unknown*, not affirmative.

## Window and source binding

Use the 30 UTC calendar dates ending inclusively on the UTC date of the pinned **PoC fork block** (timestamp from Blockscout Ethereum block metadata). A PoC fork block is **not** the historical exploit execution. These windows are descriptive source windows, not automatically attacker-relevant 30-day windows. No incident-day, rank, alert or recall inference is permitted without an independently verified execution and observation boundary.

For each date require a complete, nontruncated AWS public-blockchain S3 inventory of original \`v1.0/eth/logs/date=YYYY-MM-DD/\` Parquet parts. Retrieve \`address\`, \`block_number\`, \`transaction_index\` for **all** original rows and row groups with the pinned Phase16 byte-range reader, exact HTTP 206, \`If-Match\` opaque source ETag and recorded per-range SHA256. Record full row coverage and lowercased exact emitter-address counts. Count distinct \`(block_number, transaction_index)\` per day, not log events. Missing source/failed requests = \`UNAVAILABLE\`, never zero. No labels, raw token amounts, model score, or attacker identity enter feature readiness.

Partition into eight independent two-case CI jobs (not eight independent scientific replications). Per job cap 1000 range GETs, 1.4GB actual response payload, 1000s wall time, no retries or redirects. Require 30 accepted day measurements per complete case; else case remains incomplete. Keep full excluded and incomplete frame rows and actual-source receipts.

## Independent QA and admissibility

Reconcile case names/addresses to frozen registry, exactly 30 consecutive dates, source listing identity, nonnegative daily counts, distinct transaction count <= source core events, all case summary arithmetic and immutable output hashes. Never report a different denominator without a complete disposition table. The result is **label-free selected-transaction readiness**, not ERC20 token-specific readiness and not attack-detection performance.

For a **separate later** independent detection evaluation, freeze before scores: verified successful historical execution hashes, the target incident day, source-audited emitter/core roles, complete all-emitter selected bundles and execution statuses, original token-rank/count formulas, history/grouping/budgets, and exact-reference inventory. Mark missing evidence unavailable rather than missed or safe. Any new-case prediction must be logged before evaluating its historical transaction.

## Validity

Catalogue and core nominations are investigator-informed, some PoCs are hypothetical, non-Ethereum exploits are excluded by mainnet filter, and fork-block dates may not equal incident dates. No population significance, early detection, classifier accuracy, precision or attack recall follows from this census. Keep the primary four-family results separate, and report the sixteen candidates as screened nominations until admission.
