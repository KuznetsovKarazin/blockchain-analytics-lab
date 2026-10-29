# Phase 29 — Independent reference-role and observation-boundary adjudication

**Scope.** The fixed 16-case Phase28 frame is retained verbatim. Phase28 measured only distinct core-selected transaction traffic in the *PoC fork-block anchored* 30-day windows, not exploit-day windows. Phase29 reviews independent evidence of successful historical exploit executions, fixes role ambiguity and identifies whether the named emitter actually measures the security-relevant boundary. No detector scores, alert suppression policies or attack-hit claims are computed in this stage.

## Mandatory gates for any further detection run

1. **History truth:** identify the original Ethereum success transaction via a contemporary first-party postmortem or an independent technical analysis. Forked Foundry PoC transaction, preparation, post-incident swap and remediation must be classified separately. A verified indexed transaction status is necessary but not sufficient to call it an exploit.
2. **Event-time correction:** bind the 30 UTC dates ending on the actual execution day, **not** the PoC fork block. Preserve the Phase28 census unchanged under its original window labels. Never reuse a wrongly anchored window for attack-day hit evaluation.
3. **Emitter relevance:** document immutable deployment/proxy-emitter address in the historical transaction; never add attacker, a token or an auxiliary pool merely because this improves scores. Where victim funds cross an external ERC20 boundary rather than the nominated core, retain the mismatch.
4. **Source evidence:** separately verify original AWS Ethereum source partitions, exact transaction identity, full all-emitter log bundle and historical execution status. An explorer-indexed success with logs alone remains below original-source admission. Full independent receipt-root authentication is a further tier and must not be implied.
5. **Label completeness:** close the known execution subset as far as independent evidence permits, and disclose unknown attack transactions. Multi-stage attacks have separately recorded setup/execution/swap stages.
6. **Frozen replay:** preserve Phase16/18 formulas (min_history=19, history cap 128; rank 1/20 and sensitivity 1/10; count >=10 core logs in 60 s; grouping 300 s; greedy/paced/token bucket, B={1,5,20}). No case-specific threshold tuning or post-result emitter selection. Predict applicability from history and construct before joining labels.
7. **Unavailability:** unknown reference roles, absent source days or incomplete historical bundles exclude a candidate from a *detector-performance denominator* but not from the original 16-case screening ledger.

## Evidence layers

- `SOURCE_ONLY`: vetted Phase28 AWS traffic census; contributes to readiness only.
- `INDEXED_CANDIDATE`: Blockscout status/core-log-count metadata for an investigator-nominated hash.
- `REFERENCE_ROLE_SUPPORTED`: independently documented original exploit transaction and plausible named core, but no original-source full-window admission.
- `SOURCE_AND_REFERENCE_ADMITTED`: all gates 1–5 and an immutable source manifest passed; only then can the fixed replay run.
- `DETECTOR_REPLAY_VERIFIED`: label-blind replay on accepted observations, independent code check, and exact reference join.

The current Phase28 16-case frame has **zero** `SOURCE_AND_REFERENCE_ADMITTED` cases. The previously accepted Li.Fi/Revest/Bacon/Rari corpus is a separate exposed diagnostic sample, not automatically an independent validation sample.

## Reproducible decision rule

Read `CANDIDATE_FRAME.json` and `results/REFERENCE_PREFLIGHT.json` at immutable Phase28 commit `fc25cd8c187e6c8b0afb9afae2072f78dc2d3c0e`; join by candidate ID; record all 16 cases (including zero indexed references). Independently source and classify any prospective exploit identities. A transaction may be a known original exploit even when its nominated core emits zero logs; this is evidence of a boundary mismatch or incomplete nomination, **not proof that the whole protocol was silent**.

## Locked scientific outputs (existing)

- Phase28 traffic: 16 emitter-windows, 480 dependent emitter-days, 44,780 selected transactions; 410/480 days below the 20-selected-TX necessary condition.
- Phase26 comparative activity: 12 protocol contracts × 2 windows, not independently certified benign; z-score/MAD/EWMA are readiness of *core log counts*, **not** ERC20 token-outflow readiness.
- Full detector performance on the new sixteen **not yet established**.

The next computational operation is an exploit-day-aligned, original-source-bound acquisition for the first independently referenced and correct-core candidates; the identities, source windows and exclusion decisions must be frozen before reading any new rank output.
