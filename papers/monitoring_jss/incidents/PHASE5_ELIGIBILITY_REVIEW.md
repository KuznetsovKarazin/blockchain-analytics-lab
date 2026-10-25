# Article 2 — independent incident eligibility review

25 October 2026. Read-only review against local Article 2 commit `446b80c2b9c1117ce15b9879704f34e60b642175`. This is an advisory eligibility review, not a frozen experiment or an acquired dataset. No new raw logs, detector outputs, scores or labels joined to predictions were obtained. The existing candidate registry was not changed.

## Decision

**No currently registered case is ready for a new independent detection evaluation.** Euler and Beanstalk have already become development diagnostics. BSC Token Hub remains a potentially useful different-family case, but its data and label gates have not passed. Calling any of these an independent test now would overstate the evidence.

The concrete next acquisition candidate is **Revest on Ethereum, 27 March 2022**, subject to the gates below. It offers an Ethereum acquisition route already exercised by this project and a protocol/family not yet scored in Article 2. It is **not an unknown incident**: it occurs in the historical S2 catalogue, and its public postmortem has now been read during this review. It is a feasibility candidate, not yet an admitted holdout and not by itself the required 2–4-case, multi-family evaluation.

This distinction matters: prior knowledge of an incident does not automatically invalidate a fixed-method, protocol-held-out evaluation, but case-informed feature engineering or selection based on detector outcomes does. All prior exposure must remain visible, and claims must be limited to the declared cohort.

## Status of registered cases

| Case | Exposure supported by local evidence | Remaining issue | Permitted next role |
|---|---|---|---|
| Euler, 13 March 2023 | Historical L2 catalogue/curation and whole-chain aggregation; current outcomes inspected | Any method adapted to those outcomes cannot be independently tested on them | Development and regression diagnostic |
| Beanstalk, 17 April 2022 | Historical L2 catalogue/curation; current outcomes inspected | Same case cannot become a new holdout after observing phase 4 results | Development and regression diagnostic |
| BSC Token Hub, 6 October 2022 | Historical L0 only within the audited repositories; current source/one-receipt feasibility exposure | No complete continuous BSC/Beacon population; second positive transaction unresolved; prior public RPC log/trace probes insufficient | Reserved eligibility candidate; no cross-chain consistency evaluation yet |

The BSC source conflict is still present in the original Coinbase investigation retrieved in this review: the second wave is described with the first transaction's abbreviated identifier/link. The report gives the two event times but also an inconsistent textual interval. This is not a reason to invent the second hash. A complete transaction inventory and independent primary-chain verification are required. The already-recorded one-receipt result is not a substitute for continuous coverage. Sources: [Coinbase original investigation](https://www.coinbase.com/blog/bsc-token-hub-compromise-investigation-and-analysis-8), existing `incidents/incident_candidates_20261025.json`.

## Revest: precise evidence and limits

The official Revest security page identifies 27 March 2022 and links the protocol's postmortem. That postmortem identifies the affected Ethereum deployment, describes multiple executions during one incident, and documents subsequent contract changes. BlockSec's original investigation independently describes the same date, chain and ERC-1155 callback/reentrancy family. These are sufficient to motivate eligibility work, **not** to establish all positive transactions, a historical deployed ABI, or a complete monitored population. Sources S1–S3 below.

The historical S2 CSV already includes `Revest Finance` at line 70, with date `2022-03-27` and cause `Reentrancy`. Its `$11.2 million` catalogue field differs from the approximately `$2 million` stated in the protocol and BlockSec reports. The discrepancy is a catalogue-quality issue; do not use historical loss magnitude to rank this candidate or to claim prevented loss. This review does not modify book results.

Scoped local checks performed:

- A tracked-text search for `revest|2022-03-27` over `README.md`, `CHANGELOG.md`, `docs`, `scripts`, `src`, and `results` found only `results/security/s2_v1/incidents.csv`. This is a text search, not exhaustive historical or binary-data inspection.
- The locally preserved exposure audit lists three historical/current K4 runs with the same 49 input dates. `2022-03-27` is absent from all three date lists. This rules out that attack-day partition in those listed manifests; it does not rule out every ordinary Revest transaction on other dates.
- The pinned DeFiHackLabs 2022 README contains the incident heading at line 2695 and a reference to `src/test/2022-03/Revest_exp.sol`. The current K4 price-only loader requires a price/oracle keyword in the heading; `Revest Finance - Reentrancy` does not satisfy that filter. This code/heading inspection is evidence about the positive-cohort selection rule, not a full replay of the all-mainnet exclusion loader.
- The Revest PoC file was not downloaded or executed. Exact all-mainnet exclusion-set membership remains unresolved. Therefore classify exposure as **at least L1 confirmed, possible L2 pending targeted curation audit**, not L0.
- The existing phase 4 raw source archives include dates on and around 27 March, but only Euler and Beanstalk emitter populations were selected and scored. Prior archive acquisition is disclosed; it is not evidence that Revest-specific decision outcomes have been inspected.

The audit does not cover unuploaded book drafts, all branches or deleted scratch files, personal prior knowledge, or every row of binary K4 background tables. These limits must not be replaced by a global claim of no exposure.

## Proposed preregistration route

This is a proposed decision sequence, **not a frozen protocol**. Freeze the sequence and acceptance gates before requesting Revest payloads or inspecting any candidate's detector scores.

1. **Declare the scientific estimand first.** For the existing fixed workload rule, the claim is notification allocation and retention of independently reported incident events at measured load. It is not a validated general attack classifier. If the paper requires new semantic detectors, design and fix them using development cases first, then choose a separate test cohort. Do not derive a Revest-specific rule from the report and evaluate it as held out on Revest.
2. **Freeze the candidate frame and exclusion reasons.** Start from a versioned catalogue rather than accepting whichever candidate yields an alert. Screen all candidates in the declared frame using chain support, continuous data availability, deployment history and prior exposure. Preserve exclusions and inconclusive cases. Revest is the next feasibility probe, not a success-based replacement for Euler/Bean.
3. **Finish Revest exposure audit.** Inspect the exact pinned PoC as text and replay the two metadata loaders only; record positive-cohort and exclusion-set membership separately. Do not execute exploit code. Reconcile candidate identity across the S2 row, official report and loader metadata.
4. **Freeze population before outcomes.** Establish every in-scope protocol emitter from deployment/registry records dated before the period, plus activation/upgrade boundaries. The postmortem's patched contract is not automatically the pre-incident emitter. Include all events of the declared population, not only attacker contracts or topics seen in a positive execution. Native/ERC-20 outflows and reentrancy claims require separately specified receipt/trace/state evidence; emitter counts alone do not supply those semantics.
5. **Use a complete, prespecified window.** A 30-day proposal is `[2022-02-26T00:00:00Z, 2022-03-28T00:00:00Z)`: 29 complete UTC days before the incident date plus the incident day. It fits the agreed 30–60-day range. A 45-day-prehistory alternative must be chosen before outcomes, not expanded or shortened after seeing alerts. Unknown days remain unlabelled, never assumed benign. Initial state and any separate warm-up must be stated.
6. **Close completeness and label gates independently.** Verify all source partitions, block continuity, event identities and historical population membership. Build a report-supported positive execution inventory with receipt/block/transaction positions and an adjudication ledger that separates execution, preparation, failed attempts and subsequent swaps. Multiple executions still count as one incident. Keep label metadata outside the detector input and join only after immutable decisions close.
7. **Freeze methods, budgets and endpoints.** Keep the declared rule and B=1/5/20 with B=5 primary if using the phase 4 comparator. Record actual notification load, first eligible emitted notification, suppressed positive candidates and reason, all misses, and unknown-label coverage. Distinguish logical block time from observed arrival time. No prevention claim follows from post-transaction logs.
8. **Admit only after every gate passes.** Record either admitted-with-disclosed-L1/L2-exposure or an explicit exclusion. Revest alone cannot satisfy the intended 2–4 independent incidents across at least two mechanism families. Do not tune on Revest and retain it in the same final test cohort. If there is no valid cohort within resources, report the completed work as engineering/development evidence and keep the generalization claim open.

## Immediate recommendation for the current phase

Proceed with the root agent's controlled resource/service-cost study on the already verified stream. It closes a separate operational evidence gap without pretending to solve independent detection validity. For the following acquisition phase, begin with Revest **metadata and deployment eligibility only**, then freeze the final cohort and detector before comparison. Keep BSC reserved unless continuous data access and both-chain requirements are actually resolved. No unsupported new case is admitted by this review.

## Sources and retrieval references

- **S1:** [Revest Protocol Documentation — Security Checklist](https://docs.revest.finance/resources/security-checklist). Official protocol documentation; explicitly links its incident postmortem and later replacements. Retrieved 25 October 2026.
- **S2:** [Revest Finance — Revest Protocol Exploit Recovery Plan](https://revestfinance.medium.com/revest-protocol-exploit-recovery-plan-b06ca33fbdf5), 28 March 2022. Official protocol account, verified by S1 linkage. Used only for date/chain, incident-versus-execution distinction, loss-field discrepancy and deployment-change caution. Retrieved 25 October 2026.
- **S3:** [BlockSec — Revest Finance Vulnerabilities: More than Re-entrancy](https://blocksec.com/blog/revest-finance-vulnerabilities-more-than-re-entrancy), 31 March 2022. Original investigator analysis. Used for independent date/chain/family confirmation and loss-field discrepancy. Retrieved 25 October 2026.
- **S4:** [Coinbase Threat Intelligence and Special Investigations — BSC Token Hub Compromise investigation and analysis](https://www.coinbase.com/blog/bsc-token-hub-compromise-investigation-and-analysis-8), 31 October 2022. Original investigator report; its unresolved second-wave identifier conflict is preserved, not silently corrected.

The report paraphrases short factual points; third-party article text and imagery are not included. The coordinating review reopened all four original sources and confirmed the cited factual points before retaining this note.

## Local evidence hashes

| Evidence | SHA-256 |
|---|---|
| `monitoring-work/results/security/s2_v1/incidents.csv` | `6f129aec0e9f31d930e374625992600d4cb25ce5892968c8698ae1b2642ccf8e` |
| `exposure_source_evidence/main_k4_manifest.json` | `cc4cb3a60f3685537919f2132887bc9a53a59c039cb115724b132bca28d85820` |
| `monitoring-work/papers/monitoring_jss/incidents/exposure_audit_20261025.json` | `3942ff01b628a532a8ace13ada726bca7f4a0d97f09dfa3d6ea7cca5c26c9f00` |

Metadata provenance inherited from the scoped audit: detector default-head snapshot `77bf3d8a3aed1bf394fd850903e7fd59ad129187`; K4 execution `de55dc478e5313a6861e56744078f9bd224d4ade`; DeFiHackLabs pin `23c7bd83ccb4524972a9493617fcc8764ab6269b`. These are historical inspected revisions, not claims about the current remote head.
