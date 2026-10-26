# Phase 12: verified storage interpretation and bounded routing discovery

26 October 2026. **Three independently checked historical storage snapshots show different selector destinations despite the same reported diamond code hash at the window endpoints. Administrative history remains unavailable after a preserved provider refusal.** This phase admits no incident and computes no Li.Fi detector score. The failed event acquisition must not be interpreted as an observed empty event history.

## Scientific scope

The [admission scope review](scope_review/ADMISSION_SCOPE_REVIEW.md) retains the previously accepted historical entrypoint/routing-population target and permits bounded discovery only. It adopts no fixed-emitter fallback, new evaluation freeze or eligibility change. Candidate order, window `[2022-02-19, 2022-03-21)` UTC, methods, thresholds, warmup, grouping and budgets remain unchanged.

Complete routing history is a claim-specific requirement, not a universal prerequisite for every address-based workload or event-shape statistic. The existing measurements consume a supplied address set rather than facet or owner histories. A future fixed-address study would therefore need a separate prospective, all-frame scope amendment before affected measurement acquisition, evaluation or label joining. That amendment is not adopted here. Missing flow, no core log, cold start or weak detector response cannot justify exclusion or adding victims to the monitored population.

## Completed layout experiment

An owned synthetic probe imported the exact retained `LibDiamond.DiamondStorage` and `CBridgeFacet.Storage` types. The pinned native Solidity compiler `0.8.7+commit.e28d00a7` received the 44 retained source files and one owned probe; output selection requested only the probe's `storageLayout`. The probe was never deployed. Two separately accepted executions each made one compilation and one version invocation, with zero network requests. The auditor independently reconstructed semantically identical inputs with different serialization and obtained the same complete 6,930-byte compiler output. This is independent reconstruction using the same compiler, not compiler diversity or formal proof.

The compiler confirms relative struct-member placement and fixed-array spans. Independent source/AST review connects those types to the deployed source's assembly namespace assignments; separate review of the Solidity 0.8.7 storage and ABI rules supplies the mapping and dynamic-array formulas. These formulas are not presented as fields emitted by `storageLayout` or as independently executed EVM tests. The producer result remains immutable with its original pending-review status; the [independent review](qa/QA_PUBLIC.md) records the later PASS.

| Object | Confirmed interpretation |
|---|---|
| Diamond namespace `D` | `0xc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c` |
| CBridge namespace `C` | `0x86b79a219228d788dd4fea892f48eec79167ea6d19d7f61e274652b2797c5b12` |
| Diamond fields | Selector map at `D`; facet map at `D+1`; facet-address array length at `D+2`; interface map at `D+3`; owner at `D+4` |
| Selector-map value | Facet address in low 160 bits; selector position in upper 96 bits, including valid position zero |
| Facet-map value | Selector-array length at its mapping base; facet position at base plus one |
| Selector array | Eight `bytes4` elements per word, low-order element first |
| Facet-address array | One 20-byte address per word, in low 160 bits |
| CBridge word | Bridge address in low 160 bits; 64-bit chain identifier at byte offset 20; upper four bytes undeclared |

For mapping slots, the four selector bytes precede 28 zero bytes, whereas an address follows 12 zero bytes. The 32-byte key is concatenated with the 32-byte mapping base before Keccak. Dynamic-array elements start at the Keccak of the length slot; selector index `i` uses word `floor(i/8)` and bit offset `32*(i mod 8)`, while address index `i` uses word `i`. Slot arithmetic is modulo `2^256`.

All delegated namespace reads must target the historical diamond `0x5a9fd7c39a6c488e715437d7b1f3c823d5596ed1`. The synthetic probe's ordinary root slots 0 and 5 are not the deployed namespace roots. CBridge decoding at the diamond remains a source-guided packed-field interpretation until the corresponding facet and routing are bound active at the checkpoint; it does not alone establish effective bridge configuration. Unused high bits are retained rather than assumed zero.

The exact retained event ABIs also fix topic signatures and indexed fields: `DiamondCut` has no indexed arguments; both `OwnershipTransferred` addresses are indexed; `Inited` indexes its bridge argument only. The `Inited(address,uint64)` signature can be shared across facets, so its occurrence alone cannot identify CBridge configuration.

## Historical acquisition

The first accepted acquisition stopped with `UNAVAILABLE_UNDER_FROZEN_CAP`. It made **five RPC requests and retained 29,835 response bytes**: a successful chain identifier and three successful checkpoint headers, followed by the first `eth_getLogs` request returning HTTP 400 / JSON-RPC error 35. The provider reported a free-plan range restriction. The exact requested interval was blocks 13,984,588–13,994,587 inclusive: 10,000 blocks. This observed refusal does not establish the provider's true numerical threshold or its underlying cause.

No administrative log chunk completed and no storage keys were requested. Empty event/state arrays in the failed result therefore encode missing acquisition, not an observed empty history or empty state. The frozen runner and plan, all five request/response records and the terminal failure remain immutable. No event retry, smaller range, alternate provider or automatic cap expansion occurred.

A separately accepted checkpoint-only continuation reused the four successful chain/header responses. It made **15 new `eth_getProof` requests, requested 139 `(block, slot)` values and retained 345,304 response bytes**. Across both attempts the total is **20 RPC requests and 375,139 response bytes**, including the failed event query; reused responses are counted once. There were no log retries, new header queries, range splitting or provider fallback. The [independent actual audit](qa/QA_PUBLIC.md) passed, rederiving slots and raw-word decoding without importing the producer module or making new requests.

| Checkpoint | Block | UTC block time | Enumerated facets | Enumerated selectors | Requested (block, slot) values |
|---|---:|---|---:|---:|---:|
| Creation block end | 13,984,588 | 2022-01-11 13:47:48 | 1 | 1 | 8 |
| Immediately before window | 14,233,162 | 2022-02-18 23:59:54 | 9 | 25 | 64 |
| Last included block | 14,426,367 | 2022-03-20 23:59:50 | 9 | 28 | 67 |

At each checkpoint the decoded arrays, their positions and the queried selector-map backreferences are mutually consistent. The reported diamond code hash agrees with the previously established runtime hash. The creation block-end owner, one-facet array and selector mapping match the retained constructor bootstrap. The receipt describes its transaction; later transactions in the same block could have changed and restored state, so agreement is not a proof excluding same-block mutations.

Between the window checkpoints, five selectors appear only in the end enumeration and two only in the start enumeration. Of the 23 selectors enumerated at both checkpoints, 14 have a different facet address and nine retain the same `(facet, position)` tuple. No shared selector changes only its stored position. These are differences between two observed enumerations, **not a count of upgrade transactions or reconstructed activation epochs**. Absence from an array does not by itself prove that every corresponding unlisted mapping key is zero. The facet-address sets share four members; five appear only at each respective window endpoint. The three snapshots collectively nominate 14 distinct facet addresses and 30 selectors; these are discovery targets, not a newly admitted monitoring population. Exact inventories and accounting are recorded in the [routing findings](routing_gate/ROUTING_FINDINGS.md).

The owner is equal at all three checkpoints. The source-guided CBridge fields change from zero address / chain identifier zero at creation to bridge `0x5427fefa711eff984124bfbb1ab6fbf5e3da1820` / chain identifier one at both window checkpoints. Equal window fields do not prove uninterrupted ownership or effective bridge configuration. The historically compiled CBridge facet address appears in the start enumeration and is absent from the end enumeration; its three shared selectors name another facet at the end. This reinforces the distinction between a code target remaining deployed and that code target being selected by a registry.

The terminal continuation disposition is `CHECKPOINT_ARRAYS_OBSERVED_HISTORY_UNAVAILABLE`. No administrative event history was obtained and no event replay or event/state comparison was performed. Snapshot state is provider-returned evidence: proof nodes were retained but their Merkle paths were not verified. The arrays and backreferences do not exhaust an unbounded mapping. Other reachable writers, initializer effects and intervening change-and-restore remain unresolved; continuous routing and complete historical population are not established.

## Contribution and limits

The layout result replaces unverified manual slot assumptions with a compiler-confirmed, independently reviewed interpretation specification. The returned checkpoints then reveal different selector destinations despite the same reported diamond code hash at both window checkpoints: code identity alone is insufficient for a claim of stable historical routing. The bounded procedure also records an observed provider refusal without turning unavailable logs into a negative scientific result. The scope review also prevents an unnecessarily strong routing claim from silently becoming a universal requirement for every fixed-address measurement, while preserving the currently accepted discovery target.

This is a reproducibility and measurement-validity contribution. It supplies no new detection accuracy, attack recall, runtime-performance improvement, continuous routing proof, complete monitored population or independent case admission. The earlier conditional observation limits remain unchanged: core-emitter selection can omit transactions without a core log, and user-to-external transfers do not automatically count as monitored-core outflow.

The [method-documentation record](storage_layout/method_documentation.json) lists four primary URLs and three web-tool calls containing three search queries, four opens and three finds. These are documentation operations, not chain requests; backend HTTP counts and transferred bytes are unknown. Full source-bearing compiler material and full web renderings remain private. Public results consist of owned code, source-free facts, hashes and bounded conclusions. The published programs preserve the exact executed bytes. A public checkout alone is not a complete reproduction kit: execution also requires the exact private frozen plans, acceptances, scope/QA records and retained inputs. In particular, the public Phase11 compilation aggregate is a derivative and cannot replace the full hash-bound scientific JSON consumed by the acquisition runner. The evidence archives provide retained receipts, source-free projections and exact references; omitted third-party source sets and complete compiler inputs/outputs must be obtained separately for a complete source or compilation replay.

For the retained historical entrypoint/routing claim, the next separately frozen gate should bind the 14 snapshot-nominated facet addresses to code at the observed blocks and establish what bounded administrative history is available. This would identify which interval-level claims the evidence can support. Complete-routing obligations apply to the relevant deployed paths, not every conceivable source helper; no prospective scope amendment or case admission is implied.
