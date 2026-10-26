# Phase 13: sampled destination code and history availability

26 October 2026. **Six of 14 nominated Li.Fi facet addresses now have exact sampled source/runtime bindings, including five newly bound addresses. All 14 shared selectors whose destination changed between window endpoints also lead to different full runtime bytes. Administrative history remains unavailable.** No Li.Fi detector score or independent incident admission is produced.

## Completed evidence

| Result | Observed value |
|---|---:|
| Nominated address–checkpoint code observations | 19 across 14 addresses |
| Fresh code responses / exact retained response | 18 / 1 |
| Empty sampled runtimes | 0 |
| Exact matches to retained compiler output | 11 observations at 6 addresses |
| Newly source-bound addresses beyond CBridge | 5 |
| Changed selector destinations with different full runtime bytes | 14 of 14 |
| Phase13 new RPC methods / retained response bytes | 21 / 154,743 |
| Successful event chunks / nominal replays | 0 / 0 |

The code observations use only the checkpoint pairs nominated in Phase12. All 14 addresses have distinct full-runtime digests; the four addresses shared by the window endpoints return identical bytes at those two samples. Comparing every observation with all 36 nonempty runtime objects in the independently reproduced Phase11 output required 684 byte comparisons. Its other 23 contract outputs are empty. There was no new compilation, source fetch, settings search or metadata masking.

Exact matches identify DiamondCutFacet at creation/start/end; DiamondLoupeFacet, OwnershipFacet and WithdrawFacet at start/end; and NXTPFacet and CBridgeFacet at start. CBridge was already bound. Eight addresses remain unmatched within the retained output. Nonmatches establish neither malicious behavior nor unavailable source. The checked `diamondCut` and `transferOwnership` checkpoint bindings now support focused source review, without proving uninterrupted authority.

The diamond entrypoint's reported code hash was equal at the window endpoints. Joining its selector mappings with sampled destination code establishes different full runtime bytes for all 14 changed shared bindings. Metadata can contribute to byte differences; execution-semantic differences, transition counts and activation times are not inferred. Exact inventories are in [the acquisition findings](acquisition/FINDINGS.md).

## Preserved acquisition limits

The new schedule prospectively fixed 39 ranges of at most 5,000 blocks over 14,233,163–14,426,367, seeded by the checked pre-window state at 14,233,162. The original study window and earlier Phase12 refusal were preserved.

The dRPC attempt made 19 requests and retained 154,568 bytes. Eighteen code calls succeeded, but the first exactly 5,000-block event range returned HTTP 400 / error 35 with text referring to a 10,000-block restriction. This particular refusal does not identify a general provider limit or its cause.

A separately frozen PublicNode continuation made two requests and retained 175 bytes. Chain ID 1 succeeded; the required start header returned HTTP 200 / error 4444, reporting pruned history for block 14,233,162 and an earliest available block of 15,500,000. That is a response statement, not a measured general retention boundary. No valid new header, planned positive-control query or window query followed. Both attempts stopped without internal retry or adaptive splitting; the provider change is an explicit separate continuation. See [its findings](history_continuation/HISTORY_FINDINGS.md).

Errors are not empty event arrays. Window event counts remain unknown, and no event/state comparison occurred. The [independent review](qa/QA_PUBLIC.md) checks both attempts, byte comparisons and accounting. Documentation lookup is separate: two web-tool calls, three searches and two opens; backend HTTP counts and bytes are unknown.

## Scientific use and next step

The result supports measurement validity and reproducibility: entrypoint identity, dispatch state, destination code and observed activity require distinct evidence. It establishes no new detector, accuracy gain or algorithmic novelty. Provider observations were not cryptographically authenticated; snapshots cannot exclude change-and-restore, and relevant writers, initializers and complete historical membership remain unresolved.

The [accepted scope](scope_review/CONTINUATION_SCOPE_REVIEW.md), candidate order, window `[2022-02-19, 2022-03-21)` UTC, methods and budgets remain unchanged. No fixed-address fallback, case exclusion or evaluation freeze was adopted. Next work concerns evidenced archive/event-source coverage and proportionate source binding of the eight unmatched facets, without algorithm rework. Repeated range reductions without new evidence are not the next experiment. A different estimand would require a separate prospective all-frame amendment. Full source/compiler artifacts remain separate dependencies; public code and summaries are not a standalone full-source rebuild kit. The exact executed programs also require the archived frozen plans, acceptance records and retained private inputs. The public Phase11 compilation aggregate cannot replace the full hash-bound scientific JSON used by the programs; replaying the runtime comparison additionally requires the excluded complete compiler output. Original input identities and exclusions are recorded in the evidence archives.
