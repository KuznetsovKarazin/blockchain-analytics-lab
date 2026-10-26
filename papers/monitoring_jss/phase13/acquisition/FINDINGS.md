# Sampled runtime bindings and unavailable window events

This record covers the first Phase13 acquisition and its offline comparison with already retained compiler output. It does not cover any separately accepted later retrieval attempt.

The acquisition made **19 new RPC requests**, retaining **154,568 response bytes**: 18 successful historical `eth_getCode` calls followed by one refused event query. One exact Phase10 code response was reused, giving 19 nonempty `(address, checkpoint)` runtime observations across 14 facet addresses. The original 19-pair observation schedule was used; no unobserved facet/checkpoint grid was added.

## Exact comparison with existing compiler output

The retained, previously independently reproduced Phase11 output contains 59 compiled contracts across 44 source paths. All 36 nonempty full-runtime objects were compared with every observed code value: 684 byte-for-byte comparisons. Twenty-three empty objects were excluded explicitly; there were no missing/nonhex/placeholder objects. No compiler invocation, settings search, metadata masking or new source fetch occurred.

Eleven observed pairs match six unique addresses exactly, including compiler metadata. Five addresses add source/runtime bindings beyond the previously bound CBridge target:

| Compiled target | Address | Matching checkpoints | Runtime bytes |
|---|---|---|---:|
| WithdrawFacet | `0x5aa32689e546f04e9a8dbfc4491bd9ef691528a5` | start, end | 1600 |
| CBridgeFacet | `0x73a499e043b03fc047189ab1ba72eb595ff1fc8e` | start | 5686 |
| NXTPFacet | `0x8a017f915029e908bad589ef0f2af84d9dd4c976` | start | 7665 |
| DiamondCutFacet | `0xc46304a0b2accc4462d9bdcaa0f6bf632510d617` | creation, start, end | 5298 |
| DiamondLoupeFacet | `0xd66d7a4f3ae46ac64e492fff4236b5d97ef1c961` | start, end | 1680 |
| OwnershipFacet | `0xe7ec816130b0a2c006ec54682e08d2b38814294f` | start, end | 584 |

Eight addresses have no exact match among these retained outputs. This does not show semantic difference, malicious behavior, unavailable source or a failed scientific case. The full compiler output and source-bearing metadata stay private; [runtime_match_table.json](runtime_match_table.json) records the complete candidate inventory and source-free match results.

The 14 distinct addresses have 14 distinct observed full-runtime digests. All four addresses shared by the window endpoint enumerations return the same bytes at those two samples. For each of the 14 shared selectors with a changed facet address, its endpoint facet runtimes differ in full bytes. This strengthens the sampled identity distinction; different metadata alone can change full bytes, so execution-semantic difference and exact upgrade times are not inferred.

## Preserved provider refusal

The first fixed window query covered blocks **14,233,163–14,238,162**, exactly **5,000 inclusive blocks**. It returned HTTP 400 / JSON-RPC error 35 with the provider text `ranges over 10000 blocks are not supported on free plan`. The 113-byte response is retained. No event chunk completed and no event array was observed. The program stopped without retry, splitting, fallback or further queries. No nominal replay was performed.

The earlier Phase12 10,000-block refusal remains unchanged. These two failures establish that the specific requests were refused; the text does not determine the provider's actual general range limit or explain the refusal. They are not zero-event observations, case exclusions or detector failures.

## Relevant remaining work

At the sampled checkpoints, the canonical `diamondCut` selector binds to exact-compiled DiamondCutFacet; `transferOwnership` binds to exact-compiled OwnershipFacet at both window endpoints. Their code can now support the already identified source-shaped mutation paths in LibDiamond. This does not establish interval authority, all writes, or absence of other reachable storage writers.

Administrative history still requires a separately justified and frozen availability strategy. Future nonzero initializers or additional reached facets need explicit evidence. The eight unmatched addresses remain bounded source-binding candidates, including the endpoint CBridge successor. Do not assign its effective configuration from old namespace values alone or require unrelated unused helper contracts for fixed-address workload claims.

**No complete historical routing, detector score or new independent case admission is claimed.** The scientific window, candidate order, methods and budgets are unchanged. [findings.json](findings.json) binds the exact acquisition and comparison artifacts.
