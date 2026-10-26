# Phase 13 independent scientific QA

26 October 2026. The bounded runtime acquisition, preserved failures and retrospective full-byte comparison passed independent checks. Phase 13 made **21 new RPC requests and retained 154,743 response bytes** across two separately frozen attempts. There were no new source compilations, detector scores or incident admissions.

## Sampled runtime observations

The fixed schedule contained 19 facet/checkpoint pairs over 14 previously nominated addresses. Eighteen new `eth_getCode` responses and one exact retained Phase 10 response supply all 19 observations. Every returned runtime is nonempty. The reused response's 11,411 bytes are not charged again. The original plan, runner, source dependencies, acceptance timing, exact request prefix, all request/response hashes, envelopes and accounting were checked from retained bytes. Runtime SHA-256 and Keccak-256 values were independently reconstructed using a different retained Keccak implementation.

All four addresses shared by the window endpoint enumerations have equal returned runtime bytes at those endpoints. Conversely, each of the 14 shared selectors whose destination address changes has different full destination runtime bytes between endpoints. There are 14 distinct full runtime hashes over the 14 sampled addresses. Full byte inequality does not establish semantic behavior change: metadata is part of the comparison.

The separate retrospective identity analysis compares every sampled runtime against all nonempty runtime outputs in the already reproduced Phase 11 CBridge compilation artifact. Its 44 source paths contain 59 contract outputs: 36 nonempty strict-hex candidates and 23 empty outputs, with no missing or unresolved nonhex candidate. All 684 complete-byte comparisons were independently repeated from raw responses and the retained compiler output. Eleven sampled pairs at six addresses match exactly, including metadata: DiamondCutFacet, DiamondLoupeFacet, OwnershipFacet, WithdrawFacet, NXTPFacet and the previously bound CBridgeFacet. Five address bindings are additional to CBridge. Eight other addresses do not match this finite retained candidate set; that is not evidence of maliciousness, semantic difference or unavailable source. There was no metadata masking, settings search, new compiler run or new source fetch.

## Preserved availability failures

The first Phase 13 attempt made 19 RPC requests and retained 154,568 bytes. Its 18 new code queries succeeded. Its first inclusive 5,000-block window-log query was refused with HTTP 400 / error 35 and the same provider message mentioning ranges over 10,000 blocks. No log chunk completed. The earlier Phase 12 refusal remains unchanged. Neither response establishes a general numerical API limit.

The separately frozen PublicNode attempt made two RPC requests and retained 175 bytes. Chain ID succeeded; the first historical-header request returned HTTP 200 with JSON-RPC error 4444 reporting pruned history. No historical header result was obtained. The planned known-log positive control, end header and 39 window ranges were never reached. The audit verified both exact request/response pairs and the required stop. The reported pruning boundary describes that response; it is not a general service guarantee or a conclusion about every access tier.

No administrative event list was observed in either attempt, and nominal replay was not performed. Zero decoded records here means unavailable history, not an observed empty history. No retry, adaptive split or further endpoint substitution occurred within either attempt.

## Scope and validation limits

Twelve focused acquisition checks, eleven new provider-control checks and four checks of the newly written independent decoder passed. The twelve acquisition cases ran twice because of a prefreeze plan wording/hash change; they are twelve distinct cases, not twenty-four. The other groups ran once. Existing test suites were not rerun. The independent decoder was checked against retained constructor and seed evidence; no new chain observations arise from those checks. Actual acquisition audits did not import producer modules or perform network, compiler or EVM execution. Since history acquisition failed, the new replay implementation was not exercised on a newly collected event history.

Sampled source/runtime bindings improve the provenance of relevant administrative entrypoints, but do not prove continuous identity, all intermediate routing states, complete provider indexing, exhaustive mapping membership or all initializer/writer effects. State-root authentication was not performed. The accepted routing-population scope, original candidate order, window and detector parameters remain unchanged. A fixed-address scope amendment is not adopted. No absent flow, cold start or weak response is used to exclude a case or add a victim address.

Machine-readable receipts: `independent_actual_review.json`, `independent_runtime_match_review.json`, and `independent_history_review.json`. Exact full compiler artifacts remain private; the public aggregates are not a self-contained source-recompilation kit.
