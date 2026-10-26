# Phase 13 historical-event availability continuation

The separately frozen PublicNode attempt closed after two RPC requests and 175 retained response bytes. `eth_chainId` returned Ethereum mainnet. The subsequent request for reference block 14,233,162 returned HTTP 200 with JSON-RPC error 4444: the response described the requested history as pruned and reported earliest available block 15,500,000. This is the recorded response of this endpoint at this attempt, not a universal availability boundary for PublicNode or Ethereum.

No reference header was successfully obtained. The second reference-header request, known-constructor-log positive control and all 39 window-event queries were therefore not executed. No event replay occurred. Zero decoded window records means unavailable history, not an empty event history. There was no automatic retry, alternative endpoint or range adaptation within this attempt.

Phase 13 acquisition totals are 21 RPC requests and 154,743 retained response bytes across the original code/window attempt and this continuation. The original attempt's 19 sampled runtime observations remain available; its first 5,000-block log request and the Phase 12 refusal remain unchanged. No case was admitted or excluded, and no detector score was computed.

The exact failure, accounting and input hashes are in `history_findings.json`. The separate provider plan documents the prospective change of source. A successful future archival retrieval would still need to preserve event ordering, compare nominal transitions with the retained end state and distinguish those observations from complete writer or initializer coverage.
