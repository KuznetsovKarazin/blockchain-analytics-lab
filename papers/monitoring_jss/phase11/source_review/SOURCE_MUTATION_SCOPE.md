# Li.Fi source mutation scope

**This is a source-level review and a plan for the next proof obligations. It does not establish complete historical routing.** No new network request, chain payload, detector score or manuscript change was made for this review. After this source review, exact compilation of both targets was completed and independently reproduced. The constructor/receipt comparison also passed in an actual offline run and in an independent offset-based decoding review. The machine-readable record preserves the original pending status and adds dated updates.

The retained diamond response has 3 source files; the CBridge response has 44. There are 47 file occurrences but 44 distinct paths and source texts. Exactly three paths occur in both sets with identical UTF-8 bytes: `src/LiFiDiamond.sol`, `src/Libraries/LibDiamond.sol` and `src/Interfaces/IDiamondCut.sol`. Their hashes, complete 47-occurrence inventory and source locations are retained in the private source-inventory evidence. Additional facets, proxy helpers and test contracts present in the 44-file input are not thereby deployed or active.

Three evidence levels must remain separate: source text being present; an exact compilation matching a specific deployed target; and that target being active under a historical selector/routing configuration. Phase 10 established provider-returned creation/code consistency. Phase 11 now binds exact compiler output for those two targets, but does not establish active historical routing. The administrative DiamondCut, Ownership and Loupe source files are still only candidate code for other addresses; their presence in the input does not bind those deployed runtimes. A facet called by delegatecall executes with the diamond's storage and event-emitter context; the two targets are not automatically a two-emitter population.

## Relevant mutation paths

`LiFiDiamond.sol`8–20 sets an initial owner and installs the `diamondCut` selector through a constructor-supplied facet. Its fallback26–46 reads the current selector map and delegatecalls the selected address. The actual compiler-bound constructor check recovered both ABI address words and matched the retained receipt: owner `0xcb1e9fa11edd27098a6b2ff23cb6b79183ccf8ee`, initial upgrade facet `0xc46304a0b2accc4462d9bdcaa0f6bf632510d617`. Two canonical events agree, including a 352-byte one-selector Add cut with zero initializer. The explorer's malformed constructor annotations were not used. See [bootstrap results](BOOTSTRAP_RESULTS.md); the new facet's own code binding and subsequent history are still open.

`LibDiamond.sol`62–80 applies selector changes, emits `DiamondCut`, and **then** invokes the initializer. The initializer185–200 can delegatecall another contract or the diamond itself, using supplied calldata. Thus the event is not guaranteed to describe the final post-initializer state. An initializer can write storage after the event, invoke a newly installed selector or reach further code. Correct reconstruction needs successful execution, ancestor rollback and nested ordering, with each relevant initializer bound to its historical code. A returned complete event list alone cannot close this gap.

The same library44–56 and `OwnershipFacet.sol`8–14 implement mutable owner state. `CBridgeFacet.sol`33–38 provides a repeatable owner-gated initializer for the bridge address and chain identifier. Creation, selector activation, ownership and bridge configuration are distinct histories. A present-day owner or equal endpoint values do not prove interval authority or absence of change-and-restore. The owner must not be presumed to remain an EOA.

## Namespaced storage

The source assigns storage pointers through assembly to keccak-derived bases. An empty ordinary compiler `storageLayout` therefore does not mean that no storage exists. The following is a manual source derivation awaiting compiler AST/type and independent packing confirmation, not a historical state observation.

| Namespace | Relative position | Source-derived meaning |
|---|---:|---|
| `diamond.standard.diamond.storage` |0| Selector-to-facet mapping; each value packs an address and uint96 position |
| Same |1| Facet-to-selector-array/position mapping |
| Same |2| Facet address array length |
| Same |3| Supported-interface mapping |
| Same |4| Contract owner |
| `com.lifi.facets.cbridge2` |0| Bridge address at byte offset0 and uint64 chain ID at byte offset20 |

Mapping keys of type `bytes4` use fixed-bytes padding, unlike integer keys. Dynamic selector arrays are packed and can be reordered by swap-and-pop. Slot formulas must be checked before any query. Source-present `sstore` or delegatecall helpers also require a call/reachability argument: unused library/proxy/test code is not evidence of an active writer, while every actually active facet can potentially affect the diamond's storage.

## Minimal next continuation

The exact compilation prerequisite is complete for both retained targets using Solidity 0.8.7+commit.e28d00a7, optimizer 200 and their original metadata/settings. Independent reconstruction with the same compiler reproduced full creation/runtime bytes, including metadata; no masking or settings search was used. Both ordinary top-level storage layouts are empty, so the manual namespace/packing claims above still need independent confirmation. Compiler metadata names 3 source units for the diamond and 15 for the CBridge target; neither count describes deployed components. The constructor-event cross-check and its independent decoding review are complete using existing evidence. Neither review establishes the initial upgrade facet's runtime.

After completing the remaining slot checks, freeze a separate bounded history/state discovery gate: retain the same UTC window and state checkpoints 14233162/14426367; start reconstruction from the creation bootstrap at 13984588 or prove a complete initial-state snapshot. Bind exact administrative topics, namespace slots, providers, interval/chunk rules, request/byte/time caps and maximum facets/selectors before querying. A suggested discovery cap is 64 RPC methods, 32 MiB, 15 minutes, no retries and at most 32 facets/256 selectors per checkpoint; these are proposals, not an accepted plan. Cap exhaustion yields an unresolved disposition without truncation or population changes.

The discovery output should nominate every observed facet/initializer and compare event-derived configurations with boundary state. Each new code target needs its own historical binding. A historical loupe call also needs the loupe's code and selector binding; its name alone is not proof. No incident transaction payload or detector input is implied by this continuation. Complete routing can be claimed only after all relevant reachable writers, successful mutation intervals and index-completeness assumptions are addressed. Otherwise the valid result remains **routing unresolved**.
