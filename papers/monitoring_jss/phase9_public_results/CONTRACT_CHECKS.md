# Revest historical contract checks

Five retained source sets were compiled with Solidity 0.8.4 and then reconstructed by an independent auditor. Complete creation payloads, including constructor arguments, match the retained explorer and creation-transaction inputs. Full runtime bytes match after binding the Revest WETH immutable only at four compiler-declared locations; metadata is unchanged. This is source/explorer consistency, not formal verification or compiler diversity.

| Contract | Owner slot | Mutable `addressesProvider` slot | Separate constructor-era `addressProvider` slot |
|---|---:|---:|---:|
| Registry | 0 | Registry mapping starts at 2 | Not present |
| Revest | 2 | 3 | 4 |
| LockManager | 3 | 4 | 5 |
| TokenVault | 2 | 3 | 4 |
| FNFTHandler | 4 | 5 | 6 |

All 39 top-level storage fields were checked using independently reconstructed inheritance and packing. The similarly named provider fields are distinct. The earlier project evidence already noted their semantic difference; the new result verifies their exact locations and bytecode binding.

## Executed historical check

The fixed window is `[2022-02-26T00:00:00Z, 2022-03-28T00:00:00Z)`. Provider-returned headers and predecessor links identify the included interval as blocks **14,278,387–14,471,310**. The first included block is at 00:00:28 UTC; its predecessor is at 23:59:57 UTC on the preceding day. The first excluded block is at 00:01:09 UTC on March 28; its predecessor is at 23:59:41 UTC on March 27.

The initial capability study used 11 RPC methods; a 19-slot batch-state test used one more. Boundary capture used 35 header requests plus ten code and ten state requests. Total: **67 RPC methods and 970,115 response bytes**. Failed capability requests remain counted. Compiler acquisition is separate from these RPC counts.

All ten original-contract runtime checks—five contracts at each boundary—match. The registry's Revest pointer is the original contract before the window and the conventional address ending `dead` at the final included block. The other three core registry bindings and the inspected component-provider fields do not differ between these two states. A historical sample also has nonempty code at the registry owner's address, invalidating an argument that assumes an EOA owner throughout the window.

The endpoint difference is a counterexample to unchanged original-core routing. It does not identify a new deployed component, prove the exact transition time, establish an administrative cause, or enumerate intervening changes. Equal endpoint values in the other fields do not rule out change-and-restore.

The frozen status is `POPULATION_EXPANSION_UNRESOLVED`: in this execution it denotes an out-of-roster pointer, not a claim that a new contract was deployed. Revest remains reserved for this version of the original-core definition. The collection stopped before ownership-log and full mutation-history acquisition.

Independent audits reconstructed all returned boundary headers, code, storage keys and values. The achieved evidence tier is **boundary code/storage consistency**. The broader provider-index history tier described in the frozen continuation plan was not reached. Returned Merkle proof nodes are retained but have not been verified against a trusted state root; no consensus or whole-chain completeness proof is claimed.

No detector input stream, scores or incident-label join was produced by these checks. Deployment epochs, full measurement coverage and independently adjudicated execution labels remain necessary before an independent evaluation.
