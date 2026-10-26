# Phase 7 bounded Revest deployment review

**Decision: no case admission yet.** Creation and initial registry bindings now have concrete explorer-backed records. Continuous activation in the proposed **[2022-02-26,2022-03-28)** window remains unproved. This is a metadata/provenance review, not a new detection experiment.

All five successful creations are dated **2021-09-24**, from `0x81245E489Cf1e02e38A83C2B9618826747410C50`. Exact transaction and block hashes, timestamps, source URLs and capture hashes are in the companion JSON.

| Component | Address | Creation block | UTC | Creation transaction |
|---|---|---:|---|---|
| RevestAddressRegistry | `0xD721A90dd7e010c8C5E022cc0100c55aC78E0FC4` | 13290537 | 20:08:48 | [0xd35b2e30fb324886b5a31f6019146f11c73bf1dd84fff651d25306ecc4e7d01b](https://eth.blockscout.com/api/v2/transactions/0xd35b2e30fb324886b5a31f6019146f11c73bf1dd84fff651d25306ecc4e7d01b) |
| FNFTHandler | `0xe952bda8c06481506e4731C4f54CeD2d4ab81659` | 13290542 | 20:09:51 | [0x33a097e2d2b2320f1d9eb4f44171b15d3ca2acb1beadb3ae5efdaef78eabbe72](https://eth.blockscout.com/api/v2/transactions/0x33a097e2d2b2320f1d9eb4f44171b15d3ca2acb1beadb3ae5efdaef78eabbe72) |
| LockManager | `0x226124E83868812D3Dae87eB3C5F28047E1070B7` | 13290552 | 20:11:51 | [0x11bee6c6bee7fd8b97b44db14b9bdc5a9c3e9e29b9505c4872868bc9d89b2f3e](https://eth.blockscout.com/api/v2/transactions/0x11bee6c6bee7fd8b97b44db14b9bdc5a9c3e9e29b9505c4872868bc9d89b2f3e) |
| TokenVault | `0xA81bd16Aa6F6B25e66965A2f842e9C806c0AA11F` | 13290580 | 20:16:10 | [0x7883df1063f8e44fd614ba9c368dc0d5f12eece7063b499fb09bdcaae36aa351](https://eth.blockscout.com/api/v2/transactions/0x7883df1063f8e44fd614ba9c368dc0d5f12eece7063b499fb09bdcaae36aa351) |
| Revest | `0x2320A28f52334d62622cc2EaFa15DE55F9987eD9` | 13290587 | 20:17:37 | [0x3bf16e29aa9acc6bbdf5557ed1241b03989246ca0f4f652e9122655390b4caed](https://eth.blockscout.com/api/v2/transactions/0x3bf16e29aa9acc6bbdf5557ed1241b03989246ca0f4f652e9122655390b4caed) |

The four component constructors specify historical registry `0xD721A90dd7e010c8C5E022cc0100c55aC78E0FC4`. Each constructor argument matches the creation-input suffix. All five transaction creation inputs equal the explorer’s reported creation bytecode. This is internal consistency of captured explorer evidence, not independent recompilation or a state proof.

[Registry initialization](https://eth.blockscout.com/api/v2/transactions/0xc64620ec4d063b61b560ea86341780bb53cdb78b3622f57aa8bc7f0c1db8e9f8) succeeded at **block 13290609**, **2021-09-24T20:22:09.000000Z**. Its nine address arguments include all four historical components. Independently sliced ABI words match the explorer’s decoded arguments. The captured [direct registry transaction page](https://eth.blockscout.com/api/v2/addresses/0xD721A90dd7e010c8C5E022cc0100c55aC78E0FC4/transactions?filter=to) has 20 items and `next_page_params=null`. The last observed direct `setRevest` restores `0x2320…7eD9` at block 13680614 on 2021-11-25. That list does not cover internal calls and does not certify unchanged routing in 2022.

Four main source texts (registry, Revest, TokenVault, FNFTHandler) and shared RevestAccessControl match the phase 6 SHA256 pins byte for byte. The explorer reports all five contracts fully verified. Verification dates are 2024–2026 and are not deployment dates. The LockManager main source SHA256 is captured but had no main-file phase 6 pin. Current account classifications, tags and EIP-7702/proxy annotations must never be backdated.

| Gate | Result |
|---|---|
| Five creations before proposed window | Closed at explorer-evidence level |
| Four constructor provider arguments name historical registry | Closed at explorer-evidence level; historical storage not independently proved |
| Registry initialization binds four components | Closed at explorer-evidence level for the recorded initialization only |
| Published-source/deployed-code provenance | Partially closed: text pins and explorer verification; independent compile/historical-runtime checks open |
| Continuous window activation and upgrade boundaries | Open |
| Complete protocol population and frozen allocation experiment | Open; no case admitted |

Registry source permits repeated owner-only `initialize`, nine named mapping setters and `setDex`; those mapping writes have no dedicated change events. Components can mutate **`addressesProvider`** through `setAddressRegistry`; the separate constructor-set `addressProvider` can be stale. Registry keys are literal right-padded `bytes32` strings, not hashes. Pin canonical window boundary blocks, establish initial mapping/pointer values, then account for all successful relevant mutations including internal calls and same-block ordering. Equal boundary states alone miss change-and-restore. A separately frozen fixed-emitter workload remains possible without claiming the complete active protocol population.

Immutable source: [RevestAddressRegistry.sol](https://github.com/Revest-Finance/RevestContracts/blob/f4b5a5a898d202a5040f72ec7b1196de5f05e5f8/hardhat/contracts/RevestAddressRegistry.sol), blob `101755f2b55420379538e37457b42a22d6101d5c`; [RevestAccessControl.sol](https://github.com/Revest-Finance/RevestContracts/blob/f4b5a5a898d202a5040f72ec7b1196de5f05e5f8/hardhat/contracts/utils/RevestAccessControl.sol), blob `278273ba5b435f95f943022ed1c44e7cedaddb94`.

The bounded capture contains 24 successful public Blockscout API responses with exact URLs and SHA256 receipts, plus the review scripts. No archive-RPC state or internal-trace probe was attempted. Etherscan web access failed (403/inaccessible); this did not prevent the Blockscout capture. No detector rules, scores, thresholds, budgets, labels or proposed window changed.

Exposure note: the first exact-address web search unexpectedly returned an incident-transaction snippet and a third-party exploit-code snippet for the already-known Revest case. Those pages were not opened, copied into the evidence package or used. Record this limited exposure; do not state absolute no-exposure or blind-case eligibility. No incident evaluation endpoint was intentionally queried and no exploit code was executed.

Evidence directory: `phase7_primary_metadata/`. Reports and fetch/build scripts remain scratch intermediates for coordinator packaging; no repository edits were made by this subtask.
