# Li.Fi compiler reconstruction — phase 11

**Both the producer and an independent reconstruction exactly reproduced creation and runtime bytecode for the two retained Li.Fi targets.** No new case data or RPC responses were acquired, and no detector score was computed.

The pinned native Solidity compiler is `0.8.7+commit.e28d00a7`, SHA-256 `003d75383e45212f9812d0b6add90329fd3b239e6c378d2882f61f9345896d99`. Its separate dependency acquisition used one GET and returned 12141112 bytes. The producer performed one version probe and two standard-JSON compilations, completed on 26 October 2026 at 15:18:39 UTC.

## Exact reconstruction

| Target | Compiler creation prefix, bytes | Constructor arguments, bytes | Runtime, bytes | Full-byte comparisons |
|---|---:|---:|---:|---|
| LiFiDiamond | 9881 | 64 | 4581 | All match |
| CBridgeFacet | 5718 | 0 | 5686 | All match |

The reconstructed creation prefix plus constructor suffix equals both the retained explorer creation bytes and the successful factory creation trace. Each complete runtime equals the explorer bytes, the creation trace result and all three retained historical code observations: creation, the predecessor of the window start and the predecessor of the window end. Thus **two compiled targets match six previously acquired runtime observations**. These are reused observations, not six new requests or independent experiments.

| Target | SHA-256 of complete reconstructed runtime |
|---|---|
| LiFiDiamond | `c03fa708d3e65b647c904cbc7582412123fe5a725502ea208bd030a840534917` |
| CBridgeFacet | `c7570dde9e1e0b080f7f584a4048d4d216e74e44456a9d1b56af8e5b2794ef00` |

No metadata was stripped, no bytecode regions were masked and no immutable or library substitutions were applied. Each original settings object was preserved, with only requested compiler outputs added. The diamond explicitly specifies London, IPFS metadata, literal source content and optimizer runs 200. The facet input specifies literal content and optimizer runs 200; omitted settings were left omitted. Its compiler output reports the corresponding London/IPFS defaults. No settings search was performed.

The two bundles contain **47 source-file occurrences at 44 distinct paths**; the three shared paths have equal contents. These counts do not describe deployed contracts or a complete historical facet population.

## Constructor annotation correction

The exact diamond creation prefix ends at byte 9881 of the 9945-byte factory initcode. The compiler ABI then requires two canonical 32-byte address words:

| Constructor input | Address | Byte offset in initcode |
|---|---|---:|
| Initial owner | `0xcb1e9fa11edd27098a6b2ff23cb6b79183ccf8ee` | 9881 |
| Initial DiamondCut facet | `0xc46304a0b2accc4462d9bdcaa0f6bf632510d617` | 9913 |

The retained explorer annotation instead labels 236 bytes as constructor arguments, overreaching 172 bytes into the reconstructed creation program. Its decoded annotations were never used. The reconstruction supplies the correct 64-byte boundary while preserving the original response unchanged. This establishes constructor inputs at the observed creation; it does not establish the owner or active facets throughout the later study window.

## Remaining limits

Both ordinary `storageLayout.storage` arrays are empty. The code uses library and namespaced assembly storage, so this is not evidence of statelessness or proof of namespace positions, all writers, selector activation or configuration continuity.

The result closes exact source/settings/compiler consistency for these two code targets. Complete historical facet membership, routing, initializer effects, ownership/configuration epochs, measurement coverage and independent execution labels remain open. Independent use of the same compiler binary provides a separate reconstruction check, not compiler diversity or formal verification. Scientific admissions and new detector scores remain zero.

`compilation_results.json` contains the public factual aggregate; detailed evidence bindings remain in private evidence. It excludes source bodies, full ABI, AST, compiler metadata, raw bytecode, diagnostics and host paths.

The independent auditor completed two separately constructed standard-JSON compilations and one version probe at 15:23:35 UTC. Its input serialization differs, while both full output files are byte-identical to the producer outputs. Total execution: four compilations and two version probes; zero new chain requests. The original preflight retained two stale draft descriptions; the actual audit explicitly corrects them and verifies the executed program hash. No failed compilation or settings variant was concealed.
