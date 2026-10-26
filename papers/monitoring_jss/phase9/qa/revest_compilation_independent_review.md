# Independent Revest compilation review

**PASS, 26 October 2026.** Five source sets were independently rebuilt from the original retained explorer responses using the pinned Solidity 0.8.4 compiler. The auditor did not import or execute the producer's compilation helper. All five complete creation payloads, including constructor arguments, match both the retained verified-contract responses and their separate creation-transaction inputs. All five complete runtime byte strings match after the one justified immutable binding described below. Compiler output files are also byte-identical to the producer's files.

| Source set | Source files within set | Creation payload bytes, including arguments | Constructor words | Runtime bytes |
|---|---:|---:|---:|---:|
| Registry | 4 | 6,479 | 0 | 6,348 |
| Revest | 37 | 23,015 | 2 | 22,157 |
| LockManager | 31 | 12,966 | 1 | 12,665 |
| TokenVault | 29 | 12,956 | 1 | 12,665 |
| FNFTHandler | 27 | 16,721 | 1 | 15,908 |

The 128 source-file occurrences include shared dependencies and are not 128 distinct files. Every source path and exact content was reconstructed from the original source response and checked against the producer's hash inventory. The five original responses and five creation responses still match their phase 7 fetch-manifest hashes. Optimizer 10,000 runs, Istanbul EVM target, literal source metadata and IPFS metadata hashing were preserved. No library linking or alternate source substitution was used.

Constructor arguments were decoded according to the compiled and retained ABI; each address has canonical 12-byte zero padding. Revest's `WETH` declaration is an immutable address. The AST links its constructor assignment to the **second** constructor parameter, `weth`. Only the four compiler-declared 32-byte regions at offsets **13,343; 13,829; 14,071; 14,267** were populated from that argument. The unbound runtime differs from the retained runtime in 80 bytes, all inside those regions. No arbitrary masking was permitted. All five 53-byte metadata trailers, including their length suffix, match without changes.

The auditor independently computed C3 inheritance order and allocated all **39 top-level storage fields** from AST declarations and explicit packing rules; every label, slot and offset equals the compiler layout. Relevant positions are:

| Contract | Owner slot | Mutable `addressesProvider` slot | Separate `addressProvider` slot |
|---|---:|---:|---:|
| Registry | 0 | Not present; `_addresses` mapping starts at 2 | Not present |
| Revest | 2 | 3 | 4 |
| LockManager | 3 | 4 | 5 |
| TokenVault | 2 | 3 | 4 |
| FNFTHandler | 4 | 5 | 6 |

The two similarly named provider fields occupy distinct slots. Reading the constructor-era `addressProvider` field cannot substitute for checking the mutable `addressesProvider` used by routing.

Local negative controls confirmed that changing an ordinary runtime byte, changing a constructor word in any of the four parameterized contracts, or changing one WETH substitution causes exact comparison failure. These checks made no network calls and required no extra compilation. There were exactly five independent compiler invocations, one per source set, in addition to the producer's original five. A preliminary auditor setup stopped before compilation because it incorrectly required the optional `compilationTarget` field; the corrected auditor checks that output-only field when present. The setup failure was retained, not counted as a scientific compilation failure or silently discarded.

Original source files and producer artifacts were unchanged before and after the audit. The tracked repository tree still matched the full phase 8 baseline for all existing files; new phase 9 files are separate additions. Full compiler inputs/outputs, third-party source text, creation bytes and runtime bytes remain private. The audit script and this report contain owned validation logic, factual hashes, counts and storage positions.

This establishes **retained-source and explorer-bytecode consistency** with one pinned compiler, not independent compiler diversity, formal verification or consensus proofs. It does not prove code at every historical boundary, continuous ownership or routing, absence of change-and-restore, completeness of the protocol population, label eligibility, detection performance or admission of Revest into a new cohort. The historical capability probe and any later routing reconstruction require separate checks.

Machine-readable findings: `revest_compilation_independent_review.json` (private evidence). Reproducer: [review_revest_compilation.py](review_revest_compilation.py). The reproducer writes complete compiler evidence only to its explicit private output directory; run it within a newly declared execution budget rather than treating this report as authority for unlimited repeats.
