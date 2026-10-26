# Independent review of the Revest boundary decision

**PASS, 26 October 2026.** Independent reconstruction confirms the frozen terminal disposition **POPULATION_EXPANSION_UNRESOLVED**. The historical `REVEST` registry pointer equals the original component at the starting state, but equals the conventional `0x…dead` address at the final included state. This is a concrete counterexample to treating the original component roster as continuously active throughout the fixed window. It does not establish a newly deployed component, the exact transition time, the reason for the change or a complete protocol shutdown.

The frozen window remains **[26 February 2022 00:00:00 UTC, 28 March 2022 00:00:00 UTC)**. Independently reconstructed boundary brackets are:

| Boundary | Predecessor block and time | First block at or after boundary |
|---|---|---|
| Start | 14,278,386 — 25 February, 23:59:57 UTC | 14,278,387 — 26 February, 00:00:28 UTC |
| End | 14,471,310 — 27 March, 23:59:41 UTC | 14,471,311 — 28 March, 00:01:09 UTC |

Adjacent block hashes and parent links agree. Initial state was read at the start predecessor and terminal state at the end predecessor. The included block interval is therefore **14,278,387–14,471,310**. No interval was narrowed after observing the pointer difference.

The boundary stage used **55 RPC methods**: 35 header queries, 10 runtime queries and 10 batch-state proof queries. Its retained responses total **905,200 bytes**. Including the earlier capability and batch-state stages, the bounded routing attempt used **67 methods and 970,115 bytes**. All actual request, byte and time bounds were satisfied. The remaining request budget was not consumed after the terminal decision.

The auditor independently verified every retained request/response hash and parameter, reconstructed both boundaries from the returned headers, compared all **10 complete runtimes**, recomputed all 10 runtime Keccak hashes, and reconstructed all **54 requested storage values**. All values match the collector's outputs. Exactly one checked membership relation differs: the final `REVEST` registry pointer. The other checked core bindings and component provider pointers agree with the frozen roster at both endpoints; this endpoint agreement does not establish continuity between them.

The auditor did not import the producer's code. Storage mapping keys and runtime hashes were recomputed with a separate two-dimensional sponge implementation whose rotation offsets and round constants are generated. Its SHA3 domain was checked against **155 standard-library vectors**, followed by two Ethereum Keccak known vectors. A separate static check also verified **148 compiler-produced function selectors** and instruction-aware scans of the five runtimes, excluding PUSH data and exact metadata trailers. These are engineering consistency checks, not cryptographic certification.

**Achieved scope:** source/bytecode consistency, a historical capability sample, exact queried boundary states and an endpoint routing counterexample at the provider-returned state-consistency tier. Returned Merkle proof nodes were retained and syntax-checked; they were not verified against a canonical state root. Ownership-log histories, administrative trace histories, mutation receipts and a continuous routing replay were **not acquired** after the frozen terminal condition. The original collector summary carries the plan's target evidence-tier wording; that wording must not be read as a statement that those later stages were completed.

The machine status uses the plan's umbrella name for routing outside the frozen roster. In prose, describe **changed routing/activation requiring unresolved population treatment**, not a proven expansion to another live contract. Revest remains in reserve for this protocol version; no new incident is admitted and no detector score, attack recall or false-alarm result is produced by this gate.

Results: `revest_boundary_capture_independent_review.json` (private evidence). Offline reconstruction: [review_revest_boundary_capture.py](review_revest_boundary_capture.py). Independent hash oracle: [independent_keccak.py](independent_keccak.py). Prefetch implementation review: `revest_boundary_runner_independent_prefetch.json` (private evidence).

The public offline auditor accepts the expected plan digest through `--expected-plan-sha256`; the original fixed-digest auditor used in the reported experiment remains in private evidence. This interface change does not alter reconstruction or acceptance checks.
