# Li.Fi historical identity gate — phase 10

**Two nominated factory creations and their sampled code are verified at provider-returned consistency level. Historical routing and the complete protocol population remain unresolved.** No independent incident was admitted, no detector score was computed, and the frozen methods were unchanged.

Li.Fi is row 65, the first metadata-ready candidate under the existing catalogue-date/name/row order. Its Ethereum entrypoint and CBridge logic component were nominated from the [original BlockSec investigation](https://blocksec.com/blog/li-fi-attack-a-cross-chain-bridge-vulnerability-no-it-s-due-to-unchecked-external-call); explorer address metadata separately identified the creation transactions. The [official report](https://blog.li.fi/20th-march-the-exploit-e9e1c5c03eb9) remains the occurrence/date source. Prior report exposure is disclosed. Incident execution payloads were not acquired in this gate.

## Observed creations

| Identity target | Address | Creation block | Creation time, UTC | Runtime bytes |
|---|---|---:|---|---:|
| LiFiDiamond | `0x5a9fd7c39a6c488e715437d7b1f3c823d5596ed1` | 13984588 | 2022-01-11 13:47:48 | 4581 |
| CBridgeFacet | `0x73a499e043b03fc047189ab1ba72eb595ff1fc8e` | 14211112 | 2022-02-15 14:03:58 | 5686 |

Both observed creations precede the unchanged window **[2022-02-19 00:00:00, 2022-03-21 00:00:00) UTC**. Each creation was a successful call to the same factory. The factory input consists of a 32-byte salt followed by the exact explorer creation bytes; the CREATE2 address formula matches the nominated address. Each separately retrieved transaction, success receipt and creation trace agrees on identity, ordering and full creation input. The unique creation child returns the exact explorer runtime, with no error on its ancestor path. Creation headers and their predecessors agree with explorer metadata and the transaction's exact header position.

Code is empty at each creation predecessor and matches the explorer runtime at creation. These observations establish the nominated creation checkpoints. They do not establish first-ever deployment, initial activation, continuous code identity or the absence of an earlier code cycle. Explorer constructor annotations were not used, and no independent source recompilation was performed.

## Exact UTC boundaries and sampled code

| Boundary observation | Block | Timestamp, UTC |
|---|---:|---|
| Start predecessor | 14233162 | 2022-02-18 23:59:54 |
| First included block | 14233163 | 2022-02-19 00:00:02 |
| Last included block / end predecessor | 14426367 | 2022-03-20 23:59:50 |
| First excluded block | 14426368 | 2022-03-21 00:00:00 |

Deterministic bisection within frozen brackets identified these neighbors, and both predecessor links were checked. All four boundary runtime observations match the corresponding explorer runtime exactly.

| Target | SHA-256 of runtime bytes |
|---|---|
| LiFiDiamond | `c03fa708d3e65b647c904cbc7582412123fe5a725502ea208bd030a840534917` |
| CBridgeFacet | `c7570dde9e1e0b080f7f584a4048d4d216e74e44456a9d1b56af8e5b2794ef00` |

The eight code queries comprise two empty precreation observations and six exact runtime matches: two at creation and four at window boundaries. They are sampled code checks, not continuous routing evidence or cryptographic state proofs.

## Acquisition and preserved model stop

Stage A used 18 combined discovery items, including three searches, eight successful primary documents/files and three failed requests; one search was empty. Its two direct address responses total 2384 bytes. Search-tool backend HTTP traffic was not measurable and is not counted as direct network bytes.

The first Stage B plan assumed direct deployment. Its two successful explorer responses showed a factory call, so the runner stopped before any RPC. The rejected assumption and all 68075 response bytes are preserved. This was an acquisition-model mismatch, not a failed source response or evidence that Li.Fi is ineligible.

A separately accepted factory continuation reused those exact two responses. It completed four new explorer GETs and 56 RPC methods, retained 946448 new bytes and took 491.47 seconds. Across both Stage B attempts: **six GETs, 56 RPC methods, 62 requests and 1014523 retained response bytes**, with zero retries or transport failures. The RPC breakdown is one chain identity, two transactions, two receipts, two creation traces, 41 headers and eight code queries. The continuation stayed within its 80-RPC, cumulative 16-MiB and 15-minute limits. Discovery items, direct HTTP requests and RPC methods remain distinct counters.

## What remains open

The two addresses are identity/code targets, **not a complete protocol population or a two-address emitter roster**. Facet code executed through delegatecall uses the diamond's context. Current explorer implementations and the 3 + 44 source-file occurrences in its compiler-input bundles do not establish historical deployed-component membership.

Source review identifies additional required evidence. The diamond fallback resolves selectors from mutable storage. `LibDiamond` emits `DiamondCut` before executing a configurable delegatecall initializer; event-only reconstruction therefore needs coverage of initializer effects and every relevant active code path. `CBridgeFacet.initCbridge` is owner-gated but repeatable and changes bridge/chain configuration. Historical selectors, facets, ownership, configuration epochs, predecessor entrypoints and complete relevant mutation coverage remain unproved. Equal endpoint runtime cannot close any of those gaps.

The separate [observation-scope review](OBSERVATION_SCOPE.md) records a conditional measurement limit: a user-to-external token transfer with neither event endpoint in the fixed core contributes no core external outflow. Transaction selection by core-emitter logs has a separate coverage limit. Neither statement is an observed Li.Fi detector result or a reason to exclude the case or add victim addresses to core.

Final disposition: `DEPLOYMENT_AND_BOUNDARY_CODE_OBSERVED_ROUTING_UNRESOLVED`. The next stage needs a separately frozen source/runtime and historical routing plan. Full measurement coverage, cohort/warmup commitments and independently adjudicated execution labels remain separate gates. Exact factual aggregates are retained in `gate_results.json`; detailed evidence bindings, source provenance and acquisition receipts remain in private evidence.
