# Independent review of LiFi deployment and boundary evidence

The offline review **passed** for the narrow evidence tier
`provider_returned_creation_and_boundary_code_consistency`.
The audit independently parsed the retained responses and reconstructed their
transaction, receipt, trace, header and bytecode relationships without importing
the capture runner. It used a separately implemented Keccak routine for address
formula checks. The machine-readable review binds the frozen plan, runner,
request ledger and terminal summary by SHA-256; its exact review digest is
`a2a648a4a4cb3e7d164b83ac8d617e13abbe637fdb6be94dc45e4b7aebad2afd`.
The audit script (private evidence) records the checks.

| Observation | Independently reconstructed result |
|---|---|
| New continuation requests | 4 GET + 56 RPC = 60; 946,448 response bytes |
| Cumulative deployment-stage requests | 6 GET + 56 RPC = 62; 1,014,523 response bytes |
| LiFiDiamond creation | Block 13,984,588; 2022-01-11 13:47:48 UTC |
| CBridgeFacet creation | Block 14,211,112; 2022-02-15 14:03:58 UTC |
| Fixed window | 2022-02-19 00:00:00 UTC inclusive to 2022-03-21 00:00:00 UTC exclusive |
| Included blocks | 14,233,163 through 14,426,367 |
| First excluded block | 14,426,368; 2022-03-21 00:00:00 UTC |
| Code observations | Two empty precreation observations; six exact runtime matches |

Both nominated addresses have matching CREATE2 address formulas and successful
factory creation traces. The provider's trace model labels the creation action
`create`; this does not independently identify the executed CREATE2 opcode.
The two successful creation receipts, transaction identities, trace ancestry,
block placement and runtime bytes are mutually consistent. The boundary
bisections were replayed from the retained headers and their adjacent-block
links checked.

The initial direct-creation attempt correctly stopped after two GET requests
when the diamond deployment proved to be a factory call. Its original outputs
remain separately preserved and are included in the cumulative accounting. The
replacement plan was frozen before the continuation began. The original stop is
an acquisition assumption failure, not evidence that LiFi is ineligible.

The terminal state remains
`DEPLOYMENT_AND_BOUNDARY_CODE_OBSERVED_ROUTING_UNRESOLVED`.
These observations do not prove uninterrupted historical selector routing,
source recompilation, complete protocol membership, cryptographic chain or
state proofs, or 29 days of valid detector measurements. Equal runtime at the
boundaries does not exclude storage changes or changes followed by restoration.
No new detector metrics or scientific admissions result from this phase.

The complete CBridgeFacet source response was used for this workspace audit.
The download instead supplies a separately identified data-only projection,
whose independent audit program (private evidence) checks its
exact retained fields and source-file hash inventory. That separate audit
passed: eleven provider fields and all 44 ordered source inventories agree
with the original response, while all complete source bodies are omitted.
Its review digest is
`fdc1e3af405b402326d90bd649c1d10dbf4f63720e5ca7996b6840444c277d7f`.
The projection cannot reproduce the original response digest or the omitted
source-text review.
