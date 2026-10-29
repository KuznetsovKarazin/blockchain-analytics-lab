# Phase29 resource-bounded candidate adjudication wave

All **16** Phase28 candidates remain in the frozen screen; this is a *non-random, resource-bounded follow-up wave*, not a new 16-incident detection evaluation. It was chosen after earlier Li.Fi/Revest/Bacon/Rari outcomes were known. Four cases were prioritized because their independently documented source roles and low original core-selected 30-day transaction counts permit an exact source audit on constrained public tools.

| Phase28 ID | Priority for phase29 exact source | Source-selected TX / fork-anchored window | Independent/reference caveat |
|---|---|---:|---|
| 02 Umbrella | Wave 1 | 92 | Team confirms March20 Ethereum staking incident; single PoC hash not a complete exploit inventory |
| 09 Inverse Finance | Wave 1 | 71 | BlockSec identifies original June16 execution; yvCrv market is a named component, not all protocol economics |
| 10 Schnoodle | Wave 1 | 134 | Independent ERC777 attack analysis; proxy is a token-emitter, not necessarily a value-loss boundary |
| 13 Omni | Wave 1 | 103 | Independent published exploit hash and pool; third-party indexer did not previously provide a complete source-bound bundle |
| 05 Beanstalk | Next wave | 12,392 | Source role supported, but Phase28 PoC-fork window ends April16 whereas attack is April17; must re-anchor first |
| 14 Audius | Next wave | 38 | Multistage: last PoC swap is not core governance execution; needs primary step-specific reference inventory |
| 07 Saddle | Next wave | 44 | Independent mechanism documentation but source/reference role not closed |
| 11 XCarnival | Next wave | 43 | Multistage NFT and lending boundaries; emitter choice must be justified independently |
| 15 Nomad | Next wave | 930 | Multi-actor event; original Nomad data corpus may enable complete reference-set construction |
| 16 Bad Guys NFT | Later | 1,456 | NFT mint event-volume scenario, not an ERC20 outflow feature by construction |
| 08 ApeCoin claim | Later | 10,938 | Exploit vs claim arbitrage status unresolved; high source burden |
| 03 Ronin | Separate threat-stratum | 18,522 | Validator-key compromise, Ethereum withdrawal boundary is not the source-chain compromise |
| 01 Compound cTUSD | Not currently admitted | 15 | Potential/PoC only, no proven realized exploit |
| 04 Auctus | Not currently admitted | 0 | Missing independently accepted execution and observed writer activity |
| 06 Akutar NFT | Separate failure-stratum | 1 | NFT auction lock, not token theft; attack day Apr23 absent from Phase28 Apr22 end |
| 12 FlippazOne | Not currently admitted | 1 | PoC only, historical successful exploit unverified |

**Scientific boundary:** eligibility predicted from an emitter's transaction volume alone is a *necessary upper bound*, never actual token-specific feature computability or accuracy. No source-only record will be inserted into a known-reference hit denominator. If a source limit fails, record UNAVAILABLE; do not omit/replace that case or report misses. Reference labels remain distinct from label-blind selection and scoring.

## Source recovery rejection and correction

The first 4-case source-identity attempt had 3 rejected jobs: it read all-emitter bundles only in Parquet rowgroups containing a core log, which omitted logs of selected transactions that straddled rowgroup boundaries. This caused a mandatory log-index-contiguity rejection and **zero** accepted records from those incomplete jobs. A two-pass implementation (identify all transaction positions across every rowgroup; then assemble all emitters from every rowgroup) corrected the defect and is used in the accepted rerun.

The second Schnoodle attempt completed 29 days, then exhausted the explicitly enforced 2.8 GB original-response-byte ceiling. Its output was rejected as incomplete, never given synthetic zeros. A separate audited attempt raises only the **transport resource bound** to 3.6 GB for that case; it does **not** change the scientific method, token ranks, reference selection, policies or thresholds. No failed attempt may be reused silently as accepted evidence.

## Exact provenance

- Phase28 source census: immutable `fc25cd8c187e6c8b0afb9afae2072f78dc2d3c0e` and its 8 original AWS acquisition batches.
- Source adjudication: [REFERENCE_ROLE_LEDGER.json](REFERENCE_ROLE_LEDGER.json), plus the already retained independent source URLs.
- Original-byte source indexer: [selected_original_tx.py](selected_original_tx.py), independently checkable using [verify_source_streams.py](verify_source_streams.py).
- Blockscout transaction payload tier: [indexed_selected_bundles.py](indexed_selected_bundles.py), verified by [verify_indexed.py](verify_indexed.py).
- Fixed label-blind detection replay and postscore candidate join: [fixed_replay.py](fixed_replay.py).

Publication requires a complete machine-readable source/verifier bundle and a single commit SHA; ephemeral Actions artifacts alone are inadequate.
