# Phase31 — cohort denominators, deployment sensitivity, and source-frame reconciliation

This retrospective audit responds to reviewer M2/M3. It does not change the frozen Phase28 nominations, windows, source counts or original results. It separates three questions: activity conditional on nonempty days, exposure after indexed deployment, and completeness of the nomination frame.

## Arithmetic and exposure

The original daily CSV independently reproduces 44,780 selected transactions over 480 emitter-days. There are 302 empty days. Among the 178 nonempty days, 108 contain fewer than 20 selected transactions: **108/178 = 60.7%**. The original **410/480 = 85.4%** includes every empty day and should not be the headline result without this decomposition. These are necessary traffic screens, not positive same-token readiness or detection-performance estimates.

The separately preserved indexed creation metadata covers all 16 nominated addresses. It identifies 160 strictly predeployment dates, all empty, and eight partial deployment dates. Removing only the former yields **250/320 = 78.1%** dates with fewer than 20 transactions; retaining only complete postdeployment dates yields **243/312 = 77.9%**. Thus activity-conditioning and deployment-conditioning answer different questions. The 108/178 figure must never be labelled deployment-adjusted. Auctus was created in 2020: its empty window cannot be attributed to nonexistence. See `deployment/README.md` for per-address creation dates, recorded evidence tier and limits.

The windows include the entire UTC date containing a PoC fork block. They describe context around that anchor. They do not automatically end strictly before the exploit execution or the PoC fork timestamp. The goal of estimating history available at an attack is appropriate, but that estimand requires a transaction/time cutoff; none is retroactively asserted by this denominator audit.

## Complete directory frame and what was actually selected

We reconstructed every Solidity source file in `src/test/2022-03` through `src/test/2022-09` at DeFiHackLabs commit `0a9b9fd81c50767ff49f81089fbf8934f2f45b02`. The exact tree contains **67 PoC source files**. Literal executable fork calls classify **28 Ethereum-mainnet files** and **39 other-chain files**. The pinned `foundry.toml` maps `mainnet` to an Ethereum-mainnet endpoint. The ledger's unit is a source file, not an independently qualified incident.

Of the 28 Ethereum files:

- 16 occur in the original Phase28 component-nomination registry.
- Four correspond to Li.Fi, Revest, Bacon and Rari from the initial study.
- Eight further Ethereum files do not occur in that registry; the original frame/protocol provide **no documented exclusion rationale** for them.

The eight omitted files are `RedactedCartel_exp.sol`, `Harmony_multisig_exp.sol`, `Circle_exp1.sol`, `Circle_exp2.sol`, `LuckyTiger_exp.sol`, `XST_exp.sol`, `XST_exp2.sol` and `MEVbadc0de_exp.sol`. Multiple files can concern the same named system, so eight files must not be reported as eight independent incidents. `CATALOGUE_DISPOSITION.csv` and `.json` list **all 67** source files, network aliases, immutable links, original blob hashes, content SHA256 and exact disposition.

The original registry was introduced in commit `7a4646d11d198487acdcf8d3a97e36cb2bb6fe47` (parent `78baeb5c83a931a9f3f85e56893391f94cd0699b`), and the original protocol in `66c4b0fb73de80d3eae2426fa3805a773743e028`. Their text describes investigator-informed convenience nominations with named components fixed before the source census. It does **not** specify an exhaustive inclusion algorithm or reasons for omitting the additional eight Ethereum files. Freezing the list before measuring its traffic protects against substitution based on those measurements; it does not establish representativeness or retrospectively justify omitted entries.

Accordingly, the manuscript should describe **16 investigator-informed convenience component nominations from a 28-file Ethereum catalogue, with four initial-study files and eight other Ethereum files not nominated**. It must not claim “all Ethereum PoCs except the four initial families” or invent a previously fixed “unambiguous core address” rule. The remaining exclusion rationale is undocumented, and that limitation is explicit rather than repaired by post-hoc labels.

Suggested manuscript wording:

> We used 16 investigator-informed convenience component nominations, frozen before their traffic census. A retrospective audit of the seven source directories identified 67 PoC files: 39 used other chains and 28 forked Ethereum mainnet; of the latter, 16 were nominated, four corresponded to the initial families, and eight further files were not nominated without a documented original exclusion rationale. The complete file-level disposition ledger accompanies the artifact.

## Reproduction

From the repository root, offline:

```sh
python papers/monitoring_jss/phase31/cohort_audit/recompute_census.py
python papers/monitoring_jss/phase31/cohort_audit/audit_catalogue.py
python papers/monitoring_jss/phase31/cohort_audit/deployment/audit_deployments.py
```

The first command recomputes arithmetic from the unchanged Phase28 daily CSV. The second reconstructs dispositions from the saved catalogue metadata and checks the registry and totals. The third derives deployment sensitivity from saved raw API responses and validates their SHA256. These commands write deterministic JSON/CSV and do not require network access. Repeating them produced byte-identical outputs after initial generation.

To independently reconstruct the catalogue metadata from upstream source, provide a separate Git checkout containing the pinned commit:

```sh
python papers/monitoring_jss/phase31/cohort_audit/audit_catalogue.py --source-repo /path/to/DeFiHackLabs
```

This performs `git ls-tree` and `git show` against the exact commit and reads each original PoC. `SOURCE_INVENTORY.json` records the extracted network alias and original content identifiers; `FOUNDRY_MAINNET_BINDING.json` records the RPC alias binding. No third-party PoC code is redistributed here. The raw deployment responses use an indexed metadata evidence tier, not receipt-root authentication. This audit provides no new exploit labels, detector alerts or population-level transportability estimate.
