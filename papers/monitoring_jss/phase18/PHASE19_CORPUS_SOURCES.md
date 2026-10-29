# Phase19: reproducible external-corpus source assessment (29 October 2026)

**No new empirical case admitted, scored, or acquired here.** The current external validation remains the two exposed Phase16 families (Li.Fi and Revest), three verified known execution transactions.

## HOUSTON (NDSS 2026) — reusable reference identities, not raw observations

- Paper: https://doi.org/10.14722/ndss.2026.241534
- Official source repository at pinned Git SHA `c3dc7bc49d03c131e721f3b4b2ec6cdbd956c954`: https://github.com/ucsb-seclab/houston/tree/c3dc7bc49d03c131e721f3b4b2ec6cdbd956c954
- The `dataset/` directory currently contains `defi-incidents-dataset.pdf` (120,347 bytes). The README describes a set of incidents with attack transaction hashes and block numbers.
- **Important boundary:** the root file `defi-incidents.csv` at this pinned revision contains **only one Polynetwork example** (148 bytes), not a machine-readable export of the full reported 115 incidents.
- The repo README states that only the Polynetwork raw-data example is included because historical source data are large, and that several auxiliary components are absent. Thus neither all historic inputs nor all 115 cases are executable from the repository alone.
- The README states HOUSTON's historical evaluation uses prior protocol traffic and a 30-day evaluation horizon; this is materially different from a cold daily reset. We must position historical initialization as established evaluation practice, not claim novelty for cumulative history.
- This PDF's individual incident entries **have not yet been extracted, matched or independently adjudicated** in this phase. Copyright/licensing of the PDF should be checked before redistributing; retain upstream link rather than copying its bytes into our Git.

## DeFiHackLabs — replay examples, candidate metadata only

- Pinned snapshot: `0a9b9fd81c50767ff49f81089fbf8934f2f45b02`.
- Available source and incident files: https://github.com/SunWeb3Sec/DeFiHackLabs/tree/0a9b9fd81c50767ff49f81089fbf8934f2f45b02/src/test
- Useful for candidate chains, PoCs and sometimes historical transaction links. A Foundry fork block or PoC transaction is not necessarily a real exploited execution identity; independently check primary reports and historical chain metadata.
- The source triage of Bacon, Rari, Umbrella, Auctus and Saddle is in [PHASE19_SOURCE_TRIAGE.md](PHASE19_SOURCE_TRIAGE.md).

## AWS Public Blockchain Dataset — source coverage and cost

- Official documentation: https://aws.amazon.com/blogs/web3/access-bitcoin-and-ethereum-open-datasets-for-cross-chain-analytics/
- Registry: https://registry.opendata.aws/aws-public-blockchain/
- Ethereum paths `s3://aws-public-blockchain/v1.0/eth/logs/date=YYYY-MM-DD/`, `transactions/` and `blocks/` offer dated compressed Parquet archive partitions.
- This is the data transport previously audited for Li.Fi and Revest. A new case still requires date-level listing, full address-column scanning, selected all-emitter bundles, transaction status and independent source QA.
- No new archive listing, payload download or runtime estimate has been executed at Phase19. Never turn missing source objects into empty populations.

## Scientific decision gate

- Phase19 source-screening frame may draw from the PDF and DeFiHackLabs, but MUST be frozen and cross-deduplicated before scoring any newly admitted cases.
- Each proposed experiment needs exact Ethereum successful execution identity, fixed-core emitter role, 30-day UTC window, available source partitions, independently checked full selected bundles and an explicit `KNOWN_SUBSET_ONLY` or positive-inventory-completeness statement.
- A monitor measuring gross outflow of the core must be stratified against distinct attack-mechanism families (user-approval drain, reentrancy, pricing errors, authorization bypass).
- Compare label-free eligibility before attack labels and preserve unresolved disposition rows. Only independently validated incidents can enlarge the scientific external cohort.
- **Do not** compare 94.8% HOUSTON incident detection with our 0/3 known-reference hits as if they share data, decision units or denominators; they do not.

The next priority is independent reference-role and core checks for Bacon and Rari and feasibility checking of historical archive partitions; no detector or Phase16 parameters should be changed while making this decision.
