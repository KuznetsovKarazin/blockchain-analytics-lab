# Revest eligibility: targeted metadata audit

25 October 2026. **Candidate only; no independent holdout admitted.**
No new chain payload, detector score or incident prediction was acquired.
The Solidity proof-of-concept was read as inert text, never compiled or run.

## Result

The exact current and historical K4 metadata functions both omit Revest in
both `price_only=True` and `price_only=False` modes. In all four calls the
first failed filter is the absence of the literal substring `flash` in the
pinned Solidity source. A Uniswap callback is present in that source, but the
loader does not infer borrowing semantics from it. The loader was not repaired
or modified for this audit.

| Check | Observed result |
|---|---|
| `createSelectFork` chain | `mainnet` |
| PoC fork block, metadata only | 14465356 |
| Literal `flash` substring in source | absent |
| Price/oracle keyword in README heading | absent |
| README transaction links parsed | 1 |
| Transaction links in Solidity source | 0 |
| Current/old price-only positive selection | omitted / omitted |
| Current/old all-mainnet exclusion selection | omitted / omitted |
| S2 catalogue | Revest row, 27 March 2022, line 70 |
| Attack date in three preserved K4 input-date lists | absent in all three |

The confirmed historical exposure is **L1: catalogue metadata**. The targeted
loader results do not establish L2 exclusion-list participation through these
two paths. Their omission also does **not** establish that a Revest attack
transaction entered any K4 background table: the attack date is absent from
the three recorded input inventories. Ordinary interactions on other dates,
all binary tables, other branches/private work and personal knowledge are not
exhaustively audited. Do not describe Revest as entirely untouched.

The single parsed transaction link is catalogue metadata, not an adjudicated
or complete positive execution set. The PoC address and fork block likewise
do not establish the historical monitored population. The protocol's public
postmortem and later security checklist document replacements, so a modern
patched address cannot simply be applied to the pre-incident window.

## What can proceed next

`candidate_gate_status.json` lists each gate and its open requirement. The
remaining tasks are a historical deployment/activation inventory, a semantic
feature and availability contract, a pre-outcome cohort/population/window
freeze, then complete input and label checks. The existing proposal
`[2022-02-26, 2022-03-28)` UTC is not a new freeze. Nine dates overlap previously
acquired generic Ethereum archives, but no Revest population has been extracted
or checked. Neither those archives nor this audit authorize a detection claim.

Feature development may use declared development cases and synthetic fixtures.
Revest-specific rule design informed by its postmortem must not be evaluated
as an independent test on Revest. One candidate does not complete the intended
2–4-incident, multi-family evaluation.

## Reproduce the metadata result

1. Retrieve the five exact source files listed in
   `source_fixture_provenance.json`, using their immutable repository refs.
   Place them under a private fixture root at each stated `path`.
2. Preserve byte-exact source content. The script checks Git blob SHA and
   SHA-256 before importing either Python metadata loader. The source tree is
   deliberately a targeted fixture: one Solidity text file and the original
   root/2022 READMEs. It is not a rebuild of the entire incident catalogue.
3. With Python and the original loaders' NumPy/pandas import dependencies,
   run from any directory, giving the analytics checkout and a new output:

```sh
python audit_revest_metadata.py \
  --source-root /path/to/private/fixtures \
  --repo-root /path/to/blockchain-analytics-lab \
  --output /path/to/new_metadata_audit.json
```

The script refuses an existing output, checks the historical repository-input
hashes, invokes only metadata functions, and denies network/process-spawn
attempts during the offline audit. The timestamp/environment fields may differ;
the four loader results, source hashes, S2 row and manifest overlap must agree.
No Foundry, EVM fork, Solidity compiler or wallet is required.

Full third-party source text is outside Git and the user-facing package. The
repository license is Apache-2.0, while the exact PoC declares SPDX `UNLICENSED`;
this audit infers no redistribution permission. Immutable URLs, hashes and
our own reproduction script are provided instead.

Four older local source caches contained one extra terminal newline. Separate
private copies were restored to the freshly checked upstream Git blob bytes;
the original caches and historical evidence were preserved. Exact before/after
hashes and source pins are in `source_fixture_provenance.json`. This was byte
verification against an upstream identity, not an adjustment of expected hashes.

## Primary-source context already reviewed

- [Official Revest security checklist](https://docs.revest.finance/resources/security-checklist)
- [Protocol postmortem, 28 March 2022](https://revestfinance.medium.com/revest-protocol-exploit-recovery-plan-b06ca33fbdf5)
- [Original BlockSec investigation, 31 March 2022](https://blocksec.com/blog/revest-finance-vulnerabilities-more-than-re-entrancy)

These sources motivated the prior eligibility review, not a new detector or
positive-label join. The S2 loss field differs from the protocol/investigator
reports; loss magnitude is not used for case selection or prevented-loss claims.
