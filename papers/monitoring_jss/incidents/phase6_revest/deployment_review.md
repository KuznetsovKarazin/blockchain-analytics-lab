# Revest historical population and feature-availability review

25 October 2026. Metadata/source review only. No Revest raw event payloads, incident receipts, detector scores or new feature rules were acquired or evaluated. Solidity/JavaScript sources were read as text and were not executed. This is an eligibility input, not a frozen experiment or a deployment attestation.

**Decision:** the existing Ethereum all-topic acquisition path can support a new, explicitly scoped Revest emitter-workload test. The historical population is not yet verified well enough to admit a complete protocol-level test. The principal gap is exact activation and registry history, not the availability of an event-count implementation. Current documentation must not be substituted for the March 2022 deployment.

## Verified source map

“Verified” below means the stated source contains the address/role; it does not mean that historical on-chain bytecode, registry contents, or activation boundaries have been verified.

| Role | Address on Ethereum (chain 1) | Evidence and status |
|---|---|---|
| Historical SDK registry/ROUTER | `0xD721A90dd7e010c8C5E022cc0100c55aC78E0FC4` | Official SDK snapshot dated 18 February 2022; same constants blob at its 24 March revision. The SDK uses this address with the registry ABI and resolves component addresses dynamically. On-chain activation still unverified. |
| Revest entry point associated with incident-era stack | `0x2320A28f52334d62622cc2EaFa15DE55F9987eD9` | Official 28 March postmortem, linked as Revest.sol. No creation receipt or pre-window registry binding verified. |
| LockManager associated with that stack | `0x226124E83868812D3Dae87eB3C5F28047E1070B7` | Same official postmortem; also listed in current docs. Historical continuity is not established merely by agreement. |
| Legacy TokenVault | `0xA81bd16Aa6F6B25e66965A2f842e9C806c0AA11F` | Same postmortem; current docs explicitly label it legacy. |
| Incident-era FNFTHandler | `0xe952bda8c06481506e4731C4f54CeD2d4ab81659` | Same postmortem. Current documentation lists another FNFT handler. |

The table's four component identities/roles are the only incident mechanism information used from the postmortem. It supplies useful retrospective attribution, not an independently timestamped pre-window deployment inventory. The report also establishes that the incident affected Ethereum; no attack transaction was opened for this review. [Official postmortem](https://revestfinance.medium.com/revest-protocol-exploit-recovery-plan-b06ca33fbdf5).

The current [contract directory](https://docs.revest.finance/resources/contract-links.md) instead lists registry `0xd2c6eB7527Ab1E188638B86F2c14bbAd5A431d78`, Revest `0x9f551F75DB1c301236496A2b4F7CeCb2d1B2b242`, FNFTHandler `0xa07E6a51420EcfCB081917f40423D29529705e8a` and TokenVaultV2 `0xD672f1E3411c23Edbb49e8EB6C6b1564b2BF8E17`. These are **current-documentation identities, not accepted March population members**. The [official security checklist](https://docs.revest.finance/resources/security-checklist) separately identifies an initial hardened Revest entry point `0x36c2732f1b2ed69cf17133ab01f2876b614a2f27` and records later registry, FNFT and vault changes. It does not supply the full block-by-block activation history.

## Immutable historical code evidence

Two repositories are official through the [developer documentation](https://dev.revest.finance/) and organization identity. Git commit dates are author/committer metadata, not Ethereum timestamps; the inspected commits are unsigned.

- RevestContracts: `f4b5a5a898d202a5040f72ec7b1196de5f05e5f8`, committer date 25 February 2022 19:59:02 UTC, tree `371e4ddf17793201be19fa3cb3a1a6cf8ab2d17a`. It is the latest returned master commit before both the proposed window and the incident date. [Commit](https://github.com/Revest-Finance/RevestContracts/commit/f4b5a5a898d202a5040f72ec7b1196de5f05e5f8).
- Revest-SDK: `dcdf919452f9cee67b0fb4bda73b14a5da6c20d9`, 18 February 2022 21:52:26 UTC. [Constants](https://github.com/Revest-Finance/Revest-SDK/blob/dcdf919452f9cee67b0fb4bda73b14a5da6c20d9/src/constants.js), blob `8ccfa8d5a3b607ddd79b5e2bfa9beec07fb767f1`; [registry use](https://github.com/Revest-Finance/Revest-SDK/blob/dcdf919452f9cee67b0fb4bda73b14a5da6c20d9/src/index.js), blob `e7358cafa7b7bfcf5e6a714cbfc1d27a66c73ec3`. The only returned master commit within the proposed window, `4ac04eee298368639adf084084010eb26b3d23e0` on 24 March, retains the same constants blob. This does not prove no on-chain change occurred.

In the retrieved pre-window [registry source](https://github.com/Revest-Finance/RevestContracts/blob/f4b5a5a898d202a5040f72ec7b1196de5f05e5f8/hardhat/contracts/RevestAddressRegistry.sol), component setters update mappings without emitting dedicated mapping-change events. Its [access-control base](https://github.com/Revest-Finance/RevestContracts/blob/f4b5a5a898d202a5040f72ec7b1196de5f05e5f8/hardhat/contracts/utils/RevestAccessControl.sol) also permits changing a component's registry pointer. Consequently an all-topic **log-only** scan cannot certify that no routing/registry change occurred. This is a source-level observation; deployed-code equivalence remains unverified.

The saved source manifest records exact URLs, Git blob hashes and SHA-256 for eight source files plus the GPL licence. All nine retained file bytes were independently checked against Git's blob-hash encoding. No third-party narrative article or screenshot is copied into the evidence folder.

## Available information versus unsupported semantics

The existing collector scans the complete address column of each enumerated Ethereum log partition, retains every selected emitter's topics/data, and joins ordered headers. Once addresses and periods are frozen, this supports all-topic counts, canonical order, duplicate identity, the unchanged 60-second count rule, grouping and budget comparisons. These remain workload/allocation endpoints.

The historical source exposes application events in Revest and TokenVault; the FNFT handler is a separate ERC-1155 component. Thus a single entry-point emitter is not “all protocol events,” and ERC-20 transfer logs are emitted by token contracts outside that single address. Semantic ABI reconstruction, balances, native transfers, call nesting, intermediate state, failed/reverted actions, and registry transitions require additional receipts/traces/historical-state evidence. Source code alone does not provide those data or their availability times. No new detector should be designed from this incident report and then advertised as held out on the same case.

## Minimum freeze before any Revest payload or scores

1. Fix the estimand: a previously unscored protocol's finite emitter workload under the unchanged rule/policies, with declared prior catalogue/postmortem exposure. It is not a blind or previously unknown attack test.
2. Resolve creation receipts/code hashes and the registry bindings at the start and during the window. Audit setters, registry-pointer changes, pauses and replacements at exact block/transaction boundaries. If unavailable, exclude the complete-protocol claim; do not silently assume constant routing.
3. Choose and justify the exact emitter population independently of event counts: one historically established entry point, or a named multi-contract population. Freeze per-emitter versus shared budget/grouping semantics. The current policy core accepts one configured address; pooling addresses would require a new tested specification, not relabelling the old core.
4. Freeze the proposed `[2022-02-26T00:00:00Z, 2022-03-28T00:00:00Z)` interval, initialization/warm-up, source-object inventory, empty-day handling and completeness gates. It is incident-conditioned; no day is automatically benign. Do not replace it with the already cached March19–April17 window merely to save downloads without a documented pre-outcome design decision.
5. Freeze unchanged method bytes, B=1/5/20 (B=5 primary if retained), endpoints and exclusions before acquisition. Keep external positive-transaction adjudication separate and join only after decisions are sealed. A new workload test does not itself satisfy the article's multi-case detection requirement.

**Unresolved access:** all four historical component explorer pages linked from the postmortem returned HTTP 403 through the retrieval service. No historical RPC state or creation receipt was queried. The exact deployment/activation and upgrade gates therefore remain open. AWS object-metadata feasibility is being checked separately and does not close these deployment gates.
