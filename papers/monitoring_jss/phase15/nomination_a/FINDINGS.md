# Phase15: LiFi and Revest fixed-address nominations

Both rows have a supported finite core nomination under the accepted rule. Independent review is pending; neither case is admitted and no detector input or score was acquired.

| Original row | Historical component | Proposed Ethereum core | Qualifying roles |
|---|---|---|---|
|65, Li.Fi|March2022 diamond interface|`0x5a9fd7c39a6c488e715437d7b1f3c823d5596ed1`|Public user entrypoint|
|70, Revest Finance|Original Revest Solidity stack|`0x2320a28f52334d62622cc2eafa15de55f9987ed9`; `0xa81bd16aa6f6b25e66965a2f842e9c806c0aa11f`|Public user entrypoint; core token custody|

LiFi's [original investigator analysis](https://blocksec.com/blog/li-fi-attack-a-cross-chain-bridge-vulnerability-no-it-s-due-to-unchecked-external-call) identifies a protocol interface and separate logic component. The interface qualifies; the CBridge facet does not independently qualify as direct user entrypoint or custody. Retained creation/runtime evidence corroborates the diamond identity and its 11 January 2022 creation. The historical official README describes the diamond as the user-facing dispatcher. The current official address directory names a different common entrypoint and is not backdated.

Revest's [dated official report](https://revestfinance.medium.com/revest-protocol-exploit-recovery-plan-b06ca33fbdf5) enumerates four historical components. Revest and TokenVault meet the entrypoint/custody predicate; LockManager and FNFTHandler have supporting roles and are excluded. Retained independently checked creations place both included contracts on 24 September 2021. This includes every qualifying record in that explicit four-component description. It does not claim all protocol-owned addresses. The original controller's terminal registry deactivation remains disclosed; the fixed set and full 30-day window are preserved.

Both nominations use source tier 3 and remain incident-informed. Higher-tier historical deployment sets were not established in the inspected artifacts. A fresh 71-entry Revest source tree contains no identified production deployment roster; current directories mix later replacements. Search failures and the failed Revest tutorial retrieval are retained. These bounded observations do not establish absence across all repository history.

The Ethereum archive route is documented. LiFi's Phase14 inventory is reusable; full-window payload completeness and per-case source freezes are still required. The proposed windows remain `[2022-02-19,2022-03-21)` for LiFi and `[2022-02-26,2022-03-28)` for Revest, in UTC. No outcome, transfer volume, warmup sufficiency or alert result influenced the sets.

New work used 4 search queries, 6 explicit document retrievals and 4 cached finds in 5 web calls plus 1 GitHub fetch. One document retrieval failed. Backend HTTP counts and bytes are unknown. No new chain/data payload, source compilation, old test rerun, score or label join occurred. Exact retained-source hashes, inclusion decisions, exposure and tool-rendering receipts are in [rows.json](rows.json).
