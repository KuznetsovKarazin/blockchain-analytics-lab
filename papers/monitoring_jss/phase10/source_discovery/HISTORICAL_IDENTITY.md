# Li.Fi: historical identity and architecture, Stage A

**Two protocol components are identified well enough to freeze the next historical check. The full population remains unresolved; no case is admitted and no detector score was computed.** The unchanged window is [2022-02-19T00:00:00Z,2022-03-21T00:00:00Z).

| Nominated role | Address | Corroborating explorer metadata |
|---|---|---|
| Protocol entrypoint | `0x5a9fd7c39a6c488e715437d7b1f3c823d5596ed1` | LiFiDiamond; EIP2535 |
| Protocol logic | `0x73a499e043b03fc047189ab1ba72eb595ff1fc8e` | CBridgeFacet |

The [original BlockSec analysis](https://blocksec.com/blog/li-fi-attack-a-cross-chain-bridge-vulnerability-no-it-s-due-to-unchecked-external-call) supplies the two protocol-address links, 47 and 49. They identify protocol components, not a selected list of affected wallets. Its first link uses functional CBridge terminology; the destination is independently named as a diamond by the explorer. These nominations do not establish every historical component or prove that the logic was active throughout the window.

The two Blockscout address responses report successful creation and a common creator. They supply creation transaction locators, **but no creation block or timestamp**. The balance-update block must not be substituted for creation time. Current verification labels and proxy metadata provide identity consistency, not an exact historical runtime match. The current facet list is not the March 2022 population.

The [official historical repository snapshot](https://github.com/lifinance/contracts/tree/7b41d7d3306f213480b167e9487071d1c959d4fb) has author and committer metadata dated17 March 2022 and an untruncated 108-entry returned tree. Its README describes a diamond dispatching to business and administrative facets through delegatecall. Both retrieved file contents independently reproduce their Git blob identifiers. The ordinary Hop demo refers to a staging deployment export absent from this tree and to chain 100; it does not establish an Ethereum deployment. One snapshot is not an exhaustive history, and Git time is not activation time.

[Current official addresses](https://docs.li.fi/introduction/lifi-architecture/smart-contract-addresses) instead list the common entrypoint `0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE`. Using it for March 2022 without historical proof would change the measured population. The old README's repository-name link returned 404; both Etherscan component pages returned 403. These failed requests remain in the accounting.

The [official postmortem](https://blog.li.fi/20th-march-the-exploit-e9e1c5c03eb9) gives only approximate deployment recency and describes disabling swap methods, upgrading logic and restoring swaps. Exact times remain open. Consequently the continuation must resolve deployment/predecessor history and selector/facet epochs across the complete window, including the incident day. A source date or equal endpoint state cannot replace that evidence.

Reported unauthorized spending involves assets held by users. Such transfers may be observable yet outside the fixed core-external-out metric. This is a measurement limitation to retain, not a reason to reject the case or redefine affected users as monitored core. Source/runtime checks, observation coverage, independent execution labels and a complete cohort/warmup freeze remain outstanding.

StageA used 18 charged retrieval items, including 3 search queries, 8 successful primary documents/files and 3 failed requests. Direct explorer response bodies total 2384 bytes; other tool-rendered representations are accounted separately. The independent reviewer made no new network requests. Detailed owned findings and source locators are in `identity_findings.json`; raw representations and the offline review receipt remain private.
