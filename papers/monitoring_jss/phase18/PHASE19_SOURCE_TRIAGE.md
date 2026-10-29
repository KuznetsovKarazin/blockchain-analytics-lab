# Phase 19 candidate-source triage — 29 October 2026

**Status: candidate/source review only. No historical monitoring input acquired and no additional incident admitted.** This is a preparatory, independent-source check of five candidate external cases, following completed but *exposed* Phase 16–18 Li.Fi/Revest diagnostics. The source catalogue is DeFiHackLabs at immutable commit [0a9b9fd81c50767ff49f81089fbf8934f2f45b02](https://github.com/SunWeb3Sec/DeFiHackLabs/tree/0a9b9fd81c50767ff49f81089fbf8934f2f45b02/src/test).

## Two strongest prospects (source-level, not admissible yet)

### Bacon Protocol — Ethereum, 5 March 2022

- Independently documented exploit transaction: `0x7d2296bcb936aa5e2397ddf8ccba59f54a178c3901666b49291d880369dbcf31`.
- Published victim proxy candidate: `0xb8919522331c59f5c16bdfaa6a121a6e03a91f62`; a separate implementation `0x781ad73f140815763d9a4d4752daf9203361d07d` is unverified in the cited investigator report.
- Investigators describe reentrancy through a token-recipient callback during `lend()`, followed by `redeem()`. The investigator explicitly says the implementation cannot be definitively analyzed; do not mark exact root-cause proof as complete.
- Independent investigative source: [CertiK incident analysis](https://www.certik.com/blog/bacon-protocol-incident-anaylsis). Pinned PoC: [DeFiHackLabs Bacon](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/0a9b9fd81c50767ff49f81089fbf8934f2f45b02/src/test/2022-03/Bacon_exp.sol).
- Required next gates: exact tx-role confirmation against chain metadata, proxy log-emitter role and constructor/deployment continuity, all 30 UTC archive partitions, complete selected transaction log bundles, no missing evidence. Historical proposed UTC window is **not frozen** pending complete admission.

### Rari Fuse — Ethereum, 30 April 2022

- Independent investigator discusses transaction `0xab486012f21be741c9e674ffda227e30518e8a1e37a5f1d58d0b0d41f6e76530` and victim fETH contract `0x26267e41ceca7c8e0f143554af707336f27fa051`.
- Same report notes multiple exploited contracts but examines only one transaction. Therefore it cannot close the incident-wide reference inventory or identify all monitored cores.
- Investigator: [Beosin incident analysis](https://www.beosin.com/resources/loss-exceeds-80m-due-to-reentrancy-contract-vulnerability). Pinned PoC: [DeFiHackLabs Rari](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/0a9b9fd81c50767ff49f81089fbf8934f2f45b02/src/test/2022-04/Rari_exp.sol).
- Required next gates: candidate execution-role validation, victim-pool specificity, exact 30-day archive coverage and independently closed reference subset.

## Three supplementary prospects

**Umbrella Network**: [official 21 March 2022 post-mortem](https://medium.com/umbrella-network/update-on-polar-stream-exploit-b2f4526327f2) confirms both Ethereum and BSC Polar Stream 2.0 staking pools were exploited. The pinned [PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/0a9b9fd81c50767ff49f81089fbf8934f2f45b02/src/test/2022-03/Umbrella_exp.sol) names two execution candidates, including Ethereum `0x33479bcfbc792aa0f8103ab0d7a3784788b5b0e1467c81ffbed1b7682660b4fa`. Neither an Ethereum-specific fixed core nor the candidate's exact exploit role has yet passed an independent audit. Multi-chain data must not be mixed in one Ethereum case.

**Auctus**: [Revoke.cash historical entry](https://revoke.cash/exploits) reports a user-approval-drain mechanism involving an older options contract; DeFiHackLabs pinned [Ethereum PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/0a9b9fd81c50767ff49f81089fbf8934f2f45b02/src/test/2022-03/Auctus_exp.sol). No independently accepted exact execution/core is yet available.

**Saddle**: [BlockSec technical analysis](https://blocksec.com/blog/how-to-exploit-the-same-vulnerability-of-meta-pool-in-two-different-ways-nerve-bridge-saddle-finance-what-you-see-is-not-what-you-get) discusses the 30 April 2022 Ethereum attack and metapool mechanism. The pinned [PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/0a9b9fd81c50767ff49f81089fbf8934f2f45b02/src/test/2022-04/Saddle_exp.sol) is a *reproduction*, not a closed historical execution inventory. Multiple pools and transactions require disambiguation.

## Fixed admission principles

- Do not select an event because it creates a detector alert.
- Distinguish public PoC calls, fork block heights, and original successful transaction identities.
- Freeze original component/core selection before case scoring. Incident-informed address nomination must be disclosed, not hidden.
- Prefer matched independent source audit, source partition inventory and exact reference-role checks before admission. Missing source means *unavailable*, not detector failure.
- No additional primary monitoring performance result is claimed here. The accepted external family count **remains two**.

## Scientific prioritization

Priority for the first *independent* source-audit attempt: (1) Bacon, (2) Rari. Umbrella, Auctus and Saddle remain in the screen; they should not be silently excluded for unresolved metadata. Revisit the original 13-entry Phase15 frame with these new candidates and record any overlap before defining a larger cohort. If data-source and reference audits remain unavailable, the present paper must remain an explicitly bounded case study.
