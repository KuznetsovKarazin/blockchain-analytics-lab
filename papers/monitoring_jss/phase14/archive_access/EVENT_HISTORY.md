# Li.Fi administrative event history: observed chronology and nominal state

Five fixed Blockscout requests returned two matching constructor controls and eight records inside the original study window: seven `DiamondCut` events and one `Inited` event. The separate `OwnershipTransferred` window query returned an empty list. None of the responses reached the documented 1,000-record cap. Collection retained 15,127 response bytes and took 35.925 seconds.

Starting from the independently checked state at block 14,233,162, the nominal fold of all eight records reproduced the owner, ordered facet arrays and complete enumerated selector map at block 14,426,367. A separate decoder and list-based model reproduced that result. This is consistency between returned indexer events and observed endpoint state; complete historical routing and all writer effects remain unresolved.

All times below are **indexer-reported UTC on 20 March 2022**. Counts describe selector references in each cut; the last column follows addition/removal arithmetic from the 25-selector seed. It is a nominal event-implied count, not an independently observed intermediate storage snapshot.

| UTC | Block | Log index | Event | Remove | Replace | Add | Nominal selectors after |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| 10:11:45 | 14,422,640 | 118 | DiamondCut | 5 | 0 | 0 | 20 |
| 21:29:12 | 14,425,687 | 352 | DiamondCut | 2 | 0 | 0 | 18 |
| 22:43:23 | 14,426,018 | 4 | DiamondCut | 0 | 0 | 5 | 23 |
| 22:44:21 | 14,426,021 | 221 | DiamondCut | 0 | 4 | 2 | 25 |
| 22:45:39 | 14,426,029 | 63 | DiamondCut | 0 | 2 | 1 | 26 |
| 22:47:14 | 14,426,037 | 363 | DiamondCut | 0 | 2 | 1 | 27 |
| 22:47:14 | 14,426,037 | 364 | Inited | 0 | 0 | 0 | 27 |
| 22:50:49 | 14,426,048 | 275 | DiamondCut | 0 | 1 | 1 | 28 |

The eight records occur in seven reported transactions and seven blocks. The two records at block 14,426,037 share transaction position 501, with `DiamondCut` immediately preceding `Inited` in the returned log order. Exact transaction hashes and positions are retained in [history_findings.json](history_findings.json).

The chronology distinguishes two paths behind the 14 endpoint selector-address changes established in Phase12: nine selectors have `Replace` actions, while five are removed and later re-added at different destinations. The nominal selector count reaches 18 before ending at 28. Endpoint comparison alone did not reveal that sequence. The returned cuts do not establish why these changes occurred or whether other writes intervened.

The first cut removes `0xcf76d313`, `0x2a7a7042`, `0x2722a4a8`, `0x01c0a31a` and `0x73bbd5c6`. All five are later re-added. Their event-implied intervals between removal and re-addition span 45,156–45,544 seconds; these are not independently verified periods of unavailable execution.

The changes group into four start-facet to new-destination pairs:

| Start-checkpoint facet | New destination | Replace selectors | Previously removed selectors re-added |
| --- | --- | --- | --- |
| `0x8a017f915029e908bad589ef0f2af84d9dd4c976` | `0x517f5d5f94d2f6faa48ad889467ccf470064ba43` | `0x28225f0c`, `0x4f7c96b5`, `0xbfa1fc0a`, `0x7d7aecd3` | `0xcf76d313`, `0x2a7a7042` |
| `0x69df07bc9f91206406c85105342d2bdf4363f7c5` | `0xb4b4f5d0119f27601471a9392d78788538d52e8c` | `0xd1026c9c`, `0x327a564d` | `0x2722a4a8` |
| `0x73a499e043b03fc047189ab1ba72eb595ff1fc8e` | `0x2abfcca3672a853370f59421c6c6f72e5f215d96` | `0x4fd34907`, `0xc2c134df` | `0x01c0a31a` |
| `0xa0239e30356ba1c40ece298f6d18c0ad0cbaf1e1` | `0x4f932770648a1f53c19342d38bc02dba06527246` | `0xe18a8fdb` | `0x73bbd5c6` |

At 21:29:12, `0xcc512aad` and `0xf72fa0cb` are removed from the nominal registry and are absent from the retained end enumeration. Their start destination was `0xe73b96b69870e9db5a5283e674f9fe62c89cc7a2`, whose source remained unbound in Phase13. At 22:43:23, five selectors absent from the start enumeration—`0x536db266`, `0xfbb2d381`, `0xfcd8e49e`, `0x9afc19c7`, `0x124f1ead`—are added at `0x62f7dc4742ed19716fd4e4fd1aa79b6ec2dcced8`. These are routing observations, not evidence of account creation or of new monitored emitters.

Three cuts specify nonzero initializer targets:

| Block | Initializer target | Calldata selector | Calldata bytes |
| ---: | --- | --- | ---: |
| 14,426,021 | `0x517f5d5f94d2f6faa48ad889467ccf470064ba43` | `0xbfa1fc0a` | 36 |
| 14,426,029 | `0xb4b4f5d0119f27601471a9392d78788538d52e8c` | `0xd1026c9c` | 1,124 |
| 14,426,037 | `0x2abfcca3672a853370f59421c6c6f72e5f215d96` | `0x4fd34907` | 68 |

The following `Inited` record reports bridge `0x5427fefa711eff984124bfbb1ab6fbf5e3da1820` and chain ID 1. Its shared signature and adjacency do not independently prove facet attribution or effective configuration. Initializer effects are not modeled by the nominal routing fold. No ownership-transfer record was returned; the nominal owner remains equal to the retained endpoint owner, without proving uninterrupted ownership.

All eight window records omit `blockHash` and `removed`; those fields remain `null`. The two known-event controls and unsaturated responses do not prove complete indexing, canonical-chain authentication, absence of hidden writes or complete intermediate states. No label join, detector score, case admission or case exclusion follows from this result. Earlier failed acquisitions remain unchanged. The source-free arithmetic classification is recorded in [event_timeline.json](event_timeline.json), and the independent actual review is in [archive_access_actual_review.json](../qa/QA_PUBLIC.md).
