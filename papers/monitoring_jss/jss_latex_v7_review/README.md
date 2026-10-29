# Article 2 — JSS review revision V7

**Title retained:** When Can a Blockchain Monitor Make a Decision? Source-Audited Feature Readiness, Historical State, and Exact-Execution Evidence.

This directory is a new review revision. The V6.1 source, data and immutable release tag have not been replaced. The revision is not authorized for journal submission.

## Evidence baseline and current scope

The published V6.1 baseline is tag `article2-jss-v6.1-2026-10-29`, commit `651daa926bb3803ad76227389a4fb35c1027da63`. Its original manuscript PDF SHA-256 is `7b6ddd2036671fe98250b0e76ff5e423666e420cba9f1a87b8b18275c221c43a`.

The V6 research line branched from Phase27 commit `78baeb5c83a931a9f3f85e56893391f94cd0699b` rather than continuing the V5 manuscript revision. This is verified by the parent edge of Phase28 nomination commit `7a4646d11d198487acdcf8d3a97e36cb2bb6fe47`; the separate V5 tip is `8c9b72339c6d7055d7d3bb444e0038e909751b08`. This statement describes the verified branch origin, without assuming a fully reconstructed graph from a shallow checkout.

The final V7 evidence reference is [`article2-jss-v7-2026-10-29`](https://github.com/KuznetsovKarazin/blockchain-analytics-lab/tree/article2-jss-v7-2026-10-29). Release publication and pinned-byte verification must complete before distributing this package as the published V7 release. V6.1 remains a separate immutable baseline.

The primary study remains four incident families and five admitted successful executions. The extensions remain distinct: twelve comparison emitters, sixteen incident-derived source nominees, seven low-volume fixed-emitter replays, and a separate higher-traffic Nomad contrast. The seven low-volume streams are not a representative or independent detector-performance cohort. Provisional candidate identity joins are not admitted attack recall denominators.

The new text leads with **108/178 nonempty days (60.67%)** below twenty transactions; **302 zero-transaction days** are reported separately. Preserved creation metadata supplies a deployment-date sensitivity: excluding 160 strictly predeployment days leaves 250/320 below twenty, and excluding deployment dates too leaves 243/312. These are different estimands, not competing arithmetic corrections.

A complete catalogue reconciliation identifies **67 Solidity files**, **28 Ethereum files**, and **39 other-chain files** in the pinned March–September 2022 directories. The Ethereum files comprise sixteen nominated entries, four original-family entries and eight omissions with no documented original rationale. The revision reports this gap without inventing an exhaustive historical selection rule.

## Revisions against the supplied review

- M1: names low transaction volume as a replay-selection criterion; removes the transportability inference and the claim that this subset supplies evidence “stronger than” the warm-up inequality. A new source-complete, label-free Nomad contrast tests a different traffic stratum while preserving its frozen Replica boundary; it does not remove the sampling bias.
- M2: changes the headline denominator, distinguishes silent from nonempty days, and adds deployment-date sensitivity. PoC fork-date windows remain whole-day source windows; they are not relabelled strict attack-time histories.
- M3: states the true convenience selection and missing original exclusion rationale; the catalogue reconciliation is reported explicitly.
- M4: adds RQ4 and collects extension methods/results after the complete primary results. Duplicate source, independence and interpretive caveats were compressed. AI assistance appears only in the declaration.
- M5: reports Schnoodle burden as 27/134 (20.15 notifications per hundred selected transactions) and the verified greedy B=1 suppression of its exploit-linked candidate. B=1 yields eighteen count notifications versus twenty-seven at B=5. At the same offered B=5, token-bucket allocation suppresses the reference with credit 10871/17280 (approximately 0.6291) after only one prior emitted notification; greedy and paced allocation deliver it. Total notifications are 21 (token bucket), 27 (greedy), and 24 (paced).
- Minor corrections: causal history follows block/transaction order and includes earlier same-timestamp transactions at the inclusive seven-day boundary; exact grouping gap `>=300 s`; uniform provisional selected-candidate joins including Umbrella; repaired source-table quotation marks; published baseline tag and full commit; narrowed Highlights; stable title. The Omni date remains 9 May 2023 because the current primary page displays that date; the review's 11 May suggestion was not adopted without support.
- Additional correction: separates computational observation A from security-construct relevance, and uses `q` consistently for the rank.

## Detailed observations of the three second-wave streams

The revision includes all-stream role-specific analysis for Saddle (44 transactions), XCarnival (43), and Audius (38). The expanded twelve-hash role ledger distinguishes preparation, extraction, whitehat rescue, unsuccessful governance proposals and later sales. The original reference subset remains in the seven-stream comparison table; the expanded ledger is not pooled into an attack-performance denominator. Saddle supplies a concrete cumulative-history B-pass/C-fail case (20 prior sUSD values, rank 3/21), with an explicitly inferred subsequent-extraction role. Its two prior values at least as large as the current amount are the first documented extraction and the intervening whitehat rescue; the retained causal history is not certified benign. XCarnival identifies native ETH borrowing outside the selected XNFT emitter. Audius separates transaction success from proposal failure and identifies treasury extraction rather than the later swap.

## Higher-traffic Nomad contrast

Nomad retains the Phase28 Replica `0x5d94309e5a0090b165fa4181519701637b6daeba` and original 3 July–1 August 2022 window. Selection was prompted by its already known 930-transaction volume and frozen before its new scoring. Of those transactions, 884 occur on the final UTC day; this is a busy-stream contrast, not a uniformly high-traffic or random cohort.

Independent verification passes for all **930 transactions, 3,507 all-emitter events and 63 policy cells**. In 905 selected transactions there are 1,157 positive ERC20-shaped transfer events, but **zero positive external outflows from the frozen Replica**. Therefore all tested rank histories remain ineligible and produce zero notifications. A passed transaction-count gate must not be described as passed rank-history gate B.

The count rule produces 564 raw triggers, 12 grouped candidates, 5 greedy-B5 notifications and 7 hard-cap suppressions. **No attack-reference join was performed.** These numbers describe feature boundaries and notification workload, not exploit hits, misses or incident recall. The new source tier is original-AWS normalized event payloads and transaction `receipt_status`, with source range identities and checksums; it is not receipt-root authentication. Full original Parquet bodies are not redistributed. Offline reproduction starts from retained full normalized bundles. Acquisition interruptions and documented resource amendments remain in the source artifact.

See `phase31/nomad/` for the frozen protocol and `phase31/nomad_independent/AUDIT.json` for the independent PASS. The original seven-stream results and their 441 configurations remain separate rather than being pooled into independent incident trials.

## Reproducibility boundary

Offline scoring and notification decisions can be reproduced from the retained normalized records. The V6.1 retention gap for the three second-wave streams is now closed: `phase31/raw_payload_audit/raw_observations.zip` retains indexed HTTP response bytes, normalized full logs and success metadata for all **125** unchanged selected transactions and **2,103** event rows. Every V6.1 canonical normalized event-payload digest, frozen feature and independently decoded count/token flow matches. The newly retained HTTP response bodies and pagination need not be byte-identical to the old unretained responses. A fresh archive extraction passes with zero verification network requests, and all three altered-data checks are rejected.

| Stream | Selected transactions | All-emitter event rows |
|---|---:|---:|
| Saddle | 44 | 850 |
| XCarnival | 43 | 1,200 |
| Audius | 38 | 53 |
| Total | 125 | 2,103 |

From the repository root:

```bash
python papers/monitoring_jss/phase31/raw_payload_audit/verify_all.py --archive papers/monitoring_jss/phase31/raw_payload_audit/raw_observations.zip --integrity-tests
```

The archive SHA-256 is `3e1a3de3454c886c7a051db6780a876f435d2a96011faf1854aa0f8b53d8d77d`. It contains 1,307,523 bytes; acquisition retained 275 HTTP responses totaling 6,466,957 bytes. The result is in `FULL_RAW_OBSERVATION_AUDIT.json`. This raw-payload audit covers the 125 second-wave transactions; it must not be generalized to all earlier 667 Bacon/Rari or 400 first-wave transactions.

Original source identities and event counts came from AWS Ethereum Parquet and were cross-checked against indexed event bundles. Source identity and count agreement is not receipt-root authentication, and an indexed successful status does not by itself adjudicate an exploit role.

## Build

Use TeX Live with `elsarticle`, `lmodern`, `bibtex8` and the standard packages listed in `main.tex`:

```bash
pdflatex -interaction=nonstopmode -halt-on-error main.tex
bibtex8 main
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error main.tex
```

The local build uses the official `STM-Document-Engineering/elsarticle` source at commit `04aee43a9049051128c5d58b617dcd05e34df8b4`, with its class and BibTeX style supplied through `TEXINPUTS` and `BSTINPUTS`. This package does not redistribute a partial upstream class installation.

The revised manuscript currently compiles to 32 pages with the same 12-point preprint class. The complete revision, including Nomad, has 32 pages. The retained figure files are vector PDFs. The source asset `fig2_history_eligibility_six_views.pdf` is supplied for completeness but is not included in the revised PDF; the manuscript uses the corresponding exact readiness table to avoid duplication.

## Submission status

Competing interests, actual research funding, the exact AI-use declaration, final source/licensing checks and any archival DOI require final confirmation. No Zenodo DOI is claimed. The manuscript is not submitted, and this revision does not imply authorization to submit it.
