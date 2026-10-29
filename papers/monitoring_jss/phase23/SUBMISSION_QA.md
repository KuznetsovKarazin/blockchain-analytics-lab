# Journal submission readiness gate — Article 2 V4 (2026-10-29)

## Passed

- Six observation views across four historical incident families are clearly separated; five known successful executions are counted once per incident identity, without pooling Rari views.
- Original Phase16 evidence ZIP SHA-256 verified; earlier 948 method and 8,532 policy rows matched independently in Phase18.
- New Phase22 independent calculation re-executed locally: 252 configurations, 252 independent notification streams, no disagreement with original replay JSON/CSV and published-indexer archived inputs.
- Attack-time pre-execution counts verified from original published S3 selection identity plus independently retained indexer transaction metadata: 2, 8, 17, 18 per view.
- Reproducible Phase23 results: 4 attack-time view rows; 22 primary comparison rows; 90 readiness-sensitivity rows; 19 alert ledger rows. Script generates a SHA-256 audit manifest.
- No unadjudicated alert is presented as a false positive. Historical counters and current event-time semantics do not establish live detection latency.
- LaTeX compiled successfully with Elsevier `elsarticle` and `bibtex8`; all 29 cited BibTeX items resolved and none unused; three vector PDF figures included, plus 360-dpi PNG exports.
- PDF rendered page by page for layout QA, no overfull boxes in final compilation.

## Submission blockers / nonclaims

- Not a representative, independently blinded 20–50-case cohort or a multiple-algorithm benchmark; generic detection-performance claims remain unsupported.
- Complete incident-execution inventories are not established; the 5 known executions are not an exhaustive recall denominator.
- Additional Rari cases/pools and unadjudicated notifications need investigation for precision/FPR estimates.
- Bacon/Rari full logs/status depend on Blockscout indexed source; independent Ethereum receipt-root authentication of all selected transactions has not been performed.
- No causal live latency, prevention, actual economic harm mitigation or deployment SLA evaluation.
- Author to approve accurate funding/COI/AI-disclosure wording and corresponding email before actual submission.
- Public Git branch, exact future revision commit, stable tag/DOI and rights/checklists must be confirmed in the final data-availability statement.

**Recommendation:** strong technical review candidate, not submission-ready for JSS without remaining scientific and editorial gates.
