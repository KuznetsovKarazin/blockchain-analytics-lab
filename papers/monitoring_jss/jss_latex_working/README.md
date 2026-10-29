# Article 2 — working LaTeX for Journal of Systems and Software

**Status: a research manuscript in `elsarticle` format, not an authorized journal submission.** This copy is preliminary and follows the original Phase16/18 results plus the separately verified Phase20/21 source-only audit. The broader independent incident-detection evaluation remains open.

## Files

- [main.tex](main.tex) — 19-page working manuscript source (compiled PDF validated locally on 29 October 2026).
- [references.bib](references.bib) — journal bibliography.
- Four figure PNG files and a generated `main.bbl` are included in the complete local LaTeX package retained with the authorship workspace, but **the two source files in this Git directory alone are not a standalone compiling package**.
- The original reproducible source reports and results are in [Phase18](../phase18/), [Phase20](../phase20/) and [Phase21](../phase21/). Phase18 provides source SVG figures, Phase20/21 provide data and audit logs for the source-coverage figure.

The full package contains `main.tex`, `references.bib`, `main.bbl`, four PNGs under `figures/`, `highlights.txt`, a build README and a compiled PDF. Build with standard TeX Live `latexmk -pdf main.tex`.

## Submission boundaries

The recommended target is the *Journal of Systems and Software* special issue **Reliable and Trustworthy Automated Software Engineering** (provisional suitability assessment). If journal scope or requirements are revised, change the venue metadata without altering frozen measurements.

Only Li.Fi and Revest have accepted fixed-case external detector decisions (two incident families, three admitted known executions). Bacon and Rari contribute source-only activity and selected-transaction feasibility results, **not** two new complete attack detection validations. Phase21 code reports **256** Bacon proxy and **132** Rari fETH distinct selected transactions over their respective fixed 30-day windows, with 28/30 and 30/30 days under the necessary 20-transaction count. These are deterministic upper bounds on feature readiness under daily state resets.

No independent full 30-day token score/alert comparison for Bacon/Rari has been completed. No claims of overall detector superiority, prevention or exact incident recall are warranted.

Author must confirm competing interests, funding, use-of-AI declaration, corresponding-author address and required journal metadata before submission. **Do not submit without specific approval.**
