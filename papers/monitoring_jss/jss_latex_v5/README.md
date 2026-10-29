# Article 2 — JSS research manuscript, V5 (29 October 2026)

This is the **current externally reviewed scientific draft**, not a claim that all journal submission gates are closed.

## Manuscript
- `main.tex` — Elsevier `elsarticle` source, 29-page locally compiled version.
- `references.bib` — 29 cited bibliographic records.
- `alerts_table.tex` — complete 19-row primary semantic notification ledger.
- `fig*.pdf` — original vector scientific figures; figure 3 includes deterministic display jitter and an external legend.
- `Article2_JSS_V5_Review.docx` — editable Word review export.

Run `pdflatex main.tex; bibtex8 main; pdflatex main.tex; pdflatex main.tex` in this directory. The GitHub workflow `article2_jss_v5_latex.yml` builds an independent PDF and verifies the published experimental artifacts.

## Scientific evidence

Pinned baseline: `e720697bc3986dd291a7047c580cf973ae6e5567`.
The original source/replay artifacts are publicly preserved in `../phase25/data`; independent cross-case calculations in `../phase23`; 12 **convenience-selected, not verified benign** control emitters and 720 contract-days in `../phase26/results`; ten exact AWS/indexer log-payload comparisons in `../phase27/results`.

Scientific claim: under the tested gross-token-outflow rank, a notification depends on boundary-aligned observations (A), strictly past token-specific history (B), extreme conditional rank (C), and grouping/budget admission (D). Neither A+B alone nor an exact alert on an exploit transaction proves mechanism-specific recognition.

Four retrospectively chosen incident families, five known successful executions, and overlapping Rari views; no attack-population recall, specificity, false-positive rate, live latency or prevention claim. Fourteen view-specific unadjudicated notifications correspond to twelve distinct transactions and are not classified as benign. Experimental input selection and development exposures are disclosed; further 10–20 incident independent validation is **planned**, not performed.

## Reproducibility and submission status

The old V4 data-availability pin `590ff604` predates public inputs. Use the pinned scientific evidence snapshot `78baeb5c83a931a9f3f85e56893391f94cd0699b` (and the final V5 manuscript commit once fixed), not a floating branch alone.

A separate clean offline reproduction bundle of the earlier accepted experiments exists; the public GitHub Phase25 workflow verified the source/replay member hashes and reproduced the four cross-case CSVs from a clean directory. This folder does not contain `__pycache__` files.

Before **submission** the author must resolve funding/competing-interest declarations, confirm the AI declaration, review Blockscout redistribution conditions, verify all bibliographic metadata, and decide whether four incidents suffice or a further prospectively selected cohort is required. No Zenodo DOI or publisher submission is claimed.
