# Article 2 — JSS LaTeX V6 (research-complete edition)

**Title:** When Can a Blockchain Monitor Make a Decision? Source-Audited Feature Readiness, Historical State, and Exact-Execution Evidence

**Target:** Journal of Systems and Software (Elsevier); prospective special issue *Reliable and Trustworthy Automated Software Engineering* (RASE).

This directory contains a self-contained Elsevier `elsarticle` manuscript source. It includes the LaTeX entrypoint (`main.tex`), `references.bib`, two included LaTeX tables, and four vector PDF figures. A CI-compiled `main.pdf` is part of the verified build artifact and is published separately after build QA.

## Build

From this directory, on TeX Live with `elsarticle`, `lmodern`, `bibtex8` and standard LaTeX math/graphics packages:

```bash
pdflatex -interaction=nonstopmode -halt-on-error main.tex
bibtex8 main
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdfinfo main.pdf | grep Pages
```

The corresponding GitHub Actions build checks undefined bibliography references. Do not substitute a PDF screenshot for vector figures.

## Exact research data and reproducibility

The earlier permanently frozen Phase16 commit is `e720697bc3986dd291a7047c580cf973ae6e5567`. The full public source for Phase16–30—including the original signed/range-bound source index, the 4-case exposed evaluation, the nonrandom 16-case source readiness frame and seven follow-up fixed-emitter replay streams—is in this repository.

Run the **independent reimplementation** of the seven-stream rank/count policy outcomes, from the repo root:

```bash
python papers/monitoring_jss/phase30/independent_policy_audit.py --out /tmp/independent_policy_results.json
```

Expected: `PASS`, **7 source-linked case streams**, **525 unique selected transactions**, **441/441 fixed configurations**. This is a strict check on rank, group and budget calculations; it is not a scientific independent incident-level recall estimate.

The phase28 source census contains 16 fixed candidate emitters, 480 emitter-days and 44,780 selected transactions. Those are NOT 16 independently scored incidents. The seven subsequent replay streams were nonrandomly selected and all reference inventories are incomplete. The 12 comparison-contract emitters are not independently certified benign, and their z-score/MAD/EWMA readiness concerns **core event counts per selected transaction**, not ERC20 token-flow scores.

- `phase26/CONTROL_REGISTRY.json` and `phase26/results/` — comparison-contract readiness.
- `phase28/CANDIDATE_FRAME.json`, `phase28/results/` — prespecified source measurement nominations.
- `phase29/data`, `phase29/indexed`, `phase29/results` — four complete source-audited nominal cores, source-linked indexed data and replay.
- `phase30/data`, `phase30/indexed`, `phase30/results` — three additional cases from the frozen phase28 frame.
- `phase29/REFERENCE_ROLE_LEDGER.json` — incomplete attack-execution inventory, candidate roles and independent sources.

**Important source tier:** selected original transaction identities and emitter counts were acquired and audited from AWS historical Ethereum Parquet. The contents (`topics`/`data`) and successful statuses of selected bundles were obtained from Blockscout and cross-checked against original source identity/number-of-logs; they are not authenticated as historical Ethereum receipt roots. Some targeted source event-bundle checks were performed for earlier cases.

## Submission readiness

This is a completed, technically compiled **research manuscript edition**, not an unconditional authorization for journal submission. The following require author sign-off before submitting:

1. Confirm funding grant(s) that *actually supported this research*, precise contract IDs, or declare none.
2. Confirm competing interests declaration.
3. Approve the exact generative-AI tools and corresponding Elsevier disclosure wording.
4. Complete final bibliography, source provider licensing and editorial checks.
5. Create a Zenodo DOI only after selecting the final verified public release; no DOI should be fabricated.

The proposed release tag `article2-jss-v6-2026-10-29` must be checked against the actual published git commit before citing the repository as frozen.

**No security prevention, full exploit recall, calibrated FPR, zero-day or operational alert latency claim is made.** A count alert matching a known execution is not a proven preventive signal; unadjudicated alerts are not false positives.

The companion source archive and final build logs are verified by GitHub Actions after the release commit.
