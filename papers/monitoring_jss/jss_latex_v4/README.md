# Article 2 — Elsevier `elsarticle` V4 working submission project

Paper: *When Can a Blockchain Monitor Trigger? An Audited Study of Feature Readiness, Historical Initialization, and Known-Execution Coverage*.

**Editorial status:** compiled and independently data-checked **research draft** for Journal of Systems and Software; **not submitted**, not a completed JSS acceptance readiness assessment. No new performance superiority, incident-wide recall, precision or prevention is claimed.

The current LaTeX project has flat-file dependencies:
- `main.tex` — full English manuscript, tables and methodological limitations;
- `references.bib` — 29 actually cited bibliography records;
- `alerts_table.tex` — event-level 19-alert appendix;
- `fig1_attack_time_selected.pdf`, `fig2_history_eligibility_six_views.pdf`, `fig3_incident_relative_alerts.pdf` — vector figures.

With TeX Live and the `elsarticle` class available, build in the same directory:

```bash
pdflatex -interaction=nonstopmode -halt-on-error main.tex
bibtex main              # `bibtex8 main` is an alternative
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error main.tex
```

The research data and all code-derived tables are under `../phase23/`. Rebuild using `phase23/build_phase23_tables.py` with the separately preserved and SHA-256-bound Phase16, Phase18 and Phase22 research archives; those original source archives are *not* reproduced here. Chart creation uses `phase23/make_figures.py` and the generated CSV files. The new branch is separate from the original sealed `paper/monitoring-jss` at `e720697bc3986dd291a7047c580cf973ae6e5567`; new experimental results remain retrospective diagnostics.

**Required before submission:** verify author funding/COI/AI-assistance declarations, corresponding author details, final rights/licences, journal metadata and stable artifact citation. Future expanded prospective external validation is still desirable; no such experiments have been completed within this package.

A convenience, editable **Word review copy** is provided as `Article2_V4_review.docx`. The LaTeX files remain authoritative for Elsevier submission.
