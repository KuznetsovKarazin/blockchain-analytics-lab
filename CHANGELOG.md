# Changelog

All result folders (`results/*/*_v1`) were produced by `scripts/run_all.sh` on a
clean tree; each `manifest.json` records the code commit, input digests and
package versions of its run.

## v0.1.2 (2026-10-25)

Metadata, testing and distribution; no script and no number changed.

* Figures (`results/*/*_v1/fig_*.png|eps|pdf`, 13 studies) are no longer
  distributed: they also appear in a book whose publisher holds the rights to
  its illustrations. Each script still writes its figure when run; the
  tables and metrics of each study stay in the CSV/JSON files of the same
  folder. Releases v0.1.0 and v0.1.1 contained them.
* Version strings agree: `CITATION.cff`, `pyproject.toml` and
  `bclab.__version__` all say 0.1.2 (they said 0.1.0 in the v0.1.1 release);
  `CITATION.cff` gains `date-released` and keywords; `.zenodo.json` added for
  the Zenodo archive.
* New `tests/test_bal_integration.py` and a CI job that installs the `bal`
  extra (blockchain-detector-eval pinned at dc1ba88, release v0.4.1) and runs
  the Elliptic path the studies use (`load_elliptic` → models →
  `threshold_at_val_f1`) on a tiny fixture. The helper tests do not cover it.
* README and new `results/LICENSE`: licence of code (MIT) and of
  documentation and results (CC BY 4.0) stated per folder, with the one
  result file that keeps its source's licence.

Scope of the tests: unit tests of the helpers and one integration path on
synthetic data. The studies themselves are reproduced by `run_all.sh` on the
real inputs (hours, tens of GB), not in CI.

## v0.1.1 (2026-10-24)

* D2 figure redrawn so that the legend does not cover bars. Numbers unchanged.

## v0.1.0 (2026-10-23)

* Final run of all studies (S1, S2, A1, A1b, D1, D2, P1–P4, M1, M2, F1, F1b,
  C1) on a clean tree, commit e7aed73, with blockchain-detector-eval v0.4.1.
