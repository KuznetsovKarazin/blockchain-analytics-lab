# Phase23 — cross-case tables and independent audit

Phase23 adds a read-only evidence-bound synthesis of Phase16, 18 and 22. It does not modify frozen experiments or companion dependencies.

- `build_phase23_tables.py` calls the bundled `verify_phase22_science_independent.py` to independently verify 252 Phase22 configurations, then creates the four tables in `results/` and cryptographic checksums in `audit_manifest.json`.
- `make_figures.py` generates reproducible PDF+PNG graphical presentations from the CSV output, without inventing observations.
- `results/attack_day_before_after.csv` separates selected transactions strictly before, at, and after the known incident on the date of execution.
- `results/primary_outcomes.csv` reports exact known-set matches and realized load for semantic and count baselines.
- `results/readiness_sensitivity.csv` assesses history requirements 1, 5, 10, 19 and 39 under original and alternative past-only state conventions.
- `results/alert_ledger.csv` records the 19 observed notifications at semantic rank 1/20, greedy B=5 in the six views; unknown-reference statuses are *not* negative labels.
- `results/audit_manifest.json` binds the outputs by SHA-256 and records 252 independent configuration rechecks.

**Reproduction:** provide the original archived Phase16 sealed evidence, phase18 replay and two Phase22 indexer ZIP packages at their established Project/Library identities, then run `build_phase23_tables.py --base <archived-input-dir> --out results`. Files are SHA-checked; no network data is needed. The full version-pinned chain data have not been rehosted into this Git directory.

Only Li.Fi, Revest, Bacon and Rari contribute distinct incident families; the three Rari component views share one known execution. Five known successful executions are available across four families, but all reference inventories remain known subsets, not exhaustive attack inventories.

The `--base` directory is an explicit archival staging directory, not a Git repository dependency: it must contain the original `Article2_Phase22_CompleteReplay.zip`, both `Article2_Phase22_IndexedFull_*.zip` files, `article2_work/phase18/results/full_replay_summary.json`, `article2_work/phase18/results/recomputed_transaction_decisions.jsonl` and `article2_work/sealed_evidence.zip`. The latter is the original 4.7 MB Phase16 evidence available in the public baseline. Private local paths are input-mapping examples, not necessary for running the scoring code. Never substitute missing source files with empty data.
