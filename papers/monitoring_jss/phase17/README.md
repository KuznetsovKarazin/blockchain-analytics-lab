# Phase 17 — applicability, initialization and construct validity

This branch starts from the unchanged frozen Phase16 commit `e720697bc3986dd291a7047c580cf973ae6e5567`.

The independent Phase17 diagnostic uses the published SHA-256-pinned `sealed_evidence.zip` (SHA-256: `56f19a262c36f5438d11d19cbb8434ea3dcb731b1cbdae34f479f667ec9997e2`). No new chain data, annotations or detector training are introduced.

## Preliminary verified score calculations

| Case | History | Eligible TX / selected TX | Raw rank 1/20 | Raw rank 1/10 |
|---|---|---:|---:|---:|
| Li.Fi | Daily reset | 0/280 | 0 | 0 |
| Li.Fi | 7-day retrospective | 20/280 | 0 | 2 |
| Li.Fi | Continuous in 30-day window | 59/280 | 2 | 3 |
| Revest | Daily reset | 24/194 | 0 | 2 |
| Revest | 7-day retrospective | 64/194 | 2 | 5 |
| Revest | Continuous in 30-day window | 71/194 | 1 | 5 |

The original daily-reset output was matched at the transaction/token-score level across all 474 case-specific records. No one of the three independently admitted executions becomes a rank 1/20 or 1/10 raw trigger under retrospective history.

The new history modes are *counterfactual score diagnostics*, not full replay of grouping and budget policies or estimates of delivered notifications. Additional triggers have unknown truth status, and the initial 30-day observation boundary is not a fully warmed pre-window state.

Li.Fi's approval-drain attack transferred assets from previously approving users. Gross external outflow measured at the monitored diamond core does not represent the relevant user-to-attacker transfer boundary. At the verified Li.Fi execution, 40 ERC20-shaped logs occurred in the full transaction, but only three involved the monitored core. The 2022 original investigator report should be used for mechanism attribution.

## Reproduce

Use `phase17_quickcheck.py` with the exact published `sealed_evidence.zip` from `papers/monitoring_jss/phase16/public_evidence/`. Requires Python 3.10+ only. The script verifies archive SHA-256, recreates day-reset and historical score statistics, confirms frozen daily output, and joins previously verified reference identities after the label-blind calculations.

Do not overwrite Phase16 outputs or run `scripts/run_all.sh`. Full source tables, an independent secondary crosscheck, figures, and manuscript revisions are separate artifacts, not yet included in this Git branch.
