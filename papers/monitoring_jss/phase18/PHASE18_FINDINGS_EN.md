# Article 2 — Phase 18: full replay of initialization ablations

**Status:** completed exploratory, read-only counterfactual replay (29 October 2026). The originally published Phase 16 decisions, labels, code, parameters, archives and companion pin have not been modified. No new blockchain source data, attack adjudications, live measurements or model training were performed.

## Research question

For the same fixed-core transactions, does retaining strictly prior token-outflow history for seven days or throughout the already captured 30-day window, instead of resetting at every UTC midnight, change (i) eligibility, (ii) raw rank-trigger incidence, (iii) grouped candidates and emitted alerts under frozen budget policies, and (iv) exact notifications of the admitted successful attack executions?

The tested initialization changes are **retrospective diagnostics proposed after the initial external-case findings became known**. They are not independent pre-registered validation, do not include pre-window history, and must not be presented as evidence of deployable warm-start benefit.

## Provenance and verification

- Exact public baseline: `KuznetsovKarazin/blockchain-analytics-lab`, commit `e720697bc3986dd291a7047c580cf973ae6e5567`.
- Input: `papers/monitoring_jss/phase16/public_evidence/sealed_evidence.zip`, 4,706,961 bytes, SHA-256 `56f19a262c36f5438d11d19cbb8434ea3dcb731b1cbdae34f479f667ec9997e2`.
- Cases: Li.Fi and Revest, 30 UTC days each, 280 and 194 case-specific selected core-emitter transactions; two independently verified incident families, three admitted execution transactions.
- Changed intervention: token-positive-outflow history only (`daily_reset`, `lookback_7d`, `cumulative_in_window`); all three modes use the same observation sequence and retain the original independent daily resets for grouping and the three notification policies. Historical lookback starts at the first available observation in each original 30-day window; nothing before the window is imputed.
- Fixed scoring: positive gross external core-sender outflow separated per token; 128 previous positive observations per token maximum; at least 19 strictly prior positive observations required; fraction `(1 + # prior amount >= current amount)/(n+1)`; thresholds 1/20 and 1/10.
- Fixed notification layer: grouping within 300 s of the last candidate; daily policies greedy, paced cumulative and token bucket; B=1,5,20 notifications per UTC day. Unlike a separate older development experiment, grouping anchors here are grouped *candidates*, not emitted alerts.
- Tests: exact equality with sealed daily-reset outputs for **948 method rows and 8,532 method–policy–budget decisions**, comparing per-token raw rank counts and scores, grouping, notification decisions, suppression reasons, quotas and token credits. No mismatches. Fourteen synthetic edge-case unit tests passed, including midnight resets, per-token history, equality at 7-day lookback boundary, 300-s grouping and hard caps. Label-free scoring and replay are completed before exact reference join.
- Study results: 108 case × initialization × rank × policy × budget configurations. The configurations reuse only two independent incident families, not 108 independent observations.

## Result A: traffic-conditioned applicability

| Fixed-core population | Li.Fi | Revest |
|---|---:|---:|
| Selected transactions (30 days) | 280 | 194 |
| Selected transactions with positive core outflow | 141 | 102 |
| Distinct token-days containing positive core outflow | 83 | 17 |
| Token-days with at least 20 positive core outflow observations | 0 | 1 |
| Maximum positive observations in any single token-day | 12 | 43 |
| Transactions with eligible token score under daily resets | 0 | 24 |
| Original raw rank 1/20 triggers | 0 | 0 |

The first eligible score requires the **20th positive observation of the same token on the same UTC day** (19 previous plus the current positive observation). A total daily transaction volume of 20 is not sufficient by itself: the observations must correspond to the same token, and only positive core-sender outflow observations enter history. If a token-day has `N` positive observations, it can contribute at most `max(0,N−19)` eligible token *scores* under this rule; the number of eligible transactions can be lower if a transaction contains multiple positive tokens. The verified Li.Fi population has no qualifying token-day. Revest has exactly one (23 March 2022), contributing 24 eligible token scores/transactions. This is a necessary condition and a directly measured applicability property, not a new anomaly-detection theorem.

## Result B: complete counterfactual notification replay

The following table uses the primary rank 1/20, greedy allocation and B=5. All policies and budgets are retained in `full_replay_cells.csv` and `full_replay_summary.json`.

| Case | History mode | Eligible selected TX | Raw triggers | Grouped candidates | Emitted notifications | Hits on admitted executions |
|---|---|---:|---:|---:|---:|---:|
| Li.Fi | Daily reset | 0/280 | 0 | 0 | 0 | 0/1 |
| Li.Fi | Trailing 7d (within original window) | 20/280 | 0 | 0 | 0 | 0/1 |
| Li.Fi | Continuous (within original window) | 59/280 | 2 | 2 | 2 | 0/1 |
| Revest | Daily reset | 24/194 | 0 | 0 | 0 | 0/2 |
| Revest | Trailing 7d (within original window) | 64/194 | 2 | 2 | 2 | 0/2 |
| Revest | Continuous (within original window) | 71/194 | 1 | 1 | 1 | 0/2 |

At rank 1/20, all candidate alerts in these three-history scenarios are emitted under every B and all three allocation policies, so budgets do not explain the external result. At the more permissive 1/10 threshold, some candidates are grouped or budget-restricted, but the exact reference hit counts remain zero for **all configurations**. For example, Li.Fi continuous 1/10 gives three raw candidates and three greedy notifications at B=5; Revest trailing 7d 1/10 gives five raw triggers, four grouped candidates and four greedy notifications at B=5. These additional notifications have **unknown reference status** and are not counted as false positives.

The 7-day and continuous policies need not yield monotonic raw-trigger totals, because their sets of prior comparison amounts differ; broader eligibility does not imply that a given conditional tail rank remains small. All reported effects are conditional on the fixed archive scope and no pre-window history.

## Result C: mechanism/feature correspondence

At the admitted Li.Fi execution, the fixed-core record contains 39 core-emitter logs, 92 all-emitter logs, 40 ERC-20-shaped logs, and only three ERC-20-shaped logs involving the selected core. Positive gross core-sender USDC and USDT outflows are represented in the score features (USDC incoming equals outgoing in raw units). The attack analysis attributes the main asset theft to an unchecked external call that executed `transferFrom` of tokens from previously approving **users**. A core-boundary gross-outflow rank cannot directly observe victim-to-attacker transfers that do not cross the monitored core. The mismatch persists even when Li.Fi's historical USDC rank can be calculated (54/56) under the cumulative mode; the value is not an extreme high outflow in that comparison history.

For the two admitted Revest executions, positive external outflows from the named vault are present, but the relevant tokens have no previous positive observations in the retained 30-day history. Their mechanism involves a reentrancy/FNFT-accounting process which a token magnitude rank does not directly model. The exact frozen stage reason is therefore history ineligibility; the broader *feature-construct* limitation differs by attack family. No new exploit-mechanism label was derived solely from token events.

## Scientific interpretation

The observed conditional dependence is:

1. **Observation feasibility** — are the relevant contracts and all required logs available at the declared archive tier?
2. **Feature applicability** — is the statistic mathematically evaluable from strictly past data for the relevant token?
3. **Construct alignment** — does the monitored boundary carry an event corresponding to the attack mechanism?
4. **Trigger and dispatch** — is the score extreme enough and can its candidate pass grouping and notification allocation?

The completed intervention provides an unfavorable test for a simple explanation that 'more historical state' by itself would repair externally observed missed notifications. It does **not** establish that no other state representation, longer pre-window history, semantic feature, or policy could improve detection. Two selected incident families cannot support a general performance claim, significance test, or FPR/precision estimate.

## Software engineering implications

Before setting a quantile-like rank threshold, deployers should audit positive-observation rates at the same token granularity as the score. The `min_history=19` configuration is non-operative if no token-day reaches 20 qualifying observations. This check is label-free and can be performed before costly primary incident adjudication. Once sufficiently scored, a score must still represent the security-relevant operation: core-sender outflow magnitude is not a substitute for a whole-transaction approval-drain trace or state-invariant change. Only after these checks is it meaningful to optimize grouping and alert budgets.

## Limits and next independent validation

The study does not cover all protocol-owned contracts, historical receipts or all past-chain state, uses retrospective incident-informed nominations, and relies on known subsets of verified executions. Results are conditional on available archive subsets and original labels. Further work requires a separately frozen external case-selection protocol, verifiable primary execution references, historical core nominations, and complete source observations. New cases must not be chosen after inspecting results of the current rank method. The next planned extension uses the earlier bounded 13-case frame plus a version-pinned third-party exploit catalogue, but all new entries remain screening candidates until provenance and feasibility checks are completed.

## Reproduce without rerunning the frozen detector

```sh
python initialization_full_replay.py --evidence-zip sealed_evidence.zip --out results
python -m unittest -v test_initialization_full_replay.py
python make_phase18_figures.py --evidence-zip sealed_evidence.zip --results results --out results
```

No network, shell rebuild or raw-source download is required. Do **not** run `scripts/run_all.sh`. The independently frozen Phase16 inputs and companion pin remain unchanged. This is an exact replay of the existing observations under the stated intervention, not new on-chain measurement.
