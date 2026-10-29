# Applicability Limits of History-Dependent Blockchain Monitoring: Observation, Initialization, and Attack Semantics

**Oleksandr Kuznetsov**  
Department of Theoretical and Applied Sciences, eCampus University, Italy  
Department of Intelligent Software Systems and Technologies, School of Computer Science and Artificial Intelligence, V. N. Karazin Kharkiv National University, Ukraine  
ORCID: https://orcid.org/0000-0003-2331-6326

*Research manuscript V3 — 29 October 2026. Preserves the frozen Phase 16 external evaluation and Phase 18 exploratory history replay; adds the independently audited Phase 20 source-only feasibility bound for two further prospective components. Not submitted; prior versions unchanged.*

## Abstract

History-dependent rules are often evaluated by the notifications they produce, although such a rule may be unable to compute a valid score for much of the observed traffic. We examine this problem in Ethereum monitoring using two retrospectively selected DeFi incident families, Li.Fi and Revest. Their fixed-core observation windows contain 280 and 194 case-specific transactions over 30 UTC days each, with three independently verified successful exploit executions in the retained known reference subsets. The evaluated token-outflow rank rule requires 19 strictly preceding positive observations of the same token; the primary rank threshold is 1/20. Under daily state resets, no Li.Fi transaction and only 24 Revest transactions satisfy the history requirement, while neither population produces a primary rank trigger. We then independently replay the same observations with seven-day and within-window cumulative token histories, holding grouping and notification policies constant. Eligibility rises to 59/280 and 71/194 under cumulative histories; two and one primary-rank notifications are emitted, respectively. None coincides with an admitted exploit execution. Mechanism review additionally shows that gross outflows from the monitored Li.Fi core do not directly characterize the user-to-attacker transfers that enabled the approval-drain exploit. A separate source-only audit finds fewer than 20 core logs on 15/30 Bacon proxy days and 26/30 Rari fETH days; no further incident outcomes are inferred. These observations separate feature computability, mechanism coverage and notification allocation. The study offers a reproducible applicability audit, not a claim of detector superiority or population-level incident recall.

**Keywords:** blockchain monitoring; decentralized finance; streaming anomaly detection; feature applicability; cold start; token outflow; observational validity; historical replay; reproducibility.

## 1. Introduction

An operational blockchain monitor consists of more than a rule that returns an anomaly score. It must determine which on-chain actions are observable, extract relevant features, establish any required historical state, form candidates, and decide which notifications to emit. A score can be mathematically undefined at the moment of a security-relevant transaction even when its raw event logs are available. In such a case, changing an alert budget or a rank threshold cannot repair the missing input. Conversely, a larger historical reference set need not make the feature appropriate for the attack mechanism.

These distinctions are particularly important in decentralized finance (DeFi), where the transaction of interest may involve entrypoints, vaults, tokens, routers and accounts outside the selected monitoring boundary. A token transfer observed at one contract is not automatically the movement that constitutes the exploit. Earlier security evaluations have emphasized faithful task definitions, temporal and dataset validity, and the limits of incomplete observations (Sommer and Paxson, 2010; Arp et al., 2022). At the same time, systems such as DeFiRanger and HOUSTON use richer transaction or protocol semantics than the simple count and outflow-rank rules examined here. The present work does not attempt to replace these systems.

The original fixed-method study compared a count-based activity rule with a token-specific high-outflow rank rule under equal offered daily notification budgets. Its adverse external results were: a verified Li.Fi execution was notified by the count rule but not by the semantic rule, while neither rule notified either admitted Revest execution. The immediate reason for all three semantic losses was insufficient positive same-token history within the current UTC day. However, this execution-level explanation did not establish whether the rank method could ever operate on the broader population, whether historical initialization would restore its practical coverage, or whether it measured a relevant flow in each attack.

We address these questions without modifying the original decisions or independently adjudicated reference set. The Phase 17 diagnostics first recomputed score availability for every selected transaction without using attack labels. Phase 18 then repeated the *complete* grouping and budget-allocation calculation under two additional historical retention policies. Both additional history modes are explicitly retrospective interventions designed after the initial external outcomes became known, rather than independent prospective tests.

The article asks three questions:

**RQ1 — Applicability.** For the monitored fixed-core traffic, what fraction of transactions can satisfy the minimum positive token-history condition, and how is that condition constrained by the number of positive observations of each token within a UTC day?

**RQ2 — Initialization and notification.** If only token history retention changes while scoring thresholds, candidate grouping and notification budgets remain fixed, how do eligibility, raw triggers, actually emitted alerts and exact known-execution matches change?

**RQ3 — Construct validity.** Does the core-boundary token-outflow magnitude feature represent the transfer or state transition that constitutes the independently documented attack mechanism?

The contributions are an explicitly reproducible label-free applicability audit, an exact replay-based diagnostic of initialization with matched notification policies, and a source-grounded mechanism assessment. Each contribution is conditional on two case-specific fixed-core populations. We do not claim a new anomaly-detection algorithm, universal superiority, statistical significance or prevention.

## 2. Related work and positioning

**Attack detection and transactional semantics.** TXSPECTOR uses transaction-replay dependency analysis to identify exploit patterns; EtherClue studies forensic indicators on Ethereum. DeFiRanger identifies higher-level DeFi actions from transaction cash flows and applies patterns for price-manipulation attacks (Zhang et al., 2020; Aquilina et al., 2021; DeFiRanger, 2024). These methods demonstrate that relevant attack semantics cannot generally be inferred from a single arbitrary monitored address. HOUSTON constructs DeFi protocol-level anomaly models using control-flow information and likely data invariants and evaluates them on a much larger incident corpus (Meng et al., 2026). Our work evaluates a much narrower phenomenon: whether a fixed rule is even computable on its declared monitoring boundary, and how that limitation appears in actual notification output.

**Protocol and cross-chain monitoring.** XChainWatcher uses logic-driven event monitoring for cross-chain bridges; BridgeGuard learns graph-based representations for cross-chain attack detection (Augusto et al., 2025; Wu et al., 2025). Their datasets, features and objectives differ from our fixed Ethereum core-emitter replay. We do not compare their published classification numbers with our known-subset notification fractions. Their approaches are relevant because they make explicit which transaction relationships and semantic entities are needed to represent an attack.

**Evaluation under incomplete and delayed evidence.** Sommer and Paxson (2010) and Arp et al. (2022) explain why operational security detection needs realistic population definitions and careful interpretation of evaluation measures. The Numenta Anomaly Benchmark addresses streaming anomaly timing and practical scoring criteria (Lavin and Ahmad, 2015), but is not a benchmark for DeFi protocol exploits. The DeFi attack systematization by Zhou et al. (2023) provides a mechanism taxonomy, while the versioned DeFiHackLabs catalogue supplies a screening source of reproductions and attack references. A PoC is not itself proof that a particular real-chain execution, monitored core identity or 30-day archived population is admissible for this study.

**Scope of the contribution.** The rank formula, set-inclusion coverage bounds and standard alert-budget policies are not new. The useful empirical quantity is *measured feature applicability* under a transparent history-and-observation contract. By separating applicability from the subsequent notification decisions and from the exploit mechanism, this study identifies what can and cannot be inferred from an adverse detector result. The inference is limited to the retained historical populations.

## 3. Observation and decision model

### 3.1. Fixed-core selected transactions

For case \(c\), let \(S_c\) be the ordered transactions selected because at least one event log was emitted by one of its prespecified core addresses. All event logs in each selected transaction are retained for a transaction-level observation, including those emitted by other addresses. The fixed-core address list is a declared *observation boundary*, not a proof that every protocol-owned contract, execution path or economically relevant account has been included.

The observations contain a transaction identity, successful execution metadata, core-emitter event counts and ERC-20-shaped transfer events. These events are syntactically decoded from archived logs; token compliance, exact account balances, economic loss and authenticated receipt-root completeness are not independently established. `external_out_raw` is the **gross** integer amount reported by transfer-shaped events leaving the nominated core for addresses outside the core set. It is token-specific and is not netted against incoming amounts. Token denominations must not be added without explicit conversion and token-decimal data.

The analyses use only records with verified source membership under the previously accepted archive tier. Missing required partitions cannot be treated as zero events. All timestamps in the scoring and policy replay are logical block event times, not live observation, delivery or response times.

### 3.2. Rank rule and history feasibility

For token \(k\) and selected transaction \(i\) with positive raw core outflow \(x_{i,k}>0\), let \(H_{i,k}\) be the list of strictly earlier positive amounts for that token, truncated to the most recent 128 qualifying observations. Define the conditional rank fraction

\[
q_{i,k}=\frac{1+\sum_{h\in H_{i,k}}\mathbf{1}(h\ge x_{i,k})}{|H_{i,k}|+1}.
\]

The score is *eligible* when \(|H_{i,k}|\ge 19\). A transaction generates a raw semantic trigger if at least one eligible token has \(q_{i,k}\le 1/20\). The descriptive sensitivity threshold is \(1/10\). The fraction is not a calibrated transaction-level p-value or an estimate of false-alert probability. At the minimum history length of 19, satisfying the 1/20 rule requires the current positive amount to be strictly greater than every retained earlier amount of that token.

For a token and UTC day \((k,d)\), denote by \(N_{k,d}\) the number of selected transactions with positive gross external outflow for that token. With an independent midnight history reset, the first 19 such observations cannot be eligible. Therefore a necessary condition for even one eligible score is \(N_{k,d}\ge 20\), and the number of eligible *token scores* within a token-day is \(\max(0,N_{k,d}-19)\). Eligible *transaction* counts may be smaller than the sum over tokens because one transaction may carry multiple token scores. There is no universal threshold in ordinary transactions per day: only same-token positive outflows count.

### 3.3. Isolation of initialization

We evaluate three history policies over the *same* already captured 30-day case window:

1. **Independent UTC-day reset.** All token histories are empty at each midnight. This is the originally frozen external experiment.
2. **Trailing seven days.** At each transaction retain strictly earlier qualifying amounts in the preceding seven 24-hour periods, subject to the capacity of 128 observations per token.
3. **Cumulative within-window history.** Retain up to 128 qualifying observations per token since the first captured transaction in the 30-day window.

These definitions are retrospective score-state interventions. Neither additional mode imports data from before the retained case window, so neither demonstrates performance under a genuinely mature production monitor. The same chronological transaction order, positive-flow extraction, rank definition, thresholds, 300-second grouping interval and day-by-day notification-policy state are maintained. Importantly, **grouping and notification budgets still reset each UTC day in every mode**. Only token history retention changes.

### 3.4. Candidate formation and notification policies

A raw semantic trigger is suppressed by grouping if another candidate of the same method occurred less than 300 seconds earlier. The grouping anchor is the last *candidate*, not the last emitted notification. It is independent of which budget policy subsequently admits the candidate. The frozen count comparator uses at least ten core logs in the last 60 seconds after the current transaction, and bypasses token history eligibility.

Three policies are compared under each offered daily limit \(B\in\{1,5,20\}\): greedy admission until the limit is exhausted, cumulative pacing of the day's allowance, and a one-token-capacity token bucket replenished at the specified daily rate, additionally subject to the same hard cap. Rejected candidates are not queued. Exact input order and integer event-time arithmetic are retained; the same offered budget may produce different realized alert counts.

In total, three history modes, two rank thresholds, three allocation policies and three budgets yield 54 semantic configurations *per case*, or 108 across two cases. These are deterministic alternative computations on the same cases, not 108 independent experiments. Counts from the original fixed count comparator are retained as an external descriptive baseline.

### 3.5. Exact known-execution references

For each case, a bounded incident-reference inventory includes exact transaction identities whose unauthorized execution and role were independently reviewed. Li.Fi contributes one admitted execution; Revest contributes two. Both inventories are explicitly known subsets, not proven complete lists. Some additional exact candidates have unresolved roles and are not silently classified as benign or as attacks. A known execution receives notification credit only when its **exact** transaction is emitted; a nearby alert is not a substitute. This defines the descriptive conditional coverage measure and does not measure comprehensive incident recall or precision.

The original external-case decisions were sealed before new primary-incident reference retrieval. The history modifications examined here were designed *after those baseline outcomes were known*. We therefore separate verification of the original frozen outputs from exploratory interpretation of the new interventions.

## 4. Materials, execution and verification

### 4.1. Cases and fixed observations

The historical fixed-core cohort comprises the Li.Fi entrypoint in 19 February–20 March 2022 and the Revest entrypoint/vault pair in 26 February–27 March 2022. Both use Ethereum mainnet and full consecutive UTC days, ending after the relevant incident. The resulting 60 case-days overlap across 37 distinct calendar dates. The 280 Li.Fi and 194 Revest selected transaction counts are case-specific and are not automatically 474 unique transactions between cases. Component nominations were retrospective and informed by incident documentation.

**Table 1. Case-specific selected observations.**

| Measure | Li.Fi | Revest |
|:---|---:|---:|
| UTC study days | 30 | 30 |
| Nominated monitored core addresses | 1 | 2 |
| Selected case-specific transactions | 280 | 194 |
| Selected transactions with positive core outflow | 141 | 102 |
| Verified admitted successful executions | 1 | 2 |
| Reference completeness | Known subset only | Known subset only |
| Token-days with positive core outflows | 83 | 17 |

### 4.2. Reproduction and independent controls

The full record is bound to the published Phase 16 evidence archive by SHA-256. For the new analysis, each case's 30 daily observation files is read once; label-free histories, ranks, triggers, grouping and budgets are recomputed. Only after these computations and their checks are complete are the three previously admitted reference identities joined for exact-notification accounting.

The independent replay matches **948 original semantic method rows and 8,532 original semantic admission rows** for the daily-reset mode. Checks include chronological identity, every retained positive token score, eligible status, raw trigger, grouping reason, notification decision, suppression reason, integer quota and token-credit state. There are no mismatches. An additional 14 synthetic unit tests cover boundary and state-machine invariants. The derived full-replay table has 108 rows, and all counterfactual score results reproduce the earlier read-only Phase 17 diagnostic counts. None of these checks reacquires Ethereum source bodies, reruns the original trained models or verifies all primary-report claims afresh.

The original published baseline is commit `e720697bc3986dd291a7047c580cf973ae6e5567` in `KuznetsovKarazin/blockchain-analytics-lab`. The exact history/intervention code, compact tables and verification commands are maintained as a separate Phase 18 artifact; this draft must not imply that any optional later public release already exists unless it is independently confirmed.

## 5. Results

### 5.1. Population-wide eligibility before reading attack labels

**Table 2. Token-day feasibility under the frozen daily reset.**

| Measure | Li.Fi | Revest |
|:---|---:|---:|
| Token-days containing positive core outflow | 83 | 17 |
| Maximum same-token positive observations in a day | 12 | 43 |
| Token-days reaching the necessary 20 observations | 0 | 1 |
| Score-eligible selected transactions | 0/280 | 24/194 |
| Raw triggers at rank 1/20 | 0 | 0 |
| Raw triggers at rank 1/10 | 0 | 2 |

Figure 1 displays each token-day's positive-outflow count against the necessary 20-observation level. None of Li.Fi's 83 active token-days reaches that level. Revest has one eligible token-day, on 23 March 2022, with 43 qualifying observations and 24 eligible scores. Nonetheless, none of its eligible scores meets the primary 1/20 threshold. This result is obtained without using incident labels: for these populations, the main rank detector is non-operative under daily reset over the entire retained windows, not merely on the known exploit executions.

![Figure 1. Positive same-token core outflow observations per UTC token-day. The dashed line marks the first possible eligible score under min_history = 19.](phase18_results/fig1_token_day_gate.svg)

### 5.2. Historical retention raises applicability but not admitted-execution hits

**Table 3. Full replay, primary rank 1/20, greedy policy, B=5 notifications per UTC day.**

| Case | Token-history mode | Eligible selected TX | Raw triggers | Grouped candidates | Emitted alerts | Exact admitted-execution hits |
|:---|:---|---:|---:|---:|---:|---:|
| Li.Fi | Daily reset | 0/280 | 0 | 0 | 0 | 0/1 |
| Li.Fi | Trailing seven days | 20/280 | 0 | 0 | 0 | 0/1 |
| Li.Fi | Cumulative within window | 59/280 | 2 | 2 | 2 | 0/1 |
| Revest | Daily reset | 24/194 | 0 | 0 | 0 | 0/2 |
| Revest | Trailing seven days | 64/194 | 2 | 2 | 2 | 0/2 |
| Revest | Cumulative within window | 71/194 | 1 | 1 | 1 | 0/2 |

Eligibility improves under retained history in both cases (Figure 2). Yet the additional eligible observations do not yield a notification on any admitted execution. At the primary 1/20 threshold, all raw triggers in the new modes survive grouping and admission for all three budget policies and tested values of B, so offered budget is not the binding cause of the absence of admitted hits. Figure 3 distinguishes raw triggers and emitted alerts for the primary configuration.

![Figure 2. Fraction of selected core transactions with at least one rank-eligible token under three initialization modes.](phase18_results/fig2_history_eligibility.svg)

![Figure 3. Primary rank 1/20 raw triggers and emitted notifications under greedy B=5. No emitted notification matches an admitted execution.](phase18_results/fig3_raw_vs_notifications.svg)

At the sensitivity threshold 1/10, the cumulative mode produces three raw Li.Fi candidates and five raw Revest triggers (four after grouping), compared with none and two under daily reset, respectively. With greedy B=5, all three and four candidates are emitted. Some B=1 or token-bucket cells suppress additional candidates; their numerical outcomes are preserved in the full 108-cell report. **Every admitted-execution hit count remains zero for the semantic rule across all history modes, thresholds, policies and budgets.** Extra alerts are not independently adjudicated, and they cannot be called false positives. Lower-tail frequency or global precision cannot be estimated here.

The relationship is not monotone: Revest has two 1/20 raw triggers under seven-day retention but only one under cumulative retention. As the comparison reference set changes, the conditional fraction can increase or decrease even while more transactions become eligible. Increasing historical availability and increasing anomaly extremeness are different operations.

### 5.3. Exact reference analysis and mechanism alignment

**Table 4. Admitted execution traces and cumulative within-window rank diagnostics.**

| Verified execution | Core logs | All logs | Monitored ERC-20-shaped / all ERC-20-shaped logs | Token prior history, rank | Count baseline raw trigger |
|:---|---:|---:|:---|:---|:---|
| Li.Fi `4b4143cb…` | 39 | 92 | 3/40 | USDC: 55, 54/56; USDT: 38, 36/39 | Yes |
| Revest `e0b0c267…` | 7 | 33 | 5/14 | RENA: 0, 1/1 | No |
| Revest `19b10c6d…` | 7 | 26 | 4/7 | ECO: 0, 1/1 | No |

Under the original daily reset, the corresponding reference histories were [1,0] for the two Li.Fi tokens and [0] for each Revest token. The original reference losses are thus correctly recorded as *history-ineligible*. However, history ineligibility is the proximate stage reason, not the complete account of whether the feature is appropriate for the attack.

For Li.Fi, the project post-mortem and investigator analysis describe an unchecked external call that allowed calls to `transferFrom` on users' previously approved tokens. Such victim-to-attacker transfers do not necessarily leave the fixed monitored diamond address. The core-boundary flow feature recorded positive gross USDC and USDT outflows, but only three of the 40 transaction-level ERC-20-shaped logs concerned that core. For USDC, the recorded gross incoming and outgoing amounts were equal in raw units, meaning this feature observed a core transit rather than a net core drain. The larger retained comparison history makes both rank values computable, but they do not show extreme high outflow on the core. It is therefore unjustified to interpret this rank as measuring the asset movement that constitutes an approval-drain attack.

For Revest, the positive vault-boundary outflow is more closely connected to the attacked assets, but the referenced RENA and ECO tokens have no previous positive-outflow observations in the captured window. Their rank statistic cannot be meaningfully formed under the fixed minimum-history rule. The incident's reported reentrancy/FNFT accounting mechanism is also more specific than a single raw transfer-magnitude statistic. We do not infer transaction-level call graphs or reentrancy directly from transfer-shaped event logs.

### 5.4. Count baseline and the role of budgets

The original count-based rule generated one raw trigger in Li.Fi's selected 30-day population; that transaction was the one admitted execution, which contained 39 core-emitter logs. The rule emitted one notification under all three primary B=5 policies. This is a factual single-case success, not an externally established precision or false-positive rate. Revest's count rule produced four raw triggers, two grouped candidates and two notifications whose reference status remains unknown; neither admitted Revest execution reached the ten-core-log condition (seven logs each).

The comparison therefore exposes the important role of **feature and activity definition**: in one case, an unusual core-emitter log burst marked a verified execution that the core-outflow rank did not detect, but there is no evidence that a log-count rule would reliably detect other attack families. We cannot conclude that token ranks are universally inferior to counts. Budgets and allocation policies are meaningful operational controls, but they are not responsible for the 1/20 semantic results in these two lightly alerting external populations. Their stronger development-study effects are not combined with the two independent external families.

### 5.5. Source-only applicability bound on two further prospective components

Following the initial, exposed Li.Fi/Revest findings, we screened two additional Ethereum cases, **Bacon Protocol** (5 March 2022) and **Rari Fuse Pool 127** (30 April 2022), for source availability and component-level traffic. These cases were *not* admitted to the primary detection-performance cohort. Their historical proxy or pool addresses were selected using previously available incident reports; the resulting address-nomination procedure is retrospective and incident-informed. The audit itself used no detector scores or reference labels and was specified before reading the new 60-day address-column data.

For a fixed monitored emitter \(C\) on UTC day \(d\), let \(L_{C,d}\) denote its number of emitted log rows and \(T_{C,d}\) the number of transactions selected by those logs. Because each selected transaction emits at least one core log, \(T_{C,d}\leq L_{C,d}\). The studied rank rule adds at most one positive history observation per token per selected transaction. Therefore, \(L_{C,d}<20\) is sufficient to establish that no selected transaction can have the 19 strictly prior same-token positive observations required for an eligible rank. A day with at least 20 emitted core logs remains **indeterminate**: those logs may belong to fewer transactions, may not represent positive core-sender outflows, or may belong to different tokens.

The separate source audit enumerated the complete set of 60 daily Ethereum *logs* Parquet partitions for these two fixed historical windows and read every original address column chunk with checked HTTP byte ranges and source ETags. It covered 120,747,757 archived log rows from 13.50 GB of declared original logs objects using 306 range requests and 381,260,575 downloaded bytes. These quantities measure the source-check workload, not live monitor throughput. The detailed daily counters and source provenance are retained in the [Phase 20 source audit](https://github.com/KuznetsovKarazin/blockchain-analytics-lab/blob/research/monitoring-applicability-20261029/papers/monitoring_jss/phase20/PHASE20_SOURCE_AUDIT_FINDINGS.md).

| Proposed fixed emitter | Core log rows over 30 days | Median core logs per UTC day | Days with fewer than 20 core logs | Days not ruled out by this necessary test |
|---|---:|---:|---:|---:|
| Bacon proxy | 746 | 19 | 15/30 | 15/30 |
| Rari Pool 127 fETH | 331 | 8.5 | 26/30 | 4/30 |
| Rari Pool 127 fUSDC (separate view) | 426 | 5 | 25/30 | 5/30 |
| Rari Pool 127 Comptroller (separate view) | 146 | 3.5 | 29/30 | 1/30 |

For the nominated Bacon proxy and fETH emitters separately, daily reset renders the studied rank rule mathematically inapplicable on at least 50.0% and 86.7% of the respective windows. The fUSDC and Comptroller are alternate descriptive emitter views; the three Rari addresses have **not** been combined into a tuned or fully validated protocol-wide core. The calculation gives a lower bound on inapplicable *days*, not an exact transaction-level eligibility rate or incident-detection recall.

As a separate post-reference provenance check, the known exploit transaction of each candidate was found in the original AWS logs. The exact all-emitter log counts were 18 for Bacon and 65 for Rari, matching an independently queried Blockscout index. This check uses only the attack transaction's block and does not establish completeness of each 30-day selected transaction stream. No new primary semantic rank, grouped alert or known-attack notification comparison was computed for Bacon or Rari.

## 6. Discussion

### 6.1. Test applicability before estimating security performance

The most transferable operational recommendation is a **label-free pre-evaluation check** at the granularity of the required feature. A history-dependent monitor can have its threshold and alert budget configured, run cleanly, and produce precise-looking reporting tables while being mathematically unable to generate an eligible score in nearly all of its traffic. In this design, at least 20 positive same-token core-outflow observations within a day are needed before any daily rank-1/20 decision becomes possible. For the Li.Fi core, this requirement is never reached. For Revest, it is reached for one token-day only. Monitoring developers should record eligibility rate, conditional score coverage and score distribution separately from final notification counts.

### 6.2. Initialization and feature semantics are distinct failure modes

A historical retention policy makes the current score mathematically defined more often. It does not change the monitored addresses, introduce transaction-call semantics, or turn core-boundary transfers into user-to-attacker transfers. In the observed Li.Fi case, the core-outflow rank is not aligned with the approval-drain path; for Revest, the attacked tokens remain unseen in previous positive-outflow history even under the within-window cumulative intervention. These are different barriers to recovering a specific known execution. No strong causal generalization is possible from the two incident families, but the measurements establish why tuning the existing threshold and alert cap alone is not a sufficient corrective action.

### 6.3. A defensible next evaluation

To assess transferability beyond these exploratory cases, a future study must freeze a new independent sample and a new observation contract before viewing its detector outputs. A possible catalogue source is the version-pinned DeFiHackLabs repository, checked against a separate primary incident source and exact successful transaction identity. Its PoCs provide candidates, not accepted real-chain labels. Existing development cases and the current Li.Fi/Revest examples cannot be relabeled as fresh external validation. A practical first wave is several Ethereum incidents with diverse attack mechanisms and complete case histories; expansion toward a larger sample is justified only if provenance and availability audits succeed. The separate screening protocol specifies the admission gates and requires reporting unresolved or unavailable cases.

## 7. Threats to validity

**Case and reference selection.** Only two retrospectively selected incident families are available; the windows overlap, the core sets were nominated with incident knowledge, and the exact reference inventories are known subsets. None of the many policy cells constitutes an additional independent exploit. Unknown notifications cannot be used as negatives. Findings therefore describe the known-execution behavior of these fixed workloads, not a population recall or false-positive rate.

**Source and construct completeness.** The archived tier confirms selected-core membership and relevant transaction log bundles under enumerated partitions, but does not prove universal full-chain completeness or all relevant deployed/facet/attacker contract behavior. A token Transfer-shaped event is a syntactic indicator, not a verified economic balance delta. Monitoring the core alone can omit the actual exploited transfer route.

**Temporal and intervention validity.** Initialization interventions were chosen after the original external outcomes were known. Even the cumulative history begins at the first retained observation of the 30-day window; earlier potentially relevant history is unavailable. The analyzed time is the transaction's block event time, not historical arrival or live-alert latency. A fully warmed deployed monitor, different address boundary, alternative token feature, or earlier state could behave differently. The study does not evaluate stopping an atomic transaction or preventing losses.

**Prospective-case screening boundary.** The additional Bacon/Rari observations measure original core-emitter log counts, not positive token-flow histories, and do not verify exhaustive core nomination, complete execution inventories or alert performance. The after-the-fact candidate choice may introduce selection bias. We therefore do not count the two candidate protocols as external detection-validation cases.

**Reproducibility boundary.** Exact equality with already sealed replay decisions and independent synthetic checks confirms the stated computation, not the truth or completeness of all historical third-party narratives. The existing two incidents are adequate for a reproducible failure case but insufficient for a predictive generalization or JSS-level performance claim about DeFi-wide attack detection.

## 8. Conclusion

The fixed rank-1/20 blockchain monitor could not trigger on either external transaction population under its original daily history reset. A population-wide audit established that none of Li.Fi's 83 positive-outflow token-days reached the required 20 observations, while only one of Revest's 17 token-days did. Extending token history to seven days or to the captured window increased the share of transactions that could be scored; a complete replay generated several additional notifications but no hits on the three independently admitted exploit executions. In one case, the monitored gross core outflow was also poorly aligned with the documented approval-drain mechanism. These results show why score availability, attack-semantic alignment and notification dispatch must be evaluated separately. A separate label-free source audit found the necessary core-log-history condition unsatisfied on at least 15/30 days for a Bacon proxy and 26/30 days for Rari fETH, without evaluating their attack-detection outcomes. The reproducible case study identifies limitations of the tested configuration; a prospective multi-incident cohort is still needed to assess generality.

## Data and code availability

The immutable reference baseline and its portable verifier are publicly recorded at [blockchain-analytics-lab, commit e720697](https://github.com/KuznetsovKarazin/blockchain-analytics-lab/commit/e720697bc3986dd291a7047c580cf973ae6e5567), under `papers/monitoring_jss/phase16/public_evidence/`. The existing exploratory Phase 17 branch is [`research/monitoring-applicability-20261029`](https://github.com/KuznetsovKarazin/blockchain-analytics-lab/tree/research/monitoring-applicability-20261029). Phase 18 uses the exact same SHA-256-pinned public evidence and supplies an independent scorer, full admission replay, tests, per-case configuration table and figure-generation code. The published Phase 18 code, retrospective score and notification replays, independent checks and figure-generation instructions are accessible in the same research branch. Phase 20's bounded source-only checks, [daily original core-emitter counts](https://github.com/KuznetsovKarazin/blockchain-analytics-lab/blob/research/monitoring-applicability-20261029/papers/monitoring_jss/phase20/daily_core_log_counts.csv) and [source-audit report](https://github.com/KuznetsovKarazin/blockchain-analytics-lab/blob/research/monitoring-applicability-20261029/papers/monitoring_jss/phase20/PHASE20_SOURCE_AUDIT_FINDINGS.md) are also publicly linked there. The GitHub Actions artifacts retain detailed source-range receipts for the documented runs; they are not permanent raw-source archives. This portable archive permits historical replay and audit of *saved* observations; it does not distribute the multi-gigabyte upstream raw archive. No original source, originally frozen detector output, reference label, or companion pin was rewritten.

## References

Aquilina, S. J., et al. (2021). EtherClue: Digital investigation of attacks on Ethereum smart contracts. *Blockchain: Research and Applications*, 2(4), 100028. https://doi.org/10.1016/j.bcra.2021.100028

Arp, D., Quiring, E., Pendlebury, F., Warnecke, A., Pierazzi, F., Wressnegger, C., Cavallaro, L., & Rieck, K. (2022). Dos and Don'ts of Machine Learning in Computer Security. *31st USENIX Security Symposium*, 3971–3988. https://www.usenix.org/conference/usenixsecurity22/presentation/arp

Augusto, A., Belchior, R., Pfannschmidt, J., Vasconcelos, A., & Correia, M. (2025). XChainWatcher: Identifying Anomalies in Cross-Chain Bridges. *Middleware 2025*, 413–426. https://doi.org/10.1145/3721462.3770781

BlockSec. (2022). LI.FI Attack: a Cross-chain Bridge Vulnerability? No, It's Due to Unchecked External Call! https://blocksec.com/blog/li-fi-attack-a-cross-chain-bridge-vulnerability-no-it-s-due-to-unchecked-external-call

Forta Network. (2026). Getting started: Monitoring and detection bots. https://docs.forta.network/en/latest/getting-started/

Lavin, A., & Ahmad, S. (2015). Evaluating Real-Time Anomaly Detection Algorithms — The Numenta Anomaly Benchmark. *ICMLA 2015*. https://doi.org/10.1109/ICMLA.2015.141

LI.FI. (2022). 20th March — The Exploit: Smart Contract Vulnerability Post Mortem. https://blog.li.fi/20th-march-the-exploit-e9e1c5c03eb9

Meng, D., Gritti, F., McLaughlin, R., Ruaro, N., Grishchenko, I., Kruegel, C., & Vigna, G. (2026). HOUSTON: Real-Time Anomaly Detection of Attacks against Ethereum DeFi Protocols. *NDSS Symposium 2026*. https://doi.org/10.14722/ndss.2026.241534

Revest Finance. (2022). Revest Protocol Exploit Recovery Plan. https://revestfinance.medium.com/revest-protocol-exploit-recovery-plan-b06ca33fbdf5

Sommer, R., & Paxson, V. (2010). Outside the Closed World: On Using Machine Learning for Network Intrusion Detection. *IEEE Symposium on Security and Privacy*. https://doi.org/10.1109/SP.2010.25

SunWeb3Sec. (2026). *DeFiHackLabs*: Versioned exploit reproductions and incident references [software repository]. https://github.com/SunWeb3Sec/DeFiHackLabs

Wu, J., Lin, K., Lin, D., Zhang, B., Wu, Z., & Su, J. (2025). Safeguarding Blockchain Ecosystem: Understanding and Detecting Attack Transactions on Cross-chain Bridges. *WWW 2025*, 4902–4912. https://doi.org/10.1145/3696410.3714604

Zhang, M., Zhang, X., Zhang, Y., & Lin, Z. (2020). TXSPECTOR: Uncovering Attacks in Ethereum from Transactions. *29th USENIX Security Symposium*, 2775–2792. https://www.usenix.org/conference/usenixsecurity20/presentation/zhang-mengya

Zhou, L., Xiong, X., Ernstberger, J., Chaliasos, S., Wang, Z., Wang, Y., Qin, K., Wattenhofer, R., Song, D., & Gervais, A. (2023). SoK: Decentralized Finance (DeFi) Attacks. *IEEE Symposium on Security and Privacy*. https://doi.org/10.1109/SP46215.2023.10179435

Wu, S., Yu, Z., Wang, D., Zhou, Y., Wu, L., Wang, H., & Yuan, X. (2024). DeFiRanger: Detecting DeFi Price Manipulation Attacks. *IEEE Transactions on Dependable and Secure Computing*, 21(4), 4147–4161. https://doi.org/10.1109/TDSC.2023.3346888

Vogelsteller, F., & Buterin, V. (2015). ERC-20: Token Standard. https://eips.ethereum.org/EIPS/eip-20
