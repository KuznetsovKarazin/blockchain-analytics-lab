# External-case results: notification coverage and cold-start limits

The frozen semantic outflow-rank method did not improve exact execution coverage in either external case. At the primary offered budget of five notifications per UTC day, the count baseline notified the one verified Li.Fi execution, while the semantic method notified none. Both methods notified neither of the two verified Revest executions. All three primary policies gave these coverage outcomes. The semantic arm lost all three known executions at its token-history eligibility gate, before rank thresholding, grouping or budget allocation.

These are descriptive results for two incident families and fixed historical components. The [methods and limits](METHODS_AND_LIMITS.md) and [interpretation rules](RESULT_INTERPRETATION_RULES.md) remain unchanged. [The accompanying JSON](EXTERNAL_CASE_AGGREGATES.json) retains all 54 prespecified aggregate cells, including all 42 sensitivity cells, with coverage, funnel counts and realized notification loads.

## Completed comparison and reference scope

Each case used its complete fixed 30-day window: Li.Fi from 19 February through 20 March 2022, and Revest from 26 February through 27 March 2022, in UTC. The resulting 60 case-days span 37 distinct calendar dates. Selection produced 280 Li.Fi transaction observations and 194 Revest transaction observations; these are case-specific counts, not a claim of 474 unique transactions across cases. All methods received the same audited inputs within each case.

Both replay outputs were sealed before new primary-report acquisition. Independent audits passed for source selection and complete selected log bundles, and for all 12,798 decision rows across 1,620 daily method–policy–budget cells. These cells do not constitute 1,620 independent experiments: the cohort still contains two incident families.

Bounded review of the [Li.Fi project post-mortem](https://blog.li.fi/20th-march-the-exploit-e9e1c5c03eb9), the [original Li.Fi investigator analysis](https://blocksec.com/blog/li-fi-attack-a-cross-chain-bridge-vulnerability-no-it-s-due-to-unchecked-external-call), and the [Revest project account](https://revestfinance.medium.com/revest-protocol-exploit-recovery-plan-b06ca33fbdf5), with the retained acquisition journal, yielded five exact transaction candidates. Independent role and archive checks admitted one Li.Fi and two Revest transactions as successful unauthorized executions within their fixed windows. Two other exact candidates remain unresolved: a Li.Fi link associated with contact/bounty discussion and a Revest link associated with an asset sale. Success on chain does not resolve their attack roles. Revest additionally retains seven unresolved document locators after the document cap; they are not assumed to denote seven distinct attacks.

Both reference inventories remain `KNOWN_SUBSET_ONLY`. The Li.Fi official report's single-execution statement is retained as positive closure evidence, but the unresolved candidate prevents a complete-inventory designation under the frozen rule. Revest lacks closure evidence and retains unreturned document content. Thus the denominators below are verified known subsets, not an exhaustive count of all incident executions. There is no unresolved observation evidence for the three admitted references, so their known-set lower and upper coverage bounds coincide with the reported fractions.

## Primary results at B=5

Coverage is the number of exact reference transactions notified divided by the verified applicable reference denominator. Notification load is the total over the entire 30-day case window, with 150 offered slots per arm. Semantic denotes `outflow_rank_1_20`; count denotes `core_count_60s_10`.

| Case | Policy | Semantic coverage | Count coverage | Semantic notifications | Count notifications |
|---|---|---:|---:|---:|---:|
| Li.Fi | Greedy | 0/1 | 1/1 | 0 | 1 |
| Li.Fi | Paced cumulative | 0/1 | 1/1 | 0 | 1 |
| Li.Fi | Token bucket | 0/1 | 1/1 | 0 | 1 |
| Revest | Greedy | 0/2 | 0/2 | 0 | 2 |
| Revest | Paced cumulative | 0/2 | 0/2 | 0 | 2 |
| Revest | Token bucket | 0/2 | 0/2 | 0 | 2 |

The count arm establishes a verified Li.Fi incident hit. The other no-hit results remain indeterminate for complete incident coverage because their execution inventories are incomplete. Revest's two count notifications have unknown reference status; they are not classified as false positives. The semantic arm's zero notifications do not establish better precision or greater operational utility. Equal offered budgets did not yield equal realized load.

## Explanation and prespecified sensitivities

All three admitted executions were observed, selected by core-emitter membership and associated with a positive core-sender token outflow. None had a token with the required 19 strictly earlier positive observations within its UTC day. Their semantic terminal reason is therefore `SELECTED_COLD_START`. Positive outflow here is a feature of the declared event semantics; it does not establish the amount or ownership of stolen assets.

| Case | Verified references | Selected | Positive core outflow | Semantic history eligible | Semantic raw trigger | Count raw trigger |
|---|---:|---:|---:|---:|---:|---:|
| Li.Fi | 1 | 1 | 1 | 0 | 0 | 1 |
| Revest | 2 | 2 | 2 | 0 | 0 | 0 |

The retained transaction traces distinguish core-emitter counts from the larger all-emitter bundles. Strictly prior positive-history lengths below are per token; the semantic minimum is 19. No token has an eligible rank at these reference executions.

| Reference execution | Core-emitter logs | All-emitter logs | Transaction-final 60-second core count | Prior positive-history lengths |
|---|---:|---:|---:|---|
| Li.Fi `4b4143cb…` | 39 | 92 | 39 | 1, 0 |
| Revest `e0b0c267…` | 7 | 33 | 7 | 0 |
| Revest `19b10c6d…` | 7 | 26 | 7 | 0 |

The count arm bypasses semantic outflow/history eligibility. Its two Revest references were selected but did not meet the frozen count-trigger rule. No admitted reference was lost to grouping or budget suppression. For these references, the semantic eligibility ceiling was zero under the declared daily reset and history requirement. Changing only a rank threshold or notification budget could not overcome that gate; the experiment therefore does not discriminate rank thresholds on these references. It does not establish what continuous-history initialization or another feature definition would achieve.

All prespecified sensitivities preserved the same case-specific exact coverage: Li.Fi count 1/1 and both semantic thresholds 0/1; Revest all methods 0/2. Increasing the offered daily budget from 1 to 20 did not change these known-execution results. The 1/10 semantic threshold did change Revest's total notification load:

| Revest 1/10 policy | B=1 notifications | B=5 notifications | B=20 notifications |
|---|---:|---:|---:|
| Greedy | 1 | 2 | 2 |
| Paced cumulative | 1 | 2 | 2 |
| Token bucket | 1 | 1 | 2 |

All of these sensitivity notifications have unknown reference status. Li.Fi's semantic load remained zero at both thresholds and all budgets; Revest's primary semantic load also remained zero. Count load remained one for Li.Fi and two for Revest at every policy and budget. These load changes supply no verified-execution coverage gain.

## Contribution and limits

The external comparison gives an adverse result for the proposed semantic method on Li.Fi and a known-subset tie on Revest. The tie is not evidence of equivalence. Its scientific contribution is an audited measurement of where coverage is lost: successful source observation and positive outflow can coexist with a history requirement that excludes every verified reference. The result identifies initialization and token-history availability as prerequisites to examine before interpreting rank thresholds or alert allocation. The zero eligibility ceiling follows from the frozen gates and existing set-inclusion bounds; it is not a new detection theorem.

A bounded next study would preregister an initialization comparison between daily resets and a strictly historical warm start, then evaluate the resulting methods on new incidents. The present traces justify testing that question but do not establish a warm-start coverage gain. Such a comparison would be a separate protocol; the current results and parameters would remain intact.

The earlier Euler development result—semantic/greedy B=5 at 2/6 known executions versus count at 0/6, both with five notifications—did not establish a general advantage, and its advantage did not persist across policies. The two external cases provide no replication of semantic superiority. Euler remains development evidence and is not pooled as a third independent external case.

The engineering result is a completed, independently checked acquisition/replay/reference chain despite a recorded storage-exhaustion failure. An operational recovery amendment was accepted after disclosed source exposure and before recovery import or new requests. It preserved the failed attempt, unknown pending-response byte accounting and unchanged scientific rules. This demonstrates feasibility in the observed run; it is not a controlled throughput or storage-efficiency benchmark. Neither engineering verification nor these two selected cases support population-wide superiority, statistical significance, precision/FPR, economic-loss reduction, live detection latency or prevention claims. Archive identity checks do not constitute receipt-root authentication or universal chain completeness.

The machine-readable aggregate file binds the decision study, independently adjudicated reference inventory, exact join and independent interpretation audit by SHA-256. It is a compact result export; the detailed execution and provenance evidence are retained separately.
