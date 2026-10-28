# Rules for interpreting the external-case results

This document specifies interpretation, not an outcome. It uses the existing
[methods and limits](METHODS_AND_LIMITS.md), [coverage bounds](../../phase15/COVERAGE_BOUNDS.md),
frozen [Li.Fi](../protocol/configs/lifi.json) and [Revest](../protocol/configs/revest.json)
configurations, and the [retained Euler summary](../../phase15/README.md).
No current acquisition payload, new incident reference or detector score was used.

The primary comparison remains `outflow_rank_1_20` versus `core_count_60s_10` at
offered daily budget B=5, separately under greedy, paced-cumulative and token-bucket
policies. Threshold 1/10 and B=1,20 are sensitivities; they cannot replace an
unfavourable primary result. Grouping remains 300 seconds. State and budgets reset
at each UTC-day boundary; token history is capped at 128 and requires 19 strictly
earlier positive observations. This document changes no parameter or gate.

The two source-limited external cases contribute 60 case-days over 37 calendar dates,
not 60 independent incidents. Report each case and policy before any descriptive
aggregation. Shared dates, executions and method–policy cells do not increase the
number of incident families. Euler remains exposed development evidence: its
retained primary semantic/greedy B=5 result was 2/6 known executions versus 0/6 for
count, both at five notifications; the advantage did not persist across policies.
It motivates this external test and must not be pooled as a third independent
external validation case.

| Claim or stage | Evidence required | Permitted interpretation and boundary |
|---|---|---|
| Source observation and core membership | Independent byte/source audits, all required partitions and UTC boundaries, full address/hash scans, successful transaction metadata, and exact selected-bundle membership | Establishes availability and selection for the fixed components at the declared archive tier. An unselected reference is a selection limitation, not an input silently added after labelling. This is not receipt-root authentication or proof of every protocol-owned contract. |
| Semantic eligibility and cold start | Audited token-separated core-sender outflows and frozen per-token state traces for each reference | Positive outflow and sufficient earlier positive history are distinct prerequisites. Zero/absent outflows do not populate history; the first 19 positive observations are per token, not the first 19 transactions. Ineligibility is not a rank-threshold miss. The count arm bypasses these prerequisites. |
| Trigger, grouping and budget effects | Sealed raw-trigger, grouped-candidate and notification records with their suppression reasons and daily policy state | Separate no trigger, grouping suppression and budget suppression. Equal offered B does not imply equal realized notification load. A grouped or nearby execution cannot substitute for a notification on the exact reference transaction. |
| Exact verified-execution coverage | Both cases' decision seals precede new reference retrieval; independently adjudicated exact transaction identities; the same outer reference denominator for both arms | Credit only exact notified identities. Report numerator, denominator and realized load, retaining unselected, no-outflow and cold-start references in the denominator. Conditional eligible-subset rates may explain a result but cannot replace outer coverage. |
| Incident hit or miss | At least one exact verified reference notification for a hit; complete execution inventory and observation evidence for a complete miss | A verified hit can be established with partial known labels. No hit is indeterminate when executions or observations remain unresolved; it is not automatically a complete incident miss. |
| Precision, economic impact or live protection | Independently adjudicated notification outcomes and an appropriate negative population; separate economic or live-timing evidence respectively | Unknown notifications are not false positives. Current evidence does not support precision/FPR, monetary-loss, prevention or live-latency claims. ERC20-shaped events are not proof of balances or token compliance. |

For a known reference set P, distinguish a complete inventory from a verified known
subset. If n exact references are notified and u have unresolved observation
evidence, report the descriptive known-set bounds n/|P| to (n+u)/|P|. These bounds
do not include undiscovered executions and do not authorize an incomplete replay:
missing required source evidence still halts the accepted comparison. An empty
reference set gives no coverage rate. The selection/capacity bounds, including
the tighter semantic-eligibility bound, follow from set inclusion and daily caps;
they are not a new detection theorem.

Interpret outcomes without selecting the most favourable cell:

- **Higher semantic coverage:** supports a descriptive advantage for the stated
  case, policy, offered budget and reference set. State the exact change and both
  realized loads. Consistency across both cases or all three policies strengthens
  the description within this cohort; it does not establish population-wide
  superiority, statistical significance or a deployable prevention guarantee.
- **Tie or lower semantic coverage:** retains scientific value when the common
  inputs and labels are auditable. Report where executions were lost in the
  selection–eligibility–trigger–grouping–budget sequence. A tie is not proof of
  equivalence. If the eligibility ceiling is zero, the case diagnoses an
  observation/initialization limitation and cannot discriminate rank thresholds.
- **Policy-dependent reversal:** establishes dependence on allocation under the
  declared protocol. Preserve every policy result; a winning sensitivity or policy
  cannot rescue a primary comparison. Attribute a stage loss only when its trace
  supports that attribution.
- **No admissible full comparison:** report an unavailable or failed measurement,
  including its exposure and resource history. Partial acquisition is neither a
  measured detector miss nor evidence of equal performance.

Potential article contributions do not require superiority, but each requires
specific evidence:

- **External empirical characterization:** completed independent audits, sealed
  fixed-method decisions and bounded post-decision labels can establish coverage–
  load behaviour, ties, reversals and applicability limits in two additional fixed
  historical components. The claim remains descriptive and source-limited.
- **Measured explanation of coverage losses:** exact-reference stage membership
  and frozen state traces can separate observability, conditional token history
  and notification allocation. The contribution is making these mechanisms
  auditable and measuring them, rather than claiming novelty for elementary bounds.
- **Reproducible acquisition and recovery engineering:** independent range/blob
  integrity, strict hole-rejection and restoration checks, complete provenance,
  and actual resource ledgers can support selective archive acquisition with
  explicit failed/pending-byte accounting. Runtime feasibility must be evidenced
  in the observed environment; synthetic checks alone do not establish practical
  throughput, general storage-efficiency gains or detector effectiveness.

The final article should distinguish these contributions explicitly. Engineering
correctness cannot stand in for an external detection result; an honest null or
adverse detection result does not erase a well-supported engineering or empirical
finding.
