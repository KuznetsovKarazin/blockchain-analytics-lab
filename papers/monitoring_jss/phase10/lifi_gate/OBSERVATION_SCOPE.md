# Fixed-core outflow: a conditional observation limit

This is an offline review of the unchanged phase7/8 programs. It is **not** a Li.Fi log analysis, score, missed-incident finding or eligibility decision. No Li.Fi execution payload was read for this review.

Let `C` be the independently fixed, nonzero monitored contract-address set. In `transfer_observation.py`, lines 240–243 validate `C`; lines 173–191 decode the ERC-20-shaped event's indexed `from` and `to`; lines 315–342 classify its amount. A log contributes to `external_out_raw` exactly when its decoded `from` belongs to `C`, its decoded `to` is outside `C`, and `to` is not the zero address. Core-to-core transfers are internal; core-to-zero transfers are burns. The LOG emitter identifies the token row, not the sender or spender. The archive adapter implements the same categories in `acquire_semantic_flow_inputs.py`, lines 106–137.

Consequently, if an approved spender in `C` causes a token transfer from a user outside `C` directly to another nonzero address outside `C`, that event contributes no fixed-core flow: both event endpoints fail the membership test. The spender's authorization or call-stack presence does not replace the event's `from` address. This remains true even when the event is present in an otherwise complete selected transaction bundle. An event-shape observation also does not establish balances, economic loss, token compliance or allowance semantics.

There is a separate transaction-selection limit. The phase8 archive collector constructs its selected transaction identities from logs **emitted by** the fixed core population (`group_core`, lines 65–79), checks them against the frozen selection (lines 304–310), and validates the core log subset within each acquired all-emitter bundle (lines 92–104). A transaction that calls a core spender but emits no log from a core address is absent under that selection rule. Fetching all emitters' logs for selected transactions cannot recover transactions never selected. The indexer observation function validates an already selected transaction bundle and its source manifest; it does not itself enumerate a whole-protocol transaction population (`transfer_observation.py`, lines 194–201 and 215–247).

The unchanged semantic rule ranks only strictly positive `external_out_raw` totals (`semantic_flow_monitor.py`, lines 155–171). If an included transaction has no such total, its semantic result has no token score and reason `no_positive_external_outflow` (lines 245–276). This conditional consequence is independent of alert admission; it says nothing about the actual Li.Fi transaction, other transfers in it, or a count-rule trigger.

For the next case, retain the fixed measurement and population definitions while checking historical identity, source coverage and later labels. Do not add victims or recipients to `C` after reading incident details, switch from emitter-selected transactions to call-selected transactions without a new prespecified estimand, or exclude an otherwise eligible incident because its mechanism may not yield core outflow. A future approval or call-path monitor would measure a different property and require separate design and evidence.

## Exact reviewed sources

Line references above belong to these unchanged repository files identified by the exact source hashes below.

| Repository path | SHA-256 |
|---|---|
| `papers/monitoring_jss/transfer_observation.py` | `eb905fdbdc44033424066e4baebbbc1f6724bd68bd9e0573676f39e4908f429c` |
| `papers/monitoring_jss/acquire_semantic_flow_inputs.py` | `bc752fa2fb8ae2747730d1eb213b64beb1faec7d43cc2a214d1edf73af3b884f` |
| `papers/monitoring_jss/semantic_flow_monitor.py` | `10ac4a7bc81b76c49be07ff8125136910cbacf2782708271d057b2094bfa60ad` |

No detector code, threshold, transaction selection, population or prior receipt was changed. This note was checked against the source branches directly; it does not report a new execution test.
