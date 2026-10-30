# Nomad: attack-day burst and post-scoring documentary join

This extension addresses review P2. It preserves the V7 Replica address, 30-day
window, all 930 selected transactions, scores, grouping and notification policy.
The public references were joined **after** the immutable V7 replay. They were
not used to select a new core, move the window or tune a rule.

## Architecture and interpretation

Nomad's [protocol documentation](https://docs.nomad.xyz/token-bridge/architecture)
separates message delivery from asset custody: a Replica dispatches messages to
the BridgeRouter, which releases escrowed tokens or mints representations.
The [protocol team's root-cause analysis](https://medium.com/nomad-xyz-blog/nomad-bridge-hack-root-cause-analysis-875ad2e5aacd)
(5 August 2022) also describes fraudulent messages reaching the BridgeRouter
through the Replica. Consequently, zero positive outflow from the selected
Replica is an expected boundary mismatch at stage A, not an unexpected finding
about traffic. The retained event bundles confirm that mismatch.

The fixed stream contains 884 transactions on 1 August and only 46 during the
preceding 29 days. It is an **attack-day traffic burst**, not evidence of a
persistently busy pre-attack history.

## Documentary source

The protocol team's [Nomad Hack Data repository](https://github.com/nomad-xyz/hack-data/tree/ba9adb9323517e8e677c774fbfc58364566df43b)
is pinned at `ba9adb9323517e8e677c774fbfc58364566df43b` (last commit 20 December
2022). Its `analysis/hack/transaction_hashes.json` contains 960 unique hashes.
The team's [17 August 2022 recovery update](https://medium.com/nomad-xyz-blog/the-road-to-recovery-6abe5eec8ff1)
explicitly identifies this repository as its published dataset of addresses and
transactions involved in the exploit.

The hash list is derived from `data/hack/receive_events.json`, as recorded in
the retained upstream `transaction-hashes.ts`; we use the published hash list,
without claiming to have rerun the team's original incident classification.
The accompanying `process_events.json` supplies on-chain identity fields and
decoded event values for cross-checking the joined rows. It contains 1,182
exported rows, including seven duplicates that differ only in an export index;
these represent 1,175 unique transaction/log-index pairs. Duplicate occurrences
are validated and counted explicitly, not treated as additional observations.

The retained source files are byte-identical to their pinned Git blobs (with
the large process-event file losslessly gzip-compressed). SHA-256 and upstream
Git blob identities are in `sources/source_identity.json`. The upstream Apache
2.0 license and README are retained, and no `NOTICE` file exists in the pinned
upstream tree. This analysis and its output files are new; upstream source
content has not been edited.

## Reconciliation and results

Of the 960 published reference hashes, 921 have an event from the fixed Replica.
Of those, 877 join the selected stream and 44 have source block numbers later
than its final selected block. The other 39 hashes belong only to two different
Replica contracts. All 877 joined Process event identities and indexed topic
values agree with the retained normalized original-AWS bundles. There are 53
selected transactions not in the public list; they are not assigned a benign
or false-positive label.

The count-rule funnel is 564 raw triggers, twelve grouped candidates and five
notifications at greedy B=5. **All twelve candidates occur in the published
list.** Seven listed candidates are rejected by the hard daily cap. With the
same fixed grouping and greedy B=20, all twelve are delivered. This is a direct
stage-D difference for reference-associated candidates, not an incident recall
or false-positive-rate estimate.

| Event | UTC on 1 August 2022 | Since earliest listed transaction |
|---|---|---:|
| Earliest protocol-listed transaction | 21:32:31 | 0 |
| First count candidate and notification | 22:43:32 | 71 min 1 s |
| Fifth notification exhausts B=5 | 23:17:33 | 105 min 2 s |
| First candidate rejected by the cap | 23:23:01 | 110 min 30 s |

The budget is exhausted 34 min 1 s after the first candidate. It is **not**
exhausted in the first minutes of exploitation. The earliest listed transaction
has no count trigger; the first notification is already more than an hour
later. These are historical event-time differences, not measured detection
latencies or evidence of prevention.

Protocol-list membership is a documentary assertion about involvement in the
hack. It does not independently determine malicious intent, distinguish all
whitehat actors, establish economic loss, or close the incident inventory.

## Offline verification

From the repository root:

```bash
python papers/monitoring_jss/phase32/nomad_join/verify_join.py --check
python papers/monitoring_jss/phase32/nomad_join/independent_check.py --check
```

The standard-library verifier checks the retained upstream blobs, seven immutable
V7 inputs, all 877 shared event payloads, all 930 independently recomputed count
and grouping decisions, the B=5 and B=20 exact notification sequences, source
membership and every reported timing. It imports no replay implementation and
performs no network requests. `--out /tmp/nomad-join` regenerates the three
outputs separately for inspection.

- `JOIN_REPORT.json`: complete audit, 12 candidate decisions and limitations.
- `CANDIDATE_DISPATCH.csv`: exact candidate hashes, timestamps and B=5 outcomes.
- `SELECTED_REFERENCE_HASHES.json`: 877 matched hashes in causal stream order.
- `PROTOCOL.json`: source identities, fixed scientific scope and input hashes.

The retained `independent_check.py` separately performs a direct O(n²) count-window calculation, grouping/dispatch and source checks without importing `verify_join.py`; `--check` reproduces `INDEPENDENT_CHECK.json` exactly.

Neither source agreement nor a documentary join authenticates receipt roots.
