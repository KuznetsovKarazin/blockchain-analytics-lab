# Independent offline audit of the Nomad normalized dataset

`verify_nomad.py` uses only the Python standard library and does not import the acquisition, observation-extraction or replay implementation. It reads no attack-reference ledger and makes no network request. Its subject is the recorded data and fixed mathematical transformations.

Run only after the acquisition reports `COMPLETE`:

```sh
python papers/monitoring_jss/phase31/nomad_independent/verify_nomad.py \
  --data papers/monitoring_jss/phase31/nomad/data_attempt3 \
  --results papers/monitoring_jss/phase31/nomad/results \
  --out papers/monitoring_jss/phase31/nomad_independent/AUDIT.json
```

Omit `--results` to validate accepted data before scores exist. An incomplete acquisition is rejected without producing a PASS artifact.

Checks include strict JSON parsing, canonical digests, schema and hexadecimal encoding, unique ordered transaction identifiers, UTC date consistency, full saved event-bundle identity, consecutive event indices, daily transaction/core-event counts against the original 930-transaction census, reused-zero-day provenance, successful range receipts, ETags, range coordinates, response bytes and all acquisition resource limits. Listing request/body sizes are added to range accounting explicitly.

The independent decoder rederives all shape counts and per-token integer amount summaries, including positive external outflow, incoming, internal, mint and burn categories. Transfer shape alone is not ERC-20 compliance or a state-balance proof. When supplied label-blind replay results, a separately written integer-arithmetic implementation compares all 63 rank/count/history/dispatch combinations, including exact notified transaction identifiers and budget suppression counts.

## Source-completeness review

The acquisition scans all address/coordinate row groups before sealing selected transaction coordinates, then scans every row group again for those coordinates. This avoids choosing only the row group containing a core-emitter event, which could omit other events from the same transaction across a row-group boundary. Original daily total row count, core-event count and selected-coordinate count are checked against the fixed census. A separate transaction-table scan supplies execution status and transaction identity. A source failure or budget exhaustion leaves the acquisition incomplete.

The 18 zero-selected days reuse accepted original projected-source census evidence and immutable source identities. They do not substitute unavailable source for zero. The final independent audit also checks that the normalized selected dataset contains exactly the nonzero day populations implied by the frozen census.

The portable artifact retains normalized full event values, transaction status assertions, source identities and range response digests. The acquisition deletes downloaded sparse Parquet bodies after each day. Therefore offline auditing can reproduce feature extraction and policies from the saved normalized values, but it cannot repeat the original byte-to-Parquet normalization from retained raw ranges. Range digests are provenance records, not an independently revalidated receipt root. Online original-source reacquisition is required to repeat that earlier stage. Consecutive log indices alone cannot prove the absence of omitted leading/trailing events; the full row-group acquisition procedure and original-source census reconciliation supply the recorded completeness argument.

## Completed result

The standalone audit returned **PASS** on the accepted complete normalized source: **930 transactions, 3,507 events, 930 independently reconstructed amount/count summaries, and all 63 fixed method/history/policy/budget cells**. Exactly 1,157 positive ERC-20-shaped events occur in 905 selected transaction bundles, but none involves the fixed Replica address as sender or recipient. Hence the core-level token-flow table is empty and all rank histories are ineligible; this is distinct from an absence of token movement elsewhere in selected transactions.

The count rule has 564 raw triggers, 12 grouped candidates and five emitted notifications under greedy B=5; seven candidates are budget-suppressed. These are label-blind counts, not attack-detection scores.

Three source attempts remain visible: the original wall-limited incomplete attempt, a runtime-interrupted pending capture from which no new scientific data are admitted, and the accepted recovery. The audit conservatively charges the interrupted pending body, one lost listing and elapsed-time upper bound. Combined upper bounds are **3,481,219,099 response bytes, 519 requests and 3,029.699207 active seconds**, within the pre-score amended limits of 5 GB, 1,600 requests and 3,600 seconds. The original first-attempt 3.6 GB/1,800 s limits remain unchanged. The realized upper-bound traffic is below 3.6 GB; the 5 GB amendment supplied planning headroom and is not presented as measured necessity.

`AUDIT.json` binds the exact accepted source manifest SHA256 and verifier source SHA256. `validate_math_baseline.py` additionally checks the separately written mathematics against all 441 frozen policy cells in the prior seven-stream dataset. This is validation of the new implementation, not an additional scientific sample.

The new 930 transaction identities are reconstructed from the pinned original-source objects and reconciled with the frozen daily/core counts. The original Phase28 census did not preserve a separate Nomad transaction-hash registry, so no comparison against such a nonexistent registry is claimed.
