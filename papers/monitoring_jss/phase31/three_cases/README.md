# Phase31: detailed observations of Saddle, XCarnival and Audius

The frozen V6.1 sample and monitor outputs are preserved. This audit examines
all 125 selected transactions (44 + 43 + 38), computes strictly prior token
histories independently, and joins an expanded, role-specific reference ledger
only after label-blind decisions. It does not turn these three component
streams into three fully labelled incident-performance trials.

Run from the repository root, without network access:

```bash
python papers/monitoring_jss/phase31/three_cases/observe_three_cases.py
```

The script verifies the stored observation digests, reproduces twelve nominal
greedy-B5 method/history cells, and writes `event_observations.json`,
`role_observations.json`, and `summary.json`. Every positive token outflow has
its exact prior transaction hashes, history count and rank numerator/denominator.
Ranks shown for fewer than 19 prior values are descriptive, not eligible scores.
The count window is `(t - 60 seconds, t]`; a group candidate at exactly 300
seconds after the preceding group candidate starts a new group. Dispatch is
evaluated separately. The complete 441-cell policy audit is elsewhere in
Phase31 and is not counted again here as additional independent experiments.

| Fixed component | Selected TX | Positive-outflow TX | Eligible TX: daily / 7d / cumulative | Rank alerts: daily / 7d / cumulative | Count alerts |
|---|---:|---:|---|---|---:|
| Saddle sUSD metapool | 44 | 39 | 0 / 0 / 3 | 0 / 0 / 0 | 1 |
| XCarnival XNFT proxy | 43 | 0 | 0 / 0 / 0 | 0 / 0 / 0 | 4 |
| Audius governance proxy | 38 | 1 | 0 / 0 / 0 | 0 / 0 / 0 | 0 |

These rates are descriptive properties of the selected source streams.
They do not remove the low-volume selection bias of the pilot.

## Saddle

BlockSec's primary analysis explicitly links `0x2b023d...` as an attack
example. This supports that transaction's role more strongly than the pending
classification in the old ledger; it does not close the incident inventory.
At 07:40:24 UTC the cumulative histories contain 16 positive sUSD outflows and
5 positive LP-token outflows. Their descriptive ranks are 1/17 and 1/6. Neither
history passes the 19-prior-value gate. The current count is nine core logs,
below the count threshold of ten.

The expanded ledger separately records the 08:04:55 transaction
`0x9549c0...` as a whitehat rescue. Security Alliance's rescue registry and the
public explorer attribution support this distinction. It must not become a
harmful-extraction reference simply because it uses the same mechanism.

The later 08:24:23 transaction `0xe7e047...` has the same original attacker
sender and an exploit-like same-pool sequence with proceeds returning to that
sender. Its classification as a subsequent extraction is an explicit
chain-sequence inference; no closed incident-wide denominator is claimed.
For this transaction, cumulative sUSD history passes gate B with 20 prior
positive values, but rank 3/21 = 1/7 fails gate C at 1/20. The nine-log count
does not trigger. This is a concrete source-level example of sufficient
history without extremality.

The sole count notification occurs at `0x3189cb...`, 08:24:35, twelve seconds
later: nine logs from the preceding transaction plus one current core log
make ten. This is not an exact-transaction match and is not evidence of
prevention. The notified transaction itself remains unadjudicated.

## XCarnival

The frozen PoC distinguishes collateral-order preparation `0x422e7b...`
from the later borrowing call `0xabfcfa...`. SlowMist's investigator report
provides another explicit preparation/borrowing pair: `0x61a6a8...` and
`0x51cbfd...`. Both preparation transactions are in the selected XNFT stream;
both borrowing transactions have zero XNFT-emitted logs. The latter fact is
verified from saved complete Blockscout metadata/log bundles, separate from
the original AWS-selected population.

No selected XNFT transaction has a positive gross ERC20-shaped outflow.
The documented economic extraction is native ETH borrowing through a
different xToken proxy. This is a boundary/feature mismatch as well as a
readiness limitation; increasing the token-history window cannot repair it.
The four count notifications are not four documented successful detections.
For the newly documented preparation `0x61a6a8...`, the count reaches 24,
but grouping suppresses a new candidate. The reference-specific report records
this as a grouping outcome, not a budget failure.

## Audius

The protocol's official postmortem supplies an initial governance attempt
`0x3bbb15...` that was absent from the four-hash PoC reference list. It is
already present in the 38-row selected stream. The proposal failed, while the
Ethereum transaction was successful; these statuses are distinct.

The ledger now separates this initial attempt, renewed initialization and
proposal, vote submission, proposal execution with treasury extraction, and
the later sale. The treasury extraction is `0x4227bc...` at 23:11:36 UTC,
not the subsequent swap `0x82fc23...`. It has the only positive AUDIO outflow
in the entire captured governance-proxy stream: zero preceding positive
same-token values under all three initializations. The count window contains
three core logs. The later sale has zero governance-proxy logs and is not
part of the fixed selected stream.

## Evidence limits and raw source retention

`sources/source_catalogue.json` records public source URLs, dates, short
excerpts, exact PoC commit and file/blob digests. The PoC files declare
`SPDX-License-Identifier: UNLICENSED`; this directory redistributes their
locators and factual observations, not copied source files.

V6.1 stored complete source-selected transaction identities/counts and
derived indexer features, with hashes of the all-emitter logs. It did not
retain the raw indexed topics/data in these Phase30 observation files.
Consequently, the offline command above reproduces causal scores from
derived observations; by itself it cannot re-extract all features from logs.
Any separately retained Phase31 raw-source audit must be cited for that
additional verification. Hashes of unavailable raw bytes alone are not
offline feature-reproduction evidence.

`outside_reference_bundles/` retains complete metadata and paginated log
responses for two XCarnival borrowing references and the Audius later sale.
Its manifest records response hashes; the offline audit verifies them and
their zero fixed-core log counts. These are indexed reference bundles, not
Ethereum receipt-root proofs and not additions to the monitor population.
The optional acquisition script is networked and is not needed for replay.

All three fixed-core windows are complete at the recorded source tier.
No assertion of complete protocol-wide attack inventories, authenticated
receipt roots, recall, precision, or false-positive rate follows.
