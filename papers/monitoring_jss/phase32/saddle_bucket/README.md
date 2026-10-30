# Saddle and token-bucket review audit (P3–P5)

This additive Phase32 audit preserves the original V7 inputs and rules. It uses a
standalone standard-library implementation; no detector implementation is imported.

From the repository root:

```bash
python papers/monitoring_jss/phase32/saddle_bucket/audit.py --out /tmp/saddle_bucket_audit.json
```

The generated result equals `AUDIT.json`. Original greedy and unit-capacity bucket
notification sequences are checked against all three retained budget settings.
The capacity sensitivity is explicitly post-review and is not presented as part
of the original fixed-policy experiment.

## P3: a strict maximum is not automatically a threshold crossing

At the first documented Saddle extraction (30 April 2022, 07:40:24 UTC), the sUSD
outflow exceeds all sixteen preceding positive observations. Its descriptive
rank is therefore **1/17**, but **1/17 > 1/20**. It has three fewer observations
than the configured history minimum. Stage C is not evaluated by the detector
outside this domain; even a purely descriptive threshold comparison is false.
Consequently the review's proposed “B-fail with potential C-pass” interpretation
would be incorrect at the unchanged threshold. No hypothetical missing values
are inserted.

For the later extraction at 08:24:23, the history contains twenty observations
and the rank is **3/21**. The first extraction and the intervening rescue are
exactly the two preceding values at least as large as the later outflow. This
is an observed, incident-contaminated history, not an allegation of deliberate
training-data poisoning. Simply deleting those two observations leaves eighteen
prior values and rank **1/19**; it does not restore an admissible detection.

Suggested manuscript sentence:

> The initial sUSD outflow is a strict observed maximum, but its descriptive rank
> 1/17 still exceeds 1/20 and lies outside the configured history domain.

## P4: burst capacity and initialization matter

All variants use refill rate `B/86400` per second, reset at UTC midnight, and
retain the hard daily cap `B`. With `B=5`:

| Capacity | Initial credit | Notifications | Reference delivered |
|---:|---:|---:|---|
| 1 (original) | 1 | 21 | No |
| 5 | 1 | 24 | Yes |
| 5 | 5 | 27 | Yes |

Thus increasing capacity alone, while holding initial credit at one, restores
the reference notification. Initializing the capacity-five bucket full also
reproduces the complete greedy sequence. With a full initial bucket of capacity
`B` and a hard cap `B`, credit cannot constrain an otherwise allowed candidate
before the hard cap, so equality with greedy is structural. These results are
not a general advantage/disadvantage of the token-bucket family.

The abstract, Schnoodle paragraph, conclusion and Highlights should all identify
**unit burst capacity**, rather than attributing this loss to token buckets in
general. Suggested Highlight (within 85 characters):

> A token bucket with unit burst capacity suppresses a known match at a daily cap of 5.

## P5: the SEAL entry exists, and a primary report confirms the same hash

The full [SEAL page](https://safeharbor.securityalliance.org/whitehats) continues
after Nomad: its last entry identifies Blocksec / Saddle Finance / 2022-04-30
and lists rescue hash `0x9549c0cb48ec5a5a2c4703cbbbbea5638028b2d8c8adc103220ef1c7fe5e99a3`.
The exact hash is also the “our rescue tx” link in the
[primary BlockSec report](https://blocksec.com/blog/how-blocksec-rescued-stolen-funds-from-technical-perspectives-of-three-representative-cases),
whose displayed date is 20 February 2023. The author's
[Medium version](https://blocksecteam.medium.com/how-blocksec-rescued-stolen-funds-from-technical-perspectives-of-three-representative-cases-d9e9be682eaa)
prints the full Etherscan URL and displays 19 February 2023. Do not interchange
these version-specific dates. `SOURCE_CHECK.json` records source locations,
short labels and the exact transaction link without redistributing full pages.

No latency or effectiveness claim made by the rescue provider is adopted as a
measurement of this manuscript's monitor. Rescue attribution remains distinct
from a complete incident inventory.
