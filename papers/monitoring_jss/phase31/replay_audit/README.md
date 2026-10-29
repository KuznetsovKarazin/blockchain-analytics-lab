# V6.1 offline replay and review audit

Baseline: `article2-jss-v6.1-2026-10-29`, commit
`651daa926bb3803ad76227389a4fb35c1027da63`. Frozen Phase28–30 files are
read-only inputs. This audit does not reacquire chain data and does not
upgrade their evidence tier.

Run from the repository root (Python 3.10+, standard library only):

```bash
python papers/monitoring_jss/phase31/replay_audit/run_audit.py
```

`--out PATH` writes the same deterministic JSON reports to another directory.
The script checks source identities and all-emitter counts against the archived
Phase28 census and manifests, checks indexer observation digests, reruns the
separate 441-cell algorithm implementation, reproduces the original label-blind
replay and legacy reference-join JSON objects, and adds a quadratic count-window
oracle plus rational-arithmetic dispatch oracle. All label-blind comparisons
finish before the audit loads reference roles. The reference-free original
replays run first; legacy joins are reproduced separately afterward.

## Reproduction result

| Stream | Selected transactions | Indexed all-emitter rows | Exact policy cells |
|---|---:|---:|---:|
| Umbrella | 92 | 193 | 63 |
| Saddle | 44 | 850 | 63 |
| Inverse | 71 | 712 | 63 |
| Schnoodle | 134 | 1,319 | 63 |
| XCarnival | 43 | 1,200 | 63 |
| Omni | 103 | 8,603 | 63 |
| Audius | 38 | 53 | 63 |
| Total | 525 | 12,930 | 441 |

**PASS:** seven original-source checks, seven mixed-source/indexer checks,
441 exact policy cells, 14 original JSON objects, 63 additional count-policy
cells checked with a distinct full-scan/rational-arithmetic oracle, and seven
boundary checks. All 89 hashed frozen input files remained unchanged.
`results/INPUT_SHA256.json` contains their file digests.

The 441 cells reuse seven streams; they are not 441 independent experiments.
These checks authenticate consistency of the archived artifacts, not Ethereum
receipt roots. The public indexer bundles retain normalized feature observations
and payload digests; this audit does not reconstruct AWS topics/data or
independently authenticate every original payload.

## M5: Schnoodle dispatch is outcome-determining

The count rule produces 28 raw triggers, 27 grouped candidates and 27
notifications under primary greedy B=5 over 134 selected transactions:
**27/134 = 20.15%**. This substantial burden limits any selectivity conclusion
from one exact reference match. It is not a false-positive rate: other
notifications remain unadjudicated.

On 18 June 2022 (UTC), the first group candidate occurs at 04:04:13
(`0x78b3153f2e61b874c1ebef2b4c1697118ec050600ecb0994c4c096493fb91aee`),
followed by 04:39:02. The documented reference transaction is the third group
candidate, at 07:05:24, with 14 core logs in the trailing 60-second window:
`0x9a6227ef97d7ce75732645bd604ef128bb5dfbc1bfbe0966ad1cd2870d45a20e`.

| Policy | B | All-window notifications | Exact reference emitted | Blocking reason at reference |
|---|---:|---:|---|---|
| Greedy | 1 | 18 | No | Hard daily cap already used at 04:04:13 |
| Greedy | 5 | 27 | Yes | — |
| Greedy | 20 | 27 | Yes | — |
| Paced cumulative | 1 | 18 | No | Hard daily cap |
| Paced cumulative | 5 | 24 | Yes | — |
| Paced cumulative | 20 | 27 | Yes | — |
| Token bucket | 1 | 18 | No | Hard daily cap |
| Token bucket | 5 | 21 | No | Only 10871/17280 of one token available |
| Token bucket | 20 | 24 | Yes | — |

Thus dispatch matters even at **fixed B=5**: the token-bucket policy suppresses
the reference while greedy and paced policies emit it. At that time the bucket
has one previously emitted notification and only 0.6291088 token available;
this is a refill constraint, not exhaustion of the hard daily cap. These are
fixed policy sensitivity settings, not post-hoc changes to the primary policy.
For a count-rule example, stage B must mean availability of its count feature;
the rank rule's 19-history condition does not apply to this example.

Every same-day trigger and its decision is in
`results/SCHNOODLE_DISPATCH_TRACE.json`.

## m1: group boundary is inclusive

A raw trigger starts a new group when its gap from the previous **group
candidate** is **at least 300 seconds**. A grouped raw trigger does not move the
anchor; a candidate rejected by dispatch still does. Grouping and dispatch
reset at UTC midnight.

This matters in the historical Inverse stream. Candidates at 12:04:18 and
12:09:18 on 16 June 2022 are exactly 300 seconds apart. The frozen `>= 300`
rule yields two groups and two greedy B=5 notifications. Substituting `> 300`
yields one. The second transaction is
`0x0b4e9021a01528a703e98daf6af0df39b711e857b3ff5ce4f2f0b283f84c0a97`.
The audit retains the frozen rule and reports the alternative only as a
boundary diagnostic. Tests at 300s−1ns, 300s and 300s+1ns check both the
production count monitor and separate implementation. The count window is
`(t−60s, t]`, with corresponding lower-bound checks.

## m2: apply the same provisional hash-join criterion

The V6.1 legacy join uses only `independently_supported_reference_hash` plus
`additional_reference_candidates`. Umbrella has neither, so its successful
indexed reference is omitted. Saddle has a hash in the former field despite
the same `INCIDENT_CONFIRMED_REFERENCE_ROLE_PENDING` status. This creates the
inconsistent table cells identified by the reviewer.

`results/UNIFORM_PROVISIONAL_REFERENCE_JOIN.json` supplies a transparent
alternative without changing the frozen ledger: include every frozen
`indexed_references` entry with `status=ok` and
`within_original_fork_window=true`, then identify its presence in the
fixed-emitter selected population. This is only a **candidate hash join**;
it does not qualify a pending semantic role as an exploit execution.

| Stream | Frozen successful in-window candidate hashes | Selected subset | Primary count exact candidate match |
|---|---:|---:|---:|
| Umbrella | 1 | 1 | 0/1 |
| Saddle | 1 | 1 | 0/1 |
| Inverse | 1 | 1 | 0/1 |
| Schnoodle | 1 | 1 | 1/1 |
| XCarnival | 2 | 1 | 0/1 |
| Omni | 1 | 1 | 0/1 |
| Audius | 4 | 3 | 0/3 |

All semantic-rank variants at primary greedy B=5 have zero matches to these
candidate hashes. Each row preserves its original role status. In particular,
Audius candidate stages must not all be called successful exploit executions,
and no denominator is an incident-wide recall denominator. A strict
role-qualified attack table should instead exclude *all* still-pending roles
uniformly and report this provisional hash table separately.
