# Operational monitoring: draft protocol and pilot contract

Status: **draft, not frozen for confirmatory comparisons**. Date: 25 October 2026.
The agreed research questions and full experiment matrix remain in `protocol.json`.
This document specifies the bounded feasibility pilot. It does not preregister a
completed independent attack-detection experiment.

## Evidence and scope

The baseline is `blockchain-analytics-lab@bb80caac70f8a289e719ec5b88dafa3767c1ef79`.
The companion dependency remains `blockchain-detector-eval@dc1ba8876f3f163c27c48f3a39292fc47f71bf18`.
The pilot core does not import that dependency or train a model.

M1 contains 7,827,863 blocks, including 222,058 calibration/warm-up blocks;
evaluation uses 7,605,805 blocks across 1,065 days. Its signals have no attack
ground truth. M2's budget emits 676 alerts, but only 258 have known labels:
the reported precision 255/258 does not describe all 676 alerts. Consult
`source_audit.json` for the checked counts, historical run commits and limitations.
Historical results and scripts are retained unchanged.

The pilot uses Ethereum block headers from AWS Public Blockchain Data on
2024-03-04 UTC. The date is chosen before running the new detector. The intensive
fragment is the hour with the greatest sum of transaction counts on that date;
ties select the earliest hour. This is an exploratory workload selection from
the same day, not another independent period or attack. "Ordinary" means a
calendar workload sample, not adjudicated attack-free traffic.

The full upstream Parquet partition is fetched again because the old projected
cache omitted block hashes. Hashes, parent links, consecutive block numbers and
timestamp order must be checked. Preserve the original object checksum, download
metadata, projected-input checksum and exact acquisition command. Missing or
conflicting records fail the preparation; never manufacture missing hashes.

## Causal decision contract

`event.schema.json` describes a block-level event. Transaction, log and trace
indices are null because headers do not resolve those units. `observed_time` and
`label_available_time` remain null unless independently documented. Historical
block timestamps are not arrival observations. The immutable archived canonical
chain is assumed; live finality has not been independently observed, and reorgs
are outside this pilot.

The single detector is the fixed workload rule `transaction_count > 300`.
This threshold is chosen for code exercise, not optimized for attack detection.
No calibration, labels, retraining or external test is claimed.

Process available records in validated block order. Score the current record,
record the raw trigger, apply causal grouping, apply the hard notification budget,
and write the decision. One monitored chain/population/rule defines the grouping
key. The first eligible trigger emits immediately; subsequent triggers within
300 event-time seconds of the last **emitted** notification are suppressed.
Grouped and budget-rejected triggers never extend that cooldown. The admission
limit is five emitted notifications per replay decision UTC day, after grouping.
All suppressed triggers remain in the decision log with their reason.

Duplicates have deterministic identity based on chain and block hash. Re-delivery
does not issue a second notification. Conflicting payloads for the same identity
fail closed. Previously unseen records below the accepted block/time watermark
are logged as late and dropped; earlier decisions are never rewritten. This
strict drop policy is deliberately narrower than a watermark-based cross-chain
monitor. It cannot establish the absence of a source-chain message.

## Time and resource accounting

There are two time domains: historical block `event_time`, and the explicitly
modeled playback clock. Playback starts at 2026-10-25T00:00:00Z, later than the
input. The scheduled arrival of event i is

`playback_origin + (event_time[i] - first_event_time) / speed`.

Speeds are 1 and 1,000,000. Both preserve original event timestamps, block order
and local computation costs. The runner executes without wall-clock sleeps:
these are virtual FIFO schedules, not actually paced 24-hour/accelerated live
trials. Service costs are measured locally; virtual queueing uses those costs.
Do not subtract a historical block timestamp from a playback timestamp to claim
detection latency. Queue and scheduling values are simulated quantities.

The daily budget uses the playback decision date. Compression changes clock-day
semantics in a multi-day study; this one-day smoke test must not be generalized
to production budget equivalence. The intensive slice starts with an empty
state as a separate workload fixture. It is not a continuation of the full-day
state and its notifications must not be summed with full-day notifications.

Measure JSONL read, JSON decode, the core state/score/group/admission call and
decision writing, plus replay-loop wall time, subprocess elapsed time, peak RSS sampled at the end of replay, input/output
bytes and queue length. Report p50/p95/p99 with record counts. Three repetitions
measure execution variability, not statistical independence of incidents. The arrival queue is calculated algebraically; RSS does not measure a materialized burst-buffer queue.
Parquet acquisition and projection are preparation stages measured separately.
The core stage is aggregated in this pilot; claiming separate measurements of
scoring, grouping and admission requires additional instrumentation.

Excluded stages: live RPC, receipt/log/trace acquisition and decoding, bridge
state extraction, live finality, external notification delivery and operator
response. Local buffered/compressed file writing is not a durable remote sink.

## Correctness and recovery

Check unchanged semantic decisions when future events/labels change; historical
observation nulls; duplicate delivery; late drops; UTC budget rollover; suppression
ordering; and deterministic continuation after a serialized-state round trip.
Fixed-rule label invariance does not validate a delayed-label adaptation queue.

The snapshot test is orderly continuation, not arbitrary-crash exactly-once
delivery. A later durability experiment needs an atomic checkpoint/outbox or
idempotent sink, injected crashes between each persistence boundary, and recovery
timing. Seen identities are retained for the entire pilot; long-run state growth
remains an engineering limitation to quantify.

## Full-study decisions still open

Before comparison, freeze incident eligibility, prior exposure, protocol/contract
population, 30–60-day continuous windows, input completeness and licenses. New
candidate incidents are not eligible solely because they differ from Ronin,
Nomad and custody: check earlier book/K4 usage too.

For Elliptic, replace the old delay arithmetic with an explicit release queue.
The draft convention releases step s labels after predictions at step s+d;
they first affect step s+d+1. Zero delay still predicts before reveal. The old
M2 `DELAY=2` uses a different phase convention and is not a zero-delay-ready
implementation. Define initial labelled history, a disjoint temporal calibration
window for each retrained model, a compatible fallback, stable-ID ties and unknown
label coverage before running 0/1/2/4 delays. Keep steps as steps.

No recall, false-positive rate, prevented loss, superiority or JSS-ready novelty
follows from this pilot. The intended paper needs external evidence of a
transferable engineering result beyond this implementation.

## Reproduction and distribution

Use unique `runs/<run_id>/` directories and fail on overwrite. Each run retains
configuration, exact commands, environment, source revision/full source snapshot,
input hashes, decisions and resource summaries. Never run `scripts/run_all.sh`
as part of this pilot. Raw third-party downloads remain in ignored `data/raw/`;
publish provenance, acquisition code and our derived results with attribution.
No release, DOI creation or journal submission is part of this session.
