# Euler event-log feasibility contract

This extends the header-only pilot with a single preselected protocol-day.
It does not establish incident recall, false-positive rates, loss reduction,
or an untouched external test. The research comparison protocol remains draft.

## Population and acquisition

The population is every log emitted by Euler V1 core address
`0x27182842e098f60e3d576794a5bffb0777e025d3` in the AWS Ethereum log partition
for 2023-03-01 UTC, with no topic or attacker filter. The address is documented
in the pinned historical Euler source listed in `incidents/populations/`.
A source revision predating the day is not proof of deployed bytecode or ABI.

This core-emitter population excludes events emitted only by eToken/dToken
proxies or underlying tokens. It is not the set of all protocol transactions.
No ABI event names, monetary amounts or loss estimates are decoded. In
particular, Euler's `Withdraw` source event can represent internal balance
changes and must not automatically be counted as a token cash outflow.

Acquisition scans the address column of every row group and retains every
matching payload row. HTTP ranges require exact Content-Range and the observed
object ETag; each cached range has its own SHA-256. The partially fetched log
object has no claimed whole-object SHA-256. The smaller header object is
downloaded and hashed in full. Source listing, byte counts, complete executed
source, commands and post-run QA are retained beside the acquisition manifest.

Completeness means every matching row in the enumerated AWS partition. It has
not been independently checked against every chain receipt. Historical arrival
time, label availability, receipt status and upstream `removed` are unknown;
missing `removed` remains null. The canonical historical archive is assumed,
without a measured finality delay or live reorganization guarantee.

## Replay decisions

The event identity includes chain ID, block hash, transaction hash and log
index. The ordering key is block number, transaction index and log index.
Equal block timestamps are expected; integer nanosecond timestamps preserve
the source precision. The source happened to contain integral-second times.

The deliberately simple workload rule counts accepted logs in the interval
`(event_time - 60 seconds, event_time]`, including the current event, and triggers
at a count of at least 10. Its configuration was fixed before executing this
rule. The window starts empty; no pre-day history is supplied. This engineering
threshold was not fitted or evaluated as an attack detector.

An exact redelivery cannot affect the rolling count or issue another alert.
Conflicting payloads for one identity fail. Previously unseen records below
the accepted ordering watermark are recorded as late and dropped; prior
decisions are unchanged. This is a strict single-chain policy, not cross-chain
watermark inference. The implementation retains seen identities throughout
the run; long-term state growth remains to be measured.

The first eligible trigger emits immediately. Other triggers within 300
event-time seconds of the last emitted notification are grouped. Admission
then enforces five emitted notifications per playback decision UTC day.
Grouped and budget-rejected triggers never extend the cooldown. Every input
delivery receives a decision record with its score and suppression reason.

The block-only JSON schemas do not describe this event-log format. The new
implementation uses `LogConfig`, strict `decode_event` validation and explicit
versioned event-log state/decision records. Its invariants have separate tests.

## Time, cost and reliability

Six subprocess cells replay the same day: speed factors 1 and 1,000,000, each
repeated three times. Repetitions measure execution variability, not independent
incidents. Playback begins at 2026-10-25T00:00:00Z; arrivals follow historical
time differences divided by speed. There are no wall-clock sleeps.

JSONL read, JSON/hex syntax decoding, the aggregate state/rule/group/budget
call, and buffered gzip decision writing are measured locally. A virtual FIFO
uses those measured service durations to calculate queueing. Its pending count
does not imply a materialized input queue in the measured RSS. Reported
notification-ready offsets mean modeled completion of a local buffered write,
not durable storage, network delivery or operator receipt. Closing gzip and
exporting metric buffers have separately documented measurement boundaries.

All logs with one block timestamp receive the same modeled arrival time. Thus
nonzero queueing at speed 1 is expected even on this sparse emitter population;
it is not evidence of an observed historical arrival burst. A local scheduling
or buffered-write outlier remains in the recorded results rather than being
discarded as an inconvenient repetition.

Acquisition, Parquet extraction and header validation occur before replay.
Their resource accounting is separate. The acquisition fetched about 96.22%
of the log object's bytes despite retaining a small emitter population; do not
present projected reads as a large transfer saving. No current measurement
establishes live RPC or end-to-end production latency.

Snapshot round trips test orderly deterministic continuation. They do not
establish arbitrary-crash exactly-once delivery. Durable outbox/checkpoint
boundaries, fault injection and restart timing remain future work. Compression
also changes playback-day budget semantics for multi-day experiments; this
single-day result does not settle the full-study clock convention.
