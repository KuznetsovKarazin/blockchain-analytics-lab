# Local crash recovery: bounded SQLite/outbox experiment

This experiment adds process-crash recovery to the already checked Euler
event-log rule. It verifies conditional, unique logical effects in a local
idempotent test sink. It does not establish exactly-once external message
delivery, power-loss survival, or production reliability.

## Transaction and sink boundaries

The local SQLite transaction atomically commits the input cursor, complete
`LogReplayState` snapshot, decision record and optional outbox record. Only
after that commit may the dispatcher call the separate sink database. The
sink transaction records each delivery attempt and inserts at most one effect
for its unique `alert_id`; a conflicting payload for the same ID fails. The
dispatcher acknowledges the outbox only after the sink commit.

After restart, pending outbox records are dispatched before consuming new input.
The committed cursor determines the replay suffix. Input, configuration and
implementation hashes must agree with the stored identity. The existing replay
core still handles duplicate event identities and late records; this experiment
adds persistence boundaries without changing the count/group/budget rule.

Both operational databases use SQLite WAL with `synchronous=FULL`, checked by
the worker. A separate parent launches an actual process and requires exit
code 73 from `os._exit` at each injected boundary. A new worker then completes
the day. This is abrupt process termination at explicit program locations,
not power failure or interruption in the middle of a SQLite system call.

## Frozen experiment

The input contains the same 1,247 Euler core events from 2023-03-01. Every
scenario injects at the first emitted notification, input sequence 9 (zero
based). Three uninterrupted repetitions and three repetitions of each of the
four fault points produce 15 cells and 12 actual interrupted/resumed processes.

| Fault boundary | Expected committed cursor at restart | Pending outbox | Sink effects before restart |
|---|---:|---:|---:|
| Before local commit | 8 | 0 | 0 |
| After local commit, before dispatch | 9 | 1 | 0 |
| After sink commit, before local acknowledgement | 9 | 1 | 1 |
| After local acknowledgement | 9 | 0 | 1 |

The historical timestamp offset supplies a deterministic playback clock.
Availability, feature-ready and decision timestamps are equal under a declared
zero modeled service delay. Actual database processing times are measured
separately and do not enter these semantic timestamps. The experiment therefore
compares deterministic decisions across restarts without pretending that the
zero-delay clock is measured latency. Decision semantics also match the prior
independently audited event-log pilot exactly.

## Artifact handoff and the excluded first run

The first run `durable_20261025T090940_001269Z` is quarantined in its entirety.
Although worker-local comparisons completed, later byte-level verification
found a changed final database in one cell and unrecorded sidecars in five.
Four final database-plus-sidecar copies recovered earlier cursors; another
produced malformed-database errors. All its original summaries and the bytes
as observed are preserved, including the stale sidecars. Its timing values are
excluded. The underlying cause remains unresolved.

The replacement run `durable_20261025T092104_711695Z` uses an explicit artifact
handoff as mitigation, without claiming to have identified the earlier cause.
Operational databases reside in a unique local temporary directory. At successful
completion, each database must finish `wal_checkpoint(TRUNCATE)` with result
`[0,0,0]`, switch to DELETE journal, and produce a standalone SQLite backup whose
integrity check passes. Files and directories are synchronized after close.
Only closed files and preserved unclean diagnostic snapshots are copied to the
workspace. A private ZIP is created and verified before the parent process exits.

At each injected crash, untouched unclean database/WAL/SHM bytes are retained.
The post-crash SQL inspection runs on disposable copies. Thus inspection does
not perform recovery on the worker's original files before its timed restart.
Independent verification likewise examines copies and verifies the immutable
archive and file hashes after the orchestration has ended.

## Replacement-run results and interpretation

Every cell ends with 1,247 identical decisions, the same final state, five
acknowledged outbox records and five unique sink effects. The three
after-sink-before-ack cells each record six delivery attempts: the first effect
is retried once, with no additional logical insertion. Other cells have five
attempts. Unique effects are conditional on the sink's idempotency contract;
duplicates still occur at the delivery-attempt level.

The three uninterrupted local loops take 1.206–1.585 seconds. Their measured
local-commit p99 is 2.030–5.443 ms. These timings use the temporary runtime
filesystem documented in the manifest and are not a controlled speed ratio
against the earlier nonpersistent replay.

For the 12 resumed processes, open/hash/integrity-check/state-restore time is
2.497–4.824 ms; parent-observed restart through completion is 1.384–1.591 seconds.
The latter includes process launch, recovery, the remaining input, final sealing
and export. Pending-outbox draining is timed separately. Neither value is
network delivery latency or a bound on operational downtime. The timer does
not include an actual outage wait or fault detection delay.

The final operational local and sink databases together occupy 2,121,728 bytes
per cell. Sealed copies and diagnostic crash snapshots are additional evidence
storage, excluded from that figure. The private replacement evidence archive
contains 278 verified members, is 11,440,221 bytes, and has SHA-256
`03af89f03511f2eb034e5ef5fd113d1ebfa7ef625b74fc7e4ed0524b98455508`.

Six focused SQL tests validate idempotent attempts, conflicting-payload rejection,
resume identity, atomic rollback and final sealing. The real subprocess cells
exercise the actual crash boundaries. The author-written artifact verifier is
`qa/verify_durable_replay.py`; independent review is recorded separately.

The selected input position and single local sink limit the result. Other
positions, concurrent writers, adversarial disk corruption, network partitions,
sink availability failures, kernel crashes and power loss remain untested.
