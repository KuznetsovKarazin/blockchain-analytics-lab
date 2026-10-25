# Local service cost and state growth: frozen phase 5 design

This bounded experiment extends the accepted phase 4 workload study. Its
policies, detector, source inputs, and previously observed outcomes are fixed.
It evaluates a new instrumentation wrapper around the unchanged production
decoder and state machine. It is neither an independent attack test nor a
measurement of historical or live notification latency.

## Population and experimental units

Use the exact 30-day Euler core and Beanstalk Diamond populations in
`protocol_window_20261025T123312_675327Z`: 19,425 and 28,935 records. Include every
selected record, in original order. Retain the full original window configuration
and state across daily files. The budget is five per emitter per UTC day. Greedy,
paced cumulative, and token bucket retain their original code and parameters.

Thirty timing workers cover two emitters, three policies, and five fresh-process
repetitions. Each repetition block contains all six cells in a seeded random
order (seed 20261025). Workers execute serially on the smallest allowed CPU, with
single-thread environment settings. A separate shuffled set of 24 fresh workers
covers the same six cells at prefixes of 1,000, 5,000, 10,000, and all records.
There is only one memory probe per prefix; no confidence interval or repeated
memory experiment is claimed. The prefixes are nested and dependent workloads.

Each process starts cold in application state. Input SHA verification warms the
OS page cache; storage cache state is otherwise uncontrolled. Fresh processes do
not imply cold storage. Shared-host scheduling and CPU frequency remain outside
experimental control. Repetitions describe implementation execution variability,
not additional independent incidents or populations.

## Measured stages

Use monotonic `perf_counter_ns` boundaries for buffered line read, JSON parse,
syntactic decode, the entire `PolicyReplayState.process` call, decision JSON
encoding, and buffered gzip write. Their sum is the declared per-record service.
The core includes validation, identities, state/features, trigger, grouping, and
admission; its internal stages are not separately measured. The decision stream
must match the accepted phase 4 reference byte for byte after canonical encoding.

Trace writing, hash bookkeeping, loop checks, and timing instrumentation outside
these boundaries remain in observed loop wall time and therefore in reported
loop throughput. They are excluded from the hypothetical service used in queue
simulation. Record their measured cost where instrumented and the overall loop
residual; do not equate this residual solely with timer overhead. Record adjacent
clock-call deltas from 10,000 pairs; do not subtract them from service costs.

Interpreter/import startup, source/input preflight, file opens/closes, gzip close,
final state serialization, output hashing, and packaging are named separately.
Some file-open/close bookkeeping lies inside the loop wall boundary; the worker
records its exact boundaries. Parent subprocess elapsed time is separate from
worker loop time. No source network download or ABI interpretation is measured.
Buffered write return is not durable notification delivery; no fsync, remote
recipient, confirmation delay, or operator response is included.

Publish p50/p95/p99 by nearest rank `ceil(p*N)-1`, N, stage sums, CPU time,
loop/subprocess wall time, throughput, bytes, and every repetition. Summarize
the five repetitions with median, minimum, and maximum of run-level statistics.
Do not pool event observations into a confidence interval or select best runs.

## Memory and portable state size

Timing workers stream inputs, decisions, and traces; they do not retain lists of
records or timings. Sample process current RSS and high-water RSS before any
`state.to_dict` or final JSON serialization. No later finalization peak or
checkpoint serialization latency is claimed. RSS includes the interpreter,
allocator, buffers, and instrumentation;
baseline subtraction is not an exact measurement of state memory.

Every memory prefix uses a new process with no timing/decision sidecars. After
processing its prefix, record RSS and the exact identity, order-key, rolling
window, daily-counter, and alert-ID counts; only then serialize its checkpoint
and measure compact JSON bytes. A prefix serialization can therefore never
inflate a later prefix's RSS. The full original BudgetConfig is unchanged even
when input stops early. Ledger cardinalities and serialized sizes are descriptive
evidence of finite-window O(N) retention, not indefinite bounded-memory operation.

## Virtual FIFO scenarios

Closed timing traces feed a separate postprocessor, outside worker measurements.
Freeze five schedules: original event-time gaps; gaps divided by 1,000,000;
and constant rates of 1,000, 10,000, and 100,000 records/s. For record i starting
at zero, integer relative arrivals are `(event_ns[i]-event_ns[0])//scale` or
`i*1_000_000_000//rate`. Preserve original order for ties. Same-block arrivals
reflect block timestamp granularity, not observed network batches.

With measured service s_i, compute `start_i=max(arrival_i,finish_(i-1))` and
`finish_i=start_i+s_i`. Waiting time is start minus arrival; response time is
finish minus arrival. Peak waiting and in-system counts use half-open intervals
`[arrival,start)` and `[arrival,finish)`; exclude zero-length intervals. Report
the finite arrival horizon, completion makespan, waits, response quantiles, and
peak counts. These are modeled quantities, not measured live queues or an
estimate of sustainable long-run production capacity.

Uniform hypothetical acquisition delays of 0/12/60/180 seconds shift arrivals,
starts, and finishes equally; they cannot change queue waits. This is an
algebraic statement, not four additional experiments or observed finality.

## Acceptance and preservation

Before measurements, freeze this protocol, config, exact executed sources,
tests, accepted reference digests, all input identities, and full execution
order. Run only captured sources. Require all 30 timing semantic streams and
full final states to equal their accepted phase 4 B5 references; require all
24 memory prefix streams and full-prefix states to match their references.
Fail on missing records, input/source mutation, invalid timings, subprocess
failure, or digest mismatch. No performance-based run exclusion or tuning.

Validate instrumentation and queue edge cases on synthetic fixtures first.
After actual execution, independently check closed outputs, all hashes, counts,
quantiles, queue scenarios, and original source invariance. Isolated temporary
staging, closed-file verification, an explicit member allowlist, and an atomic
sealed export preserve evidence. Any failed attempt remains separately labelled;
never repair an expected hash to legitimize changed bytes.
