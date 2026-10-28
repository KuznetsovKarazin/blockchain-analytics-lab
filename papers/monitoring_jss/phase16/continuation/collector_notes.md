# Candidate continuation collector

This candidate has not been applied to real evidence. It is outside the original
frozen implementation. Root must prospectively accept the continuation amendment
for both cases after A1 closes and before calling this constructor on A1 bytes.
The constructor authenticates and copies payload ranges; it is not a metadata-only
eligibility probe.

```python
session = ContinuationSession(
    original_plan['collector'], new_output / 'transport', a1_collection,
    parent_bindings=sealed_parent_bindings,
    continuation_plan_sha256=accepted_new_plan_sha,
    original_plan_sha256=validated_original_plan_binding['sha256'],
    manual_reacquisition=exact_final_failed_get_or_none,
    repo=repo,
)
if exact_final_failed_get_or_none is not None:
    session.reacquire_final_failed_range()  # Explicit operation, at most once.
reader = SourceReader(source, session, new_output / 'cache', pa, pq, reuse=reuse)
reader.open()
# Frozen SourceReader projection APIs remain available.
session.close('COMPLETE')
```

The original collector is imported only after its frozen SHA256 is checked. Its
strict HTTP range method is reused with cumulative counters and a monotonic clock
anchored to A1's actual UTC start. The new absolute deadline is exactly that start
plus14,400seconds, including time between stages. The original5,000GET and16GiB
response-byte ceilings include all A1 and A2 attempts and partial/unaccepted bodies.
For budgeting, each failed/pending GET is charged its full declared length:
`cumulative_charged_response_bytes = cumulative_response_bytes +
reserved_parent_failed_response_bytes + reserved_new_failed_or_pending_response_bytes`.
The ordinary response-byte fields remain exact retained counts. This conservative
reservation handles possibly unreturned buffered bytes and does not claim a
complete wire-byte measurement. It is checked before every new GET.
Automatic retries remain zero. The one declared manual reacquisition counts as a
retry in `cumulative_retry_count`, with explicit original request lineage.

Eligible A1 closures are narrowly checked: an explicit wall-guard failure, a
pre-GET `wall/request cap` failure with request count below5,000, or a producer
COMPLETE whose final elapsed time exceeds7,200seconds while every accepted GET
finished within its original deadline. Protocol acceptance must additionally
establish that only the operational wall condition justifies continuation.
A narrow separately disclosed exception accepts only the sole final failed GET
with `TimeoutError: timed out`, `TimeoutError: The read operation timed out`, or
their exact `URLError: <urlopen error ...>` wrappers. It must start in the original
final60seconds, complete at/after the deadline, and precede the finalized closure;
UTC and original monotonic closure clocks must agree within2seconds. Any recorded
response headers must all meet the exact original acceptance predicates; an
absent response-header tuple requires zero retained bytes. The classification is
`DEADLINE_ASSOCIATED_TIMEOUT_CAUSALITY_UNRESOLVED`: the actual timeout argument was
not recorded, and its exact causal contribution is unknown. Generic network,
DNS/SSL/certificate, data/schema and identity failures remain ineligible.
Expired14,400second deadlines and changed sealed metadata are rejected.

`parent_bindings` maps original collection-relative filenames to exact SHA256
values; `None` explicitly binds absence. Required keys are `frozen_plan.json`,
`transport/plan.json`, `transport/session.json`, `transport/requests.json`, and
`runtime_source_paths.json`, plus the applicable `failure.json` or
`collection_result.json`. The runtime path map may be absent following a failed
initial source open; only the canonical source-ID cache path is then inferred.
The original hash-bound inventory restricts every new request to the same sources.
`original_plan_sha256` comes from the validated original accepted-plan binding;
it is required for the producer-COMPLETE branch. The original pipeline's runtime
`frozen_plan.json` is a reserialized copy and need not have the same file hash as
the accepted input bytes. Its separate parent evidence hash remains enforced.

All positive A1 bodies are rehashed before any A2 GET. Successful ranges are
stream-copied into a new sparse cache at their original offsets. Failed A1 bodies
are checked at the original path and remain there, unaccepted. Even a complete
body rejected after the original deadline requires the explicitly declared new
GET. Reacquisition must reproduce any retained failed-response prefix; a
contradiction stops A2 and excludes its new range from usable evidence.

Evidence remains separated:

- `inherited_requests.json` preserves the complete original A1 ledger bytes.
- `requests.json` contains only A2 requests, using cumulative global ordinals.
- `session.json` reports inherited, new and cumulative costs and timestamps.
- `accepted_range_evidence.json` is an explicitly named successful evidence
  view, with original attempt/ordinal references; it never replaces cost ledgers.
- Per-source cache manifests distinguish unchanged inherited receipt wrappers
  from new receipts. Source manifests preserve the frozen projection description
  and add explicit evidence origins.

`session.requests` is the cumulative in-memory ledger used by the original HTTP
method's request cap; `session.new_requests` is the A2-only view. Neither the
failed original request nor its costs disappear. Any new HTTP failure latches A2
closed. COMPLETE also checks the absolute deadline after CPU preparation and
after checkpoint serialization, and rehashes all sealed parent metadata. No third continuation or automatic resume is
implemented.

The new cache adds disk usage approximately equal to successful inherited bytes
plus newly accepted ranges. The original cache is never written or removed.
Range copying uses at most1MiB per read plus receipt metadata. Existing one-attempt
audit/delivery tools must not be pointed at the continuation as if it were an
ordinary original capture; use the explicitly bound continuation adapters.

Focused candidate checks (synthetic files and mocked HTTP only):

```bash
PYTHONPATH="$PINNED_PYARROW_SITE" python -m unittest -v test_collector.py
```

Checks cover clean and partial deadline closures, conservative cumulative accounting, exact
manual retry lineage, immutable original evidence, header/footer inheritance with
a real synthetic PyArrow26 Parquet roundtrip, conflicting bytes, narrow timeout
and exact wrapper handling, generic-error exclusion, failed-new-GET latching,
and final CPU/checkpoint work crossing the deadline.
