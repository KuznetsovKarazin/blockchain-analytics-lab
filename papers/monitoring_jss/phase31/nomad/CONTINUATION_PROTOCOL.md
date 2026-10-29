# Conditional source-only continuation amendment

This amendment is fixed before any detector scoring and before a continuation is launched. The first source attempt retains its original 1,800-second deadline and original manifest. This amendment does not convert a failed attempt into a successful one.

Observed transport latency is approximately five seconds per ranged request. The first two complete nonempty days required about eight minutes despite transferring less than one GB. Therefore the initial wall cap may bind before all twelve nonempty days are complete. This is a transport constraint, not a detector-dependent stopping rule.

A second attempt is permitted only if the first terminates INCOMPLETE at its original wall cap. It must:

1. Retain the first attempt's immutable incomplete manifest, request/session receipts and complete normalized day bundles.
2. Verify that the prior frame/census/core and canonical bundle/observation hashes are unchanged. Reuse only days fully validated against original log payloads, all selected transaction identities and original receipt statuses. Partial source days are never represented as complete.
3. Acquire only remaining days of the exact same Phase28 window/core. Partial Parquet source bytes from the failed attempt are not silently recycled; any reread is counted as a new transfer.
4. Limit the sum of both attempts to 5,000,000,000 response bytes and 1,600 requests, including separately recorded transaction-listing requests/bodies. Reserve 100,000 bytes and twelve requests for new listings. Each attempt has at most1,800 active seconds; the combined active-source wall time is at most3,600 seconds.
5. Publish a combined final normalized source only if all thirty days and exactly930 selected transactions pass. The final manifest records both attempts, exact complete-day reuse and cumulative resource accounting. If the cumulative cap binds, the result remains incomplete and is not scored.

All feature rules, history policies, thresholds, grouping, budgets, nominated core and temporal window remain unchanged. No known-attack reference ledger is consulted before a complete label-blind replay is sealed.

## Concrete pre-score continuation

The first attempt ended with a `URLError: <urlopen error timed out>` at1800.032 recorded seconds. Its final request was limited by the2.269 seconds remaining before the original deadline. Eight nonempty days (36 selected transactions) and16 zero-selected days were fully validated; the incomplete July27 day is re-read. The remaining nonempty dates are July27, July30, July31 and August1, containing894 selected transactions.

The earlier attempt consumed2,363,605,540 ranged response bytes. Remaining full log objects total905,086,518 bytes, and the largest observed completed-day transaction projection is76,957,156 bytes. Reusing this overhead as a planning bound gives3,576,520,682 bytes, leaving only23,479,318 bytes below the initial3.6GB limit before listing costs and variability in the unobserved transaction projections. A conservative cumulative5GB ceiling is therefore fixed before the continuation; this is not a claimed measured requirement. See `CONTINUATION_LIMITS.json` for exact source-bound values and pre-launch timestamp.
