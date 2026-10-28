# Unused wall-limit continuation candidate

This directory was prepared prospectively for a possible wall-limit termination. It was never accepted or executed on actual source data. Attempt A1 instead ended with externally observed ENOSPC while its original checkpoint remained `OPEN_REQUEST_PENDING`; that condition is ineligible for this candidate.

The separately accepted `../storage_recovery/` protocol preserves that resource failure and prior source-only exposure. It uses compact immutable response blobs and its own cumulative cost accounting. Its acquisition implementation imports explicitly hash-bound pure receipt and JSON/reproduction helpers from this directory; it does not call the wall-continuation authorization or acquisition path.

The empty `independent_scope_preflight.json` is an interrupted write from the disk failure, not a valid review or PASS report, and is excluded from publication. The preliminary archive-reference wrapper here was not activated. Actual replay and reference work use separately reviewed storage-recovery wrappers.
