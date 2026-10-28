# Phase16 external-case results and public evidence

The fixed Li.Fi and Revest experiments are complete. The primary semantic method
did not improve exact execution coverage in either case. At B=5 notifications
per UTC day, all three policies give Li.Fi count 1/1 versus semantic 0/1 and
Revest 0/2 for both methods. These fractions describe verified known executions,
not exhaustive incident inventories. See the
[results](manuscript/EXTERNAL_CASE_RESULTS.md) and
[all 54 aggregate cells](manuscript/EXTERNAL_CASE_AGGREGATES.json).

All three verified references had positive core-boundary token outflow but
insufficient earlier same-token positive history within their UTC day. Histories
were [1,0], [0] and [0], below the minimum of 19. Their semantic coverage loss
therefore occurred before rank thresholding, grouping or budget allocation.
The count feature was 39, 7 and 7 against a threshold of 10. The experiment
measures this applicability limit; it does not establish general method
superiority, significance, precision, false-positive rate or prevention.

## Check the published result

Start with [public_evidence/README.md](public_evidence/README.md). That directory
provides exact selected observations, sealed method/admission decisions,
reference adjudication and source-fact reports, joined results, and a separate
portable path map. Its verifier uses the unchanged frozen exact join to check
and aggregate the sealed decisions. It does not run a new detector experiment.
The verification report describes the checks actually performed.

Original hash-bound manifests retain their historical path strings and bytes.
Portability is implemented separately; a relocated path is accepted only with
the original expected SHA-256. A historical PASS report records an earlier
audit, not a fresh proof of source completeness on the reader's machine.

## Execution code and provenance

| Material | Role |
|---|---|
| [protocol/](protocol/) and [acceptances/](acceptances/) | Frozen two-case scope, methods, windows, reference rules and original acceptances |
| [storage_recovery/](storage_recovery/) | Executed compact recovery, cumulative accounting, independent source audits, and gated replay/reference wrappers |
| [storage_recovery/actual/](storage_recovery/actual/) | Original recovery amendment and execution gates, with disclosed prior source exposure |
| [reference/](reference/) | Exact transaction source facts and unchanged post-decision reference join |
| [qa/](qa/) | Independent decision and interpretation checks and their focused tests |
| [continuation/STATUS.md](continuation/STATUS.md) | Explicitly inactive wall-limit candidate; only its two pinned helper modules were reused by the executed recovery route |
| [delivery/](delivery/) | Byte-preservation/restoration code and recorded synthetic validation |

The inactive wall-limit candidate is retained as history, not advertised as a
complete runnable route. Its prospective references can name files that were
never created. The accepted storage-recovery route preserves A1's observed disk
failure, pending-response uncertainty and prior source exposure; it does not
convert the failed original attempt into a successful or globally blind one.

The original code is published byte-for-byte. Some operational documentation
refers to private delivery catalogs, including `delivery/a1_durable_preservation.json`
and the concrete `delivery/COMPACT_A2_DELTA.md` command sheet. Those personal
saved-file manifests are not part of this public tree. No substitute has been
written under their old filenames or hashes. The generic restoration procedure
is in [COMPACT_A2_DELTA_RESTORE.md](delivery/COMPACT_A2_DELTA_RESTORE.md).

## What requires the full source archives

The public review package supports verification from selected observations and
sealed decisions. It does not contain the multi-gigabyte accepted source-response
bodies or the 18 reused whole source objects. A fresh full-source audit requires
those exact archives or a separately bounded acquisition of the declared source
objects. The original acquisition and audits covered 113 source objects: the
37 study dates plus two exterior header-control partitions, producing 60
case-days. Neither the public package
nor historical archive checks establish receipt-root authentication or universal
chain completeness.

Both reference inventories remain `KNOWN_SUBSET_ONLY`. Two exact candidate roles
remain unresolved, and Revest has additional unresolved document locators.
Full copyrighted primary-page retrievals are not redistributed; authored factual
evidence, source URLs, locations and hashes are retained. Unknown notifications
are not classified as false positives.

A future initialization comparison must use its own declared protocol and
exposure history. No warm-start benefit has been measured by this experiment.
