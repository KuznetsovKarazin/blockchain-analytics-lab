# Phase 9: incident evidence and historical contract identity

The completed work improves the evidence needed for an independent monitoring evaluation. It does not add detector scores or admit a new incident.

- The fixed 13-entry catalogue screen retains five candidates for historical checks, two disclosure/remediation entries, four unresolved entries and two prior development exclusions. See [the complete screen](SCREENING_RESULTS.md) and [structured facts](screening_results.json).
- Five retained Revest source sets compile to exact creation payloads and runtime bytes. An independent implementation confirms the matches and all 39 top-level storage fields.
- Historical boundary checks find that the registry's Revest pointer changes from the original component to the conventional address ending `dead`. All five original runtime images still match at both boundaries. Code identity therefore does not establish unchanged routing or activation.

The historical check used 67 RPC method invocations and retained 970,115 response bytes. These are acquisition counts, not runtime-monitor throughput or latency measurements. The returned state-proof nodes were not cryptographically verified. Full ownership and administrative-mutation histories were not acquired; the transition time and any intermediate configurations remain unresolved. The frozen procedure stops with Revest reserved for the current original-core definition.

[Russian report](../SESSION_9_REPORT_RU.md) · [Contract checks and limits](CONTRACT_CHECKS.md) · [Independent compilation review](../phase9/qa/revest_compilation_independent_review.md)

## Reusable code

The published programs include [source recompilation](../phase9/revest_gate/compile_retained_sources.py), [historical capability checks](../phase9/revest_gate/probe_historical_capabilities.py), [batch-state checks](../phase9/revest_gate/probe_batch_state.py), [boundary capture](../phase9/revest_gate/capture_boundary_states.py), [write-surface analysis](../phase9/revest_gate/analyze_write_surface.py), and independent auditors. They operate on explicit input files and separately supplied plans; no submitted transaction or exploit execution is involved.

Raw source responses, compiler binaries and outputs, historical responses, frozen acquisition plans and execution receipts are retained in private evidence. This public projection contains owned programs and factual summaries. It is not a self-contained copy of the historical experiment.

The phase 8 methods, thresholds, history rules and results are unchanged. The finite, report-informed candidate frame is not representative sampling; known mechanism diversity is not an evaluated multi-family cohort. No precision, false-positive rate, prevention, independent recall or submission-readiness claim follows from phase 9.
