# Independent historical-capability review

**PASS at the stated capability scope, 26 October 2026.** The auditor reconstructed all 11 request/response pairs from retained bytes without making additional network calls. Request and response hashes, RPC envelopes, parameters, per-provider counts and actual byte/time limits agree with the capture. Total retained responses are **42,538 bytes**: five Publicnode calls and six dRPC calls.

Publicnode returned chain ID 1 but did not supply the requested old header, runtime, storage or trace data through the selected public route. Those failures establish a limitation of that route at the time of the probe, not global unavailability of Ethereum history.

dRPC supplied the registry runtime and owner slot at block 14,300,000, whose returned timestamp is **1 March 2022, 08:25:09 UTC**, inside the proposed window. The complete 6,348-byte runtime matches the independently compiled registry. The owner at that sample has **170 bytes of nonempty code**. Therefore a claim that the registry owner was an EOA throughout the whole interval cannot use this sample as support; the conditional EOA-only shortcut is unavailable.

The returned administrative initialization trace was independently matched to the original phase 7 transaction and block: full calldata, sender, recipient, value, transaction position and block hash agree. It is a successful top-level `CALL`, with empty trace path and zero subtraces; the retained transaction reports success. There is no hidden-ancestor rollback ambiguity for this particular sample.

The probe's existing Boolean checks are weaker than a continuity verifier: the aggregate capability Boolean does not require a valid in-window header, and its trace-schema test chiefly checks field presence and selector. The actual successful sample passes the stronger independent checks above. Preserve the executed probe unchanged; a subsequent continuity collector needs stronger validators rather than borrowing those Booleans as proof.

The result supports **CAPABILITY_AVAILABLE_ROUTING_UNPROVED**, with zero case admissions. It establishes neither complete provider indexing nor historical routing continuity. In particular, a successful child trace can be rolled back by an ancestor; a terminal empty page proves exhaustion of returned pagination, not absence of omitted index entries; equal endpoint state does not exclude intermediate changes.

The proposed continuation needs exact UTC boundary bracketing, complete ownership intervals, all relevant registry/provider setters, correct `CALL` storage context, receipts and full ancestor error context. Receipt status zero is a valid reverted outcome, not malformed evidence. Trace preorder can drive a mutation replay only after source review establishes that relevant writes cannot interleave with external calls. Newly referenced components require a predetermined provenance/closure rule or an unresolved terminal result. Provider-index completeness remains an explicit assumption at this evidence tier.

Machine-readable findings and evidence hashes: `revest_capability_independent_review.json` (private evidence). Offline reproducer: [review_revest_capabilities.py](review_revest_capabilities.py). Full RPC source bytes remain private.
