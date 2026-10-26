# Phase12 independent QA

Independent checks passed for the namespace layout, retained request accounting and three checkpoint enumerations. These results do not admit LiFi to the scientific evaluation population or establish continuous routing history.

The producer and independent auditor each made one layout compilation and one version probe: **2 compilations and 2 version probes** in total. Both used the pinned Solidity 0.8.7 compiler. Independently serialized inputs produced identical compiler output. The probe imported the retained structs; their member offsets and packing were checked against the actual assembly storage-pointer assignments. Mapping-key padding and dynamic-array indexing were reviewed separately under the Solidity storage and ABI rules. These formulas are not fields emitted by `storageLayout`, and the synthetic probe was never deployed.

**25 offline checks** covered the retained constructor events, canonical and malformed ABI encodings, ordered add/replace/remove operations, failed-event isolation, independently derived storage keys, selectors crossing the eighth/ninth-element boundary, whole-word address stride, valid position zero, unused high bits, and missing, extra or duplicate normalized proof keys. These fixtures are implementation checks, not historical observations.

The first acquisition stopped after **5 RPC methods and 29,835 response bytes**. Chain identity and three headers succeeded. The first log request covered exactly 10,000 inclusive blocks and received HTTP 400 with JSON-RPC error 35. No log chunk completed; no checkpoint storage was requested. The refusal was preserved. It does not establish an empty event history or a general numerical API limit.

A separately accepted continuation reused those four successful chain/header responses and made **15 `eth_getProof` requests**, retaining **345,304 bytes**. It requested **139 block-slot values** across three checkpoints; this is a request count, not a count of globally distinct slots. No log request, header request or provider fallback was repeated. Across both attempts the totals are **20 RPC methods and 375,139 response bytes**.

| Checkpoint | Block | Enumerated facets | Enumerated selectors | Requested block-slot values |
|---|---:|---:|---:|---:|
| Creation block end | 13,984,588 | 1 | 1 | 8 |
| Window start predecessor | 14,233,162 | 9 | 25 | 64 |
| Window end predecessor | 14,426,367 | 9 | 28 | 67 |

The actual audit imported no acquisition modules. Using an alternate retained Keccak implementation, it independently reconstructed every requested slot, decoded every returned word, checked complete key coverage, account-field consistency across each checkpoint's batches, array positions and inverse mappings, and matched the producer's three state projections. It also rechecked all original request and response bytes, including the failed log request.

The creation-block-end owner and enumerated registry agreed with the retained constructor bootstrap. Constructor execution and block-end state remain different observation times. Between the window endpoint enumerations, five selectors appeared, two were absent, and fourteen common selectors had different facet addresses. None of those fourteen differences was solely a position change. Owner and source-guided CBridge fields were equal at the endpoints; these observations do not identify intermediate changes, timing or cause.

Proof nodes were retained and shape-checked, **not cryptographically verified against the header state root**. Enumerated arrays and their inverse keys do not exclude hidden mapping keys. Event history, all possible writers, active code for every facet and continuous routing remain unresolved. CBridge fields are source-guided interpretations and are not established effective configuration. No detector score, method adjustment, window change or scientific admission resulted from this phase.
