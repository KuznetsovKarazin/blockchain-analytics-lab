# Fixed development sample for source-bound transfer observations

The sample is selected from the accepted Euler core emitter stream on 1 March
2023: 1,247 logs in 218 transactions. Freeze the first ten unique transaction
hashes in canonical (block, transaction index, log index) order. The selected
transactions have 58 archived core logs. The calendar day is a previously used
development workload, not adjudicated attack-free traffic. No labels or detector
scores influence selection. Failures remain in the ledger; no replacements.

Fetch only Blockscout public Ethereum v2 transaction metadata and all log pages
for each fixed transaction. Exactly one metadata request and at most ten log
pages per transaction are permitted: at most 110 requests. Each response is
limited to 1 MiB, with a 30-second timeout and two workers. No retries, redirects,
provider fallback, other transactions, token metadata, balances, prices, traces,
state changes or attack-label queries are allowed. Preserve every original HTTP
body and receipt privately, including failed attempts. A partial or capped
pagination chain is unavailable, never a zero-log observation.

Only explicit terminal next_page_params=null establishes exhaustion of this
provider's pagination. Each next request must use exactly the preceding cursor;
reject loops and unexpected query keys. Normalize the complete returned log
collection by global log index; require unique contiguous ascending indices in
the normalized transaction bundle. Preserve original page order separately.
This structural check cannot detect an omitted non-core prefix or tail by the
provider; it does not establish receipt/root or full-chain completeness.

The bound transaction metadata supplies transaction hash, block number, position,
execution status and exact UTC timestamp. Cross-check order, block hash and time
against the archived source. Every raw log must match the transaction/block;
validate optional raw block timestamps and transaction indices if present.
Missing ordering/time fields remain unavailable rather than being invented.

Normalize address/address_hash as the emitter; if both exist they must agree.
Ignore smart_contract for emitter identity: upstream Blockscout code uses it for
the top-level transaction recipient. Its topics array contains four positional
slots; strip only trailing nulls and reject interior nulls. Four non-null topics
remain four. Ignore provider-decoded labels, method names and token metadata.
The immutable upstream source reference is documented in source_provenance.json;
it does not establish which exact code revision is deployed at this instance.

Compare canonical payload bytes for every provider log emitted by Euler core
against all archived core logs of the selected transaction, with no extra or
missing core logs. The projection includes chain/address, block and transaction
identities, order, timestamp, topics and data. Unknown source-specific removed,
observed-time and acquisition-row fields are not treated as equal known facts.
This is normalized payload equality, not equality of the original JSON formatting.

Only after source binding and structural checks may transfer_observation.py
produce its predefined syntactic event observations. Keep per-token raw integer
amounts as decimal strings and never sum across assets. Status, shape counts and
hashes may be public; raw responses, exact normalized records and token flows
remain private. No detection rule, threshold, attack label, economic loss, actual
balance change, token-compliance or intervention claim is part of this exercise.

Before the first selected transaction request, freeze this protocol, configuration,
public selection, collector/core source hashes and offline test results. Retain
all run commands, timestamps, HTTP statuses, SHA-256/byte receipts, and exclusions.
Do not overwrite any output or change method bytes after observing results.
