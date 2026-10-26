# Source-bound transfer observations

26 October 2026. This contract adds typed, transaction-level observations to the
existing count-only development pipeline. It defines no attack rule, threshold,
model fit, budget change, independent incident test or prevention claim. Euler
and Beanstalk remain declared development cases; Revest has not supplied detector
features, thresholds or outcomes. Freeze this contract, module and tests before
executing the bounded real-data sample chosen separately by the coordinator.

## Unit and availability

The unit is one explicitly normalized, mined transaction-log bundle backed by
the original Blockscout V2 transaction-metadata response and **all pages** from
its unfiltered transaction-logs endpoint. This is an indexer's representation,
not a raw `eth_getTransactionReceipt` response. The module never disguises it as
JSON-RPC. The collector selects transactions and fixes their expected chain,
block identity, transaction position and historical timestamp before requests.

An observation becomes available only after metadata, terminal pagination,
normalization and all source/identity checks have completed. No provisional
per-log net flow is emitted and later amended. Historical block time is retained
as exact integer nanoseconds; historical `observed_time` remains null. Current
acquisition time is provenance, not the original observation time. No live
finality or reorganization handling is claimed.

Missing/pending metadata, mined ordering fields or execution status raises
`ObservationUnavailable`. This is distinct from a valid successful transaction
with an empty log list. Provider status `ok` maps to 1 and `error` maps to 0;
unknown status is not guessed. A failed transaction with nonempty committed
logs is rejected as inconsistent evidence.

## Source binding and its limits

`observe_transaction_log_bundle(bundle_bytes, source_record, *,
expected_source_record_sha256, monitored_addresses, raw_sources)` is pure and
uses only the Python standard library. It performs no network, filesystem or
detector operation. `canonical_json_bytes` and `canonical_sha256` define the
compact, sorted-key UTF-8 JSON representation, without NaN or Infinity.

The caller obtains `expected_source_record_sha256` from the separately retained
collector manifest. The module checks that digest, the normalized bundle's exact
SHA-256/byte count, and every original response's SHA-256/byte count. It checks
the actual raw page JSON, items count, recorded next cursor, first empty request,
successive cursor equality, URLs and terminal null cursor. Repeated cursors,
missing pages, additional topic filters or unaccounted response bytes fail.
Normalized fields are independently reconstructed from the raw response objects
and must match the supplied bundle exactly. Merely setting `complete=true` does
not satisfy these checks.

The evidence tier is `provider_pagination_exhausted_structure_checked`. It does
not prove that the provider indexed every chain log or did not omit a first or
last log. Source digests bind captured evidence; they do not authenticate a
blockchain receipt root. The parser cannot turn an invented manifest into an
independent source. The collector and external audit remain responsible for
the acquisition record, frozen selection and context source. A complete
comparison against an independently acquired source is a separate future gate.

The required source record uses schema `transfer_source_record_v1`:

- `source_kind = blockscout_v2_paginated_transaction_logs`, `chain_id`,
  `requested_transaction_hash`, UTC `acquired_at_utc`;
- `selection_manifest_sha256` and `normalizer_source_sha256`;
- `normalized_bundle_sha256`, `normalized_bundle_bytes`;
- `expected_block`: block hash/number, transaction index, exact event-time ns;
- `metadata`: original response key, URL, SHA-256 and byte count;
- `pages`: the same response identity fields plus `request_params`,
  `next_page_params`, `item_count` for every page in request order.

`raw_sources` maps those keys to exact HTTP response bodies. The bundle uses
schema `transaction_log_bundle_v1`, contains chain/block/transaction identity,
transaction index, `event_time_ns`, normalized `receipt_status` (only the
provider's execution status), and `logs`. Each log contains `address`, `topics`,
`data`, global block `log_index`, block hash/number, transaction hash/index and
`removed` (null or false). Extra metadata may be retained in the source record;
it does not upgrade the evidence tier. A claim that an actual RPC receipt was
acquired is rejected for this adapter.

## Provider normalization and order

Blockscout transaction metadata provides `hash`, `block_number`, `position`,
`timestamp` and status. Its log objects provide the emitter address, `index`,
data, topics and transaction/block identity. Any nonnull per-log
`block_timestamp` must also agree with the bound transaction timestamp.
The emitter is taken from
`address` or `address_hash`; if both supply hashes, they must agree.
`smart_contract` is **not** used for emitter identity: the inspected provider
view can populate it from the transaction recipient, which need not emit a log.

Only trailing null topic slots are stripped. Internal null slots are malformed.
Provider numeric positions are integers or canonical hexadecimal quantities;
the normalized bundle requires actual integers and rejects booleans. Addresses,
hashes and data have exact lengths/byte syntax and are lowercase after
normalization. Unknown `removed` remains null; true is unsupported.

Provider pages may present logs in descending index order. After all pages have
arrived, the module reconstructs and sorts their complete collection by global
`log_index`. The supplied normalized bundle must already have that order. It
must contain one transaction/block only, unique indices and consecutive indices
within the transaction. The first global index need not be zero. Duplicate,
conflicting, unsorted normalized or internally gapped bundles are rejected;
there is no silent deduplication or repair. Contiguity detects interior gaps,
but cannot establish absence of omitted prefix/suffix logs.

## Typed observations and exact features

The known `Transfer(address,address,uint256)` event signature is classified by
its entire layout, not topic zero alone:

| Layout | Classification | Value treatment |
|---|---|---|
| Three topics, canonical zero-padded indexed addresses, exactly 32 data bytes | `erc20_shaped` | Decode uint256 raw amount |
| Four topics, canonical indexed addresses, empty data | `erc721_shaped` | Recognize NFT-shaped event; no fungible amount aggregation |
| Different topic zero or no topics | `opaque` | Count, retain provenance; no invented meaning |
| Matching topic zero with malformed/unsupported layout | Reject entire bundle | No partial transfer aggregate |

The standard-library SHA3-256 function is not used as a replacement for Ethereum
Keccak. The fixed topic is explicit. This parser verifies event layout only:
an arbitrary contract can emit the same layout. It does not establish ERC-20
compliance, deployed ABI equivalence or the meaning of a protocol-specific event.

For a nonempty, duplicate-free, explicitly supplied address set, each qualifying
event is attributed separately by `(chain_id, token emitter)`. The zero address
cannot be a monitored member. The categories are disjoint:

| Category | Condition |
|---|---|
| External in | Nonzero sender outside the set; recipient inside |
| External out | Sender inside; nonzero recipient outside |
| Internal | Both endpoints inside, including self-transfers |
| Mint-from-zero pattern | Zero sender; recipient inside |
| Burn-to-zero pattern | Sender inside; zero recipient |

Events with neither endpoint monitored remain in the overall shape counts but
do not produce a population flow. Zero-valued transfers count as events. Mint
and burn names identify zero-address event patterns, not verified supply changes.

Per token, retain each category's count and raw amount sum, total participating
transfer count, `net_external_in_raw = external_in_raw - external_out_raw`, and
`net_event_in_raw = net_external_in_raw + mint_from_zero_raw - burn_to_zero_raw`.
Internal movement contributes zero to both net values. Tokens are never added
together. All arithmetic uses arbitrary-precision Python integers. Every emitted
field ending `_raw` is a signed/unsigned base-10 **string**, declared by
`raw_amount_encoding = base10_integer_string`, so JSON readers do not silently
round values above 2^53. Sums may exceed uint256 even though individual events
cannot; signed net values may be negative.

No decimals, symbols, prices or initial balances are inferred. Transfer-event
sums are not actual balance changes: omitted/nonstandard events, rebasing,
fees or dishonest emissions may invalidate that interpretation. Native currency,
call traces and economic losses are outside this adapter. No risk score or
notification is generated by these features.

## Available development evidence

The accepted Euler-core and Beanstalk-Diamond JSONLs retain only logs emitted
by those addresses. Underlying token Transfer logs can be emitted elsewhere;
therefore those filtered streams cannot validate complete asset flow. They may
serve as a source-bound subset check when an ordinary development transaction's
full provider log bundle is newly captured. Matching the subset proves only
that subset, not full transaction completeness.

The coordinator separately freezes a small ordinary-development selection,
bounded requests, preserved failures and stopping rule before acquisition. No
replacement is selected because a transaction has many transfers or gives a
desirable feature value. Synthetic correctness is required first. Failure to
obtain provider data remains an availability result, not successful zero flow.
Current work does not require protocol-specific deployed ABI claims and does
not resolve Revest's population or external-cohort gates.

## Acceptance tests and reproducibility

Run `python -m unittest discover -s papers/monitoring_jss/tests
-p test_transfer_observation.py -v` from the repository root. The suite covers
21 adversarial synthetic cases: exact category accounting, self/zero/mint/burn,
uint256 and larger sums, signed values and portable JSON, token separation,
ERC-721 signature collision, malformed matching events, unknown versus empty
success, failed logs, page/order invariance, duplicate/gap/mixed identities,
recipient-versus-emitter distinction, source/bundle tampering, incomplete or
filtered pagination, topic padding, integer/JSON strictness and future-bundle
independence. These fixtures contain no historical incident payloads.

The pure adapter has no cross-transaction accumulator, deduplication ledger,
calibration or delayed-label state. Existing pipeline restart/budget invariants
remain separate. Deterministic repeatability of one complete observation must
not be presented as new end-to-end exactly-once behavior.

## Primary specifications and inspected implementation

- [ERC-20](https://eips.ethereum.org/EIPS/eip-20): Transfer layout, zero values,
  zero-origin creation convention and optional token metadata.
- [ERC-721](https://eips.ethereum.org/EIPS/eip-721): indexed token ID distinguishes
  its Transfer layout from the fungible layout.
- [Solidity ABI specification](https://docs.soliditylang.org/en/latest/abi-spec.html):
  indexed/non-indexed encoding and canonical address padding.
- [Ethereum JSON-RPC](https://ethereum.org/developers/docs/apis/json-rpc/): receipt
  status/log context and pending/missing distinction; this adapter does not claim
  that such a receipt was acquired.
- [Blockscout transaction view, pinned source commit](https://github.com/blockscout/blockscout/blob/9cd48cc0708d520f093ec8a8c37d9a998b258171/apps/block_scout_web/lib/block_scout_web/views/api/v2/transaction_view.ex):
  `apps/block_scout_web/lib/block_scout_web/views/api/v2/transaction_view.ex`,
  Git blob `b462c59a68adeecc24613bdebac97329c26b8ad1`, especially emitter versus
  `smart_contract` and padded topic fields. Captured
  provider-source provenance is retained by the collector; a code snapshot does
  not prove which server version answered any request.

Specifications were checked on 26 October 2026. Only short factual requirements
are paraphrased; third-party source text is not embedded in this contract.
