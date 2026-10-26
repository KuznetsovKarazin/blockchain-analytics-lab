# Fixed-core day adapter

`fixed_core_adapter.py` provides a pure Ethereum normalization step for the accepted fixed-address workload. It accepts multiple source parts, preserves covered days with no selected transactions, and rejects unavailable days. It does not acquire files, run a detector, admit an incident or certify the upstream archive.

The adapter reads complete **normalized rows** for every declared logs, transactions and blocks part. It checks exact part membership, row counts, normalized-row hashes, source-receipt bindings and configured part/row/declared-byte caps. The inventory must identify all three tables even when a logs part has zero rows. Source ETags are opaque identifiers. An independent collector/auditor must still verify listing exhaustion, HTTP object/range identity, original bytes, Parquet schemas and normalization. A locally consistent inventory cannot prove those facts.

## Sequence

1. Supply the fixed sorted core addresses, a complete day inventory and all log parts to `select_core_day`. The selection contains exactly the transactions with at least one core-emitted log. Topics, transfer amounts and labels do not affect selection.
2. Persist and seal the canonical selection before expansion or transfer decoding. Canonical hashes here cover JSON bytes **without a trailing newline**. `prepare_day` checks the supplied seal and recomputes selection from the same complete log parts before accepting it.
3. Supply all three tables plus the immediately adjacent predecessor and successor headers. `prepare_day` checks consecutive headers and increasing times, UTC boundaries, unique transaction positions and hashes, transaction counts against full headers, actual integer statuses, log identities/order and exact core payload membership. All logs of each selected transaction are retained.
4. Validate adjacent prepared days with `validate_adjacent_days`. The arguments must already have passed `prepare_day`; the helper compares both neighboring boundary headers exactly. The window assembler must retain all 30 days and bind each prepared-day hash.
5. After an independent source audit, call `observations` with the sealed prepared-day hash, the **global** source-audit digest and **global full-window** selection-file digest. The latter differs from each day selection seal. The unchanged frozen observation builder and transfer-shape decoder produce the existing `archive_transfer_observation_v1` schema. Raw amounts remain decimal integer strings.

The global selection wrapper uses the driver's `fixed_address_transaction_selection_v1` schema; each day has `day_utc` and this adapter's selection `transactions`. The driver in `../driver/fixed_address_replay.py` separately validates the complete 30-day observation/selection/source-audit manifests. This adapter does not manufacture a driver `PASS` attestation or auto-fill its coverage checks.

## Limits

This implementation consumes full normalized transaction-table rows and checks their count against every header. It is a correctness-oriented pure component, not an efficient Parquet collector. The future collector may project the required columns, but a selected-row-only interface needs a separately reviewed contract. In-memory normalized rows must already fit the declared resource plan; these limits are not network-byte or peak-memory measurements.

Both the adapter and current driver are explicitly Ethereum chain 1. Other affected chains remain in frame dispositions; this implementation does not silently convert or omit them. Missing source data is an error, not an empty day. Missing leading/trailing provider logs, source index completeness, receipt roots, continuous contract identity and historical observation time remain unproved. No balance-change or economic-loss claim follows from event amounts.

Dependencies are pinned by SHA-256 at runtime: `retained_observation_core.py` and the unchanged public `transfer_observation.py`. The small core module copies exact owned pure-function source segments from the frozen acquirer, with function/span digests in `extraction_provenance.json`. It includes no network collector, CLI or private path code. The original full acquirer is needed only to verify extraction provenance; it is not a runtime dependency of this adapter.

## Focused validation

Run `python -m unittest discover -s papers/monitoring_jss/phase15/adapter -p test_fixed_core_adapter.py -v` from the repository root. The 18 distinct synthetic tests cover multi-part expansion, an externally transferred amount above 2^200, covered-empty days, unavailable/missing/stale sources, status and ordering failures, header/time/count mismatches, forbidden selection expansion, Boolean/integer membership aliasing, malformed Transfer rejection and cross-day links. They use no real incident rows. Test execution history and exact file bindings are in `test_report.json`.
