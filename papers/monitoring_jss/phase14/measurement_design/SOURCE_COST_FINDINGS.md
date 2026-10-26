# Measurement source metadata and first-day projection cost

The archive route now has a complete listed object inventory for the original 30-day LiFi window. A deterministic first-day footer probe confirms that the needed raw fields exist and gives exact physical column-span costs. **No LiFi detector-workload rows, transfer observations or detector scores were acquired by these archive probes.** Uniform core nomination and a separate measurement freeze remain pending; the accepted scope amendment alone admits no case.

## Inventory and actual acquisition

Four metadata GETs returned 46,920 bytes. Two complete prior March monthly listings were reused. The combined inventory covers 90 day/table cells and 90 objects, with 17,414,029,046 declared source bytes across logs, blocks and transactions. These whole-object bytes were not downloaded. All 46 overlapping identities agree with the retained Phase6 metadata.

Six exact trailer/footer range GETs returned 21,179 bytes for February19,2022, the preselected first window date. Every response passed its frozen ETag, status206, Content-Range and Content-Length checks. PyArrow26.0.0 was reused; no package was installed. Both acquisitions and the footer calculations passed separate actual-evidence audits.

Archive-metadata work totals 10 GETs and 68,099 retained bytes. Administrative-event requests and method-documentation lookups are accounted separately.

## First-day schema metadata

| Table | Whole-object bytes | Metadata row count | Row groups | Footer bytes |
|---|---:|---:|---:|---:|
| logs | 200,751,669 | 1,880,963 | 2 | 4,537 |
| blocks | 5,419,161 | 6,407 | 1 | 5,770 |
| transactions | 361,011,091 | 1,150,162 | 3 | 10,848 |

The listed row counts describe entire source partitions, not LiFi activity. Log fields include raw emitter, topics, data, transaction/log positions and block identity/time. Transaction metadata includes integer receipt status; block fields include height, hash, parent hash, timestamp and transaction count. Data-page readability, nullability of actual rows, canonical order and continuous header coverage still require a separately frozen payload acquisition.

## Footer-derived compressed column spans

| Table | Scenario | Payload bytes if fetched | Merged range requests |
|---|---|---:|---:|
| logs | address_scan | 5,892,710 | 2 |
| logs | all_required_columns | 190,898,456 | 2 |
| logs | selection_columns_union | 56,170,582 | 4 |
| logs | transaction_hash_scan | 50,277,872 | 2 |
| blocks | all_required_columns | 909,431 | 5 |
| transactions | all_required_columns | 74,210,433 | 12 |
| transactions | transaction_hash_scan | 73,304,230 | 3 |

The all-required-columns scenario totals **266,018,320 bytes in 19 ranges**, versus **567,181,921 bytes** for the three whole objects. The two log selection columns together are the union of address and transaction-hash scans, not an additional disjoint cost to add again. Likewise, each all-required-columns scenario includes its scan columns. These are exact physical-span calculations from retained metadata; the data pages were not transferred, and this is not a measured download benchmark.

The address-only log scan can establish which source row groups contain the fixed core. Later payload cost depends on those matches and on transaction-hash expansion. It cannot be inferred exactly from metadata alone. No first-day result is multiplied into a claimed 30-day total.

## Evidence limits and next action

Raw footers may contain data-derived column statistics; their values were not exported or used to choose a core, date or parameter. The decoder's leading PAR1 was synthetic. Retained footer/trailer hashes and response receipts are the actual source evidence. Independent QA reconstructed metadata through a different API of the same pinned parser, without reading rows or importing the producer.

After uniform per-row core nomination and a separate measurement freeze, acquire the planned source columns, establish complete source/header coverage, and seal the core-log transaction set before all-emitter expansion and scoring. Valid covered empty days remain in the study; missing data remains unavailable. [The aggregate JSON](measurement_metadata_findings.json) binds the exact source summaries and independent reviews, while [the observation proposal](observation_contract_proposal.json) defines the intended adapter boundary.
