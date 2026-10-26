# Fixed-address replay controller

This controller makes the frozen comparison usable for a declared Ethereum
case and a finite core-address set over the complete 30-day window
`[D−29 days 00:00 UTC, D+1 day 00:00 UTC)`. It removes the old Euler address,
two-date and predetermined transaction-count checks. It does not acquire data
or change a scoring, grouping or notification rule.

`fixed_address_replay.py` imports the original `semantic_flow_replay.replay_day`
without copying its implementation. That routine uses the unchanged
`SemanticFlowMonitor`, `CountMonitor` and `AdmissionState`. Their exact source
hashes and the original parameter file are checked before and after an accepted
CLI run. The three methods, three policies and daily budgets 1, 5 and 20 give
810 day/method/policy/budget cells over 30 days. A day is a replay partition,
not an independent scientific incident.

Version 1 deliberately accepts **Ethereum chain 1 only** because the original
count and admission classes enforce that chain. A BSC or Fantom case is rejected;
the controller does not replace or disguise its chain identifier. Supporting
another chain requires separately reviewed plumbing and budget scope.

## Input boundary

The config uses `fixed_address_replay_config_v1`, with an explicit `case_id`,
`chain_id`, sorted unique nonzero `population_addresses`, and `window` containing
`execution_date_utc`, `start_date_utc` and `end_date_utc_exclusive`.
`state_initialization` must equal `independent_utc_day_reset`. The method fields
must exactly equal their corresponding fields in the frozen Phase8 config:
`methods`, `semantic`, `primary_semantic_method`, `sensitivity_method`,
`count_baseline`, `grouping_ns`, `policies`, `budgets` and `primary_budget`.
`source_scope` is `aws_public_blockchain_parquet_transaction_subset` and
`source_tier` is `enumerated_daily_partition_and_transaction_metadata_checked`.
Unknown config fields are rejected.

The loader checks every day and every observation before computing scores:

- The observation manifest, selection and source audit must each contain the
  same 30 dates, consecutively and in order. The source audit binds the config
  and sealed selection, complete header-chain checks and endpoint checks.
- Every day must be `COVERED`, with strict Boolean assertions for enumeration
  of all parts, scanning all address row groups, complete headers, complete
  selected log bundles and selected transaction statuses. The audit binds the
  partition, header-chain and address-scan records by SHA-256.
- Each observation file is bound by byte size, SHA-256 and every canonical
  JSONL row digest. Rows retain the original `archive_transfer_observation_v1`
  schema, successful transaction status, raw integer flow amounts and the
  same complete observation for every comparison arm.
- The selected transaction list binds exact identity, positive core-log count
  and the core-payload digest. Its ordered membership must equal the actual
  observations. Transaction identities, time, ordering and duplicate checks
  span the entire window, including UTC-day boundaries.
- A verified empty day is an empty file with zero declared transactions and
  core logs. All coverage requirements still apply. Missing, partially covered
  or unavailable data fails; it cannot become an empty day.

The three audit hashes and `PASS` status are **external audit attestations**.
The controller binds their exact bytes but does not reconstruct original HTTP,
Parquet or chain evidence. It cannot prove that a provider indexed every log,
authenticate receipt roots, or make an invented source record independent.
A separate source auditor and exact acquisition plan remain necessary.

## Scientific acceptance and output

The CLI requires a separate root receipt with schema
`fixed_address_measurement_acceptance_v1`, status
`ACCEPTED_FOR_DECLARED_FIXED_ADDRESS_MEASUREMENT`, explicit UTC acceptance time,
and assertions that acceptance preceded affected payload acquisition and that
all frame dispositions were completed. It binds the config, this driver, the
unchanged dependencies, and six gate files: `frame_dispositions`,
`cohort_selection`, `core_nomination`, `source_plan`, `label_join_protocol` and
`denominators`. Each gate file uses a relative `path` and its exact `sha256`;
stage required gate files within the acceptance directory. Hashes preserve the
recorded root decision; this program does not independently adjudicate it.

An invocation has the following form, using actual accepted artifacts:

```sh
python papers/monitoring_jss/phase15/driver/fixed_address_replay.py \
  --config CONFIG.json \
  --measurement-acceptance ACCEPTANCE.json \
  --expected-acceptance-sha256 ACCEPTANCE_SHA256 \
  --input-manifest INPUT_MANIFEST.json \
  --expected-input-manifest-sha256 INPUT_MANIFEST_SHA256 \
  --output NEW_OUTPUT_DIRECTORY
```

The pure `load_inputs` and `replay_loaded` functions are components for testing
and integration. Their caller must bind the parsed config to its supplied file
digest and satisfy scientific acceptance; calling these functions directly is
not case admission. The CLI performs those config-byte and acceptance checks.

Each day creates fresh feature histories, grouping anchors and notification
states. Method outputs and all admission decisions are retained as deterministic
gzip JSONL, with summaries, final states and a sealed run manifest. Output paths
in that manifest are relative. Existing output directories are never reused.
A failed CLI attempt retains a failure receipt and any partial artifacts, with
`accepted_result=false`; partial output is not an accepted comparison.

The program reads no attack labels. A post-decision label join and the outer
reference/coverage denominators remain separate. Logical block-event time is
not measured live notification latency. Zero triggers, absent flow and cold
start remain outcomes, not case-exclusion rules.

## Focused verification

The first execution of `test_fixed_address_replay.py` passed 13 distinct test
methods, including malformed-input subcases. The tests use invented
observations and explicitly synthetic source attestations. They check verified
empty windows, unavailable and missing days, coverage booleans, exact windows
and population restrictions, cross-day identity invariants, selected membership,
file tampering, label-field rejection, daily feature/grouping/budget resets and
separate scientific acceptance. The direct comparison with frozen `replay_day`
verifies unchanged reuse; it is not an independent algorithm implementation.

See `test_report_attempt1.json` for exact code hashes and accounting. No old test
suite, network acquisition, historical workload, real-case score or label join
was run by these checks. This is engineering preparation for an independently
audited experiment, not new evidence of detector performance.
