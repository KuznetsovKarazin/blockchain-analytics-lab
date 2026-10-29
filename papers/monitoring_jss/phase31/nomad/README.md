# Nomad high-volume follow-up

`ACCEPTED_DATA.json` identifies the complete accepted source: `data_attempt3`, 930 transactions and 3507 full normalized original-AWS log events with original transaction receipt statuses. `FINDINGS.md` gives the verified result and limitations. Attempts 1 and 2 remain incomplete/interrupted history and must not be scored.

## Offline reproduction

Run from the repository root with Python's standard library. The output directory must not already exist.

```bash
python papers/monitoring_jss/phase31/nomad/replay_and_verify.py --data papers/monitoring_jss/phase31/nomad/data_attempt3 --out /tmp/nomad-replay
python papers/monitoring_jss/phase31/nomad_independent/verify_nomad.py --data papers/monitoring_jss/phase31/nomad/data_attempt3 --results /tmp/nomad-replay --out /tmp/nomad-independent-audit.json
python papers/monitoring_jss/phase31/nomad/boundary_diagnostics.py --data papers/monitoring_jss/phase31/nomad/data_attempt3 --out /tmp/nomad-boundary.json
```

The replay checks the frozen population/core/window, all daily/core counts, unique canonical order, normalized bundle identities, independent gross positive outflows, all 63 policy cells and 6510 method traces. The separate standalone audit independently reconstructs all flow/count fields and all 63 cells, then verifies source and resource provenance. No reference ledger is read.

## Files and provenance

- `PROTOCOL.md`, `acquire.py`: original fixed source acquisition; attempt 1 stopped at its original deadline.
- `CONTINUATION_PROTOCOL.md`, `CONTINUATION_LIMITS.json`, `acquire_continue.py`: source-only continuation; attempt 2 was interrupted with unknown runtime cause.
- `RECOVERY_LIMITS.json`, `acquire_recover.py`: bounded recovery including conservative interrupted-byte/listing/wall accounting; attempt 3 completed the source.
- `data_attempt3/`: accepted full normalized selected bundles, observations, manifests and inherited/current range receipts.
- `results/`: sealed label-blind replay, method traces, policy CSV, comparison audit and boundary diagnostics.
- `../nomad_independent/AUDIT.json`: standalone independent verification.

After acquisition, all 18 source files were atomically copied/fsynced and their hashes checked in a separate fresh execution. `data_attempt3/PERSISTENCE_CHECK.json` records that checkpoint. The accepted pointer was written only after the numerical and standalone provenance audits passed.

Sparse Parquet caches are temporary and excluded from Git/publication. Full original Parquet-to-normalization verification requires network reacquisition with `pyarrow==19.0.1`; offline claims start from the complete normalized selected values. The payload/status tier is original AWS Parquet; receipt-root authentication and economic-loss ground truth are not claimed.
