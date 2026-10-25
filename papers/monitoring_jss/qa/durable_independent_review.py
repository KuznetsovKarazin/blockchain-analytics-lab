"""Offline forensic audit of existing durable artifacts; never runs a worker.

SQLite is opened only on disposable copies including any WAL/SHM sidecars.
Original source, input, databases, snapshots, exports and manifests are read-only.
Usage: python -B papers/monitoring_jss/qa/durable_independent_review.py --run RUN --output REPORT.json
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile

ROOT = Path(__file__).resolve().parents[3]
PAPER = ROOT / "papers/monitoring_jss"
DEFAULT_RUN = "durable_20261025T090940_001269Z"
PRIOR_RUN = "event_logs_20261025T084327_927529Z"
CLOCKS = {"replay_available_time", "feature_ready_time", "decision_time", "observed_time", "label_available_time"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def inventory(path):
    return {str(p.relative_to(path)): {"sha256": sha(p), "bytes": p.stat().st_size,
             "mtime_ns": p.stat().st_mtime_ns} for p in sorted(path.rglob("*")) if p.is_file()}


def sqlite_copy_observation(source):
    """Recover only disposable copies. Immutable original opens would ignore WAL."""
    with tempfile.TemporaryDirectory(prefix="durable_independent_audit_") as td:
        target = Path(td)
        for p in source.iterdir():
            if p.is_file() and p.name.startswith(("local.sqlite", "sink.sqlite")):
                shutil.copy2(p, target / p.name)
        local = sink = None
        try:
            local, sink = sqlite3.connect(target / "local.sqlite"), sqlite3.connect(target / "sink.sqlite")
            integrity = {"local": local.execute("PRAGMA integrity_check").fetchall(),
                         "sink": sink.execute("PRAGMA integrity_check").fetchall()}
            cursor, state_text = local.execute("SELECT cursor,state FROM checkpoint WHERE id=1").fetchone()
            return {"integrity": integrity, "cursor": cursor, "state_text": state_text,
                    "state": json.loads(state_text),
                    "decisions": local.execute("SELECT seq,event_id,payload FROM decisions ORDER BY seq").fetchall(),
                    "outbox": local.execute("SELECT alert_id,seq,payload,acknowledged FROM outbox ORDER BY seq").fetchall(),
                    "effects": sink.execute("SELECT alert_id,payload FROM effects ORDER BY alert_id").fetchall(),
                    "attempts": sink.execute("SELECT attempt,alert_id,inserted FROM attempts ORDER BY attempt").fetchall(),
                    "identities": {"local": read_identity(local), "sink": read_identity(sink)}}
        finally:
            if local is not None:
                local.close()
            if sink is not None:
                sink.close()


def read_identity(db):
    return json.loads(db.execute("SELECT value FROM meta WHERE name='identity'").fetchone()[0])


def expected_state(raw, decisions, config, cursor):
    prefix, trace = raw[:cursor + 1], decisions[:cursor + 1]
    emitted = [row for row in trace if row["notification_emitted"]]
    seen = {}
    fields = ("chain_id", "address", "block_number", "block_hash", "transaction_index", "transaction_hash",
              "log_index", "event_time_ns", "topics", "data", "removed")
    for event, row in zip(prefix, trace):
        seen[row["event_id"]] = digest({k: event.get(k) for k in fields})
    last = prefix[-1] if prefix else None
    return {"schema_version": "event_log_replay_state_v1", "config": config["core"], "seen": seen,
        "watermark": [last[k] for k in ("block_number", "transaction_index", "log_index")] if last else None,
        "watermark_time_ns": last["event_time_ns"] if last else None,
        "window": [r["event_time_ns"] for r in prefix if r["event_time_ns"] > last["event_time_ns"] - config["core"]["window_seconds"] * 10**9] if last else [],
        "last_emitted_time_ns": emitted[-1]["event_time_ns"] if emitted else None,
        "last_decision_time": trace[-1]["decision_time"] if trace else None,
        "daily_counts": dict(Counter(row["budget_day_utc"] for row in emitted)),
        "alert_ids": [row["alert_id"] for row in emitted]}


def observe_safely(path):
    try:
        return sqlite_copy_observation(path), None
    except Exception as error:
        return None, f"{type(error).__name__}: {error}"


def summarize_db(observation):
    if observation is None:
        return None
    return {"cursor": observation["cursor"], "decisions": len(observation["decisions"]),
            "outbox": len(observation["outbox"]), "acknowledged": sum(r[3] for r in observation["outbox"]),
            "sink_effects": len(observation["effects"]), "sink_attempts": len(observation["attempts"]),
            "duplicate_attempts": sum(not r[2] for r in observation["attempts"]),
            "integrity": observation["integrity"], "state_sha256": hashlib.sha256(observation["state_text"].encode()).hexdigest()}


def review(run_id):
    run = PAPER / "runs" / run_id
    manifest, config, pilot = read(run / "manifest.json"), read(run / "config.json"), read(run / "pilot_summary.json")
    private = ROOT / manifest["private_path"]
    before = inventory(private)
    input_path = ROOT / manifest["input_path"]
    raw = [json.loads(line) for line in input_path.read_text().splitlines()]
    prior_path = PAPER / "runs" / PRIOR_RUN / "day_x1_r1"
    prior_summary = read(prior_path / "summary.json")
    with gzip.open(prior_path / "decisions.jsonl.gz", "rt") as stream:
        prior_decisions = [json.loads(line) for line in stream]
    prior_semantic = [{k: v for k, v in row.items() if k not in CLOCKS} for row in prior_decisions]
    global_checks = {
        "input_sha_matches": sha(input_path) == manifest["input_sha256"],
        "snapshot_source_hashes": all(sha(run / "source_snapshot" / name) == value for name, value in manifest["source_hashes"].items()),
        "copied_config_hash_matches": sha(run / "config.json") == manifest["source_hashes"]["durable_replay_config.json"],
        "prior_semantic_hash_recomputed": digest(prior_semantic) == prior_summary["semantic_decisions_sha256"],
        "exact_15_cells": len(pilot["cells"]) == 15,
        "expected_cell_names": {c["cell"] for c in pilot["cells"]} == {f"{point}_r{r}" for r in (1, 2, 3) for point in ("uninterrupted", *config["fault_points"])},
    }
    cells = []
    all_decisions = []
    for record in pilot["cells"]:
        name, fault = record["cell"], record["fault"]
        cell, dbdir = run / name, private / name
        summary = read(cell / "summary.json")
        checks, errors = {}, []
        checks["pilot_embeds_cell_summary"] = all(record.get(k) == value for k, value in summary.items())
        actual = {str(p.relative_to(dbdir)): {"sha256": sha(p), "bytes": p.stat().st_size} for p in dbdir.rglob("*") if p.is_file()}
        mismatch = {rel: {"expected_sha256": value, "actual": actual.get(rel)} for rel, value in summary["private_file_hashes"].items()
                    if actual.get(rel, {}).get("sha256") != value}
        extras = {rel: value for rel, value in actual.items() if rel not in summary["private_file_hashes"]}
        checks["recorded_private_hashes_match"] = not mismatch
        checks["no_unrecorded_private_files"] = not extras
        checks["database_size_matches"] = sum((dbdir / name).stat().st_size for name in ("local.sqlite", "sink.sqlite")) == summary["database_bytes_after_close"]
        trace = None
        try:
            with gzip.open(cell / "decisions.jsonl.gz", "rt") as stream:
                trace = [json.loads(line) for line in stream]
            checks["gzip_full_read_crc"] = True
            checks["gzip_sha256"] = sha(cell / "decisions.jsonl.gz") == summary["file_hashes"]["decisions.jsonl.gz"]
            checks["all_1247_decisions"] = len(trace) == len(raw) == summary["decision_count"] == 1247
            checks["canonical_decisions_hash"] = digest(trace) == summary["decisions_sha256"]
            semantics = [{k: v for k, v in row.items() if k not in CLOCKS} for row in trace]
            checks["prior_euler_semantics_equal"] = semantics == prior_semantic and digest(semantics) == summary["semantic_decisions_sha256"]
            origin = datetime.fromisoformat(config["playback_origin"]).timestamp()
            clocks = [origin + (row["event_time_ns"] - raw[0]["event_time_ns"]) / 10**9 for row in raw]
            checks["declared_zero_service_clock"] = all(row["replay_available_time"] == row["feature_ready_time"] == row["decision_time"] == clock for row, clock in zip(trace, clocks))
            checks["historical_times_unknown"] = all(row["observed_time"] is None and row["label_available_time"] is None for row in trace)
            all_decisions.append(digest(trace))
        except Exception as error:
            checks["gzip_full_read_crc"] = False
            errors.append(f"decision export: {type(error).__name__}: {error}")
        final, error = observe_safely(dbdir)
        checks["final_database_readable"] = error is None
        if error:
            errors.append(f"final disposable DB copy: {error}")
        if final is not None and trace is not None:
            checks["final_integrity"] = all(value == [("ok",)] for value in final["integrity"].values())
            checks["exact_cursor_and_sequences"] = final["cursor"] == 1246 and [r[0] for r in final["decisions"]] == list(range(1247))
            checks["decision_payloads_equal_gzip"] = [json.loads(r[2]) for r in final["decisions"]] == trace and all(r[1] == json.loads(r[2])["event_id"] for r in final["decisions"])
            emitted = [(row["alert_id"], seq, canonical(row), 1) for seq, row in enumerate(trace) if row["notification_emitted"]]
            checks["five_acknowledged_outbox_payloads"] = final["outbox"] == emitted and len(emitted) == 5
            checks["five_unique_matching_sink_effects"] = final["effects"] == sorted((row[0], row[2]) for row in emitted)
            checks["attempts_match_fault_boundary"] = len(final["attempts"]) == (6 if fault == "after_sink_commit" else 5) and sum(not row[2] for row in final["attempts"]) == (1 if fault == "after_sink_commit" else 0)
            checks["attempt_ids_refer_to_effects"] = all(row[1] in {r[0] for r in emitted} for row in final["attempts"])
            checks["checkpoint_state_matches_entire_prefix"] = final["state"] == expected_state(raw, trace, config, 1246)
            checks["checkpoint_state_hash"] = hashlib.sha256(final["state_text"].encode()).hexdigest() == summary["state_sha256"]
            checks["local_sink_identity"] = all(value == summary["input_identity"] for value in final["identities"].values())
            exported_effects = [{"alert_id": r[0], "payload_sha256": hashlib.sha256(r[1].encode()).hexdigest()} for r in final["effects"]]
            exported_attempts = [{"attempt": r[0], "alert_id": r[1], "inserted": bool(r[2])} for r in final["attempts"]]
            checks["sink_export_matches_db"] = exported_effects == read(dbdir / "sink_effects.json") and exported_attempts == read(dbdir / "sink_attempts.json") and digest(exported_effects) == summary["sink_effects_sha256"]
        crash_summary, marker = None, None
        if fault:
            marker, observed = read(cell / "fault_marker.json"), read(cell / "post_crash_observation.json")
            checks["exit73_seq9_marker"] = marker["exit_code"] == 73 and marker["seq"] == 9 and marker["point"] == fault
            crash, error = observe_safely(dbdir / "unclean_snapshot")
            checks["unclean_copy_readable"] = error is None
            if error:
                errors.append(f"unclean disposable DB copy: {error}")
            checks["unclean_snapshot_hashes"] = all(sha(dbdir / "unclean_snapshot" / rel) == value for rel, value in observed["unclean_file_sha256"].items())
            if crash is not None and trace is not None:
                cursor = 8 if fault == "before_local_commit" else 9
                outbox = 0 if fault == "before_local_commit" else 1
                pending = int(fault in ("after_local_commit", "after_sink_commit"))
                effects = int(fault in ("after_sink_commit", "after_ack"))
                checks["unclean_expected_boundary"] = crash["cursor"] == cursor and len(crash["decisions"]) == cursor + 1 and len(crash["outbox"]) == outbox and sum(not r[3] for r in crash["outbox"]) == pending and len(crash["effects"]) == effects and len(crash["attempts"]) == effects
                checks["unclean_integrity"] = all(value == [("ok",)] for value in crash["integrity"].values())
                checks["unclean_exact_prefix_payloads"] = [json.loads(r[2]) for r in crash["decisions"]] == trace[:cursor + 1]
                checks["unclean_exact_prefix_checkpoint"] = crash["state"] == expected_state(raw, trace, config, cursor)
                checks["resume_cursor_matches_snapshot"] = summary["resumed_cursor"] == cursor
                crash_summary = summarize_db(crash)
        else:
            checks["fresh_baseline_cursor"] = summary["resumed_cursor"] == -1
        stages = summary["stage_distributions"]
        expected_remaining = 1247 - (summary["resumed_cursor"] + 1)
        checks["successful_worker_stage_counts"] = summary["events_processed_this_process"] == expected_remaining and stages["local_commit_seconds"]["n"] == stages["state_serialization_seconds"]["n"] == expected_remaining and stages["sink_commit_seconds"]["n"] == stages["ack_commit_seconds"]["n"] == (4 if fault == "after_ack" else 5)
        checks["timing_scope_inequalities"] = summary["worker_to_loop_end_seconds"] >= summary["restart_open_validate_restore_seconds"] + summary["restart_pending_drain_seconds"] + summary["replay_loop_seconds_this_process"] - 1e-8 and (record["restart_process_to_complete_seconds"] if fault else record["initial_process_elapsed_seconds"]) >= summary["worker_to_loop_end_seconds"]
        cells.append({"cell": name, "fault": fault, "passed": all(checks.values()), "checks": checks, "errors": errors,
                      "private_hash_mismatches": mismatch, "unrecorded_private_files": extras,
                      "final_database": summarize_db(final), "unclean_database": crash_summary, "marker": marker,
                      "summary_sha256": sha(cell / "summary.json")})
    global_checks["all_decision_exports_equal"] = len(all_decisions) == 15 and len(set(all_decisions)) == 1
    global_checks["twelve_fault_markers"] = sum(cell["marker"] is not None for cell in cells) == 12
    after = inventory(private)
    global_checks["original_private_files_unchanged_by_audit"] = before == after
    return {"schema_version": "durable_independent_review_v1", "run_id": run_id,
        "checked_utc": datetime.now(timezone.utc).isoformat(), "passed": all(global_checks.values()) and all(c["passed"] for c in cells),
        "audit_script_sha256": sha(__file__), "manifest_sha256": sha(run / "manifest.json"), "global_checks": global_checks,
        "cells": cells, "original_private_inventory_before": before,
        "raw_changes_during_audit": {key: {"before": before.get(key), "after": after.get(key)} for key in set(before) | set(after) if before.get(key) != after.get(key)},
        "prior_semantic_reference": {"run": PRIOR_RUN, "cell": "day_x1_r1", "actual_semantic_sha256": digest(prior_semantic), "trace_sha256": sha(prior_path / "decisions.jsonl.gz")},
        "measurement_review": [
            {"location": "source_snapshot/durable_replay.py:134-187", "finding": "Deterministic availability/feature-ready/decision clocks have zero modeled service delay. Persistence timings are separate observations; they do not measure externally delivered alert latency."},
            {"location": "source_snapshot/durable_replay.py:167-182", "finding": "State serialization timer includes both checkpoint and decision JSON. local_commit_seconds includes BEGIN, inserts/update and COMMIT, not only COMMIT."},
            {"location": "source_snapshot/durable_replay.py:115-127", "finding": "Sink timer includes the whole local sink transaction; ack timer includes BEGIN/update/COMMIT. The after-sink fault permits an extra attempt while unique matching alert_id prevents another effect."},
            {"location": "source_snapshot/durable_replay.py:188-230", "finding": "Worker-to-loop-end excludes final DB export, close, gzip and summary. RSS is sampled after materializing decision/effect/attempt lists, before export/close. Stage statistics in fault cells describe only the successful resumed worker; aborted-worker samples are not preserved."},
            {"location": "source_snapshot/durable_replay.py:307-341", "finding": "Parent initial/restart process elapsed values include process launch, execution, exports and exit; restart measurement excludes preceding crash inspection/snapshot work."}],
        "limitations": [
            "Artifact review only; no worker, fault or production replay rerun. SQLite recovery occurs only in disposable copies containing captured sidecars.",
            "Markers plus preserved source and completed parent guard support reported os._exit(73) injections. Raw child return codes are checked in code but not separately serialized as OS receipts.",
            "No arbitrary crash-location coverage: four selected boundaries at the first notification only, three repetitions each.",
            "Conditional single-writer, same-machine SQLite sink contract; not general exactly-once network delivery, power-loss durability, kernel-crash recovery or live reorg handling.",
            "No independent reconstruction of perf_counter observations/quantiles: only published scope, counts and internal inequalities can be audited from persisted summaries.",
            "Any failed recorded DB hash or malformed recovered-copy state invalidates accepting the whole run as final durable evidence until resolved; preserve original evidence, never rewrite hashes to force a pass."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", default=DEFAULT_RUN)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = review(args.run)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
    print(json.dumps({"passed": report["passed"], "output": str(args.output), "failed_cells": [r["cell"] for r in report["cells"] if not r["passed"]]}))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
