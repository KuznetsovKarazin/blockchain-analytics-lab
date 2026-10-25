"""Atomic local cursor/state/decision/outbox and an idempotent local test sink.

This bounded experiment kills worker processes at four declared boundaries.
It tests a conditional sink contract, not general exactly-once network delivery.
SQLite FULL/WAL does not make this a power-loss or kernel-crash experiment.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

PAPER = Path(__file__).resolve().parent
ROOT = PAPER.parents[1]
SPEC = importlib.util.spec_from_file_location("durable_event_core", PAPER / "event_log_replay.py")
core = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = core
SPEC.loader.exec_module(core)
FAULTS = ("before_local_commit", "after_local_commit", "after_sink_commit", "after_ack")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def dump(value, path):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def connect(path):
    db = sqlite3.connect(path, isolation_level=None)
    mode = db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
    db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA busy_timeout=5000")
    if mode.lower() != "wal" or db.execute("PRAGMA synchronous").fetchone()[0] != 2:
        raise RuntimeError("required SQLite FULL/WAL settings not active")
    return db


def initialize(local, sink, identity, config):
    local.executescript("""
        CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS checkpoint (id INTEGER PRIMARY KEY CHECK(id=1), cursor INTEGER NOT NULL, state TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS decisions (seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS outbox (alert_id TEXT PRIMARY KEY, seq INTEGER NOT NULL, payload TEXT NOT NULL, acknowledged INTEGER NOT NULL CHECK(acknowledged IN (0,1)));
    """)
    sink.executescript("""
        CREATE TABLE IF NOT EXISTS effects (alert_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS attempts (attempt INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL, inserted INTEGER NOT NULL CHECK(inserted IN (0,1)));
        CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);
    """)
    encoded = canonical(identity)
    for db in (local, sink):
        old = db.execute("SELECT value FROM meta WHERE name='identity'").fetchone()
        if old is not None and old[0] != encoded:
            raise ValueError("refusing resume with changed input, config or implementation")
        db.execute("INSERT OR IGNORE INTO meta VALUES ('identity', ?)", (encoded,))
    local.execute("INSERT OR IGNORE INTO checkpoint VALUES (1,-1,?)",
                  (canonical(core.LogReplayState(core.LogConfig(**config["core"])).to_dict()),))


def deliver(sink, alert_id, payload):
    """Commit one attempted delivery and at most one matching logical effect."""
    sink.execute("BEGIN IMMEDIATE")
    try:
        old = sink.execute("SELECT payload FROM effects WHERE alert_id=?", (alert_id,)).fetchone()
        if old is not None and old[0] != payload:
            raise ValueError("sink idempotency key reused with conflicting payload")
        inserted = old is None
        if inserted:
            sink.execute("INSERT INTO effects VALUES (?,?)", (alert_id, payload))
        sink.execute("INSERT INTO attempts (alert_id,inserted) VALUES (?,?)", (alert_id, int(inserted)))
        sink.execute("COMMIT")
        return inserted
    except BaseException:
        sink.execute("ROLLBACK")
        raise


def hard_exit(point, seq, args):
    if args.fault != point:
        return
    # This marker proves the intended injection point was reached. It is not
    # part of the application's recovery state and is never read by a worker.
    marker = args.cell / "fault_marker.json"
    with marker.open("x") as f:
        json.dump({"point": point, "seq": seq, "exit_code": 73,
                   "utc": datetime.now(timezone.utc).isoformat()}, f)
        f.flush()
        os.fsync(f.fileno())
    os._exit(73)


def drain(local, sink, args, metrics):
    rows = local.execute("SELECT alert_id,seq,payload FROM outbox WHERE acknowledged=0 ORDER BY seq").fetchall()
    for alert_id, seq, payload in rows:
        t0 = time.perf_counter()
        deliver(sink, alert_id, payload)
        metrics["sink_commit_seconds"].append(time.perf_counter() - t0)
        hard_exit("after_sink_commit", seq, args)
        t0 = time.perf_counter()
        local.execute("BEGIN IMMEDIATE")
        local.execute("UPDATE outbox SET acknowledged=1 WHERE alert_id=?", (alert_id,))
        local.execute("COMMIT")
        metrics["ack_commit_seconds"].append(time.perf_counter() - t0)
        hard_exit("after_ack", seq, args)


def stats(values):
    return core.quantiles(values) if values else {"n": 0}


def worker(args):
    process_start = time.perf_counter()
    config = json.loads(args.config.read_text())
    identity = {"input_sha256": sha(args.input), "config_sha256": sha(args.config),
                "durable_source_sha256": sha(Path(__file__)), "core_source_sha256": sha(PAPER / "event_log_replay.py")}
    private = args.private
    private.mkdir(parents=True, exist_ok=True)
    local, sink = connect(private / "local.sqlite"), connect(private / "sink.sqlite")
    initialize(local, sink, identity, config)
    integrity = {"local": local.execute("PRAGMA integrity_check").fetchone()[0],
                 "sink": sink.execute("PRAGMA integrity_check").fetchone()[0]}
    if set(integrity.values()) != {"ok"}:
        raise RuntimeError("database integrity check failed")
    cursor, snapshot = local.execute("SELECT cursor,state FROM checkpoint WHERE id=1").fetchone()
    state = core.LogReplayState.from_dict(json.loads(snapshot))
    recovered = time.perf_counter()
    metrics = {k: [] for k in ("state_serialization_seconds", "local_commit_seconds", "sink_commit_seconds", "ack_commit_seconds")}
    drain(local, sink, args, metrics)  # pending committed notifications precede new input
    pending_drained = time.perf_counter()
    origin = datetime.fromisoformat(config["playback_origin"]).timestamp()
    first_time = None
    processed = 0
    tloop = time.perf_counter()
    with args.input.open() as stream:
        for seq, line in enumerate(stream):
            raw = json.loads(line)
            if first_time is None:
                first_time = raw["event_time_ns"]
            if seq <= cursor:
                continue
            event = core.decode_event(raw)
            clock = origin + (event["event_time_ns"] - first_time) / 1_000_000_000
            decision = state.process(event, replay_available_time=clock, feature_ready_time=clock, decision_time=clock)
            t0 = time.perf_counter()
            state_json, decision_json = canonical(state.to_dict()), canonical(decision)
            metrics["state_serialization_seconds"].append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            local.execute("BEGIN IMMEDIATE")
            try:
                local.execute("INSERT INTO decisions VALUES (?,?,?)", (seq, decision["event_id"], decision_json))
                local.execute("UPDATE checkpoint SET cursor=?,state=? WHERE id=1", (seq, state_json))
                if decision["notification_emitted"]:
                    local.execute("INSERT INTO outbox VALUES (?,?,?,0)", (decision["alert_id"], seq, decision_json))
                    hard_exit("before_local_commit", seq, args)
                local.execute("COMMIT")
            except BaseException:
                local.execute("ROLLBACK")
                raise
            metrics["local_commit_seconds"].append(time.perf_counter() - t0)
            if decision["notification_emitted"]:
                hard_exit("after_local_commit", seq, args)
            drain(local, sink, args, metrics)
            processed += 1
    loop_end = time.perf_counter()
    final_cursor, final_snapshot = local.execute("SELECT cursor,state FROM checkpoint WHERE id=1").fetchone()
    decisions = [json.loads(r[0]) for r in local.execute("SELECT payload FROM decisions ORDER BY seq")]
    effects = [dict(alert_id=r[0], payload_sha256=hashlib.sha256(r[1].encode()).hexdigest())
               for r in sink.execute("SELECT alert_id,payload FROM effects ORDER BY alert_id")]
    attempts = [dict(attempt=r[0], alert_id=r[1], inserted=bool(r[2]))
                for r in sink.execute("SELECT attempt,alert_id,inserted FROM attempts ORDER BY attempt")]
    outbox = local.execute("SELECT COUNT(*),COALESCE(SUM(acknowledged),0) FROM outbox").fetchone()
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    db_settings = {"sqlite_version": sqlite3.sqlite_version, "journal_mode": local.execute("PRAGMA journal_mode").fetchone()[0],
                   "synchronous": local.execute("PRAGMA synchronous").fetchone()[0],
                   "wal_autocheckpoint_pages": local.execute("PRAGMA wal_autocheckpoint").fetchone()[0],
                   "page_size": local.execute("PRAGMA page_size").fetchone()[0]}
    local.close(); sink.close()
    dpath = args.cell / "decisions.jsonl.gz"
    with gzip.open(dpath, "wt") as f:
        for row in decisions:
            f.write(canonical(row) + "\n")
    with gzip.open(dpath, "rt") as f:
        if [json.loads(x) for x in f] != decisions:
            raise RuntimeError("persisted decision export differs from database")
    dump(attempts, private / "sink_attempts.json")
    dump(effects, private / "sink_effects.json")
    summary = {"schema_version": "durable_replay_cell_v1", "input_identity": identity,
               "resumed_cursor": cursor, "final_cursor": final_cursor, "events_processed_this_process": processed,
               "decision_count": len(decisions), "decisions_sha256": core.digest(decisions),
               "semantic_decisions_sha256": core.digest([core.semantic(d) for d in decisions]),
               "state_sha256": hashlib.sha256(final_snapshot.encode()).hexdigest(),
               "sink_effects_sha256": core.digest(effects), "sink_unique_effects": len(effects),
               "sink_delivery_attempts": len(attempts), "duplicate_delivery_attempts": sum(not a["inserted"] for a in attempts),
               "outbox_rows": outbox[0], "outbox_acknowledged": outbox[1], "all_outbox_acknowledged": outbox[0] == outbox[1],
               "restart_open_validate_restore_seconds": recovered - process_start,
               "restart_pending_drain_seconds": pending_drained - recovered,
               "replay_loop_seconds_this_process": loop_end - tloop,
               "worker_to_loop_end_seconds": loop_end - process_start,
               "stage_distributions": {k: stats(v) for k,v in metrics.items()},
               "peak_rss_bytes": rss, "sqlite": db_settings, "entry_integrity": integrity,
               "file_hashes": {"decisions.jsonl.gz": sha(dpath)},
               "private_file_hashes": {str(p.relative_to(private)): sha(p) for p in private.rglob("*") if p.is_file()},
               "private_bytes_after_close": sum(p.stat().st_size for p in private.rglob("*") if p.is_file()),
               "database_bytes_after_close": sum((private / name).stat().st_size for name in ("local.sqlite", "sink.sqlite")),
               "storage_scope": "database_bytes counts final local+sink SQLite files; private_bytes additionally includes diagnostic unclean snapshots and exported sink audit records",
               "timing_scope": "process-local open/input hash/check/restore, pending-drain, loop and commit calls measured; process spawn and total restart separately parent measured; deterministic modeled decision clock excludes these durations",
               "finished_utc": datetime.now(timezone.utc).isoformat()}
    dump(summary, args.cell / "summary.json")


def crash_observation(private):
    """Preserve unclean bytes; inspect a disposable copy, never pre-recover worker DBs."""
    saved = private / "unclean_snapshot"
    saved.mkdir(exist_ok=False)
    files = [p for p in private.iterdir() if p.is_file()]
    before = {p.name: sha(p) for p in files}
    for path in files:
        shutil.copy2(path, saved / path.name)
    with tempfile.TemporaryDirectory(prefix="durable_inspection_") as temp:
        target = Path(temp)
        for path in saved.iterdir():
            shutil.copy2(path, target / path.name)
        local = sqlite3.connect(target / "local.sqlite")
        sink = sqlite3.connect(target / "sink.sqlite")
        result = {"cursor": local.execute("SELECT cursor FROM checkpoint").fetchone()[0],
                  "decisions": local.execute("SELECT COUNT(*) FROM decisions").fetchone()[0],
                  "outbox": local.execute("SELECT COUNT(*) FROM outbox").fetchone()[0],
                  "unacknowledged": local.execute("SELECT COUNT(*) FROM outbox WHERE acknowledged=0").fetchone()[0],
                  "sink_effects": sink.execute("SELECT COUNT(*) FROM effects").fetchone()[0],
                  "sink_attempts": sink.execute("SELECT COUNT(*) FROM attempts").fetchone()[0],
                  "integrity": [local.execute("PRAGMA integrity_check").fetchone()[0], sink.execute("PRAGMA integrity_check").fetchone()[0]]}
        local.close(); sink.close()
    result["unclean_file_sha256"] = before
    result["original_unclean_files_unchanged_before_restart"] = before == {p.name: sha(p) for p in files}
    if not result["original_unclean_files_unchanged_before_restart"]:
        raise RuntimeError("inspection changed the databases before restart")
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--config", type=Path, default=PAPER / "durable_replay_config.json")
    ap.add_argument("--run-id")
    ap.add_argument("--worker", action="store_true")
    ap.add_argument("--cell", type=Path)
    ap.add_argument("--private", type=Path)
    ap.add_argument("--fault", choices=FAULTS)
    args = ap.parse_args()
    args.input, args.config = args.input.resolve(), args.config.resolve()
    if args.worker:
        worker(args)
        return
    config = json.loads(args.config.read_text())
    if config["fault_points"] != list(FAULTS) or config["crash_exit_code"] != 73:
        raise ValueError("unsupported fault configuration")
    run_id = args.run_id or datetime.now(timezone.utc).strftime("durable_%Y%m%dT%H%M%S_%fZ")
    if Path(run_id).name != run_id:
        raise ValueError("invalid run ID")
    out, private_root = PAPER / "runs" / run_id, ROOT / "data/raw/monitoring_jss/durable" / run_id
    out.mkdir(parents=True, exist_ok=False); private_root.mkdir(parents=True, exist_ok=False)
    snapshot = out / "source_snapshot"; snapshot.mkdir()
    source_hashes = {}
    for source in (Path(__file__), PAPER / "event_log_replay.py", args.config, PAPER / "tests/test_durable_replay.py"):
        shutil.copy2(source, snapshot / source.name)
        source_hashes[source.name] = sha(snapshot / source.name)
    shutil.copy2(args.config, out / "config.json")
    manifest = {"schema_version": "durable_replay_run_v1", "run_id": run_id, "status": "running",
                "started_utc": datetime.now(timezone.utc).isoformat(), "input_path": str(args.input.relative_to(ROOT)),
                "input_sha256": sha(args.input), "source_hashes": source_hashes,
                "base_commit": subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
                "command": sys.argv, "python": sys.version, "platform": platform.platform(), "sqlite_version": sqlite3.sqlite_version,
                "private_path": str(private_root.relative_to(ROOT)), "limits": config["limits"]}
    dump(manifest, out / "manifest.json")
    results = []
    for repetition in range(1, config["repetitions"] + 1):
        for fault in (None, *FAULTS):
            name = f"{fault or 'uninterrupted'}_r{repetition}"
            cell, private = out / name, private_root / name
            cell.mkdir()
            command = [sys.executable, str(snapshot / "durable_replay.py"), "--worker", "--input", str(args.input),
                       "--config", str(out / "config.json"), "--cell", str(cell), "--private", str(private)]
            first_command = command + (["--fault", fault] if fault else [])
            t0 = time.perf_counter()
            with (cell / "initial.stdout.txt").open("w") as stdout, (cell / "initial.stderr.txt").open("w") as stderr:
                p = subprocess.run(first_command, cwd=ROOT, stdout=stdout, stderr=stderr)
            initial_elapsed = time.perf_counter() - t0
            if p.returncode != (73 if fault else 0):
                raise RuntimeError(f"unexpected worker exit in {name}: {p.returncode}")
            crash, restart_elapsed = None, None
            if fault:
                marker = json.loads((cell / "fault_marker.json").read_text())
                crash = crash_observation(private)
                crash["marker"] = marker
                expected_committed = marker["seq"] + (0 if fault == "before_local_commit" else 1)
                crash["boundary_checks"] = {
                    "correct_point": marker["point"] == fault,
                    "expected_decisions": crash["decisions"] == expected_committed,
                    "expected_cursor": crash["cursor"] == expected_committed - 1,
                    "expected_outbox": crash["outbox"] == (0 if fault == "before_local_commit" else 1),
                    "expected_pending": crash["unacknowledged"] == (1 if fault in ("after_local_commit", "after_sink_commit") else 0),
                    "expected_sink": crash["sink_effects"] == (1 if fault in ("after_sink_commit", "after_ack") else 0),
                    "integrity_ok": set(crash["integrity"]) == {"ok"},
                }
                if not all(crash["boundary_checks"].values()):
                    raise RuntimeError(f"unexpected crash boundary state in {name}: {crash}")
                dump(crash, cell / "post_crash_observation.json")
                t0 = time.perf_counter()
                with (cell / "resume.stdout.txt").open("w") as stdout, (cell / "resume.stderr.txt").open("w") as stderr:
                    resumed = subprocess.run(command, cwd=ROOT, stdout=stdout, stderr=stderr)
                restart_elapsed = time.perf_counter() - t0
                if resumed.returncode:
                    raise RuntimeError(f"resume failed in {name}")
            summary = json.loads((cell / "summary.json").read_text())
            summary.update({"cell": name, "fault": fault, "repetition": repetition,
                            "initial_process_elapsed_seconds": initial_elapsed,
                            "restart_process_to_complete_seconds": restart_elapsed,
                            "post_crash_observation": crash})
            results.append(summary)
    baseline = results[0]
    equality = all(all(r[k] == baseline[k] for k in ("decision_count", "decisions_sha256", "semantic_decisions_sha256", "state_sha256", "sink_effects_sha256", "sink_unique_effects")) for r in results)
    attempts_ok = all(r["duplicate_delivery_attempts"] == (1 if r["fault"] == "after_sink_commit" else 0) for r in results)
    cursors_ok = all(r["final_cursor"] + 1 == r["decision_count"] and r["all_outbox_acknowledged"] for r in results)
    unchanged = manifest["input_sha256"] == sha(args.input) and all(sha(snapshot / n) == h for n,h in source_hashes.items())
    checks = {"all_final_states_decisions_sink_effects_equal": equality, "duplicate_attempts_match_boundary": attempts_ok,
              "cursor_and_outbox_consistent": cursors_ok, "source_input_unchanged": unchanged}
    manifest.update({"status": "complete" if all(checks.values()) else "failed", "finished_utc": datetime.now(timezone.utc).isoformat(), "checks": checks})
    dump(manifest, out / "manifest.json")
    dump({"schema_version": "durable_replay_summary_v1", "run_id": run_id, "checks": checks, "cells": results}, out / "pilot_summary.json")
    if not all(checks.values()):
        raise RuntimeError("durable replay comparisons failed")
    print(canonical({"run": str(out.relative_to(ROOT)), "cells": len(results), "checks": checks}))


if __name__ == "__main__":
    main()
