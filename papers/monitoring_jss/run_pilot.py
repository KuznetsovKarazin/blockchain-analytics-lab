"""Measured local header replay with an explicit virtual FCFS queue.

No real-time pacing occurs. Arrival gaps are virtual, scaled by a declared
factor. Event timestamps remain historical; availability/decision timestamps
use the fixed playback epoch. Never subtract one clock domain from the other.
Each independent worker handles one period, speed and repetition. JSONL input
read, JSON decode, core execution, and buffered gzip decision write are timed.
Acquisition, Parquet preparation, fsync, receipts/logs/traces, remote RPC and
real consensus finality are outside the per-event replay timing.
"""
from __future__ import annotations

import argparse
import bisect
import csv
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import sys
import time

from fetch_pilot import sha256
from replay_core import ReplayConfig, ReplayState

ROOT = Path(__file__).resolve().parents[2]
PAPER = Path(__file__).resolve().parent


def dump(value, path: Path) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def percentile(values, q):
    if not values:
        return None
    values = sorted(values)
    offset = (len(values) - 1) * q
    low = int(offset)
    high = min(low + 1, len(values) - 1)
    return values[low] + (values[high] - values[low]) * (offset - low)


def distributions(rows, keys):
    return {key: {"n": len(rows), "p50": percentile([r[key] for r in rows], .50),
                  "p95": percentile([r[key] for r in rows], .95),
                  "p99": percentile([r[key] for r in rows], .99),
                  "max": max((r[key] for r in rows), default=None)} for key in keys}


def worker(args) -> None:
    cell = args.cell
    cell.mkdir(parents=True, exist_ok=False)
    config = json.loads(args.config.read_text())
    state = ReplayState(ReplayConfig(**{key: config[key] for key in
                         ("threshold", "cooldown_seconds", "daily_budget", "chain_id", "population_id")}))
    origin = datetime.fromisoformat(config["playback_origin"]).timestamp()
    source = args.inputs / args.period
    with source.open() as stream:
        first_time = json.loads(stream.readline())["event_time"]
    metrics = []
    completion_offsets = []
    previous_finish = 0.0
    decisions = cell / "decisions.jsonl.gz"
    wall_start = time.perf_counter()
    start_utc = datetime.now(timezone.utc).isoformat()
    with source.open("rb") as stream, gzip.open(decisions, "wt", compresslevel=6) as log:
        index = 0
        while True:
            t0 = time.perf_counter()
            line = stream.readline()
            t_read = time.perf_counter()
            if not line:
                break
            event = json.loads(line)
            t_decode = time.perf_counter()
            arrival_offset = (event["event_time"] - first_time) / args.speed
            start_offset = max(arrival_offset, previous_finish)
            service_start = origin + start_offset
            ready = service_start + (t_decode - t0)
            # Measured elapsed read/decode/core pre-admission work is added to the
            # VIRTUAL service clock. The core invokes this clock after scoring.
            result = state.process(event, replay_available_time=origin + arrival_offset,
                                   feature_ready_time=ready,
                                   decision_time=lambda: service_start + (time.perf_counter() - t0))
            t_core = time.perf_counter()
            log.write(json.dumps(result, separators=(",", ":"), sort_keys=True, allow_nan=False) + "\n")
            t_write = time.perf_counter()
            service = t_write - t0
            finish_offset = start_offset + service
            queue_before = index - bisect.bisect_right(completion_offsets, arrival_offset)
            metrics.append({"event_index": index, "event_id": result["event_id"],
                            "read_seconds": t_read - t0, "decode_seconds": t_decode - t_read,
                            "core_seconds": t_core - t_decode, "write_seconds": t_write - t_core,
                            "local_service_seconds": service, "virtual_arrival_offset_seconds": arrival_offset,
                            "virtual_service_start_offset_seconds": start_offset,
                            "virtual_finish_offset_seconds": finish_offset,
                            "virtual_queue_wait_seconds": start_offset - arrival_offset,
                            "virtual_notification_ready_seconds": finish_offset - arrival_offset,
                            "queued_or_in_service_at_arrival": queue_before})
            completion_offsets.append(finish_offset)
            previous_finish = finish_offset
            index += 1
        close_start = time.perf_counter()
    close_seconds = time.perf_counter() - close_start
    wall_seconds = time.perf_counter() - wall_start
    timing_path = cell / "timing.csv.gz"
    with gzip.open(timing_path, "wt", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(metrics[0]))
        writer.writeheader()
        writer.writerows(metrics)
    # Rebuild substantive metrics FROM persisted decision and timing logs.
    summarize_cell(cell, config, {"input_path": str(source.relative_to(ROOT)), "input_sha256": sha256(source),
                    "period": args.period, "speed_factor": args.speed, "repetition": args.rep,
                    "worker_command": sys.argv, "started_utc": start_utc,
                    "finished_utc": datetime.now(timezone.utc).isoformat(), "wall_runtime_seconds": wall_seconds,
                    "gzip_close_seconds": close_seconds,
                    "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
                    "ram_scope": "Linux worker high-water RSS sampled at end of replay and timing export; includes interpreter, state and timing buffer, excludes later summary aggregation",
                    "source_bytes": source.stat().st_size, "input_historical_first_event_time": first_time,
                    "playback_origin": config["playback_origin"], "thread_count": 1})


def summarize_cell(cell: Path, config, measurements):
    with gzip.open(cell / "decisions.jsonl.gz", "rt") as handle:
        rows = [json.loads(line) for line in handle]
    with gzip.open(cell / "timing.csv.gz", "rt", newline="") as handle:
        timings = list(csv.DictReader(handle))
    for row in timings:
        for key in row:
            if key != "event_id":
                row[key] = float(row[key])
    if len(rows) != len(timings) or any(r["event_id"] != t["event_id"] for r, t in zip(rows, timings)):
        raise RuntimeError("persisted decision/timing identity mismatch")
    by_day = {}
    reasons = {}
    ids = []
    for row in rows:
        if row["notification_emitted"]:
            by_day[row["budget_day_utc"]] = by_day.get(row["budget_day_utc"], 0) + 1
            ids.append(row["alert_id"])
        reasons[str(row["suppression_reason"])] = reasons.get(str(row["suppression_reason"]), 0) + 1
    numeric_keys = ("read_seconds", "decode_seconds", "core_seconds", "write_seconds", "local_service_seconds",
                    "virtual_queue_wait_seconds", "virtual_notification_ready_seconds", "queued_or_in_service_at_arrival")
    duration = sum(t["local_service_seconds"] for t in timings)
    origin = datetime.fromisoformat(measurements["playback_origin"]).timestamp()
    completions = []
    fcfs_valid = True
    queue_counts_valid = True
    for index, timing in enumerate(timings):
        arrival = timing["virtual_arrival_offset_seconds"]
        expected_start = max(arrival, completions[-1] if completions else 0.0)
        fcfs_valid &= abs(timing["virtual_service_start_offset_seconds"] - expected_start) < 1e-9
        fcfs_valid &= abs(timing["virtual_finish_offset_seconds"] - expected_start - timing["local_service_seconds"]) < 1e-9
        queue_counts_valid &= timing["queued_or_in_service_at_arrival"] == index - bisect.bisect_right(completions, arrival)
        completions.append(timing["virtual_finish_offset_seconds"])
    checks = {"no_duplicate_alert_id": len(ids) == len(set(ids)),
              "hard_budget_respected": all(n <= config["daily_budget"] for n in by_day.values()),
              "historical_observed_time_unknown": all(r["observed_time"] is None for r in rows),
              "labels_unused": all(r["label_used"] is False for r in rows),
              "causal_playback_timestamps": all(r["replay_available_time"] <= r["feature_ready_time"] <= r["decision_time"] for r in rows),
              "fcfs_schedule_reconstructed": fcfs_valid,
              "queue_counts_reconstructed": queue_counts_valid,
              "stage_sum_matches_service": all(abs(sum(t[k] for k in ("read_seconds", "decode_seconds", "core_seconds", "write_seconds")) - t["local_service_seconds"]) < 1e-10 for t in timings),
              "decision_before_buffered_write_completion": all(r["decision_time"] <= origin + t["virtual_finish_offset_seconds"] + 1e-6 for r, t in zip(rows, timings))}
    summary = {"schema_version": "monitoring_pilot_cell_v1", **measurements,
               "evidence_role": "new exploratory real-header feasibility run; no attack labels",
               "events": len(rows), "raw_triggers": sum(r["raw_trigger"] is True for r in rows),
               "notifications": len(ids), "notifications_by_playback_utc_day": by_day,
               "suppression_counts": reasons, "budget_exceedance_count": sum(max(0, n-config["daily_budget"]) for n in by_day.values()),
               "checks": checks, "distributions": distributions(timings, numeric_keys),
               "local_service_throughput_events_per_second": len(rows) / duration,
               "wall_loop_throughput_events_per_second": len(rows) / measurements["wall_runtime_seconds"],
               "virtual_completion_seconds": timings[-1]["virtual_finish_offset_seconds"],
               "logs_bytes": sum((cell / name).stat().st_size for name in ("decisions.jsonl.gz", "timing.csv.gz")),
               "log_sha256": {name: sha256(cell / name) for name in ("decisions.jsonl.gz", "timing.csv.gz")},
               "timing_scope": {"measured": ["buffered JSONL read", "JSON decode", "header state/score/group/budget core", "buffered gzip decision write"],
                                "modeled": ["FCFS arrival schedule", "queue wait", "notification-ready offset"],
                                "excluded": ["network acquisition", "Parquet conversion", "remote RPC", "receipts/logs/traces", "consensus finality", "fsync/durable notification", "timing-buffer append and export", "result aggregation"],
                                "clock_warning": "Historical event_time and playback timestamps have distinct epochs. Do not subtract across them.",
                                "compression_warning": "Budget uses playback UTC day; compression is an engineering stress experiment, not an equal-production-horizon comparison."}}
    dump(summary, cell / "summary.json")
    if not all(checks.values()):
        raise RuntimeError(f"pilot validation failed: {checks}")


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=PAPER / "pilot_config.json")
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--cell", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--period", help=argparse.SUPPRESS)
    parser.add_argument("--speed", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--rep", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.config = args.config.resolve()
    config = json.loads(args.config.read_text())
    args.inputs = args.inputs or ROOT / "data/raw/monitoring_jss" / config["source_day"]
    args.inputs = args.inputs.resolve()
    if args.worker:
        worker(args)
        return
    run_id = args.run_id or datetime.now(timezone.utc).strftime("pilot_%Y%m%dT%H%M%S_%fZ")
    if Path(run_id).name != run_id:
        raise ValueError("run-id must be a single path component")
    out = PAPER / "runs" / run_id
    out.mkdir(parents=True, exist_ok=False)
    source_manifest = json.loads((args.inputs / "input_manifest.json").read_text())
    if source_manifest["config_sha256"] != sha256(args.config):
        raise RuntimeError("config changed since source preparation")
    for item in source_manifest["files"]:
        if sha256(args.inputs / item["name"]) != item["sha256"]:
            raise RuntimeError(f"input hash mismatch: {item['name']}")
    shutil.copy2(args.config, out / "config.json")
    shutil.copy2(args.inputs / "input_manifest.json", out / "input_manifest.json")
    snapshot = out / "source_snapshot"
    snapshot.mkdir()
    source_files = []
    for path in PAPER.rglob("*"):
        relative = path.relative_to(PAPER)
        if not path.is_file() or relative.parts[0] == "runs" or "__pycache__" in relative.parts or path.suffix not in (".py", ".json", ".md", ".txt"):
            continue
        target = snapshot / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        source_files.append({"path": str(relative), "sha256": sha256(target)})
    env = {"python": sys.version, "platform": platform.platform(), "machine": platform.machine(),
           "processor": platform.processor(), "logical_cpus": os.cpu_count(),
           "worker_threads": 1, "packages": {dist.metadata["Name"]: dist.version for dist in importlib.metadata.distributions()},
           "cpuinfo": Path("/proc/cpuinfo").read_text().split("\n\n")[0] if Path("/proc/cpuinfo").exists() else None}
    manifest = {"schema_version": "monitoring_pilot_run_v1", "run_id": run_id,
                "started_utc": datetime.now(timezone.utc).isoformat(), "base_commit": git("rev-parse", "HEAD"),
                "branch": git("branch", "--show-current"), "working_tree_status": git("status", "--short"),
                "source_snapshot": source_files, "source_snapshot_scope": "full paper code/config/schema/document text; historical base supplied by base_commit; raw inputs excluded",
                "command": sys.argv, "config_sha256": sha256(args.config), "seed": config["seed"], "environment": env,
                "cells": [], "source_snapshot_note": "complete files saved; no reliance on hash of an unsaved diff"}
    dump(manifest, out / "manifest.json")
    for period in ("ordinary_day.jsonl", "intensive_hour.jsonl"):
        for speed in config["playback_speed_factors"]:
            for rep in range(1, config["repetitions"] + 1):
                name = f"{Path(period).stem}_x{speed}_r{rep}"
                command = [sys.executable, str(Path(__file__).resolve()), "--worker", "--config", str(out / "config.json"),
                           "--inputs", str(args.inputs), "--cell", str(out / name), "--period", period,
                           "--speed", str(speed), "--rep", str(rep)]
                subprocess_start = time.perf_counter()
                completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
                subprocess_seconds = time.perf_counter() - subprocess_start
                (out / (name + ".stdout.txt")).write_text(completed.stdout)
                (out / (name + ".stderr.txt")).write_text(completed.stderr)
                if completed.returncode:
                    raise RuntimeError(f"worker failed: {name}: {completed.stderr}")
                result = json.loads((out / name / "summary.json").read_text())
                manifest["cells"].append({"name": name, "command": command,
                                         "full_worker_wall_seconds": subprocess_seconds,
                                         "full_worker_wall_scope": "startup, replay, timing export and summary aggregation",
                                         "summary_sha256": sha256(out / name / "summary.json")})
                print(json.dumps({"cell": name, "events": result["events"], "notifications": result["notifications"],
                                  "runtime_s": result["wall_runtime_seconds"], "peak_rss_bytes": result["peak_rss_bytes"]}), flush=True)
    manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["status"] = "complete"
    dump(manifest, out / "manifest.json")
    results = [json.loads((out / c["name"] / "summary.json").read_text()) for c in manifest["cells"]]
    # Changing playback speed or measured worker cost must not alter the
    # semantic fixed-rule decisions in this one-day pilot. This is checked,
    # not assumed to generalize across midnight or to adaptive methods.
    semantic_digests = {}
    for cell_entry, result in zip(manifest["cells"], results):
        h = hashlib.sha256()
        with gzip.open(out / cell_entry["name"] / "decisions.jsonl.gz", "rt") as handle:
            for line in handle:
                decision = json.loads(line)
                h.update(json.dumps({key: decision[key] for key in
                         ("event_id", "score", "raw_trigger", "notification_emitted", "alert_id", "suppression_reason")},
                         sort_keys=True, separators=(",", ":")).encode())
        semantic_digests.setdefault(result["period"], []).append(h.hexdigest())
    semantic_invariance = all(len(set(digests)) == 1 for digests in semantic_digests.values())
    if not semantic_invariance:
        raise RuntimeError("semantic decisions differ across pilot playback modes/repeats")
    summary_rows = []
    for r in results:
        summary_rows.append({"period": r["period"], "speed_factor": r["speed_factor"], "repetition": r["repetition"],
            "events": r["events"], "raw_triggers": r["raw_triggers"], "notifications": r["notifications"],
            "budget_exceedances": r["budget_exceedance_count"], "wall_runtime_seconds": r["wall_runtime_seconds"],
            "peak_rss_bytes": r["peak_rss_bytes"], "logs_bytes": r["logs_bytes"],
            "local_service_p50_seconds": r["distributions"]["local_service_seconds"]["p50"],
            "local_service_p95_seconds": r["distributions"]["local_service_seconds"]["p95"],
            "local_service_p99_seconds": r["distributions"]["local_service_seconds"]["p99"],
            "virtual_queue_wait_p99_seconds": r["distributions"]["virtual_queue_wait_seconds"]["p99"],
            "virtual_queue_wait_max_seconds": r["distributions"]["virtual_queue_wait_seconds"]["max"],
            "virtual_queue_max_events": r["distributions"]["queued_or_in_service_at_arrival"]["max"]})
    with (out / "pilot_summary.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary_rows[0]))
        writer.writeheader()
        writer.writerows(summary_rows)
    dump({"run_id": run_id, "cells": summary_rows, "all_checks_pass": semantic_invariance and all(all(r["checks"].values()) for r in results),
          "semantic_invariance_across_modes_and_repeats": semantic_invariance, "semantic_sha256_by_period": semantic_digests,
          "evidence_role": "exploratory real-header software feasibility only", "full_grid_executed": False}, out / "pilot_summary.json")
    print(str(out))


if __name__ == "__main__":
    main()
