"""Read-only offline oracle for persisted Euler pilot evidence; no replay rerun.

Requires the original acquired JSONL input and run directory in the repository.
Does not import the production replay module or modify its inputs/outputs.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
from pathlib import Path
import platform
import sys


PAPER = Path(__file__).resolve().parents[1]
ROOT = PAPER.parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def close(actual, expected, tolerance=1e-10):
    assert math.isfinite(actual) and abs(actual - expected) <= tolerance, (actual, expected)


def distribution(values):
    values = sorted(values)
    def percentile(p):
        position = (len(values) - 1) * p
        low = math.floor(position)
        high = math.ceil(position)
        return values[low] + (values[high] - values[low]) * (position - low)
    return {"n": len(values), "p50": percentile(.5), "p95": percentile(.95),
            "p99": percentile(.99), "max": values[-1]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, default=PAPER / "runs/event_logs_20261025T084327_927529Z")
    parser.add_argument("--output", type=Path, default=Path(__file__).with_suffix(".json"))
    args = parser.parse_args()
    run = args.run.resolve()
    manifest = json.loads((run / "manifest.json").read_text())
    config = json.loads((run / "config.json").read_text())
    core = config["core"]
    assert manifest["status"] == "complete"
    assert sha(run / "config.json") == manifest["config_sha256"]
    for source in manifest["source_snapshot"]:
        assert sha(run / "source_snapshot" / source["path"]) == source["sha256"]
    input_path = ROOT / manifest["input_path"]
    assert sha(input_path) == manifest["input_sha256"]
    acquisition = json.loads((run / "acquisition_manifest.json").read_text())
    assert acquisition["status"] == "complete" and all(acquisition["checks"].values())
    assert [item["sha256"] for item in acquisition["files"] if Path(item["path"]).name == input_path.name] == [manifest["input_sha256"]]
    inputs = [json.loads(line) for line in input_path.read_text().splitlines()]
    keys = [(e["block_number"], e["transaction_index"], e["log_index"]) for e in inputs]
    assert all(a < b for a, b in zip(keys, keys[1:]))
    assert all(a["event_time_ns"] <= b["event_time_ns"] for a, b in zip(inputs, inputs[1:]))
    assert len({(e["chain_id"], e["block_hash"], e["transaction_hash"], e["log_index"]) for e in inputs}) == len(inputs)
    assert all(e["chain_id"] == core["chain_id"] and e["address"].lower() == core["address"].lower() for e in inputs)
    assert all(e.get("observed_time") is None and e.get("label_available_time") is None and e.get("removed") is None for e in inputs)
    origin = datetime.fromisoformat(config["playback_origin"]).timestamp()
    model_version = "accepted_log_count_v1:" + digest(core)[:16]
    semantic_exclusions = {"replay_available_time", "feature_ready_time", "decision_time", "observed_time", "label_available_time"}
    all_semantics, results, hashed_logs = [], [], []
    expected_cells = {f"day_x{speed}_r{rep}" for speed in config["playback_speed_factors"] for rep in range(1, config["repetitions"] + 1)}
    assert set(manifest["cells"]) == expected_cells
    aggregate = json.loads((run / "pilot_summary.json").read_text())
    for cell in manifest["cells"]:
        directory = run / cell
        summary = json.loads((directory / "summary.json").read_text())
        assert next(item for item in aggregate["cells"] if item["cell"] == cell) == {"cell": cell, **summary}
        assert summary["input_sha256"] == manifest["input_sha256"]
        streams = {}
        for filename in ("decisions.jsonl.gz", "timing.jsonl.gz"):
            path = directory / filename
            assert sha(path) == summary["log_sha256"][filename]
            with gzip.open(path, "rt") as source:
                streams[filename] = [json.loads(line) for line in source]
            hashed_logs.append({"path": str(path.relative_to(ROOT)), "sha256": sha(path), "gzip_crc_eof_verified": True})
        decisions, timings = streams["decisions.jsonl.gz"], streams["timing.jsonl.gz"]
        assert len(decisions) == len(timings) == len(inputs)
        emitted_at = None
        day_counts, reasons = Counter(), Counter()
        alert_ids, semantics, completions = [], [], []
        same_timestamp_queued = 0
        for i, (e, row, timing) in enumerate(zip(inputs, decisions, timings)):
            # Deliberately scan the accepted prefix, independently of the production deque.
            count = sum(prior["event_time_ns"] > e["event_time_ns"] - core["window_seconds"] * 1_000_000_000 for prior in inputs[:i + 1])
            raw = count >= core["threshold_count"]
            grouped = raw and emitted_at is not None and e["event_time_ns"] - emitted_at < core["cooldown_seconds"] * 1_000_000_000
            candidate = raw and not grouped
            day = datetime.fromtimestamp(row["decision_time"], timezone.utc).date().isoformat()
            emitted = candidate and day_counts[day] < core["daily_budget"]
            reason = "below_threshold" if not raw else "grouped" if grouped else "budget" if not emitted else None
            event_id = "event:" + digest([e["chain_id"], e["block_hash"].lower(), e["transaction_hash"].lower(), e["log_index"]])
            alert_id = "alert:" + digest([model_version, event_id]) if emitted else None
            if emitted:
                emitted_at = e["event_time_ns"]
                day_counts[day] += 1
                alert_ids.append(alert_id)
            expected = {"schema_version": "event_log_replay_decision_v1", "event_id": event_id,
                        "clock_domain": "independent_playback_posix_seconds", "model_version": model_version,
                        "score": count, "raw_trigger": raw, "group_candidate": candidate,
                        "notification_emitted": emitted, "alert_id": alert_id, "suppression_reason": reason,
                        "budget_day_utc": day, "notifications_on_day": day_counts[day], "daily_budget": core["daily_budget"],
                        "event_time": e["event_time_ns"] / 1_000_000_000, "label_used": False,
                        "data_bytes": len(bytes.fromhex(e["data"][2:])), "topic_count": len(e["topics"]), "removed": None}
            for field in ("chain_id", "block_number", "transaction_index", "log_index", "event_time_ns"):
                expected[field] = e[field]
            for field in ("address", "block_hash", "transaction_hash"):
                expected[field] = e[field].lower()
            actual_semantic = {k: v for k, v in row.items() if k not in semantic_exclusions}
            assert actual_semantic == expected, (cell, i, actual_semantic, expected)
            assert row["observed_time"] is None and row["label_available_time"] is None
            semantics.append(actual_semantic)
            reasons[str(reason)] += 1
            assert timing["event_id"] == event_id
            arrival = (e["event_time_ns"] - inputs[0]["event_time_ns"]) / 1_000_000_000 / summary["speed_factor"]
            service = sum(timing[k] for k in ("read_seconds", "decode_seconds", "core_seconds", "write_seconds"))
            assert all(timing[k] >= 0 for k in ("read_seconds", "decode_seconds", "core_seconds", "write_seconds"))
            close(timing["service_seconds"], service, 1e-12)
            start = max(arrival, completions[-1] if completions else 0)
            finish = start + service
            close(timing["arrival_offset_seconds"], arrival)
            close(timing["start_offset_seconds"], start)
            close(timing["finish_offset_seconds"], finish)
            close(timing["queue_wait_seconds"], start - arrival)
            close(timing["notification_ready_offset_seconds"], finish - arrival)
            assert timing["pending_at_arrival"] == sum(end > arrival for end in completions)
            completions.append(finish)
            close(row["replay_available_time"], origin + arrival, 1e-6)
            assert row["replay_available_time"] <= row["feature_ready_time"] <= row["decision_time"] <= origin + finish + 1e-6
            assert origin + start + timing["read_seconds"] + timing["decode_seconds"] <= row["feature_ready_time"] + 1e-6
            assert row["decision_time"] <= origin + start + service - timing["write_seconds"] + 1e-6
            if i:
                assert decisions[i-1]["decision_time"] <= row["decision_time"]
            if summary["speed_factor"] == 1 and start > arrival:
                assert i and e["event_time_ns"] == inputs[i-1]["event_time_ns"]
                same_timestamp_queued += 1
        assert len(alert_ids) == len(set(alert_ids)) and all(n <= core["daily_budget"] for n in day_counts.values())
        assert summary["notifications_by_day"] == dict(day_counts)
        assert summary["suppression_counts"] == dict(reasons)
        assert summary["counts"] == {"events": len(inputs), "notifications": len(alert_ids), "raw_triggers": sum(r["raw_trigger"] for r in decisions), "unknown_observed": len(inputs), "unknown_removed": len(inputs)}
        assert digest(semantics) == summary["semantic_decisions_sha256"]
        for name, persisted in summary["distributions"].items():
            actual = distribution([t[name] for t in timings])
            for key in actual:
                close(persisted[key], actual[key])
        close(summary["local_service_throughput_events_per_second"], len(inputs) / sum(t["service_seconds"] for t in timings), 1e-8)
        assert summary["wall_replay_seconds"] >= sum(t["service_seconds"] for t in timings) + summary["gzip_close_seconds"]
        assert summary["peak_rss_after_replay_bytes"] > 0 and summary["thread_count"] == 1
        assert summary["output_bytes"] == sum((directory / f).stat().st_size for f in streams)
        assert all(summary["checks"].values())
        all_semantics.append(semantics)
        results.append({"cell": cell, "counts": summary["counts"], "suppression_counts": dict(reasons),
                        "wall_replay_seconds": summary["wall_replay_seconds"], "peak_rss_after_replay_bytes": summary["peak_rss_after_replay_bytes"],
                        "local_service_throughput_events_per_second": summary["local_service_throughput_events_per_second"],
                        "service_p99_seconds": summary["distributions"]["service_seconds"]["p99"],
                        "virtual_queue_wait_p99_seconds": summary["distributions"]["queue_wait_seconds"]["p99"],
                        "virtual_buffer_complete_p99_seconds": summary["distributions"]["notification_ready_offset_seconds"]["p99"],
                        "pending_at_arrival_max": summary["distributions"]["pending_at_arrival"]["max"],
                        "x1_queued_same_timestamp_count": same_timestamp_queued if summary["speed_factor"] == 1 else None,
                        "all_checks_pass": True})
    assert all(rows == all_semantics[0] for rows in all_semantics)
    numeric = ("wall_replay_seconds", "peak_rss_after_replay_bytes", "local_service_throughput_events_per_second", "service_p99_seconds", "virtual_queue_wait_p99_seconds", "virtual_buffer_complete_p99_seconds", "pending_at_arrival_max")
    report = {"schema_version": "event_log_independent_review_v1", "run_id": manifest["run_id"],
              "verdict": "PASS_FOR_SINGLE_DAY_ENGINEERING_SCOPE", "all_checks_pass": True,
              "review_script_sha256": sha(Path(__file__)), "python": sys.version, "platform": platform.platform(),
              "review_method": "Independent prefix-count/group/budget oracle and direct FIFO arithmetic; production module not imported; no training, live fetch or pilot rerun.",
              "source_and_input_hashes_verified": True, "input_sha256": manifest["input_sha256"],
              "source_snapshot": manifest["source_snapshot"], "cells_checked": len(results),
              "decisions_checked": sum(r["counts"]["events"] for r in results), "gzip_logs_checked": len(hashed_logs),
              "input_events": len(inputs), "transactions": len({e["transaction_hash"] for e in inputs}),
              "blocks": len({e["block_hash"] for e in inputs}), "same_semantics_all_six_cells": True,
              "ranges_all_cells": {key: {"min": min(r[key] for r in results), "max": max(r[key] for r in results)} for key in numeric},
              "cells": results, "gzip_logs": hashed_logs,
              "limitations": [
                  "One preselected Euler protocol-day, no attack labels and no precision/recall or attack-detection claim.",
                  "At x1, every nonzero queue wait occurs within equal historical block-timestamp groups. These synthetic simultaneous arrivals are not observed arrival bursts; observed_time remains null.",
                  "Service is measured local buffered JSONL read, JSON/hex decode, count/group/budget and buffered gzip decision write. Virtual FIFO wait and buffer-complete offset are computed from these durations, not measured historical/live latency.",
                  "The buffer-complete distribution covers every input log, including suppressed/non-trigger rows; it is not an alert-only operator delivery metric. No fsync or remote operator delivery is timed.",
                  "Replay-loop wall time includes decisions-file close and loop overhead but excludes acquisition, Parquet work, post-replay timing export/verification and summary. RSS is worker high-water through replay, includes state/metric buffers, excludes later validation reads; audit verifies recorded values and scope, not an independent remeasurement.",
                  "Initial count window is empty. Grouping uses original event time and last emitted alert; daily budget uses playback decision day. Compressed-mode equality in this one-day fixture does not establish budget invariance across arbitrary day boundaries.",
                  "Persisted gzip SHA and full decompression verify this run's files; orderly state snapshots do not prove arbitrary-crash or transactional-outbox recovery."
              ]}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"file": str(args.output), "cells": len(results), "decisions": report["decisions_checked"], "gzip_logs": len(hashed_logs), "ranges": report["ranges_all_cells"], "all_checks_pass": True}))


if __name__ == "__main__":
    main()
