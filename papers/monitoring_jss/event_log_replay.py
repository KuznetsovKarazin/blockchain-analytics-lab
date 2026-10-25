"""Bounded Euler event-log replay: syntactic decoding, count, group, budget, log.

The input is a locally acquired/validated all-topic emitter JSONL stream.
Historical event_time_ns is exact and immutable. Playback uses another declared
epoch; never subtract historical timestamps from playback timestamps as latency.
Arrival/queue schedules are virtual, using measured local service costs. No
semantic ABI/monetary decoding, attack labels, remote RPC, or reorg handling.

The rolling window includes every accepted current/past source log and excludes
duplicates and late deliveries. State starts empty, without pre-day history.
Checkpoint round trips are orderly continuation, not crash-safe outbox delivery.
"""
from __future__ import annotations

import argparse
import bisect
from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import subprocess
import sys
import time

PAPER = Path(__file__).resolve().parent
ROOT = PAPER.parents[1]
HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})*\Z")
ADDRESS = "0x27182842e098f60e3d576794a5bffb0777e025d3"


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


def dump(value, path):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def integer(value, name, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def clock(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be finite nonnegative POSIX seconds")
    return float(value)


def hex_field(value, name, size=None):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError(f"{name} must be 0x-prefixed whole hexadecimal bytes")
    decoded = bytes.fromhex(value[2:])
    if size is not None and len(decoded) != size:
        raise ValueError(f"{name} must contain {size} bytes")
    return value.lower(), len(decoded)


def decode_event(raw):
    """Validate/decode raw hexadecimal syntax without interpreting event meanings."""
    e = {name: integer(raw[name], name, 1 if name == "chain_id" else 0)
         for name in ("chain_id", "block_number", "transaction_index", "log_index", "event_time_ns")}
    for name, size in (("address", 20), ("block_hash", 32), ("transaction_hash", 32)):
        e[name] = hex_field(raw[name], name, size)[0]
    e["data"], e["data_bytes"] = hex_field(raw["data"], "data")
    if not isinstance(raw["topics"], (list, tuple)) or len(raw["topics"]) > 4:
        raise ValueError("topics must be a list of at most four EVM log topics")
    e["topics"] = [hex_field(topic, "topic", 32)[0] for topic in raw["topics"]]
    e["removed"] = raw.get("removed")
    if e["removed"] not in (None, False) or type(e["removed"]) not in (type(None), bool):
        raise ValueError("removed log unsupported by canonical-archive pilot")
    e["observed_time"] = raw.get("observed_time")
    e["label_available_time"] = raw.get("label_available_time")
    for name in ("observed_time", "label_available_time"):
        if e[name] is not None:
            e[name] = clock(e[name], name)
    e["event_time"] = e["event_time_ns"] / 1_000_000_000
    return e


@dataclass(frozen=True)
class LogConfig:
    address: str = ADDRESS
    chain_id: int = 1
    window_seconds: int = 60
    threshold_count: int = 10
    cooldown_seconds: int = 300
    daily_budget: int = 5

    def __post_init__(self):
        hex_field(self.address, "address", 20)
        for name in ("chain_id", "window_seconds", "threshold_count"):
            integer(getattr(self, name), name, 1)
        for name in ("cooldown_seconds", "daily_budget"):
            integer(getattr(self, name), name)

    @property
    def model_version(self):
        return "accepted_log_count_v1:" + digest(asdict(self))[:16]


class LogReplayState:
    def __init__(self, config=None):
        self.config = config or LogConfig()
        self.seen = {}
        self.watermark = None
        self.watermark_time_ns = None
        self.window = deque()
        self.last_emitted_time_ns = None
        self.last_decision_time = None
        self.daily_counts = {}
        self.alert_ids = []

    def to_dict(self):
        return {"schema_version": "event_log_replay_state_v1", "config": asdict(self.config),
                "seen": dict(self.seen), "watermark": self.watermark,
                "watermark_time_ns": self.watermark_time_ns, "window": list(self.window),
                "last_emitted_time_ns": self.last_emitted_time_ns,
                "last_decision_time": self.last_decision_time, "daily_counts": dict(self.daily_counts),
                "alert_ids": list(self.alert_ids)}

    @classmethod
    def from_dict(cls, value):
        if value.get("schema_version") != "event_log_replay_state_v1":
            raise ValueError("unsupported state schema")
        result = cls(LogConfig(**value["config"]))
        result.seen = dict(value["seen"])
        result.watermark = tuple(value["watermark"]) if value["watermark"] is not None else None
        result.watermark_time_ns = value["watermark_time_ns"]
        result.window = deque(value["window"])
        result.last_emitted_time_ns = value["last_emitted_time_ns"]
        result.last_decision_time = value["last_decision_time"]
        result.daily_counts = dict(value["daily_counts"])
        result.alert_ids = list(value["alert_ids"])
        return result

    def process(self, event, *, replay_available_time, feature_ready_time, decision_time):
        # Callers pass decode_event output; decoding is measured separately.
        e = event
        if e["chain_id"] != self.config.chain_id or e["address"] != self.config.address.lower():
            raise ValueError("event outside configured chain/emitter population")
        available = clock(replay_available_time, "replay_available_time")
        key = (e["block_number"], e["transaction_index"], e["log_index"])
        eid = "event:" + digest([e["chain_id"], e["block_hash"], e["transaction_hash"], e["log_index"]])
        fingerprint = digest({k: e[k] for k in ("chain_id", "address", "block_number", "block_hash",
                             "transaction_index", "transaction_hash", "log_index", "event_time_ns", "topics", "data", "removed")})
        reason, score, raw, candidate, accepted = None, None, None, False, False
        next_window = None
        if eid in self.seen:
            if self.seen[eid] != fingerprint:
                raise ValueError("conflicting payload for same log identity")
            reason = "duplicate"
        elif self.watermark is not None and key < self.watermark:
            reason = "late"
        elif self.watermark is not None and key == self.watermark:
            raise ValueError("different log identity at same exact order key")
        else:
            if self.watermark_time_ns is not None and e["event_time_ns"] < self.watermark_time_ns:
                raise ValueError("timestamp decreases in increasing canonical chain order")
            accepted = True
            cutoff = e["event_time_ns"] - self.config.window_seconds * 1_000_000_000
            next_window = [t for t in self.window if t > cutoff] + [e["event_time_ns"]]
            score = len(next_window)
            raw = score >= self.config.threshold_count
            if not raw:
                reason = "below_threshold"
        # The rolling feature is now computed. The runner samples this callback
        # here, rather than mislabelling the earlier JSON decode as feature-ready.
        ready = clock(feature_ready_time() if callable(feature_ready_time) else feature_ready_time,
                      "feature_ready_time")
        if available > ready:
            raise ValueError("feature ready before replay availability")
        if accepted and raw:
            if (self.last_emitted_time_ns is not None and
                    e["event_time_ns"] - self.last_emitted_time_ns < self.config.cooldown_seconds * 1_000_000_000):
                reason = "grouped"
            else:
                candidate = True
        decision = clock(decision_time() if callable(decision_time) else decision_time, "decision_time")
        if decision < ready or (self.last_decision_time is not None and decision < self.last_decision_time):
            raise ValueError("decision is before feature ready or preceding decision")
        day = datetime.fromtimestamp(decision, timezone.utc).date().isoformat()
        emitted = candidate and self.daily_counts.get(day, 0) < self.config.daily_budget
        if candidate and not emitted:
            reason = "budget"
        aid = "alert:" + digest([self.config.model_version, eid]) if emitted else None
        self.seen[eid] = fingerprint
        if accepted:
            self.watermark, self.watermark_time_ns = key, e["event_time_ns"]
            self.window = deque(next_window)
        if emitted:
            self.last_emitted_time_ns = e["event_time_ns"]
            self.daily_counts[day] = self.daily_counts.get(day, 0) + 1
            self.alert_ids.append(aid)
        self.last_decision_time = decision
        return {"schema_version": "event_log_replay_decision_v1", "event_id": eid,
                "chain_id": e["chain_id"], "address": e["address"], "block_number": e["block_number"],
                "block_hash": e["block_hash"], "transaction_hash": e["transaction_hash"],
                "transaction_index": e["transaction_index"], "log_index": e["log_index"],
                "event_time_ns": e["event_time_ns"], "event_time": e["event_time"],
                "observed_time": e["observed_time"], "removed": e["removed"],
                "label_available_time": e["label_available_time"], "label_used": False,
                "data_bytes": e["data_bytes"], "topic_count": len(e["topics"]),
                "replay_available_time": available, "feature_ready_time": ready, "decision_time": decision,
                "clock_domain": "independent_playback_posix_seconds", "model_version": self.config.model_version,
                "score": score, "raw_trigger": raw, "group_candidate": candidate,
                "notification_emitted": emitted, "alert_id": aid, "suppression_reason": reason,
                "budget_day_utc": day, "notifications_on_day": self.daily_counts.get(day, 0),
                "daily_budget": self.config.daily_budget}


def quantiles(values):
    x = sorted(values)
    def q(f):
        z = (len(x) - 1) * f
        a = int(z)
        return x[a] + (x[min(a + 1, len(x) - 1)] - x[a]) * (z - a)
    return {"n": len(x), "p50": q(.5), "p95": q(.95), "p99": q(.99), "max": x[-1]}


def semantic(row):
    return {k: v for k, v in row.items() if k not in
            ("replay_available_time", "feature_ready_time", "decision_time", "observed_time", "label_available_time")}


def worker(args):
    args.cell.mkdir(parents=True, exist_ok=False)
    config = json.loads(args.config.read_text())
    state = LogReplayState(LogConfig(**config["core"]))
    origin = datetime.fromisoformat(config["playback_origin"]).timestamp()
    with args.input.open() as handle:
        first = json.loads(handle.readline())["event_time_ns"]
    finish, completions, times, semantics = 0.0, [], [], []
    reasons, by_day = Counter(), Counter()
    counts = Counter()
    begin = time.perf_counter()
    started = datetime.now(timezone.utc).isoformat()
    dpath, tpath = args.cell / "decisions.jsonl.gz", args.cell / "timing.jsonl.gz"
    with args.input.open("rb") as source, gzip.open(dpath, "wt", compresslevel=6) as sink:
        while True:
            t0 = time.perf_counter()
            line = source.readline()
            tr = time.perf_counter()
            if not line:
                break
            e = decode_event(json.loads(line))
            td = time.perf_counter()
            arrival = (e["event_time_ns"] - first) / 1_000_000_000 / args.speed
            start = max(arrival, finish)
            row = state.process(e, replay_available_time=origin + arrival,
                                feature_ready_time=lambda: origin + start + (time.perf_counter() - t0),
                                decision_time=lambda: origin + start + (time.perf_counter() - t0))
            tc = time.perf_counter()
            sink.write(json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
            tw = time.perf_counter()
            service = tw - t0
            finish = start + service
            pending = len(completions) - bisect.bisect_right(completions, arrival)
            times.append({"event_id": row["event_id"], "read_seconds": tr - t0,
                          "decode_seconds": td - tr, "core_seconds": tc - td, "write_seconds": tw - tc,
                          "service_seconds": service, "arrival_offset_seconds": arrival,
                          "start_offset_seconds": start, "finish_offset_seconds": finish,
                          "queue_wait_seconds": start - arrival, "pending_at_arrival": pending,
                          "notification_ready_offset_seconds": finish - arrival})
            completions.append(finish)
            semantics.append(semantic(row))
            reasons[str(row["suppression_reason"])] += 1
            counts["events"] += 1
            counts["raw_triggers"] += row["raw_trigger"] is True
            counts["notifications"] += row["notification_emitted"]
            counts["unknown_removed"] += row["removed"] is None
            counts["unknown_observed"] += row["observed_time"] is None
            if row["notification_emitted"]:
                by_day[row["budget_day_utc"]] += 1
        tclose = time.perf_counter()
    close_seconds = time.perf_counter() - tclose
    wall = time.perf_counter() - begin
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    with gzip.open(tpath, "wt", compresslevel=6) as target:
        for row in times:
            target.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    # Verify actual files after close, not merely in-memory rows.
    with gzip.open(dpath, "rt") as source:
        persisted = [json.loads(line) for line in source]
    with gzip.open(tpath, "rt") as source:
        measured = [json.loads(line) for line in source]
    checks = {"persisted_decisions_match": [semantic(r) for r in persisted] == semantics,
              "persisted_timings_match": measured == times,
              "hard_budget": all(n <= state.config.daily_budget for n in by_day.values()),
              "unique_alert_ids": len(state.alert_ids) == len(set(state.alert_ids)),
              "timestamps_causal": all(r["replay_available_time"] <= r["feature_ready_time"] <= r["decision_time"] for r in persisted),
              "historical_observed_unknown": counts["unknown_observed"] == counts["events"],
              "removed_unknown_preserved": counts["unknown_removed"] == counts["events"],
              "timing_stage_sum": all(abs(sum(t[k] for k in ("read_seconds", "decode_seconds", "core_seconds", "write_seconds")) - t["service_seconds"]) < 1e-12 for t in times),
              "decision_before_buffered_output_complete": all(r["decision_time"] <= origin + t["finish_offset_seconds"] + 1e-6 for r, t in zip(persisted, times))}
    timing_keys = ("read_seconds", "decode_seconds", "core_seconds", "write_seconds", "service_seconds",
                   "queue_wait_seconds", "pending_at_arrival", "notification_ready_offset_seconds")
    summary = {"schema_version": "event_log_pilot_cell_v1", "input_sha256": sha256(args.input),
               "speed_factor": args.speed, "repetition": args.rep, "counts": dict(counts),
               "suppression_counts": dict(reasons), "notifications_by_day": dict(by_day), "checks": checks,
               "semantic_decisions_sha256": digest(semantics), "semantic_hash_exclusions": ["playback stage timestamps", "observed_time", "label_available_time"],
               "distributions": {k: quantiles([t[k] for t in times]) for k in timing_keys},
               "wall_replay_seconds": wall, "gzip_close_seconds": close_seconds,
               "local_service_throughput_events_per_second": len(times) / sum(t["service_seconds"] for t in times),
               "peak_rss_after_replay_bytes": rss, "rss_scope": "Linux worker high-water through replay including state and metric buffers; excludes subsequent validation reads",
               "thread_count": 1, "input_bytes": args.input.stat().st_size,
               "output_bytes": sum(p.stat().st_size for p in (dpath, tpath)),
               "log_sha256": {p.name: sha256(p) for p in (dpath, tpath)},
               "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
               "command": sys.argv,
               "timing_scope": {"measured": ["buffered JSONL read", "JSON and raw-hex syntax decode", "rolling count/group/budget core", "buffered gzip decision write"],
                                "modeled": ["FIFO arrivals", "queue wait", "notification-ready offset"],
                                "excluded": ["AWS acquisition", "Parquet projection", "header joining", "ABI/monetary decoding", "live RPC/finality", "fsync/outbox/operator", "metric buffer export and summary"],
                                "warning": "Original event_time and playback times have different epochs; compressed queue tests do not imply historical latency or production-day budget equivalence."}}
    dump(summary, args.cell / "summary.json")
    if not all(checks.values()):
        raise RuntimeError(f"event-log pilot checks failed: {checks}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--config", type=Path, default=PAPER / "event_log_pilot_config.json")
    ap.add_argument("--run-id")
    ap.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--cell", type=Path, help=argparse.SUPPRESS)
    ap.add_argument("--speed", type=int, help=argparse.SUPPRESS)
    ap.add_argument("--rep", type=int, help=argparse.SUPPRESS)
    args = ap.parse_args()
    args.input, args.config = args.input.resolve(), args.config.resolve()
    if args.worker:
        worker(args)
        return
    config = json.loads(args.config.read_text())
    run_id = args.run_id or datetime.now(timezone.utc).strftime("event_logs_%Y%m%dT%H%M%S_%fZ")
    if Path(run_id).name != run_id:
        raise ValueError("run-id must be a single path component")
    out = PAPER / "runs" / run_id
    out.mkdir(parents=True, exist_ok=False)
    source = out / "source_snapshot"
    source.mkdir()
    snapshot = []
    for path in (Path(__file__), args.config, PAPER / "tests/test_event_log_replay.py"):
        target = source / path.name
        shutil.copy2(path, target)
        snapshot.append({"path": target.name, "sha256": sha256(target)})
    acquisition_path = PAPER / "runs" / args.input.parent.name / "acquisition_manifest.json"
    acquisition = json.loads(acquisition_path.read_text())
    if acquisition["status"] != "complete" or not all(acquisition["checks"].values()):
        raise RuntimeError("input acquisition is incomplete or failed checks")
    matches = [r for r in acquisition["files"] if Path(r["path"]).name == args.input.name]
    if len(matches) != 1 or matches[0]["sha256"] != sha256(args.input):
        raise RuntimeError("input differs from completed acquisition manifest")
    shutil.copy2(acquisition_path, out / "acquisition_manifest.json")
    shutil.copy2(args.config, out / "config.json")
    git_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    manifest = {"schema_version": "event_log_pilot_run_v1", "run_id": run_id,
                "status": "running", "started_utc": datetime.now(timezone.utc).isoformat(),
                "input_path": str(args.input.relative_to(ROOT)), "input_sha256": sha256(args.input),
                "config_sha256": sha256(args.config), "source_snapshot": snapshot, "base_commit": git_head,
                "command": sys.argv, "seed": config["seed"],
                "environment": {"python": sys.version, "platform": platform.platform(), "cpu_count": os.cpu_count(), "worker_threads": 1,
                                "cpu_model": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), platform.processor()) if Path("/proc/cpuinfo").exists() else platform.processor()},
                "worker_source": "workers execute the captured source_snapshot/event_log_replay.py with run-local config.json",
                "scope": "one preselected protocol-day; six engineering runs; no attack labels, independent incidents or full method grid"}
    dump(manifest, out / "manifest.json")
    summaries = []
    for speed in config["playback_speed_factors"]:
        for rep in range(1, config["repetitions"] + 1):
            cell = out / f"day_x{speed}_r{rep}"
            command = [sys.executable, str(source / "event_log_replay.py"), "--worker", "--input", str(args.input),
                       "--config", str(out / "config.json"), "--cell", str(cell), "--speed", str(speed), "--rep", str(rep)]
            with (out / f"{cell.name}.stdout.txt").open("w") as stdout, (out / f"{cell.name}.stderr.txt").open("w") as stderr:
                result = subprocess.run(command, cwd=ROOT, stdout=stdout, stderr=stderr)
            if result.returncode:
                manifest["status"] = "failed"
                manifest["failed_cell"] = cell.name
                dump(manifest, out / "manifest.json")
                raise RuntimeError(f"worker failed: {cell.name}; see stderr")
            summaries.append({"cell": cell.name, **json.loads((cell / "summary.json").read_text())})
    check = len({s["semantic_decisions_sha256"] for s in summaries}) == 1
    frozen_sources_unchanged = all(sha256(source / item["path"]) == item["sha256"] for item in snapshot)
    input_config_unchanged = sha256(args.input) == manifest["input_sha256"] and sha256(out / "config.json") == manifest["config_sha256"]
    check = check and frozen_sources_unchanged and input_config_unchanged
    manifest.update({"status": "complete" if check else "failed_semantic_invariance",
                     "finished_utc": datetime.now(timezone.utc).isoformat(),
                     "modes_and_repeats_semantic_invariance": len({s["semantic_decisions_sha256"] for s in summaries}) == 1,
                     "frozen_sources_unchanged": frozen_sources_unchanged, "input_config_unchanged": input_config_unchanged,
                     "cells": [s["cell"] for s in summaries]})
    dump(manifest, out / "manifest.json")
    dump({"schema_version": "event_log_pilot_summary_v1", "run_id": run_id,
          "modes_and_repeats_semantic_invariance": check, "cells": summaries}, out / "pilot_summary.json")
    if not check:
        raise RuntimeError("semantic decisions differ across modes/repeats")
    print(json.dumps({"status": "complete", "run": str(out.relative_to(ROOT)),
                      "events_per_cell": summaries[0]["counts"]["events"], "cells": len(summaries)}))


if __name__ == "__main__":
    main()
