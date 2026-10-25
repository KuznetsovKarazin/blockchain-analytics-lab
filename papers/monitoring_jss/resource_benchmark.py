"""External resource instrumentation for the unchanged finite-window policy core.

One invocation executes one fresh-process job. Timing traces and decisions stream
to disk; this worker never retains a per-record timing array. Local service is
read/parse/syntactic-decode/aggregate-core/encode/buffered-gzip-write. It excludes
trace bookkeeping and file open/close; actual loop wall time includes those
costs. No historical arrival, network, durability or attack-quality claim follows.

Memory jobs stop at one declared prefix, sample RSS, then serialize state. A new
process is required for each prefix, so serialization cannot taint later samples.
Queue/quantile helpers are postprocessing only and must run in another process.
"""
from __future__ import annotations

import argparse
from collections import deque
from dataclasses import asdict
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import resource
import sys
import time

PAPER = Path(__file__).resolve().parent
if str(PAPER) not in sys.path:
    sys.path.insert(0, str(PAPER))
from budget_policy_replay import BudgetConfig, PolicyReplayState, utc_day
from event_log_replay import decode_event, integer, sha256

STAGES = ("read_ns", "parse_ns", "decode_ns", "core_ns", "encode_ns", "write_ns")
SOURCE_NAMES = ("resource_benchmark.py", "budget_policy_replay.py", "event_log_replay.py")
THREAD_VARIABLES = ("PYTHONHASHSEED", "OMP_NUM_THREADS", "MKL_NUM_THREADS",
                    "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def write_json(path, value):
    with Path(path).open("xb") as handle:
        handle.write(json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n")


def resident_bytes():
    """Linux current RSS; ru_maxrss remains a separate process-lifetime value."""
    with Path("/proc/self/statm").open() as handle:
        resident_pages = int(handle.read().split()[1])
    return resident_pages * os.sysconf("SC_PAGE_SIZE")


def memory_sample():
    if not sys.platform.startswith("linux"):
        raise RuntimeError("this resource measurement contract requires Linux RSS units")
    return {"current_rss_bytes": resident_bytes(),
            "process_peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024}


def validate_job(job):
    if job.get("schema_version") != "resource_benchmark_job_v1":
        raise ValueError("unsupported resource job schema")
    if job["mode"] not in ("timing", "memory"):
        raise ValueError("unknown resource job mode")
    config = BudgetConfig(**job["policy_config"])
    if config.daily_budget != 5:
        raise ValueError("this resource study is restricted to the frozen primary budget B5")
    if job.get("gzip_compresslevel") != 6:
        raise ValueError("gzip compression level must equal the frozen value six")
    if set(job["source_sha256"]) != set(SOURCE_NAMES):
        raise ValueError("exact three executable source hashes required")
    for name, expected in job["source_sha256"].items():
        if sha256(PAPER / name) != expected:
            raise ValueError("executable source hash mismatch: " + name)
    if not job["inputs"]:
        raise ValueError("no input files")
    paths = set()
    days = []
    total = 0
    for item in job["inputs"]:
        path = Path(item["path"])
        if not path.is_absolute() or str(path) in paths:
            raise ValueError("input paths must be absolute and distinct")
        paths.add(str(path))
        days.append(item["day_utc"])
        total += integer(item["rows"], "input rows")
        if path.stat().st_size != integer(item["bytes"], "input bytes") or sha256(path) != item["sha256"]:
            raise ValueError("input size/hash mismatch: " + str(path))
    if days != sorted(set(days)):
        raise ValueError("input days must be unique and chronological")
    reference = job["reference"]
    expected_count = integer(reference["records"], "reference records", 1)
    if job["mode"] == "timing":
        if expected_count != total or job.get("prefix_records") is not None:
            raise ValueError("timing job must replay the complete frozen population")
    else:
        if integer(job["prefix_records"], "prefix records", 1) != expected_count or expected_count > total:
            raise ValueError("invalid memory prefix")
    for key in ("decision_stream_sha256", "final_state_sha256"):
        value = reference.get(key)
        if value is None and key == "final_state_sha256" and expected_count < total and job["mode"] == "memory":
            continue
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("invalid reference digest: " + key)
    affinity = job["cpu_affinity"]
    if not affinity or any(type(x) is not int or x < 0 for x in affinity) or len(set(affinity)) != len(affinity):
        raise ValueError("invalid CPU affinity")
    if not set(affinity).issubset(os.sched_getaffinity(0)):
        raise ValueError("requested CPU affinity unavailable")
    return config, expected_count


def _gzip_output(path):
    raw = Path(path).open("xb")
    return raw, gzip.GzipFile(filename="", mode="wb", compresslevel=6, fileobj=raw, mtime=0)


def _read_back_decisions(path):
    h, n = hashlib.sha256(), 0
    with gzip.open(path, "rb") as handle:
        for line in handle:
            if canonical(json.loads(line)) + b"\n" != line:
                raise ValueError("noncanonical decision output")
            h.update(line)
            n += 1
    return n, h.hexdigest()


def _read_back_trace(path, expected_rows, totals):
    observed = dict.fromkeys(STAGES, 0)
    with gzip.open(path, "rb") as handle:
        n = 0
        for n, line in enumerate(handle, 1):
            row = json.loads(line)
            if row["record_index"] != n - 1:
                raise ValueError("timing trace ordering mismatch")
            for key in STAGES:
                observed[key] += integer(row[key], key)
            if row["service_ns"] != sum(row[key] for key in STAGES):
                raise ValueError("timing stage sum differs from service interval")
    if n != expected_rows or observed != totals:
        raise ValueError("timing trace count/totals mismatch")


def run_worker(job_path, output):
    """Execute a single job; callers must spawn a new interpreter for each call."""
    job_path, output = Path(job_path).resolve(), Path(output).resolve()
    job_bytes = job_path.read_bytes()
    job = json.loads(job_bytes)
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "job.json", job)
    preflight_start = time.perf_counter_ns()
    config, limit = validate_job(job)
    os.sched_setaffinity(0, set(job["cpu_affinity"]))
    preflight_ns = time.perf_counter_ns() - preflight_start
    state = PolicyReplayState(config)
    decision_hash = hashlib.sha256()
    stage_totals = dict.fromkeys(STAGES, 0)
    raw_sink = sink = raw_trace = trace = None
    if job["mode"] == "timing":
        raw_sink, sink = _gzip_output(output / "decisions.jsonl.gz")
        raw_trace, trace = _gzip_output(output / "timings.jsonl.gz")
    baseline = memory_sample()
    loop_start = time.perf_counter_ns()
    cpu_start = time.process_time_ns()
    records = input_bytes = source_open_close_ns = eof_read_ns = 0
    trace_encode_ns = trace_write_ns = 0
    traversed = []
    stopped = False
    try:
        for item in job["inputs"]:
            if records == limit:
                break
            t_open = time.perf_counter_ns()
            source = Path(item["path"]).open("rb")
            source_open_close_ns += time.perf_counter_ns() - t_open
            input_hash, file_rows = hashlib.sha256(), 0
            reached_eof = False
            try:
                while records < limit:
                    t0 = time.perf_counter_ns()
                    line = source.readline()
                    t1 = time.perf_counter_ns()
                    if not line:
                        eof_read_ns += t1 - t0
                        reached_eof = True
                        break
                    raw_event = json.loads(line)
                    t2 = time.perf_counter_ns()
                    event = decode_event(raw_event)
                    t3 = time.perf_counter_ns()
                    decision = state.process(event)
                    t4 = time.perf_counter_ns()
                    encoded = canonical(decision) + b"\n"
                    t5 = time.perf_counter_ns()
                    if sink is not None:
                        sink.write(encoded)
                    t6 = time.perf_counter_ns()
                    # All bookkeeping after t6 is outside defined local service.
                    if utc_day(event["event_time_ns"]) != item["day_utc"]:
                        raise ValueError("record outside declared input day")
                    decision_hash.update(encoded)
                    input_hash.update(line)
                    input_bytes += len(line)
                    file_rows += 1
                    stamps = (t0, t1, t2, t3, t4, t5, t6)
                    if trace is not None:
                        timing = {key: stamps[i + 1] - stamps[i] for i, key in enumerate(STAGES)}
                        timing.update(record_index=records, event_time_ns=event["event_time_ns"], service_ns=t6 - t0)
                        trace_t0 = time.perf_counter_ns()
                        encoded_timing = canonical(timing) + b"\n"
                        trace_t1 = time.perf_counter_ns()
                        trace.write(encoded_timing)
                        trace_t2 = time.perf_counter_ns()
                        trace_encode_ns += trace_t1 - trace_t0
                        trace_write_ns += trace_t2 - trace_t1
                        for key in STAGES:
                            stage_totals[key] += timing[key]
                    records += 1
                # At an exact final-row limit, read EOF for a full-population job
                # so completeness/hash checks still cover the last source file.
                if records == limit and job["mode"] == "timing":
                    t_eof = time.perf_counter_ns()
                    trailing = source.readline()
                    eof_read_ns += time.perf_counter_ns() - t_eof
                    if trailing:
                        raise ValueError("reference population ends before source EOF")
                    reached_eof = True
            finally:
                t_close = time.perf_counter_ns()
                source.close()
                source_open_close_ns += time.perf_counter_ns() - t_close
            if reached_eof and (file_rows != item["rows"] or input_hash.hexdigest() != item["sha256"]):
                raise ValueError("input bytes/count changed while replaying")
            traversed.append({"path": item["path"], "rows_read": file_rows,
                              "bytes_read_sha256": input_hash.hexdigest(), "read_to_eof": reached_eof})
        cpu_ns = time.process_time_ns() - cpu_start
        loop_wall_ns = time.perf_counter_ns() - loop_start
        before_serialization = memory_sample()
        # Capture peak before close/verification/state serialization allocations.
        close_start = time.perf_counter_ns()
        for handle in (sink, raw_sink, trace, raw_trace):
            if handle is not None:
                handle.close()
        output_close_ns = time.perf_counter_ns() - close_start
        stopped = True
    finally:
        if not stopped:
            for handle in (sink, raw_sink, trace, raw_trace):
                if handle is not None:
                    handle.close()
    if records != limit or decision_hash.hexdigest() != job["reference"]["decision_stream_sha256"]:
        raise ValueError("semantic decision stream differs from accepted reference")
    # This is intentionally after the measured RSS sample in both job modes.
    state_bytes = canonical(state.to_dict())
    state_digest = hashlib.sha256(state_bytes).hexdigest()
    if job["reference"].get("final_state_sha256") is not None and state_digest != job["reference"]["final_state_sha256"]:
        raise ValueError("final state differs from accepted reference")
    state_raw, state_sink = _gzip_output(output / "final_state.json.gz")
    try:
        state_sink.write(state_bytes)
    finally:
        state_sink.close()
        state_raw.close()
    with gzip.open(output / "final_state.json.gz", "rb") as handle:
        if handle.read() != state_bytes:
            raise ValueError("state readback mismatch")
    if job["mode"] == "timing":
        if _read_back_decisions(output / "decisions.jsonl.gz") != (records, decision_hash.hexdigest()):
            raise ValueError("decision output readback mismatch")
        _read_back_trace(output / "timings.jsonl.gz", records, stage_totals)
    # Prefix jobs may stop before EOF. Rehash all original inputs afterwards;
    # these checks do not enter the measured loop or pre-serialization RSS.
    for item in job["inputs"]:
        if sha256(item["path"]) != item["sha256"] or Path(item["path"]).stat().st_size != item["bytes"]:
            raise ValueError("input changed after replay")
    for name, expected in job["source_sha256"].items():
        if sha256(PAPER / name) != expected:
            raise ValueError("executable source changed while replaying")
    filenames = ["job.json", "final_state.json.gz"]
    if job["mode"] == "timing":
        filenames += ["decisions.jsonl.gz", "timings.jsonl.gz"]
    result = {"schema_version": "resource_benchmark_result_v1", "status": "complete",
              "completed_utc": datetime.now(timezone.utc).isoformat(),
              "cell_id": job["cell_id"], "population_id": job["population_id"], "mode": job["mode"],
              "policy_config": asdict(config), "records": records, "input_bytes_read": input_bytes,
              "job_source_sha256": hashlib.sha256(job_bytes).hexdigest(),
              "source_sha256": job["source_sha256"], "decision_stream_sha256": decision_hash.hexdigest(),
              "final_state_sha256": state_digest, "canonical_state_bytes": len(state_bytes),
              "seen_entries": len(state.seen), "order_key_entries": len(state.order_keys),
              "rolling_window_entries": len(state.window), "notification_ids": len(state.alert_ids),
              "baseline_memory": baseline, "before_serialization_memory": before_serialization,
              "preflight_ns": preflight_ns, "loop_wall_ns": loop_wall_ns, "loop_cpu_ns": cpu_ns,
              "source_open_close_ns": source_open_close_ns, "eof_read_ns": eof_read_ns,
              "output_close_ns": output_close_ns,
              "trace_encode_ns": trace_encode_ns if job["mode"] == "timing" else None,
              "trace_write_ns": trace_write_ns if job["mode"] == "timing" else None,
              "stage_total_ns": stage_totals if job["mode"] == "timing" else None,
              "service_total_ns": sum(stage_totals.values()) if job["mode"] == "timing" else None,
              "traversed_inputs": traversed,
              "artifacts": {name: {"sha256": sha256(output / name), "bytes": (output / name).stat().st_size}
                            for name in filenames},
              "environment": {"python": sys.version, "platform": platform.platform(), "pid": os.getpid(),
                              "cpu_affinity": sorted(os.sched_getaffinity(0)),
                              "thread_environment": {k: os.environ.get(k) for k in THREAD_VARIABLES},
                              "perf_counter": vars(time.get_clock_info("perf_counter"))},
              "scope": {"service_clock": "local perf_counter_ns, independent of logical policy event time",
                        "historical_observed_time_inferred": False, "durable_or_remote_sink": False,
                        "rss_excludes_postprocessing_and_state_serialization": True,
                        "rss_is_whole_process_not_state_only": True,
                        "cache_state": "preflight hashes read all inputs; uncontrolled filesystem/OS cache",
                        "process_peak_scope": "lifetime peak includes interpreter/import/preflight before baseline",
                        "trace_bookkeeping": "excluded from service; included in actual loop wall and CPU",
                        "trace_timers": "encode/write intervals only, not total or counterfactual incremental instrumentation cost",
                        "memory_prefix": "one fresh process per prefix; no earlier state serialization"}}
    write_json(output / "summary.json", result)
    return result


def nearest_rank(values, percent):
    if not values:
        return None
    values = sorted(values)
    return values[max(0, math.ceil(len(values) * percent / 100) - 1)]


def arrival_times(event_times_ns, schedule):
    """Declared integer arrivals; does not change original policy timestamps."""
    previous = None
    first = None
    for i, event_time in enumerate(event_times_ns):
        integer(event_time, "event timestamp")
        if previous is not None and event_time < previous:
            raise ValueError("decreasing historical event timestamps")
        previous = event_time
        first = event_time if first is None else first
        if schedule["kind"] == "constant_rate":
            rate = integer(schedule["events_per_second"], "arrival rate", 1)
            yield i * 1_000_000_000 // rate
        elif schedule["kind"] == "event_gaps":
            scale = integer(schedule["scale"], "event time scale", 1)
            yield (event_time - first) // scale
        else:
            raise ValueError("unknown virtual arrival schedule")


def simulate_fifo(arrivals, service_ns):
    """Postprocessing-only finite FCFS queue; waiting excludes in-service item.

    Equal arrival times retain source order. Zero service is allowed. Queue at
    t contains jobs with arrival<=t<start; starts at t have already left queue.
    Memory here is O(N), intentionally outside all measured worker processes.
    """
    from itertools import zip_longest
    sentinel = object()
    previous_arrival = first_arrival = None
    finish = 0
    waiting = deque()
    waits, responses, starts, finishes = [], [], [], []
    peak = busy = 0
    for arrival, service in zip_longest(arrivals, service_ns, fillvalue=sentinel):
        if arrival is sentinel or service is sentinel:
            raise ValueError("arrival/service counts differ")
        integer(arrival, "arrival")
        integer(service, "service")
        if previous_arrival is not None and arrival < previous_arrival:
            raise ValueError("arrivals decrease")
        first_arrival = arrival if first_arrival is None else first_arrival
        while waiting and waiting[0] <= arrival:
            waiting.popleft()
        start = max(arrival, finish)
        finish = start + service
        if start > arrival:
            waiting.append(start)
        peak = max(peak, len(waiting))
        busy += service
        starts.append(start)
        finishes.append(finish)
        waits.append(start - arrival)
        responses.append(finish - arrival)
        previous_arrival = arrival
    n = len(waits)
    horizon = finish - first_arrival if n else 0
    return {"records": n, "starts_ns": starts, "finishes_ns": finishes,
            "wait_ns": waits, "response_ns": responses, "peak_waiting_records": peak,
            "waiting_records_after_final_arrival": len(waiting),
            "horizon_ns": horizon, "busy_ns": busy, "idle_ns": horizon - busy,
            "terminal_drain_ns": finish - previous_arrival if n else 0,
            "mean_waiting_records_over_drain_horizon": sum(waits) / horizon if horizon else None,
            "utilization_over_drain_horizon": busy / horizon if horizon else None,
            "finite_trace_completion_rate_per_second": n * 1_000_000_000 / horizon if horizon else None,
            "waiting_p50_ns": nearest_rank(waits, 50), "waiting_p95_ns": nearest_rank(waits, 95),
            "waiting_p99_ns": nearest_rank(waits, 99), "response_p50_ns": nearest_rank(responses, 50),
            "response_p95_ns": nearest_rank(responses, 95), "response_p99_ns": nearest_rank(responses, 99),
            "interpretation": "virtual local FCFS finite trace, not live arrival/detection latency or steady capacity"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_worker(args.job, args.output)
    print(json.dumps({"status": result["status"], "cell_id": result["cell_id"], "records": result["records"]}))


if __name__ == "__main__":
    main()
