"""Postprocess closed phase-5 workers without importing measured production code.

All arrays and FIFO simulations exist only in this separate postprocessing
process. They cannot contribute to worker RSS or measured service. The virtual
arrival schedules are workload assumptions, never historical observations.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import csv
import gzip
import hashlib
import json
import math
from pathlib import Path
import statistics

STAGES = ("read_ns", "parse_ns", "decode_ns", "core_ns", "encode_ns", "write_ns")
NS = 1_000_000_000
MIB = 1024 ** 2


def sha256(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def nearest_rank(values, percentage):
    """The value at ceil(p*N)-1, including exact endpoints for p in [0,100]."""
    if not values:
        return None
    if not 0 <= percentage <= 100:
        raise ValueError("percentage outside [0,100]")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * percentage / 100) - 1)]


def distribution(values):
    return {"count": len(values), "total": sum(values),
            "p50": nearest_rank(values, 50), "p95": nearest_rank(values, 95),
            "p99": nearest_rank(values, 99), "maximum": max(values, default=None)}


def repeat_summary(values):
    if not values:
        raise ValueError("no repetitions")
    return {"repetitions": len(values), "minimum": min(values),
            "median": statistics.median(values), "maximum": max(values)}


def schedule_name(schedule):
    if schedule["kind"] == "event_gaps":
        return f"event_gaps_x{integer(schedule['scale'], 'scale', 1)}"
    if schedule["kind"] == "constant_rate":
        return f"constant_{integer(schedule['events_per_second'], 'rate', 1)}_per_second"
    raise ValueError("unknown virtual schedule")


def schedule_arrivals(event_times, schedule):
    if not event_times:
        raise ValueError("empty event schedule")
    for value in event_times:
        integer(value, "event time")
    if any(a > b for a, b in zip(event_times, event_times[1:])):
        raise ValueError("event times decrease")
    schedule_name(schedule)
    if schedule["kind"] == "event_gaps":
        origin = event_times[0]
        return [(value - origin) // schedule["scale"] for value in event_times]
    return [i * NS // schedule["events_per_second"] for i in range(len(event_times))]


def peak_overlap(intervals):
    """Peak occupancy of half-open intervals; zero-length intervals do not exist."""
    edges = []
    for start, finish in intervals:
        if finish < start:
            raise ValueError("reversed interval")
        if finish > start:
            edges.extend(((start, 1), (finish, -1)))
    # Endpoints (-1) precede starts (+1) at a common timestamp.
    occupancy = peak = 0
    for _, delta in sorted(edges):
        occupancy += delta
        if occupancy < 0:
            raise AssertionError("interval sweep became negative")
        peak = max(peak, occupancy)
    if occupancy:
        raise AssertionError("unclosed interval sweep")
    return peak


def fifo_metrics(arrivals, services):
    """Finite, lossless FCFS; no queue-capacity or steady-state assumption."""
    if not arrivals or len(arrivals) != len(services):
        raise ValueError("nonempty equal-length inputs required")
    for value in arrivals:
        integer(value, "arrival")
    for value in services:
        integer(value, "service")
    if any(a > b for a, b in zip(arrivals, arrivals[1:])):
        raise ValueError("arrival order decreases")
    starts, finishes, waits, responses = [], [], [], []
    previous_finish = arrivals[0]
    for arrival, service in zip(arrivals, services):
        start = max(arrival, previous_finish)
        finish = start + service
        starts.append(start)
        finishes.append(finish)
        waits.append(start - arrival)
        responses.append(finish - arrival)
        previous_finish = finish
    makespan = finishes[-1] - arrivals[0]
    return {"records": len(arrivals), "arrival_horizon_ns": arrivals[-1] - arrivals[0],
            "makespan_ns": makespan, "service_total_ns": sum(services),
            "waiting_ns": distribution(waits), "response_ns": distribution(responses),
            "peak_waiting_records": peak_overlap(zip(arrivals, starts)),
            "peak_in_system_records": peak_overlap(zip(arrivals, finishes)),
            "modeled_busy_fraction": sum(services) / makespan if makespan else None,
            "completion_throughput_records_per_second": len(arrivals) * NS / makespan if makespan else None}


def read_trace(path, result, decision_path):
    values = {key: [] for key in (*STAGES, "service_ns")}
    event_times = []
    decision_digest = hashlib.sha256()
    with gzip.open(path, "rb") as traces, gzip.open(decision_path, "rb") as decisions:
        for i, line in enumerate(traces):
            row = json.loads(line)
            decision_line = decisions.readline()
            if not decision_line:
                raise ValueError("decision trace shorter than timing trace")
            decision_digest.update(decision_line)
            decision = json.loads(decision_line)
            if row["record_index"] != i or row["event_time_ns"] != decision["event_time_ns"]:
                raise ValueError("trace/decision identity or event-time mismatch")
            for key in values:
                values[key].append(integer(row[key], key))
            if row["service_ns"] != sum(row[key] for key in STAGES):
                raise ValueError("service differs from six stage durations")
            event_times.append(integer(row["event_time_ns"], "event time"))
        if decisions.read(1):
            raise ValueError("decision trace longer than timing trace")
    if len(event_times) != result["records"]:
        raise ValueError("trace row count mismatch")
    if decision_digest.hexdigest() != result["decision_stream_sha256"]:
        raise ValueError("uncompressed decision stream hash mismatch")
    if any(a > b for a, b in zip(event_times, event_times[1:])):
        raise ValueError("decreasing original event time")
    if {key: sum(values[key]) for key in STAGES} != result["stage_total_ns"]:
        raise ValueError("worker stage totals mismatch")
    if sum(values["service_ns"]) != result["service_total_ns"]:
        raise ValueError("worker service total mismatch")
    return event_times, values


def validate_worker(folder, entry):
    result_path = folder / "summary.json"
    result = json.loads(result_path.read_text())
    if result.get("status") != "complete" or result.get("schema_version") != "resource_benchmark_result_v1":
        raise ValueError("worker is incomplete or has an unknown schema")
    expected_names = {"job.json", "final_state.json.gz"}
    if result["mode"] == "timing":
        expected_names.update(("decisions.jsonl.gz", "timings.jsonl.gz"))
    if set(result["artifacts"]) != expected_names:
        raise ValueError("unexpected worker artifact allowlist")
    for name, expected in result["artifacts"].items():
        artifact = folder / name
        if artifact.stat().st_size != expected["bytes"] or sha256(artifact) != expected["sha256"]:
            raise ValueError("worker artifact changed: " + str(artifact))
    job = json.loads((folder / "job.json").read_text())
    if (job["cell_id"] != entry["job_id"] or result["cell_id"] != entry["job_id"] or
            job["mode"] != result["mode"] or result["mode"] != entry["mode"] or
            job["population_id"] != result["population_id"] or
            result["population_id"] != entry["population_id"] or
            result["policy_config"] != job["policy_config"] or
            job["policy_config"]["policy"] != entry["policy"] or
            result["source_sha256"] != job["source_sha256"] or
            result["decision_stream_sha256"] != job["reference"]["decision_stream_sha256"] or
            result["records"] != job["reference"]["records"]):
        raise ValueError("worker job/manifest/result mismatch")
    if entry["exit_code"] != 0:
        raise ValueError("failed worker in accepted manifest")
    with gzip.open(folder / "final_state.json.gz", "rb") as handle:
        state_bytes = handle.read()
    if (len(state_bytes) != result["canonical_state_bytes"] or
            hashlib.sha256(state_bytes).hexdigest() != result["final_state_sha256"]):
        raise ValueError("uncompressed checkpoint mismatch")
    if (job["reference"]["final_state_sha256"] is not None and
            result["final_state_sha256"] != job["reference"]["final_state_sha256"]):
        raise ValueError("reference checkpoint mismatch")
    state = json.loads(state_bytes)
    if (len(state["seen"]) != result["seen_entries"] or
            len(state["order_keys"]) != result["order_key_entries"] or
            result["seen_entries"] != result["records"] or
            result["order_key_entries"] != result["records"]):
        raise ValueError("unexpected finite-window identity retention")
    return result, job, {"path": str(result_path), "sha256": sha256(result_path)}


def aggregate_rows(rows, keys, metrics):
    grouped = defaultdict(list)
    for row in rows:
        grouped[tuple(row[k] for k in keys)].append(row)
    output = []
    for key, members in sorted(grouped.items()):
        for metric in metrics:
            output.append({**dict(zip(keys, key)), "metric": metric,
                           **repeat_summary([r[metric] for r in members])})
    return output


def write_csv(path, rows):
    if not rows:
        raise ValueError("empty output table")
    with Path(path).open("x", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def make_figure(output, timing, memory, config):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    labels = {"euler_core": "Euler", "beanstalk_diamond": "Beanstalk"}
    short = {"greedy": "Greedy", "paced_cumulative": "Paced", "token_bucket": "Token"}
    colors = {"euler_core": "#176b91", "beanstalk_diamond": "#b65c23"}
    styles = {"greedy": "-", "paced_cumulative": "--", "token_bucket": ":"}
    groups = [(pop, policy) for pop in config["populations"] for policy in config["policies"]]
    fig, axes = plt.subplots(2, 2, figsize=(12, 8.2), constrained_layout=True)
    for axis, metric, scale, title, ylabel in (
            (axes[0, 0], "service_p95_ns", 1000, "A. Per-record local service", "p95 service (microseconds)"),
            (axes[0, 1], "loop_throughput_records_per_second", 1, "B. Instrumented loop throughput", "Records / second")):
        for position, (pop, policy) in enumerate(groups):
            vals = [r[metric] / scale for r in timing if r["population_id"] == pop and r["policy"] == policy]
            med = statistics.median(vals)
            axis.errorbar(position, med, yerr=[[med - min(vals)], [max(vals) - med]],
                          fmt="o", capsize=4, color=colors[pop], markersize=6)
            axis.scatter([position] * len(vals), vals, color=colors[pop], s=10, alpha=.45)
        axis.set_xticks(range(len(groups)), [labels[p] + "\n" + short[q] for p, q in groups], fontsize=8)
        axis.set_title(title, loc="left", fontsize=11, fontweight="bold")
        axis.set_ylabel(ylabel)
        axis.grid(axis="y", alpha=.2)
        axis.set_ylim(bottom=0)
    for axis, metric, title, ylabel in (
            (axes[1, 0], "canonical_state_bytes", "C. Compact checkpoint size", "Checkpoint (MiB)"),
            (axes[1, 1], "current_rss_before_serialization_bytes", "D. RSS before checkpoint serialization", "Whole-process RSS (MiB)")):
        for pop, policy in groups:
            selected = sorted((r for r in memory if r["population_id"] == pop and r["policy"] == policy),
                              key=lambda r: r["records"])
            axis.plot([r["records"] / 1000 for r in selected], [r[metric] / MIB for r in selected],
                      marker="o", markersize=3, linewidth=1.4, color=colors[pop], linestyle=styles[policy],
                      label=labels[pop] + " / " + short[policy])
        axis.set_title(title, loc="left", fontsize=11, fontweight="bold")
        axis.set_xlabel("Processed records (thousands)")
        axis.set_ylabel(ylabel)
        axis.grid(alpha=.2)
        axis.set_ylim(bottom=0)
    axes[1, 0].legend(fontsize=7, ncol=2, loc="upper left")
    fig.suptitle("Local replay cost and finite-window state (daily budget B = 5)", fontsize=14)
    fig.supxlabel("Timing: median and full range of 5 fresh processes; shared host, warmed/uncontrolled cache.\n"
                  "Memory: one fresh process per prefix; dependent prefixes, no uncertainty intervals. Buffered output is not durable delivery.",
                  fontsize=8)
    metadata = {"Creator": "summarize_resource_benchmark.py", "Date": None}
    fig.savefig(output / "resource_benchmark_primary.svg", metadata=metadata)
    fig.savefig(output / "resource_benchmark_primary.png", dpi=170,
                metadata={"Software": "summarize_resource_benchmark.py"})
    plt.close(fig)


def summarize(run, config_path, output):
    run, config_path, output = Path(run).resolve(), Path(config_path).resolve(), Path(output).resolve()
    if output.exists():
        raise FileExistsError(output)
    config = json.loads(config_path.read_text())
    manifest_path = run / "execution_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("status") != "complete":
        raise ValueError("only closed complete executions can be summarized")
    timing, memory, queues, provenance = [], [], [], []
    seen_paths, seen_timing, seen_memory = set(), set(), set()
    groups = {(p, q) for p in config["populations"] for q in config["policies"]}
    full_counts = {}
    for entry in manifest["jobs"]:
        relative = Path(entry["output_path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("worker paths must stay relative to the execution")
        folder = (run / relative).resolve()
        folder.relative_to(run)
        if folder in seen_paths:
            raise ValueError("duplicate worker output")
        seen_paths.add(folder)
        result, job, evidence = validate_worker(folder, entry)
        provenance.append(evidence)
        pop, policy = result["population_id"], result["policy_config"]["policy"]
        if (pop, policy) not in groups or result["policy_config"]["daily_budget"] != config["daily_budget"]:
            raise ValueError("worker outside frozen population/policy grid")
        total = sum(item["rows"] for item in job["inputs"])
        if pop in full_counts and full_counts[pop] != total:
            raise ValueError("population count differs between workers")
        full_counts[pop] = total
        common = {"job_id": entry["job_id"], "population_id": pop, "policy": policy,
                  "daily_budget": result["policy_config"]["daily_budget"], "records": result["records"]}
        if result["mode"] == "timing":
            rep = integer(entry["repetition"], "repetition", 1)
            key = (pop, policy, rep)
            if key in seen_timing or rep > config["timing_repetitions"] or result["records"] != total:
                raise ValueError("unexpected or duplicate timing repetition")
            seen_timing.add(key)
            event_times, traces = read_trace(folder / "timings.jsonl.gz", result, folder / "decisions.jsonl.gz")
            if result["service_total_ns"] > result["loop_wall_ns"]:
                raise ValueError("defined service exceeds complete loop wall")
            row = {**common, "repetition": rep, "loop_wall_ns": result["loop_wall_ns"],
                   "loop_cpu_ns": result["loop_cpu_ns"],
                   "subprocess_wall_ns": integer(entry["subprocess_wall_ns"], "subprocess wall", 1),
                   "loop_throughput_records_per_second": result["records"] * NS / result["loop_wall_ns"],
                   "service_total_ns": result["service_total_ns"],
                   "nonservice_loop_ns": result["loop_wall_ns"] - result["service_total_ns"],
                   "source_open_close_ns": result["source_open_close_ns"], "eof_read_ns": result["eof_read_ns"],
                   "trace_encode_ns": result["trace_encode_ns"], "trace_write_ns": result["trace_write_ns"],
                   "output_close_ns": result["output_close_ns"], "preflight_ns": result["preflight_ns"],
                   "current_rss_before_serialization_bytes": result["before_serialization_memory"]["current_rss_bytes"],
                   "process_peak_rss_before_serialization_bytes": result["before_serialization_memory"]["process_peak_rss_bytes"]}
            for stage in (*STAGES, "service_ns"):
                for percentage in (50, 95, 99):
                    row[stage.removesuffix("_ns") + f"_p{percentage}_ns"] = nearest_rank(traces[stage], percentage)
            timing.append(row)
            for schedule in config["virtual_schedules"]:
                metrics = fifo_metrics(schedule_arrivals(event_times, schedule), traces["service_ns"])
                queues.append({**common, "repetition": rep, "schedule": schedule_name(schedule),
                               "arrival_horizon_ns": metrics["arrival_horizon_ns"],
                               "makespan_ns": metrics["makespan_ns"],
                               "peak_waiting_records": metrics["peak_waiting_records"],
                               "peak_in_system_records": metrics["peak_in_system_records"],
                               "waiting_p50_ns": metrics["waiting_ns"]["p50"],
                               "waiting_p95_ns": metrics["waiting_ns"]["p95"],
                               "waiting_p99_ns": metrics["waiting_ns"]["p99"],
                               "waiting_maximum_ns": metrics["waiting_ns"]["maximum"],
                               "response_p50_ns": metrics["response_ns"]["p50"],
                               "response_p95_ns": metrics["response_ns"]["p95"],
                               "response_p99_ns": metrics["response_ns"]["p99"],
                               "response_maximum_ns": metrics["response_ns"]["maximum"],
                               "modeled_busy_fraction": metrics["modeled_busy_fraction"],
                               "completion_throughput_records_per_second": metrics["completion_throughput_records_per_second"]})
        else:
            prefix = integer(entry["prefix_records"], "prefix records", 1)
            allowed = {total if v == "full" else v for v in config["memory_prefixes"]}
            key = (pop, policy, prefix)
            if key in seen_memory or prefix not in allowed or prefix != result["records"] or entry["repetition"] is not None:
                raise ValueError("unexpected or duplicate memory prefix")
            seen_memory.add(key)
            before, base = result["before_serialization_memory"], result["baseline_memory"]
            memory.append({**common, "canonical_state_bytes": result["canonical_state_bytes"],
                           "seen_entries": result["seen_entries"], "order_key_entries": result["order_key_entries"],
                           "rolling_window_entries": result["rolling_window_entries"],
                           "notification_ids": result["notification_ids"],
                           "baseline_current_rss_bytes": base["current_rss_bytes"],
                           "current_rss_before_serialization_bytes": before["current_rss_bytes"],
                           "process_peak_rss_before_serialization_bytes": before["process_peak_rss_bytes"],
                           "rss_difference_from_baseline_bytes": before["current_rss_bytes"] - base["current_rss_bytes"]})
    expected_timing = {(p, q, r) for p, q in groups for r in range(1, config["timing_repetitions"] + 1)}
    expected_memory = {(p, q, full_counts[p] if n == "full" else n) for p, q in groups for n in config["memory_prefixes"]}
    if seen_timing != expected_timing or seen_memory != expected_memory:
        raise ValueError("incomplete frozen execution grid")
    timing.sort(key=lambda r: (r["population_id"], r["policy"], r["repetition"]))
    memory.sort(key=lambda r: (r["population_id"], r["policy"], r["records"]))
    queues.sort(key=lambda r: (r["population_id"], r["policy"], r["schedule"], r["repetition"]))
    timing_metrics = ["loop_throughput_records_per_second", "loop_wall_ns", "loop_cpu_ns",
                      "process_peak_rss_before_serialization_bytes", "nonservice_loop_ns"]
    timing_metrics += [s.removesuffix("_ns") + f"_p{p}_ns" for s in (*STAGES, "service_ns") for p in (50, 95, 99)]
    timing_groups = aggregate_rows(timing, ("population_id", "policy"), timing_metrics)
    queue_metrics = ["makespan_ns", "peak_waiting_records", "peak_in_system_records",
                     "waiting_p95_ns", "waiting_p99_ns", "waiting_maximum_ns", "response_p95_ns", "response_maximum_ns"]
    queue_groups = aggregate_rows(queues, ("population_id", "policy", "schedule"), queue_metrics)
    result = {"schema_version": "resource_benchmark_summary_v1", "status": "complete",
              "summarizer_sha256": sha256(__file__), "config_sha256": sha256(config_path),
              "execution_manifest_sha256": sha256(manifest_path),
              "timing_workers": len(timing), "memory_workers": len(memory), "virtual_scenarios": len(queues),
              "timing_records": sum(r["records"] for r in timing),
              "worker_summaries": provenance, "timing_runs": timing, "memory_probes": memory,
              "virtual_queue_runs": queues, "timing_group_summaries": timing_groups,
              "virtual_queue_group_summaries": queue_groups,
              "interpretation": {
                  "quantiles": "Nearest rank ceil(p*N)-1 separately per worker; median/min/max across five runs, no pooled confidence interval.",
                  "service": "Six contiguous local stages: buffered read, JSON parse, syntactic decode, aggregate unchanged core, decision JSON encode, buffered gzip write.",
                  "nonservice_loop": "All measured loop wall outside those stages, including trace output, hashing, validation, bookkeeping and file open/close; not pure instrumentation overhead.",
                  "core": "Combined state, feature/rule, grouping and allocation work; component costs are not separately identified.",
                  "queue": "Lossless finite-trace virtual FCFS; original event-time budgets unchanged. Half-open waiting [arrival,start) and system [arrival,finish), zero intervals excluded.",
                  "arrival_assumptions": config["virtual_schedules"],
                  "uniform_acquisition_delays": "Adding any common nonnegative acquisition delay to all modeled arrivals shifts starts/finishes equally; waiting, response, makespan and queue occupancy are invariant. No extra measured experiments.",
                  "memory": "One separate fresh process per nested prefix; RSS sampled before checkpoint serialization. Whole-process memory is not exact Python state size; seen and order-key ledgers retain every accepted record.",
                  "unsupported": ["historical arrival or live end-to-end latency", "durable notification delivery", "unbounded-horizon bounded memory", "independent attack detection", "steady-state maximum throughput", "causal policy speed superiority on a shared host"]}}
    output.mkdir(parents=True, exist_ok=False)
    write_csv(output / "resource_timing_runs.csv", timing)
    write_csv(output / "resource_timing_groups.csv", timing_groups)
    write_csv(output / "resource_memory_probes.csv", memory)
    write_csv(output / "resource_virtual_queues.csv", queues)
    write_csv(output / "resource_virtual_queue_groups.csv", queue_groups)
    make_figure(output, timing, memory, config)
    names = ["resource_timing_runs.csv", "resource_timing_groups.csv", "resource_memory_probes.csv",
             "resource_virtual_queues.csv", "resource_virtual_queue_groups.csv",
             "resource_benchmark_primary.svg", "resource_benchmark_primary.png"]
    result["artifacts"] = {name: {"bytes": (output / name).stat().st_size, "sha256": sha256(output / name)} for name in names}
    with (output / "summary.json").open("x") as handle:
        json.dump(result, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")
    return {"status": result["status"], "output": str(output), "timing_workers": len(timing),
            "memory_workers": len(memory), "virtual_scenarios": len(queues),
            "summary_sha256": sha256(output / "summary.json")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(summarize(args.run, args.config, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
