"""Synthetic wrapper preservation, fail-closed inputs and exact queue tests."""
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

PAPER = Path(__file__).resolve().parents[1]
if str(PAPER) not in sys.path:
    sys.path.insert(0, str(PAPER))
SPEC = importlib.util.spec_from_file_location("monitoring_resource_benchmark", PAPER / "resource_benchmark.py")
bench = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bench
SPEC.loader.exec_module(bench)

NS = 1_000_000_000
DAY = 86400 * NS
BASE = 1677628800 * NS
ADDRESS = "0x27182842e098f60e3d576794a5bffb0777e025d3"


def fixture(root, policy="greedy", mode="timing", prefix=None):
    records = []
    for i, offset in enumerate([0] * 12 + [301 * NS] * 12 + [DAY] * 12):
        block = 1 + i // 12
        records.append({"chain_id": 1, "address": ADDRESS, "block_number": block,
                        "block_hash": "0x" + f"{block:064x}", "transaction_index": 0,
                        "transaction_hash": "0x" + f"{block:064x}", "log_index": i % 12,
                        "topics": ["0x" + "11" * 32], "data": "0x1234",
                        "event_time_ns": BASE + offset, "observed_time": None,
                        "label_available_time": None, "removed": None})
    inputs = []
    for day, rows in [("2023-03-01", records[:24]), ("2023-03-02", records[24:])]:
        path = root / (day + ".jsonl")
        path.write_bytes(b"".join(bench.canonical(r) + b"\n" for r in rows))
        inputs.append({"path": str(path), "sha256": bench.sha256(path),
                       "bytes": path.stat().st_size, "rows": len(rows), "day_utc": day})
    config = {"policy": policy, "daily_budget": 5, "window_start_ns": BASE,
              "window_end_ns": BASE + 2 * DAY, "address": ADDRESS, "chain_id": 1,
              "window_seconds": 60, "threshold_count": 10, "cooldown_seconds": 300}
    state = bench.PolicyReplayState(bench.BudgetConfig(**config))
    selected = records if prefix is None else records[:prefix]
    expected = [state.process(bench.decode_event(row)) for row in selected]
    expected_bytes = b"".join(bench.canonical(r) + b"\n" for r in expected)
    job = {"schema_version": "resource_benchmark_job_v1", "mode": mode,
           "cell_id": "fixture__" + policy, "population_id": "fixture", "policy_config": config,
           "inputs": inputs, "gzip_compresslevel": 6,
           "cpu_affinity": [min(os.sched_getaffinity(0))],
           "source_sha256": {name: bench.sha256(PAPER / name) for name in bench.SOURCE_NAMES},
           "reference": {"records": len(selected),
                         "decision_stream_sha256": hashlib.sha256(expected_bytes).hexdigest(),
                         "final_state_sha256": hashlib.sha256(bench.canonical(state.to_dict())).hexdigest()
                         if len(selected) == len(records) else None}}
    if mode == "memory":
        job["prefix_records"] = len(selected)
    return job, expected


def execute(root, job, name="result", check=True):
    job_path = root / (name + ".job.json")
    job_path.write_bytes(bench.canonical(job))
    env = dict(os.environ, PYTHONHASHSEED="0", OMP_NUM_THREADS="1", MKL_NUM_THREADS="1",
               OPENBLAS_NUM_THREADS="1", NUMEXPR_NUM_THREADS="1", PYTHONDONTWRITEBYTECODE="1")
    process = subprocess.run([sys.executable, str(PAPER / "resource_benchmark.py"),
                              "--job", str(job_path), "--output", str(root / name)],
                             env=env, capture_output=True, text=True)
    if check and process.returncode:
        raise AssertionError(process.stderr)
    return process, root / name


class WorkerTests(unittest.TestCase):
    def test_timing_subprocess_preserves_all_policies_and_traces(self):
        for policy in ("greedy", "paced_cumulative", "token_bucket"):
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                job, expected = fixture(root, policy)
                _, out = execute(root, job)
                result = json.loads((out / "summary.json").read_text())
                self.assertEqual(result["status"], "complete")
                self.assertEqual(result["records"], 36)
                self.assertEqual(result["seen_entries"], 36)
                self.assertEqual(result["order_key_entries"], 36)
                self.assertEqual(result["environment"]["cpu_affinity"], job["cpu_affinity"])
                self.assertEqual(result["environment"]["thread_environment"]["PYTHONHASHSEED"], "0")
                self.assertGreaterEqual(result["loop_wall_ns"], result["service_total_ns"])
                self.assertEqual(sum(result["stage_total_ns"].values()), result["service_total_ns"])
                self.assertTrue(all(r["read_to_eof"] for r in result["traversed_inputs"]))
                with gzip.open(out / "decisions.jsonl.gz", "rt") as f:
                    observed = [json.loads(line) for line in f]
                self.assertEqual(observed, expected)
                with gzip.open(out / "timings.jsonl.gz", "rt") as f:
                    traces = [json.loads(line) for line in f]
                for i, row in enumerate(traces):
                    self.assertEqual(row["record_index"], i)
                    self.assertEqual(row["service_ns"], sum(row[k] for k in bench.STAGES))
                    self.assertEqual(row["event_time_ns"], expected[i]["event_time_ns"])
                    self.assertTrue(all(row[k] >= 0 for k in bench.STAGES))
                for name, receipt in result["artifacts"].items():
                    self.assertEqual(bench.sha256(out / name), receipt["sha256"])
                    self.assertEqual((out / name).stat().st_size, receipt["bytes"])

    def test_memory_prefixes_use_new_processes_and_do_not_write_timing_trace(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pids = []
            sizes = []
            for prefix in (10, 24, 36):
                job, expected = fixture(root, mode="memory", prefix=prefix)
                _, out = execute(root, job, "prefix_" + str(prefix))
                result = json.loads((out / "summary.json").read_text())
                pids.append(result["environment"]["pid"])
                sizes.append(result["canonical_state_bytes"])
                self.assertEqual(result["seen_entries"], prefix)
                self.assertEqual(result["order_key_entries"], prefix)
                self.assertIsNone(result["service_total_ns"])
                self.assertFalse((out / "decisions.jsonl.gz").exists())
                self.assertFalse((out / "timings.jsonl.gz").exists())
                with gzip.open(out / "final_state.json.gz", "rb") as f:
                    state_bytes = f.read()
                self.assertEqual(len(state_bytes), result["canonical_state_bytes"])
                self.assertEqual(hashlib.sha256(state_bytes).hexdigest(), result["final_state_sha256"])
                self.assertGreater(result["before_serialization_memory"]["current_rss_bytes"], 0)
            self.assertEqual(len(set(pids)), 3)
            self.assertEqual(sizes, sorted(set(sizes)))

    def test_fail_closed_for_wrong_reference_and_input_hash(self):
        for failure in ("semantic", "input", "source", "partition", "count"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                job, _ = fixture(root)
                if failure == "semantic":
                    job["reference"]["decision_stream_sha256"] = "0" * 64
                elif failure == "input":
                    job["inputs"][0]["sha256"] = "0" * 64
                elif failure == "source":
                    job["source_sha256"]["budget_policy_replay.py"] = "0" * 64
                elif failure == "partition":
                    job["inputs"][0]["day_utc"] = "2023-02-28"
                else:
                    job["reference"]["records"] -= 1
                process, out = execute(root, job, check=False)
                self.assertNotEqual(process.returncode, 0)
                self.assertFalse((out / "summary.json").exists())

    def test_output_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            job, _ = fixture(root)
            _, out = execute(root, job)
            original = (out / "summary.json").read_bytes()
            process, _ = execute(root, job, check=False)
            self.assertNotEqual(process.returncode, 0)
            self.assertEqual((out / "summary.json").read_bytes(), original)


class QueueTests(unittest.TestCase):
    def test_exact_queue_oracles_including_zero_duration(self):
        cases = [
            ([0, 10, 20], [3, 4, 5], [0, 10, 20], [3, 14, 25], [0, 0, 0], 0),
            ([0, 0, 0], [5, 2, 3], [0, 5, 7], [5, 7, 10], [0, 5, 7], 2),
            ([0, 5, 5], [5, 0, 2], [0, 5, 5], [5, 5, 7], [0, 0, 0], 0),
            ([0, 1, 2], [5, 0, 2], [0, 5, 5], [5, 5, 7], [0, 4, 3], 2),
            ([0, 2, 4], [5, 5, 5], [0, 5, 10], [5, 10, 15], [0, 3, 6], 2),
            ([0, 0, 100], [5, 2, 1], [0, 5, 100], [5, 7, 101], [0, 5, 0], 1)]
        for arrivals, service, starts, finishes, waits, peak in cases:
            with self.subTest(arrivals=arrivals, service=service):
                result = bench.simulate_fifo(arrivals, service)
                self.assertEqual(result["starts_ns"], starts)
                self.assertEqual(result["finishes_ns"], finishes)
                self.assertEqual(result["wait_ns"], waits)
                self.assertEqual(result["peak_waiting_records"], peak)
                self.assertEqual(result["horizon_ns"], result["busy_ns"] + result["idle_ns"])
                self.assertEqual(result["terminal_drain_ns"], finishes[-1] - arrivals[-1])

    def test_queue_peak_matches_interval_enumeration(self):
        rng = random.Random(831)
        for _ in range(100):
            arrivals = sorted(rng.randrange(15) for _ in range(rng.randrange(1, 20)))
            service = [rng.randrange(8) for _ in arrivals]
            result = bench.simulate_fifo(arrivals, service)
            # Independent exhaustive half-open interval count at every integer
            # timestamp; this tests queue semantics, not just FCFS recurrence.
            queues = [sum(a <= t < start for a, start in zip(arrivals, result["starts_ns"]))
                      for t in range(result["finishes_ns"][-1] + 1)]
            self.assertEqual(result["peak_waiting_records"], max(queues))
            self.assertEqual(sum(queues), sum(result["wait_ns"]))

    def test_arrivals_preserve_integer_precision_and_stable_ties(self):
        base = 10**18 + 123
        event_times = [base, base + 999999, base + 1000000, base + 1000001]
        self.assertEqual(list(bench.arrival_times(event_times, {"kind": "event_gaps", "scale": 1000000})), [0, 0, 1, 1])
        self.assertEqual(list(bench.arrival_times(event_times, {"kind": "event_gaps", "scale": 1})), [0, 999999, 1000000, 1000001])
        self.assertEqual(list(bench.arrival_times(event_times, {"kind": "constant_rate", "events_per_second": 100000})), [0, 10000, 20000, 30000])
        self.assertEqual(list(bench.arrival_times(event_times, {"kind": "constant_rate", "events_per_second": 3})), [0, 333333333, 666666666, 1000000000])

    def test_invalid_schedules_and_empty_queue(self):
        for arrivals, service in [([1, 0], [1, 1]), ([0], [-1]), ([0], [True]), ([0, 1], [1]), ([0.0], [1])]:
            with self.subTest(arrivals=arrivals, service=service), self.assertRaises(ValueError):
                bench.simulate_fifo(arrivals, service)
        with self.assertRaises(ValueError):
            list(bench.arrival_times([2, 1], {"kind": "constant_rate", "events_per_second": 10}))
        for schedule in ({"kind": "constant_rate", "events_per_second": 0}, {"kind": "event_gaps", "scale": 0}, {"kind": "unknown"}):
            with self.assertRaises(ValueError):
                list(bench.arrival_times([1], schedule))
        empty = bench.simulate_fifo([], [])
        self.assertEqual(empty["records"], 0)
        self.assertIsNone(empty["waiting_p99_ns"])
        self.assertIsNone(empty["utilization_over_drain_horizon"])
        zero = bench.simulate_fifo([0, 0], [0, 0])
        self.assertEqual(zero["peak_waiting_records"], 0)
        self.assertIsNone(zero["finite_trace_completion_rate_per_second"])


if __name__ == "__main__":
    unittest.main()
