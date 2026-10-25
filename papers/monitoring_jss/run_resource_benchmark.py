"""Freeze, execute serial captured workers, and seal the local resource study."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

PAPER = Path(__file__).resolve().parent
ROOT = PAPER.parents[1]
SOURCES = ["resource_benchmark.py", "budget_policy_replay.py", "event_log_replay.py",
           "run_resource_benchmark.py", "summarize_resource_benchmark.py"]
DOCUMENTS = ["RESOURCE_BENCHMARK_PROTOCOL.md", "resource_benchmark_config.json",
             "resource_semantic_reference.json", "budget_policy_study_config.json",
             "qa/resource_benchmark_design_review.txt", "qa/test_suite_20261025_phase5.json"]
TESTS = ["tests/test_resource_benchmark.py", "tests/test_resource_summary.py"]

def sha(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()

def write(path, value):
    with Path(path).open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")

def now():
    return datetime.now(timezone.utc).isoformat()

def freeze(config_path):
    assert config_path.resolve() == (PAPER / "resource_benchmark_config.json").resolve()
    config = json.loads(config_path.read_text())
    assert config["timing_repetitions"] == 5 and config["parallel_workers"] == 1
    assert config["memory_prefixes"] == [1000, 5000, 10000, "full"]
    for key in ("study_config", "input_manifest"):
        assert sha(ROOT / config[key]) == config[key + "_sha256"]
    study = json.loads((ROOT / config["study_config"]).read_text())
    acquired = json.loads((ROOT / config["input_manifest"]).read_text())
    references = json.loads((ROOT / config["semantic_reference"]).read_text())
    assert acquired["status"] == "complete"
    run_id = "resource_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    stage = Path(tempfile.mkdtemp(prefix="monitoring-resource-")) / run_id
    stage.mkdir()
    snap = stage / "source_snapshot"
    snap.mkdir()
    hashes = {}
    for name in SOURCES + DOCUMENTS + TESTS:
        source = PAPER / name
        target = snap / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        assert sha(source) == sha(target)
        hashes[name] = sha(target)
    shutil.copyfile(ROOT / config["input_manifest"], snap / "input_manifest.json")
    hashes["input_manifest.json"] = sha(snap / "input_manifest.json")
    cpu = min(os.sched_getaffinity(0))
    inputs = {}
    for population in acquired["populations"]:
        pid = population["population_id"]
        inputs[pid] = []
        for item in population["inputs"]:
            source = ROOT / item["path"]
            assert sha(source) == item["sha256"] and source.stat().st_size == item["bytes"]
            inputs[pid].append({**item, "path": str(source.resolve())})
        assert len(inputs[pid]) == 30
    pairs = [(e, p) for e in study["emitters"] for p in config["policies"]]
    rng = random.Random(config["order_seed"])
    ordered = []
    for repetition in range(1, 6):
        shuffled = list(pairs)
        rng.shuffle(shuffled)
        ordered.extend(("timing", e, p, repetition, None) for e, p in shuffled)
    memory = [("memory", e, p, None, prefix) for e, p in pairs for prefix in config["memory_prefixes"]]
    rng.shuffle(memory)
    ordered.extend(memory)
    (stage / "jobs").mkdir()
    jobs = []
    for mode, emitter, policy, repetition, prefix in ordered:
        pid = emitter["id"]
        semantic_id = f"{pid}__{policy}__B5"
        reference = references["cells"][semantic_id]
        n = reference["records"] if prefix in (None, "full") else prefix
        job_id = semantic_id + (f"__rep{repetition:02d}" if mode == "timing" else f"__prefix{n}")
        policy_config = {"policy": policy, "daily_budget": 5,
                         "window_start_ns": study["window"]["start_ns"],
                         "window_end_ns": study["window"]["end_ns"],
                         "address": emitter["address"], "chain_id": emitter["chain_id"], **study["detector"]}
        job = {"schema_version": "resource_benchmark_job_v1", "mode": mode,
               "cell_id": job_id, "population_id": pid, "policy_config": policy_config,
               "inputs": inputs[pid], "source_sha256": {name: hashes[name] for name in SOURCES[:3]},
               "reference": {"records": n,
                   "decision_stream_sha256": reference["prefix_decision_stream_sha256"][str(n)],
                   "final_state_sha256": reference["final_state_sha256"] if n == reference["records"] else None},
               "cpu_affinity": [cpu], "gzip_compresslevel": 6}
        if mode == "memory":
            job["prefix_records"] = n
        job_path = stage / "jobs" / (job_id + ".json")
        write(job_path, job)
        jobs.append({"job_id": job_id, "job_path": str(job_path.relative_to(stage)),
                     "job_sha256": sha(job_path), "output_path": "cells/" + job_id,
                     "repetition": repetition, "mode": mode, "population_id": pid,
                     "policy": policy, "prefix_records": n if mode == "memory" else None})
    assert len(jobs) == 54 and len({j["job_id"] for j in jobs}) == 54
    descriptor = {"schema_version": "resource_benchmark_freeze_v1", "status": "frozen_before_measurement",
                  "created_utc": now(), "run_id": run_id, "stage": str(stage),
                  "local_source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  "source_hashes": hashes, "config_sha256": sha(config_path), "jobs": jobs,
                  "full_source_snapshot_retained": True, "actual_cpu_affinity": [cpu],
                  "measurements_executed": False, "scope": config["scope"]}
    write(stage / "design_freeze.json", descriptor)
    print(json.dumps({"stage": str(stage), "freeze": str(stage / "design_freeze.json"),
                      "sha256": sha(stage / "design_freeze.json"), "jobs": len(jobs)}), flush=True)

def execute(freeze_path, expected):
    assert sha(freeze_path) == expected
    frozen = json.loads(freeze_path.read_text())
    stage = freeze_path.parent
    assert str(stage) == frozen["stage"]
    assert not (stage / "execution_started.json").exists()
    snap = stage / "source_snapshot"
    for name, expected_hash in frozen["source_hashes"].items():
        assert sha(snap / name) == expected_hash
    assert sha(Path(__file__)) == frozen["source_hashes"]["run_resource_benchmark.py"]
    config = json.loads((snap / "resource_benchmark_config.json").read_text())
    env = {**os.environ, **config["thread_environment"], "PYTHONDONTWRITEBYTECODE": "1"}
    metadata = {"schema_version": "resource_execution_v1", "status": "running", "started_utc": now(),
                "design_freeze_sha256": expected, "run_id": frozen["run_id"], "jobs": [],
                "environment": {"python": sys.version, "executable": sys.executable,
                    "platform": platform.platform(), "cpu_count": os.cpu_count(),
                    "original_affinity": sorted(os.sched_getaffinity(0)),
                    "thread_environment": config["thread_environment"],
                    "cpu_model": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), None),
                    "cgroup_cpu_max": Path("/sys/fs/cgroup/cpu.max").read_text().strip() if Path("/sys/fs/cgroup/cpu.max").exists() else None}}
    write(stage / "execution_started.json", metadata)
    (stage / "cells").mkdir()
    (stage / "worker_logs").mkdir()
    original_affinity = os.sched_getaffinity(0)
    os.sched_setaffinity(0, set(frozen["actual_cpu_affinity"]))
    clock_pairs = []
    for _ in range(10000):
        a = time.perf_counter_ns()
        b = time.perf_counter_ns()
        clock_pairs.append(b - a)
    os.sched_setaffinity(0, original_affinity)
    ordered_pairs = sorted(clock_pairs)
    write(stage / "clock_calibration.json", {
        "counter": "perf_counter_ns", "samples": 10000,
        "cpu_affinity": frozen["actual_cpu_affinity"], "raw_adjacent_call_deltas_ns": clock_pairs,
        "minimum_ns": ordered_pairs[0], "p50_ns": ordered_pairs[4999],
        "p95_ns": ordered_pairs[9499], "p99_ns": ordered_pairs[9899],
        "maximum_ns": ordered_pairs[-1], "subtracted_from_service": False,
        "scope": "One separate parent-process diagnostic; not a measurement of total instrumentation overhead."})
    start = time.perf_counter_ns()
    try:
        for index, spec in enumerate(frozen["jobs"], 1):
            job_path = stage / spec["job_path"]
            assert sha(job_path) == spec["job_sha256"]
            command = [sys.executable, str(snap / "resource_benchmark.py"), "--job", str(job_path),
                       "--output", str(stage / spec["output_path"])]
            t0 = time.perf_counter_ns()
            run = subprocess.run(command, env=env, cwd=stage, capture_output=True,
                                 timeout=config["time_limits_seconds_per_worker"])
            duration = time.perf_counter_ns() - t0
            (stage / "worker_logs" / (spec["job_id"] + ".stdout.txt")).write_bytes(run.stdout)
            (stage / "worker_logs" / (spec["job_id"] + ".stderr.txt")).write_bytes(run.stderr)
            record = {**spec, "command": command, "subprocess_wall_ns": duration, "exit_code": run.returncode}
            metadata["jobs"].append(record)
            if run.returncode:
                raise RuntimeError(f"worker failed: {spec['job_id']}; see captured stderr")
            summary_path = stage / spec["output_path"] / "summary.json"
            summary = json.loads(summary_path.read_text())
            assert summary["status"] == "complete"
            record["summary_sha256"] = sha(summary_path)
            print(json.dumps({"completed": index, "total": 54, "job_id": spec["job_id"],
                              "records": summary["records"]}), flush=True)
        metadata["status"] = "complete"
    except BaseException as error:
        metadata["status"] = "failed"
        metadata["error"] = str(error)
        raise
    finally:
        metadata["completed_utc"] = now()
        metadata["all_workers_wall_ns"] = time.perf_counter_ns() - start
        write(stage / "execution_manifest.json", metadata)
    for name, expected_hash in frozen["source_hashes"].items():
        assert sha(snap / name) == expected_hash
    assert sha(freeze_path) == expected

def seal(stage, target):
    metadata = json.loads((stage / "execution_manifest.json").read_text())
    frozen = json.loads((stage / "design_freeze.json").read_text())
    assert metadata["status"] == "complete" and len(metadata["jobs"]) == 54
    assert sha(stage / "design_freeze.json") == metadata["design_freeze_sha256"]
    for name, expected in frozen["source_hashes"].items():
        assert sha(stage / "source_snapshot" / name) == expected
    names = ["design_freeze.json", "execution_started.json", "execution_manifest.json", "clock_calibration.json"]
    names += ["source_snapshot/" + name for name in frozen["source_hashes"]]
    for job in metadata["jobs"]:
        assert sha(stage / job["job_path"]) == job["job_sha256"]
        names += [job["job_path"], "worker_logs/" + job["job_id"] + ".stdout.txt",
                  "worker_logs/" + job["job_id"] + ".stderr.txt"]
        cell = stage / job["output_path"]
        assert sha(cell / "summary.json") == job["summary_sha256"]
        summary = json.loads((cell / "summary.json").read_text())
        names += [job["output_path"] + "/summary.json"]
        expected_artifacts = {"job.json", "final_state.json.gz"}
        if job["mode"] == "timing":
            expected_artifacts |= {"decisions.jsonl.gz", "timings.jsonl.gz"}
        assert set(summary["artifacts"]) == expected_artifacts
        for name, artifact in summary["artifacts"].items():
            path = cell / name
            assert path.stat().st_size == artifact["bytes"] and sha(path) == artifact["sha256"]
            names.append(job["output_path"] + "/" + name)
    assert len(names) == len(set(names))
    entries = [{"path": name, "bytes": (stage / name).stat().st_size, "sha256": sha(stage / name)} for name in sorted(names)]
    manifest = {"schema_version": "resource_seal_v1", "run_id": frozen["run_id"],
                "status": "complete", "created_utc": now(), "files": entries,
                "explicit_allowlist_only": True, "scientific_review_is_separate": True}
    sealed = stage.parent / (frozen["run_id"] + "_sealed_evidence.zip")
    with zipfile.ZipFile(sealed, "x", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        archive.writestr("ARCHIVE_MANIFEST.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        for entry in entries:
            archive.write(stage / entry["path"], entry["path"])
    with zipfile.ZipFile(sealed) as archive:
        assert len(archive.infolist()) == len(entries) + 1
        for entry in entries:
            with archive.open(entry["path"]) as handle:
                assert hashlib.file_digest(handle, "sha256").hexdigest() == entry["sha256"]
            assert archive.getinfo(entry["path"]).file_size == entry["bytes"]
    assert not target.exists()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".partial")
    with sealed.open("rb") as source, temporary.open("xb") as sink:
        shutil.copyfileobj(source, sink, 1024 * 1024)
        sink.flush()
        os.fsync(sink.fileno())
    assert sha(temporary) == sha(sealed)
    os.rename(temporary, target)
    receipt = {"status": "sealed", "run_id": frozen["run_id"], "isolated_stage": str(stage),
               "archive": str(target), "sha256": sha(target), "bytes": target.stat().st_size,
               "members": len(entries) + 1, "all_member_crc_and_sha_verified": True}
    write(target.with_suffix(".publication.json"), receipt)
    print(json.dumps(receipt), flush=True)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    f = sub.add_parser("freeze")
    f.add_argument("--config", type=Path, default=PAPER / "resource_benchmark_config.json")
    e = sub.add_parser("execute")
    e.add_argument("--freeze", type=Path, required=True)
    e.add_argument("--freeze-sha256", required=True)
    s = sub.add_parser("seal")
    s.add_argument("--stage", type=Path, required=True)
    s.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "freeze":
        freeze(args.config)
    elif args.action == "execute":
        execute(args.freeze, args.freeze_sha256)
    else:
        seal(args.stage, args.target)

if __name__ == "__main__":
    main()
