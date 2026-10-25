"""Read-only incident-day oracle plus descriptive frozen-transaction join audit."""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
PAPER = HERE.parent
ROOT = PAPER.parents[1]


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def metrics(rows):
    result = {"events": len(rows)}
    result.update({field: sum(row[field] is True for row in rows)
                   for field in ("raw_trigger", "group_candidate", "notification_emitted")})
    counts = Counter(row["suppression_reason"] for row in rows)
    result.update({"reason_" + name: counts[name] for name in ("below_threshold", "budget", "grouped", "duplicate", "late")})
    return result


def review(run):
    run = run.resolve()
    with tempfile.TemporaryDirectory(prefix="incident_day_readonly_audit_") as temp:
        output = Path(temp) / "base.json"
        process = subprocess.run([sys.executable, "-B", str(HERE / "event_log_independent_review.py"),
                                  "--run", str(run), "--output", str(output)], capture_output=True, text=True)
        if process.returncode:
            raise RuntimeError("independent event oracle failed: " + process.stderr)
        report = read(output)
    manifest, config, acquisition = (read(run / n) for n in ("manifest.json", "config.json", "acquisition_manifest.json"))
    prior = PAPER / "runs/event_logs_20261025T084327_927529Z"
    oldconfig, oldmanifest = read(prior / "config.json"), read(prior / "manifest.json")
    descriptive = read(run / "descriptive_label_evaluation.json")
    freeze_path = run / "source_snapshot" / (run.name + "_evaluation_freeze.json")
    join_path = run / "source_snapshot" / (run.name + "_raw_join.json")
    label_path = run / "source_snapshot/euler_20230313_labels.json"
    freeze, joined, labels = read(freeze_path), read(join_path), read(label_path)
    artifact_index = read(run / "descriptive_evaluation_artifacts.json")
    input_path = ROOT / manifest["input_path"]
    events = [json.loads(line) for line in input_path.read_text().splitlines()]
    headers_path = ROOT / next(f["path"] for f in acquisition["files"] if Path(f["path"]).name == "matching_headers.jsonl")
    headers = {row["block_number"]: row for row in map(json.loads, headers_path.read_text().splitlines())}
    positive = labels["exploit_transactions"]
    hashes = {row["tx_hash"] for row in positive}
    differences = sorted(k for k in set(config) | set(oldconfig) if config.get(k) != oldconfig.get(k))
    source_hash = lambda m: next(s["sha256"] for s in m["source_snapshot"] if s["path"] == "event_log_replay.py")
    checks = {
        "base_event_oracle_passed": report["all_checks_pass"],
        "only_three_descriptive_config_changes": differences == sorted(["source_day", "rule_purpose", "claim_scope"]) == freeze["config_changes_from_ordinary_day"],
        "core_identical_to_accepted_ordinary_day": config["core"] == oldconfig["core"] == freeze["frozen_core"],
        "exact_same_replay_source": source_hash(manifest) == source_hash(oldmanifest),
        "day_and_population_match": config["source_day"] == acquisition["scope"]["day_utc"] == "2023-03-13" and all(datetime.fromtimestamp(e["event_time_ns"] // 10**9, timezone.utc).date().isoformat() == "2023-03-13" and e["chain_id"] == config["core"]["chain_id"] and e["address"] == config["core"]["address"] for e in events),
        "freeze_before_run_before_descriptive_results": datetime.fromisoformat(freeze["frozen_before_worker_execution_utc"]) < datetime.fromisoformat(manifest["started_utc"]) < datetime.fromisoformat(manifest["finished_utc"]) <= datetime.fromisoformat(descriptive["created_utc"]),
        "frozen_label_hash": sha(label_path) == descriptive["label_manifest_sha256_before_and_after"] == "145bdb4c60aed2f67648c71aad99a40c2865b49e502f0d389562d9f6d5d0360a",
        "six_reported_positive_hashes": len(positive) == len(hashes) == 6 and all(r["positive_incident_label"] is True and r["role"] == "exploit_execution" for r in positive),
        "freeze_and_join_hashes": sha(freeze_path) == descriptive["evaluation_freeze_sha256"] and sha(join_path) == descriptive["raw_join_sha256"] == freeze["raw_join_sha256"],
        "all_frozen_source_files_hashes": all(sha(ROOT / path) == value for path, value in freeze["source_file_hashes"].items()),
        "descriptive_artifact_index": all(sha(ROOT / r["path"]) == r["sha256"] and (ROOT / r["path"]).stat().st_size == r["bytes"] for r in artifact_index["files"]),
    }
    expected_positions = []
    join_checks = []
    for label in positive:
        selected = [event for event in events if event["transaction_hash"] == label["tx_hash"]]
        actual = next(row for row in joined["reported_executions"] if row["transaction_hash"] == label["tx_hash"])
        first = selected[0]
        coords = {(r["block_number"], r["block_hash"], r["transaction_index"], r["event_time_ns"]) for r in selected}
        ok = len(coords) == 1 and all(actual[k] == first[k] for k in ("block_number", "block_hash", "transaction_index", "event_time_ns"))
        ok = ok and actual["core_log_count"] == len(selected) and actual["first_log_index"] == min(r["log_index"] for r in selected) and actual["last_log_index"] == max(r["log_index"] for r in selected)
        ok = ok and all(r["block_hash"] == headers[r["block_number"]]["block_hash"] and r["event_time_ns"] == headers[r["block_number"]]["event_time_ns"] for r in selected)
        ok = ok and all(label.get(k) is None or label[k] == first[k] for k in ("block_number", "block_hash", "transaction_index"))
        if label.get("block_timestamp_utc"):
            ok = ok and datetime.fromisoformat(label["block_timestamp_utc"].replace("Z", "+00:00")).timestamp() * 10**9 == first["event_time_ns"]
        expected_positions.append((first["block_number"], first["transaction_index"], label["tx_hash"]))
        join_checks.append({"transaction_hash": label["tx_hash"], "source_log_count": len(selected), "passed": ok})
    expected_positions.sort()
    first_position = expected_positions[0][:2]
    checks["raw_join_coordinates_counts_headers"] = all(r["passed"] for r in join_checks)
    checks["canonical_order_not_report_order"] = [r["transaction_hash"] for r in joined["reported_executions"]] == [r[2] for r in expected_positions] and list(first_position) == joined["first_reported_execution_transaction_position"]
    cells = []
    for evaluated in descriptive["cells"]:
        path = run / evaluated["cell"] / "decisions.jsonl.gz"
        with gzip.open(path, "rt") as stream:
            rows = [json.loads(line) for line in stream]
        selected = [r for r in rows if r["transaction_hash"] in hashes]
        preceding = [r for r in rows if (r["block_number"], r["transaction_index"]) < first_position]
        prior_counts = dict(Counter(r["budget_day_utc"] for r in preceding if r["notification_emitted"]))
        by_tx = [{"transaction_hash": tx, **metrics([r for r in selected if r["transaction_hash"] == tx])} for _, _, tx in expected_positions]
        pre = {"all_source_logs": len(preceding), "daily_budget": config["core"]["daily_budget"], "emitted_notifications": sum(prior_counts.values()), "emitted_by_playback_budget_day": prior_counts}
        emitted = [{k: r[k] for k in ("alert_id", "transaction_hash", "block_number", "transaction_index", "log_index", "event_time_ns", "budget_day_utc")} for r in selected if r["notification_emitted"]]
        ok = metrics(rows) == evaluated["whole_day"] and metrics(selected) == evaluated["reported_execution_union"] and by_tx == evaluated["by_reported_execution"] and pre == evaluated["pre_first_reported_execution"] and emitted == evaluated["emitted_notifications_with_reported_execution_source"] and sha(path) == evaluated["decisions_sha256"] and all(r["label_used"] is False for r in rows)
        cells.append({"cell": evaluated["cell"], "passed": ok, "whole_day": metrics(rows), "reported_execution_union": metrics(selected), "pre_first_reported_execution": pre})
    checks["descriptive_membership_and_budget_counts"] = len(cells) == 6 and all(c["passed"] for c in cells)
    report["all_checks_pass"] = all(checks.values())
    report["verdict"] = "PASS_FOR_DESCRIPTIVE_PREVIOUSLY_EXPOSED_INCIDENT_DAY" if report["all_checks_pass"] else "FAIL"
    report["descriptive_independent_review"] = {"checks": checks, "source_transaction_membership": join_checks,
        "cells": cells, "wrapper_sha256": sha(__file__), "frozen_labels_sha256": sha(label_path),
        "interpretation": "The fixed five-notification playback-day budget was exhausted before the first reported execution. These source-transaction memberships are descriptive; no other transaction is assigned a negative label, and zero emitted memberships is not attack recall."}
    report["limitations"][0] = "One reported L2-exposed Euler incident day. Six externally reported executions are one incident; labels are joined after decisions, not used as worker inputs. No independent attack evaluation or false-positive/recall estimate."
    report["limitations"].append("Freeze timestamps and unchanged captured source establish this run's recorded execution order, not an externally registered blind study. Receipt success, complete attack-set adjudication and historical label availability remain unverified.")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = review(args.run)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
    print(json.dumps({"passed": report["all_checks_pass"], "output": str(args.output), "checks": report["descriptive_independent_review"]["checks"]}))
    raise SystemExit(0 if report["all_checks_pass"] else 1)


if __name__ == "__main__":
    main()
