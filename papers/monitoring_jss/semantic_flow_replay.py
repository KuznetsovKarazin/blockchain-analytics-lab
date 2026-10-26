"""Frozen development replay: transaction-final features, common candidates, exact caps.

No labels, prices, RPC, model fitting, delivery or live-latency measurement.
The two days are separate development streams, not independent scientific cases.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import date
import gzip
import hashlib
import json
from pathlib import Path
import platform
import re
import sys
from datetime import datetime, timezone

PAPER = Path(__file__).resolve().parent
sys.path.insert(0, str(PAPER))
NS = 1_000_000_000
DAY_NS = 86_400 * NS
POLICIES = ("greedy", "paced_cumulative", "token_bucket")
METHODS = ("core_count_60s_10", "outflow_rank_1_20", "outflow_rank_1_10")
ADDRESS = "0x27182842e098f60e3d576794a5bffb0777e025d3"
SOURCE_SCOPE = "aws_public_blockchain_parquet_transaction_subset"
EVIDENCE_TIER = "enumerated_daily_partition_and_transaction_metadata_checked"
HEX32 = re.compile(r"0x[0-9a-f]{64}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for data in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value
    def constant(value):
        raise ValueError("nonfinite JSON constant")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name}: integer >= {minimum} required")
    return value


def sha(value, name):
    if type(value) is not str or SHA256.fullmatch(value) is None:
        raise ValueError(f"{name}: SHA256 required")
    return value


def day_start(day):
    if type(day) is not str or date.fromisoformat(day).isoformat() != day:
        raise ValueError("canonical UTC day required")
    return (date.fromisoformat(day) - date(1970, 1, 1)).days * DAY_NS


def transaction_identity(tx):
    if type(tx) is not dict:
        raise ValueError("transaction object required")
    for key in ("block_hash", "transaction_hash"):
        if type(tx[key]) is not str or HEX32.fullmatch(tx[key]) is None:
            raise ValueError(f"invalid canonical {key}")
    for key in ("block_number", "transaction_index", "event_time_ns"):
        integer(tx[key], key)
    if type(tx["chain_id"]) is not int or tx["chain_id"] != 1:
        raise ValueError("Ethereum chain1 required")
    return (tx["block_number"], tx["transaction_index"]), tx["event_time_ns"]


class CountMonitor:
    """Counts only core logs, after each complete transaction has become available.

    The caller binds and validates the observation source. This component takes
    only its validated transaction identity and positive core-log count.
    """
    def __init__(self, *, start_ns, end_ns, window_ns=60 * NS,
                 threshold_count=10, grouping_ns=300 * NS):
        self.start_ns = integer(start_ns, "start_ns")
        self.end_ns = integer(end_ns, "end_ns")
        if end_ns <= start_ns:
            raise ValueError("empty count horizon")
        self.window_ns = integer(window_ns, "window_ns", 1)
        self.threshold_count = integer(threshold_count, "threshold_count", 1)
        self.grouping_ns = integer(grouping_ns, "grouping_ns")
        self.window = deque()
        self.count = 0
        self.watermark = None
        self.last_time_ns = start_ns
        self.last_candidate_ns = None

    def observe(self, tx, core_log_count):
        key, t = transaction_identity(tx)
        core_count = integer(core_log_count, "core_log_count", 1)
        if not self.start_ns <= t < self.end_ns:
            raise ValueError("count observation outside configured day")
        if self.watermark is not None and key <= self.watermark:
            raise ValueError("count transaction order is not strictly increasing")
        if t < self.last_time_ns:
            raise ValueError("count timestamp decreases")
        # All validation precedes mutation. Cutoff is open at t-window_ns.
        cutoff = t - self.window_ns
        while self.window and self.window[0][0] <= cutoff:
            _, n = self.window.popleft()
            self.count -= n
        self.window.append((t, core_count))
        self.count += core_count
        raw = self.count >= self.threshold_count
        grouped = (raw and self.last_candidate_ns is not None
                   and t - self.last_candidate_ns < self.grouping_ns)
        candidate = raw and not grouped
        if candidate:
            self.last_candidate_ns = t
        self.watermark, self.last_time_ns = key, t
        return {"raw_trigger": raw, "group_candidate": candidate,
                "grouping_reason": "below_threshold" if not raw else "grouped" if grouped else "candidate",
                "rolling_core_log_count": self.count,
                "positive_token_count": None, "eligible_token_count": None,
                "token_scores": [], "transaction": dict(tx)}

    def snapshot(self):
        return {"schema_version": "transaction_final_count_state_v1",
                "start_ns": self.start_ns, "end_ns": self.end_ns,
                "window_ns": self.window_ns, "threshold_count": self.threshold_count,
                "grouping_ns": self.grouping_ns, "window": list(self.window),
                "count": self.count, "watermark": self.watermark,
                "last_time_ns": self.last_time_ns, "last_candidate_ns": self.last_candidate_ns}


@dataclass(frozen=True)
class AdmissionConfig:
    policy: str
    daily_budget: int
    start_ns: int
    end_ns: int
    method: str

    def __post_init__(self):
        if self.policy not in POLICIES or self.method not in METHODS:
            raise ValueError("unknown policy or method")
        integer(self.daily_budget, "daily_budget")
        integer(self.start_ns, "start_ns")
        integer(self.end_ns, "end_ns")
        if self.start_ns % DAY_NS or self.end_ns != self.start_ns + DAY_NS:
            raise ValueError("one complete UTC day required")


class AdmissionState:
    """Pure causal admission, independent of scoring and grouping state."""
    def __init__(self, config):
        self.config = config
        self.clock_ns = config.start_ns
        self.watermark = None
        self.notifications = 0
        self.credit = DAY_NS

    def process(self, tx, candidate):
        c = self.config
        key, t = transaction_identity(tx)
        if type(candidate) is not bool:
            raise ValueError("candidate must be boolean")
        if not c.start_ns <= t < c.end_ns:
            raise ValueError("admission observation outside configured day")
        if self.watermark is not None and key <= self.watermark:
            raise ValueError("admission transaction order is not strictly increasing")
        if t < self.clock_ns:
            raise ValueError("admission timestamp decreases")
        credit = self.credit
        if c.policy == "token_bucket":
            credit = min(DAY_NS, credit + (t - self.clock_ns) * c.daily_budget)
        quota = (min(c.daily_budget, 1 + c.daily_budget * (t - c.start_ns) // DAY_NS)
                 if c.policy == "paced_cumulative" and c.daily_budget else c.daily_budget)
        emitted = False
        if not candidate:
            reason = "not_candidate"
        elif self.notifications >= c.daily_budget:
            reason = "hard_daily_cap"
        elif c.policy == "paced_cumulative" and self.notifications >= quota:
            reason = "paced_quota"
        elif c.policy == "token_bucket" and credit < DAY_NS:
            reason = "token_shortage"
        else:
            emitted, reason = True, "emitted"
            if c.policy == "token_bucket":
                credit -= DAY_NS
        count = self.notifications + int(emitted)
        alert_id = ("alert:" + digest([asdict(c), tx["chain_id"], tx["block_hash"],
                                      tx["transaction_hash"]]) if emitted else None)
        self.watermark, self.clock_ns = key, t
        self.credit, self.notifications = credit, count
        return {"notification_emitted": emitted, "suppression_reason": reason,
                "notifications_on_day": count, "daily_quota": quota,
                "token_credit_units": credit if c.policy == "token_bucket" else None,
                "token_units_per_token": DAY_NS if c.policy == "token_bucket" else None,
                "notification_time_ns": t if emitted else None, "alert_id": alert_id}

    def snapshot(self):
        return {"schema_version": "semantic_admission_state_v1", "config": asdict(self.config),
                "clock_ns": self.clock_ns, "watermark": self.watermark,
                "notifications": self.notifications, "token_credit_units": self.credit}


def validate_config(config):
    if config.get("schema_version") != "semantic_flow_study_config_v1":
        raise ValueError("unsupported study config")
    if config["methods"] != list(METHODS) or config["policies"] != list(POLICIES):
        raise ValueError("method/policy grid differs from frozen design")
    if config["budgets"] != [1, 5, 20] or config["primary_budget"] != 5:
        raise ValueError("budget grid differs from frozen design")
    for budget in config["budgets"]:
        integer(budget, "budget", 1)
    integer(config["chain_id"], "chain_id", 1)
    if config["semantic"] != {"history_size": 128, "min_history": 19, "max_tokens": 4096,
                               "thresholds": [{"numerator": 1, "denominator": 20},
                                              {"numerator": 1, "denominator": 10}]}:
        raise ValueError("semantic parameters differ from frozen design")
    if config["count_baseline"] != {"window_ns": 60 * NS, "threshold_count": 10}:
        raise ValueError("count parameters differ from frozen design")
    if config["grouping_ns"] != 300 * NS or config["population_addresses"] != [ADDRESS] or config["chain_id"] != 1:
        raise ValueError("grouping/population differs from frozen design")
    expected = [("2023-03-01", 218, 1247), ("2023-03-13", 676, 3283)]
    if [(x["day_utc"], x["transaction_count"], x["core_log_count"]) for x in config["days"]] != expected:
        raise ValueError("development days or counts differ from frozen design")
    if config["execution"]["cells"] != 54 or config["execution"]["repetitions"] != 1:
        raise ValueError("unexpected cell count")
    return config


def resolve_path(value, parent):
    path = Path(value)
    return path if path.is_absolute() else parent / path


def load_inputs(config, manifest_path, expected_manifest_sha256, *, expected_selection_manifest_sha256):
    """Bind full files and all rows before producing accepted replay output."""
    from semantic_flow_monitor import validate_observation
    manifest_path = Path(manifest_path)
    if file_digest(manifest_path) != sha(expected_manifest_sha256, "expected manifest digest"):
        raise ValueError("input manifest digest mismatch")
    manifest = strict_json(manifest_path.read_bytes())
    if (manifest.get("schema_version") != "semantic_flow_observation_manifest_v1"
            or manifest.get("status") != "complete"):
        raise ValueError("input collection is not complete")
    source_audit = sha(manifest["source_audit_manifest_sha256"], "source audit digest")
    source_audit_path = resolve_path(manifest["source_audit_manifest_path"], manifest_path.parent)
    if file_digest(source_audit_path) != source_audit:
        raise ValueError("source audit manifest bytes do not match")
    audit = strict_json(source_audit_path.read_bytes())
    selection_digest = sha(expected_selection_manifest_sha256, "pre-acquisition selection digest")
    if (manifest["selection_manifest_sha256"] != selection_digest
            or audit.get("schema_version") != "semantic_flow_source_audit_v1" or audit.get("status") != "PASS"
            or audit.get("selection_manifest_sha256") != selection_digest):
        raise ValueError("source audit or selection does not match frozen design")
    selection_path = resolve_path(manifest["selection_manifest_path"], manifest_path.parent)
    if file_digest(selection_path) != selection_digest:
        raise ValueError("frozen selection bytes do not match")
    selection = strict_json(selection_path.read_bytes())
    if selection.get("schema_version") != "semantic_flow_transaction_selection_v1":
        raise ValueError("unknown selection schema")
    if manifest["source_scope"] != SOURCE_SCOPE:
        raise ValueError("unsupported source scope")
    expected_days = config["days"]
    if [x["day_utc"] for x in manifest["days"]] != [x["day_utc"] for x in expected_days]:
        raise ValueError("missing, repeated or extra day")
    if [x["day_utc"] for x in selection["days"]] != [x["day_utc"] for x in expected_days]:
        raise ValueError("selection days differ from frozen design")
    result = {}
    for spec, item, selected_day in zip(expected_days, manifest["days"], selection["days"]):
        path = resolve_path(item["path"], manifest_path.parent)
        if path.stat().st_size != integer(item["bytes"], "input bytes") or file_digest(path) != sha(item["sha256"], "input digest"):
            raise ValueError("observation file integrity mismatch")
        if item["transaction_count"] != spec["transaction_count"] or item["core_log_count"] != spec["core_log_count"]:
            raise ValueError("declared day population mismatch")
        row_hashes = item["observation_sha256"]
        if type(row_hashes) is not list or len(row_hashes) != spec["transaction_count"]:
            raise ValueError("missing per-observation anchors")
        selected = selected_day["transactions"]
        if type(selected) is not list or len(selected) != spec["transaction_count"]:
            raise ValueError("selection transaction count mismatch")
        observations, previous, previous_t, seen, core_sum = [], None, day_start(spec["day_utc"]), set(), 0
        with path.open("rb") as handle:
            for raw in handle:
                if not raw.endswith(b"\n") or raw == b"\n":
                    raise ValueError("noncanonical or partial JSONL row")
                observation = strict_json(raw)
                if canonical(observation) + b"\n" != raw:
                    raise ValueError("observation JSONL must use canonical encoding")
                index = len(observations)
                if index >= len(row_hashes) or digest(observation) != sha(row_hashes[index], "row digest"):
                    raise ValueError("observation digest mismatch")
                validate_observation(observation, expected_observation_sha256=row_hashes[index],
                                     config=semantic_config(config, 20),
                                     source_audit_sha256=source_audit, source_scope=SOURCE_SCOPE)
                if observation.get("schema_version") != "archive_transfer_observation_v1" or observation.get("status") != "observed_success":
                    raise ValueError("unavailable or unsupported observation")
                if type(observation.get("dataset_execution_status")) is not int or observation["dataset_execution_status"] != 1:
                    raise ValueError("dataset execution status not verified successful")
                if observation["population_addresses"] != config["population_addresses"]:
                    raise ValueError("observation population differs")
                evidence = observation["evidence"]
                if (evidence["tier"] != EVIDENCE_TIER or evidence["source_audit_manifest_sha256"] != source_audit
                        or evidence["selection_manifest_sha256"] != selection_digest
                        or evidence["observed_time"] is not None):
                    raise ValueError("source audit/tier or historical observation time mismatch")
                tx = observation["transaction"]
                expected_tx = {name: selected[index][name] for name in
                               ("chain_id", "block_number", "block_hash", "transaction_hash", "transaction_index", "event_time_ns")}
                if tx != expected_tx or observation["archived_core_log_count"] != selected[index]["archived_core_log_count"]:
                    raise ValueError("observation identity/core count differs from frozen selection")
                key, t = transaction_identity(tx)
                if not day_start(spec["day_utc"]) <= t < day_start(spec["day_utc"]) + DAY_NS:
                    raise ValueError("observation lies outside declared day")
                if previous is not None and key <= previous or t < previous_t:
                    raise ValueError("observation order/time violation")
                if observations and tx["block_number"] == observations[-1]["transaction"]["block_number"]:
                    prior_tx = observations[-1]["transaction"]
                    if tx["block_hash"] != prior_tx["block_hash"] or t != prior_tx["event_time_ns"]:
                        raise ValueError("conflicting block identity/time")
                if tx["transaction_hash"] in seen:
                    raise ValueError("duplicate transaction in population")
                seen.add(tx["transaction_hash"])
                previous, previous_t = key, t
                core_sum += integer(observation["archived_core_log_count"], "archived core count", 1)
                observations.append(observation)
        if len(observations) != spec["transaction_count"] or core_sum != spec["core_log_count"]:
            raise ValueError("actual day population/core total mismatch")
        result[spec["day_utc"]] = observations
    return manifest, result


def semantic_config(config, denominator):
    return {"schema_version": "semantic_flow_monitor_config_v1",
            "history_size": config["semantic"]["history_size"],
            "min_history": config["semantic"]["min_history"],
            "max_tokens": config["semantic"]["max_tokens"],
            "threshold_numerator": 1, "threshold_denominator": denominator,
            "grouping_ns": config["grouping_ns"], "chain_id": config["chain_id"],
            "population_addresses": config["population_addresses"]}


def replay_day(config, day, observations, *, source_audit_sha256, source_scope):
    # Imported at actual use; policy/count offline tests do not need the adapter.
    from semantic_flow_monitor import SemanticFlowMonitor
    start = day_start(day)
    monitors = {"core_count_60s_10": CountMonitor(start_ns=start, end_ns=start + DAY_NS,
                grouping_ns=config["grouping_ns"], **config["count_baseline"]),
                "outflow_rank_1_20": SemanticFlowMonitor(semantic_config(config, 20),
                    source_audit_sha256=source_audit_sha256, source_scope=source_scope),
                "outflow_rank_1_10": SemanticFlowMonitor(semantic_config(config, 10),
                    source_audit_sha256=source_audit_sha256, source_scope=source_scope)}
    policy_states = {(method, policy, budget): AdmissionState(AdmissionConfig(
        policy, budget, start, start + DAY_NS, method))
        for method in METHODS for policy in POLICIES for budget in config["budgets"]}
    method_rows = {name: [] for name in METHODS}
    decisions = {key: [] for key in policy_states}
    for observation in observations:
        tx, obs_hash = observation["transaction"], digest(observation)
        # Semantic validation precedes count use of the same complete observation.
        scored = {name: monitors[name].observe(observation, expected_observation_sha256=obs_hash)
                  for name in METHODS[1:]}
        scored[METHODS[0]] = monitors[METHODS[0]].observe(tx, observation["archived_core_log_count"])
        for method in METHODS:
            row = dict(scored[method])
            row.update(schema_version="semantic_flow_method_decision_v1", method=method,
                       day_utc=day, observation_sha256=obs_hash,
                       archived_core_log_count=observation["archived_core_log_count"],
                       historical_observed_time=None,
                       clock_domain="historical_event_time_ns_logical_simulation",
                       feature_availability="after_complete_transaction_bundle_under_replay_assumption",
                       label_used=False)
            method_rows[method].append(row)
            for policy in POLICIES:
                for budget in config["budgets"]:
                    key = method, policy, budget
                    admission = policy_states[key].process(tx, row["group_candidate"])
                    decisions[key].append({"schema_version": "semantic_flow_admission_decision_v1",
                        "day_utc": day, "method": method, "policy": policy, "daily_budget": budget,
                        "transaction": tx, "observation_sha256": obs_hash,
                        "method_decision_sha256": digest(row), "raw_trigger": row["raw_trigger"],
                        "group_candidate": row["group_candidate"], "grouping_reason": row["grouping_reason"],
                        "label_used": False, **admission})
    method_summaries = {}
    for method, rows in method_rows.items():
        semantic = method != METHODS[0]
        positives = sum(r["positive_token_count"] for r in rows) if semantic else None
        eligible = sum(r["eligible_token_count"] for r in rows) if semantic else None
        method_summaries[method] = {"transactions": len(rows),
            "raw_triggers": sum(r["raw_trigger"] for r in rows),
            "group_candidates": sum(r["group_candidate"] for r in rows),
            "grouped_raw_triggers": sum(r["raw_trigger"] and not r["group_candidate"] for r in rows),
            "positive_token_observations": positives, "eligible_token_scores": eligible,
            "cold_start_token_scores": positives - eligible if semantic else None,
            "transactions_with_positive_outflow": sum(r["positive_token_count"] > 0 for r in rows) if semantic else None,
            "transactions_with_eligible_token_score": sum(r["eligible_token_count"] > 0 for r in rows) if semantic else None,
            "candidate_transaction_hashes": [r["transaction"]["transaction_hash"] for r in rows if r["group_candidate"]]}
    cell_summaries = []
    for (method, policy, budget), rows in decisions.items():
        reasons = Counter(row["suppression_reason"] for row in rows)
        emitted = [row for row in rows if row["notification_emitted"]]
        if len(emitted) > budget:
            raise AssertionError("hard cap exceeded")
        expected_candidates = method_summaries[method]["candidate_transaction_hashes"]
        if [row["transaction"]["transaction_hash"] for row in rows if row["group_candidate"]] != expected_candidates:
            raise AssertionError("candidate stream differs across budget cells")
        cell_summaries.append({"day_utc": day, "method": method, "policy": policy,
            "daily_budget": budget, "transactions": len(rows), "notifications": len(emitted),
            "unused_daily_slots": budget - len(emitted), "hard_cap_exceeded": False,
            "raw_triggers": method_summaries[method]["raw_triggers"],
            "group_candidates": len(expected_candidates), "suppression_counts": dict(sorted(reasons.items())),
            "notification_transaction_hashes": [row["transaction"]["transaction_hash"] for row in emitted],
            "first_notification_time_ns": emitted[0]["transaction"]["event_time_ns"] if emitted else None,
            "last_notification_time_ns": emitted[-1]["transaction"]["event_time_ns"] if emitted else None})
    return {"methods": method_rows, "decisions": decisions,
            "method_summaries": method_summaries, "cell_summaries": cell_summaries,
            "final_method_states": {key: monitor.snapshot() for key, monitor in monitors.items()},
            "final_policy_states": {"__".join(map(str, key)): state.snapshot() for key, state in policy_states.items()}}


def write_json(path, value):
    with Path(path).open("xb") as handle:
        handle.write(canonical(value) + b"\n")


def write_jsonl_gzip(path, rows):
    with Path(path).open("xb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed:
            for row in rows:
                compressed.write(canonical(row) + b"\n")


def validate_freeze(path, config_path):
    freeze = strict_json(Path(path).read_bytes())
    if freeze.get("schema_version") != "semantic_flow_design_freeze_v1":
        raise ValueError("unsupported design freeze")
    if freeze["config_sha256"] != file_digest(config_path):
        raise ValueError("configuration changed after freeze")
    sha(freeze["selection_manifest_sha256"], "frozen selection digest")
    source_hashes = freeze["source_sha256"]
    for required in ("semantic_flow_replay.py", "semantic_flow_monitor.py"):
        if required not in source_hashes:
            raise ValueError("missing required executable source in freeze")
    for name, expected in source_hashes.items():
        if file_digest(PAPER / name) != sha(expected, "frozen source digest"):
            raise ValueError(f"source changed after freeze: {name}")
    return freeze


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--design-freeze", required=True, type=Path)
    parser.add_argument("--input-manifest", required=True, type=Path)
    parser.add_argument("--expected-input-manifest-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    config = validate_config(strict_json(args.config.read_bytes()))
    freeze = validate_freeze(args.design_freeze, args.config)
    args.output.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    try:
        manifest, days = load_inputs(config, args.input_manifest, args.expected_input_manifest_sha256,
                                     expected_selection_manifest_sha256=freeze["selection_manifest_sha256"])
        summaries = []
        for day, observations in days.items():
            run = replay_day(config, day, observations,
                             source_audit_sha256=manifest["source_audit_manifest_sha256"],
                             source_scope=manifest["source_scope"])
            folder = args.output / day
            folder.mkdir()
            for method, rows in run["methods"].items():
                write_jsonl_gzip(folder / (method + "__methods.jsonl.gz"), rows)
            for key, rows in run["decisions"].items():
                write_jsonl_gzip(folder / ("__".join(map(str, key)) + "__decisions.jsonl.gz"), rows)
            for key in ("method_summaries", "cell_summaries", "final_method_states", "final_policy_states"):
                write_json(folder / (key + ".json"), run[key])
            summaries.extend(run["cell_summaries"])
        validate_freeze(args.design_freeze, args.config)
        if file_digest(args.input_manifest) != args.expected_input_manifest_sha256:
            raise ValueError("input manifest changed during replay")
        artifacts = [{"path": str(path.relative_to(args.output)), "bytes": path.stat().st_size,
                      "sha256": file_digest(path)} for path in sorted(args.output.rglob("*")) if path.is_file()]
        result = {"schema_version": "semantic_flow_replay_run_v1", "status": "complete",
                  "started_utc": started, "completed_utc": datetime.now(timezone.utc).isoformat(),
                  "config_sha256": file_digest(args.config), "design_freeze_sha256": file_digest(args.design_freeze),
                  "input_manifest_sha256": args.expected_input_manifest_sha256,
                  "source_sha256": freeze["source_sha256"], "cells": len(summaries),
                  "decision_rows": sum(row["transactions"] for row in summaries),
                  "summaries": summaries, "artifacts": artifacts,
                  "python": sys.version, "platform": platform.platform(),
                  "command": sys.argv if argv is None else argv,
                  "clock": "historical_event_time_ns_logical_simulation",
                  "independent_scientific_incidents": 0, "labels_used": False,
                  "scope": "Two separate previously exposed development days; deterministic functional comparison, not independent attack evaluation or live performance."}
        write_json(args.output / "run_manifest.json", result)
        print(json.dumps({"status": "complete", "cells": len(summaries), "decision_rows": result["decision_rows"]}))
    except Exception as error:
        write_json(args.output / "failure.json", {"status": "failed", "started_utc": started,
            "failed_utc": datetime.now(timezone.utc).isoformat(), "error_type": type(error).__name__,
            "error": str(error), "accepted_result": False, "labels_used": False})
        raise


if __name__ == "__main__":
    main()
