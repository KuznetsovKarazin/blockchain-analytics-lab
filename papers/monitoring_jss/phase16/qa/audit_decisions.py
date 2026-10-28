"""Independently check sealed Phase16 replay calculations without calling replay.

Reads accepted observations and existing decisions only. The reference equations
below use integer amounts/ranks and fresh UTC-day state. This is validation of
the one accepted replay, not a second scientific run and not a label join.
"""
from __future__ import annotations
import argparse
from collections import Counter, deque
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import sys

PAPER = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PAPER / "phase15" / "driver"))
import fixed_address_replay as driver

DAY = 86_400_000_000_000
METHODS = ("core_count_60s_10", "outflow_rank_1_20", "outflow_rank_1_10")
POLICIES = ("greedy", "paced_cumulative", "token_bucket")


def need(test, message):
    if not test:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def read(path):
    return driver.frozen.strict_json(Path(path).read_bytes())


def sealed(path, expected):
    need(file_sha(path) == expected, "sealed bytes changed: " + str(path))
    return read(path)


def rows(path):
    with gzip.open(path, "rb") as f:
        for line in f:
            row = driver.frozen.strict_json(line)
            need(line == canonical(row) + b"\n", "noncanonical decision row")
            yield row


def same(actual, expected, context):
    for key, value in expected.items():
        need(canonical(actual[key]) == canonical(value), context + ": " + key)


def semantic_config(config, denominator):
    return {"schema_version": "semantic_flow_monitor_config_v1", "chain_id": config["chain_id"],
            "population_addresses": config["population_addresses"], "history_size": 128, "min_history": 19,
            "threshold_numerator": 1, "threshold_denominator": denominator, "grouping_ns": 300_000_000_000,
            "max_tokens": 4096}


def method_reference(observations, method, start):
    """Yield independent method fields, retaining the final state as return value."""
    histories, window, previous_candidate, rolling = {}, deque(), None, 0
    last_tx = None
    for observation in observations:
        tx = observation["transaction"]; t = tx["event_time_ns"]
        obs_sha = digest(observation)
        if method == METHODS[0]:
            while window and window[0][0] <= t - 60_000_000_000:
                rolling -= window.popleft()[1]
            window.append([t, observation["archived_core_log_count"]])
            rolling += observation["archived_core_log_count"]
            raw = rolling >= 10
            base = {"rolling_core_log_count": rolling, "positive_token_count": None,
                    "eligible_token_count": None, "token_scores": []}
        else:
            denominator = 20 if method == METHODS[1] else 10
            positive = [x for x in observation["token_flows"] if int(x["external_out_raw"]) > 0]
            token_scores, triggers = [], []
            eligible_count = 0
            for flow in positive:
                token = flow["token_address"]; amount = int(flow["external_out_raw"])
                history = histories.get(token, [])
                n = len(history); rank = 1 + sum(int(x["amount_raw"]) >= amount for x in history)
                eligible = n >= 19
                trigger = eligible and rank * denominator <= n + 1
                eligible_count += int(eligible)
                if trigger:
                    triggers.append(token)
                token_scores.append({"token_address": token, "external_out_raw": str(amount),
                    "external_in_raw": flow["external_in_raw"], "net_external_in_raw": flow["net_external_in_raw"],
                    "history_count": n, "eligible": eligible, "trigger": trigger,
                    "tail_rank": {"numerator": rank, "denominator": n + 1},
                    "reference_oldest_event_time_ns": history[0]["event_time_ns"] if history else None,
                    "reference_newest_event_time_ns": history[-1]["event_time_ns"] if history else None})
            raw = bool(triggers)
            base = {"positive_token_count": len(positive), "eligible_token_count": eligible_count,
                    "cold_start_token_count": len(positive) - eligible_count,
                    "triggering_token_addresses": triggers, "token_scores": token_scores,
                    "last_candidate_time_ns_before": previous_candidate, "rank_is_calibrated_p_value": False}
            for flow in positive:
                token = flow["token_address"]
                history = histories.setdefault(token, [])
                history.append({"amount_raw": flow["external_out_raw"], "event_time_ns": t,
                    "block_number": tx["block_number"], "transaction_index": tx["transaction_index"],
                    "observation_sha256": obs_sha})
                if len(history) > 128:
                    del history[0]
            need(len(histories) <= 4096, "token capacity exceeded")
            base.update(history_token_count_after=len(histories), history_record_count_after=sum(map(len, histories.values())))
        grouped = raw and previous_candidate is not None and t - previous_candidate < 300_000_000_000
        candidate = raw and not grouped
        if candidate:
            reason = "candidate"
        elif grouped:
            reason = "grouped"
        elif method == METHODS[0]:
            reason = "below_threshold"
        elif not positive:
            reason = "no_positive_external_outflow"
        elif not eligible_count:
            reason = "cold_start_only"
        else:
            reason = "rank_not_exceeded"
        if candidate:
            previous_candidate = t
        last_tx = tx
        yield base | {"transaction": tx, "observation_sha256": obs_sha,
                      "archived_core_log_count": observation["archived_core_log_count"],
                      "raw_trigger": raw, "group_candidate": candidate, "grouping_reason": reason}
    return {"histories": histories, "window": list(window), "count": rolling,
            "last_candidate": previous_candidate, "last_transaction": last_tx}


def calculate_methods(observations, method, start):
    stream = method_reference(observations, method, start)
    output = []
    while True:
        try:
            output.append(next(stream))
        except StopIteration as end:
            return output, end.value


def policy_reference(method_rows, policy, budget, method, start):
    clock, credit, emitted = start, DAY, 0
    cfg = {"policy": policy, "daily_budget": budget, "start_ns": start, "end_ns": start + DAY, "method": method}
    results = []
    for row in method_rows:
        tx = row["transaction"]; t = tx["event_time_ns"]
        if policy == "token_bucket":
            credit = min(DAY, credit + (t - clock) * budget)
        quota = min(budget, 1 + budget * (t - start) // DAY) if policy == "paced_cumulative" else budget
        if not row["group_candidate"]:
            reason = "not_candidate"
        elif emitted == budget:
            reason = "hard_daily_cap"
        elif policy == "paced_cumulative" and emitted >= quota:
            reason = "paced_quota"
        elif policy == "token_bucket" and credit < DAY:
            reason = "token_shortage"
        else:
            reason = "emitted"
            emitted += 1
            if policy == "token_bucket":
                credit -= DAY
        success = reason == "emitted"
        results.append({"notification_emitted": success, "suppression_reason": reason,
            "notifications_on_day": emitted, "daily_quota": quota,
            "token_credit_units": credit if policy == "token_bucket" else None,
            "token_units_per_token": DAY if policy == "token_bucket" else None,
            "notification_time_ns": t if success else None,
            "alert_id": "alert:" + digest([cfg, tx["chain_id"], tx["block_hash"], tx["transaction_hash"]]) if success else None})
        clock = t
    return results, {"clock_ns": clock, "watermark": None if not method_rows else [method_rows[-1]["transaction"]["block_number"],
                    method_rows[-1]["transaction"]["transaction_index"]], "notifications": emitted, "token_credit_units": credit, "config": cfg}


def audit_day(config, day, observations, folder, source_audit_sha):
    start = driver.frozen.day_start(day)
    final_methods = read(folder / "final_method_states.json")
    final_policies = read(folder / "final_policy_states.json")
    summaries = []
    for method in METHODS:
        actual = list(rows(folder / (method + "__methods.jsonl.gz")))
        expected, state = calculate_methods(observations, method, start)
        need(len(actual) == len(expected), "method row count differs")
        for checked, target in zip(actual, expected):
            same(checked, target, method + " independent method equation")
            same(checked, {"schema_version": "semantic_flow_method_decision_v1", "method": method, "day_utc": day,
                          "label_used": False, "historical_observed_time": None,
                          "clock_domain": "historical_event_time_ns_logical_simulation",
                          "feature_availability": "after_complete_transaction_bundle_under_replay_assumption"}, "method scope")
        last = state["last_transaction"]
        if method == METHODS[0]:
            same(final_methods[method], {"schema_version": "transaction_final_count_state_v1", "start_ns": start,
                "end_ns": start + DAY, "window_ns": 60_000_000_000, "threshold_count": 10, "grouping_ns": 300_000_000_000,
                "window": state["window"], "count": state["count"],
                "watermark": None if last is None else [last["block_number"], last["transaction_index"]],
                "last_time_ns": start if last is None else last["event_time_ns"], "last_candidate_ns": state["last_candidate"]}, "count final state")
        else:
            cfg = semantic_config(config, 20 if method == METHODS[1] else 10)
            same(final_methods[method], {"schema_version": "semantic_flow_monitor_state_v1", "config": cfg,
                "config_sha256": digest(cfg), "source_audit_sha256": source_audit_sha, "source_scope": config["source_scope"],
                "processed_observations": len(observations), "observation_schema": "archive_transfer_observation_v1" if observations else None,
                "last_transaction": last, "last_candidate_time_ns": state["last_candidate"], "histories": state["histories"]}, "semantic final state")
        for policy in POLICIES:
            for budget in config["budgets"]:
                stem = "__".join(map(str, (method, policy, budget)))
                admissions = list(rows(folder / (stem + "__decisions.jsonl.gz")))
                expect_admissions, final = policy_reference(expected, policy, budget, method, start)
                need(len(admissions) == len(expected), "admission row count differs")
                for decision, calculation, method_row in zip(admissions, expect_admissions, actual):
                    same(decision, calculation, stem + " independent admission equation")
                    same(decision, {"schema_version": "semantic_flow_admission_decision_v1", "day_utc": day,
                        "method": method, "policy": policy, "daily_budget": budget, "label_used": False,
                        "method_decision_sha256": digest(method_row), **{k: method_row[k] for k in
                        ("transaction", "observation_sha256", "raw_trigger", "group_candidate", "grouping_reason")}}, "admission binding")
                same(final_policies[stem], {"schema_version": "semantic_admission_state_v1", **final}, "policy final state")
                notified = [x for x, calc in zip(actual, expect_admissions) if calc["notification_emitted"]]
                summaries.append({"day_utc": day, "method": method, "policy": policy, "daily_budget": budget,
                    "transactions": len(observations), "notifications": len(notified), "unused_daily_slots": budget - len(notified),
                    "hard_cap_exceeded": False, "raw_triggers": sum(x["raw_trigger"] for x in expected),
                    "group_candidates": sum(x["group_candidate"] for x in expected),
                    "suppression_counts": dict(sorted(Counter(x["suppression_reason"] for x in expect_admissions).items())),
                    "notification_transaction_hashes": [x["transaction"]["transaction_hash"] for x in notified],
                    "first_notification_time_ns": notified[0]["transaction"]["event_time_ns"] if notified else None,
                    "last_notification_time_ns": notified[-1]["transaction"]["event_time_ns"] if notified else None})
    need(read(folder / "cell_summaries.json") == summaries, "cell summaries differ from independent equations")
    return summaries


def run(args):
    own_sha = file_sha(__file__)
    config = driver.validate_config(read(args.config))
    config_sha = file_sha(args.config)
    acceptance = driver.validate_freeze(args.acceptance, args.config, expected_freeze_sha256=args.expected_acceptance_sha256)
    run_manifest = sealed(args.run_manifest, args.expected_run_sha256)
    same(run_manifest, {"schema_version": "fixed_address_replay_run_v1", "status": "COMPLETE", "case_id": config["case_id"],
        "config_sha256": config_sha, "measurement_acceptance_sha256": args.expected_acceptance_sha256,
        "input_manifest_sha256": args.expected_input_sha256, "driver_sha256": acceptance["driver_sha256"],
        "dependency_sha256": driver.DEPENDENCIES, "state_initialization": "independent_utc_day_reset", "days": 30,
        "cells": 810, "labels_used": False, "label_join_performed": False}, "run binding")
    manifest, observations = driver.load_inputs(config, args.input_manifest,
        expected_manifest_sha256=args.expected_input_sha256, expected_config_sha256=config_sha)
    expected_paths = set()
    for day in observations:
        expected_paths.update(day + "/" + m + "__methods.jsonl.gz" for m in METHODS)
        expected_paths.update(day + "/" + "__".join(map(str, (m, p, b))) + "__decisions.jsonl.gz"
                              for m in METHODS for p in POLICIES for b in config["budgets"])
        expected_paths.update(day + "/" + name + ".json" for name in
                              ("method_summaries", "cell_summaries", "final_method_states", "final_policy_states"))
    need(len(run_manifest["artifacts"]) == len(expected_paths)
         and {x["path"] for x in run_manifest["artifacts"]} == expected_paths, "artifact population differs")
    for artifact in run_manifest["artifacts"]:
        path = driver.bound_file({k: artifact[k] for k in ("path", "sha256")}, args.run_manifest.parent)
        need(path.stat().st_size == artifact["bytes"], "artifact size differs")
    summaries = []
    for day, obs in observations.items():
        summaries.extend(audit_day(config, day, obs, args.run_manifest.parent / day, manifest["source_audit"]["sha256"]))
    need(run_manifest["summaries"] == summaries and run_manifest["decision_rows"] == sum(x["transactions"] for x in summaries),
         "run summary arithmetic differs")
    need(file_sha(__file__) == own_sha and file_sha(args.run_manifest) == args.expected_run_sha256,
         "audited code or run changed")
    result = {"schema_version": "phase16_independent_sealed_decision_audit_v1", "status": "PASS_ALL_SEALED_DECISIONS",
        "case_id": config["case_id"], "completed_utc": datetime.now(timezone.utc).isoformat(), "reviewer_sha256": own_sha,
        "run_manifest_sha256": args.expected_run_sha256, "input_manifest_sha256": args.expected_input_sha256,
        "measurement_acceptance_sha256": args.expected_acceptance_sha256, "config_sha256": config_sha,
        "days": 30, "cells": 810, "decision_rows_checked": sum(x["transactions"] for x in summaries),
        "checks": ["all exact artifact seals", "same accepted observation identities in every arm", "independent UTC-day reset",
                   "strictly past per-token positive128 history and19 warmup", "integer tied-tail rank at1/20 and1/10",
                   "transaction-final open-left60-second count", "candidate-anchored300-second grouping independent of budget",
                   "integer greedy/paced/token-bucket admission", "all final states", "summary arithmetic"],
        "labels_read": False, "scientific_replay_rerun": False,
        "interpretation": "Independent calculation audit of the single accepted sealed replay. No additional incident, effectiveness estimate, label adjudication or live-performance claim."}
    need(not args.output.exists(), "refuse to overwrite audit")
    args.output.write_bytes(canonical(result) + b"\n")
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "acceptance", "input-manifest", "run-manifest", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    for name in ("acceptance", "input", "run"):
        p.add_argument("--expected-" + name + "-sha256", required=True)
    result = run(p.parse_args())
    print(json.dumps({"status": result["status"], "case_id": result["case_id"], "cells": result["cells"]}))
