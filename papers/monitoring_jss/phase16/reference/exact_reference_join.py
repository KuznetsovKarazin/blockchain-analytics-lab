"""Post-decision exact-execution join; no retrieval, scoring or label inference.

Hash bindings establish retained bytes and ordering, not the truth of an audit.
The separately named independent reviewer adjudicates primary attribution,
identity evidence, source coverage and positive inventory closure.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import gzip
from pathlib import Path
import sys

PAPER = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PAPER / "phase15" / "driver"))
import fixed_address_replay as driver

frozen = driver.frozen
require = driver.require
CASES = ("lifi_20220320", "revest_20220327")
INVENTORY_STATUSES = {"COMPLETE_WITH_POSITIVE_CLOSURE_EVIDENCE", "KNOWN_SUBSET_ONLY",
                      "UNRESOLVED_CONFLICT", "NO_VERIFIED_EXECUTION_UNDER_CAP"}
ADJUDICATIONS = {"VERIFIED_APPLICABLE_EXECUTION", "VERIFIED_OUTSIDE_WINDOW",
                "NOT_ATTACK_EXECUTION", "UNRESOLVED", "UNVERIFIED_DUE_TO_CAP"}
CATEGORIES = ("UNAVAILABLE_REFERENCE_OR_OBSERVATION_EVIDENCE",
              "OBSERVED_NOT_SELECTED_NO_CORE_EMITTER_LOG", "SELECTED_NO_POSITIVE_CORE_OUTFLOW",
              "SELECTED_COLD_START", "SELECTED_ELIGIBLE_NO_RAW_TRIGGER", "RAW_TRIGGER_GROUPED",
              "CANDIDATE_BUDGET_SUPPRESSED", "EXACT_EXECUTION_NOTIFIED")


def read(path):
    return frozen.strict_json(Path(path).read_bytes())


def utc(value):
    require(type(value) is str, "explicit UTC timestamp required")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.utcoffset() == timedelta(0), "explicit UTC timestamp required")
    return parsed


def nonempty(value, name):
    require(type(value) is str and bool(value.strip()), "missing " + name)


def binding(value, folder):
    # Retained bundles can use absolute paths but cannot silently follow a
    # different digest. The frozen input/gate readers keep their stricter paths.
    driver.exact_keys(value, ("path", "sha256"), "reference binding")
    nonempty(value["path"], "binding path")
    path = Path(value["path"])
    path = path if path.is_absolute() else Path(folder) / path
    require(path.is_file() and frozen.file_digest(path) == frozen.sha(value["sha256"], "binding"),
            "bound file digest mismatch: " + str(path))
    return path


def pinned(path, expected):
    require(frozen.file_digest(path) == frozen.sha(expected, "external seal"), "external seal mismatch")
    return read(path)


def identity(tx):
    driver.exact_keys(tx, driver.TX_KEYS, "reference transaction")
    frozen.transaction_identity(tx)
    return tx["chain_id"], tx["transaction_hash"]


def row_stream(path):
    with gzip.open(path, "rb") as handle:
        for raw in handle:
            require(raw.endswith(b"\n") and raw != b"\n", "incomplete decision JSONL")
            row = frozen.strict_json(raw)
            require(raw == frozen.canonical(row) + b"\n", "noncanonical decision JSONL")
            yield row


def method_summary(rows, semantic):
    positive = sum(r["positive_token_count"] for r in rows) if semantic else None
    eligible = sum(r["eligible_token_count"] for r in rows) if semantic else None
    return {"transactions": len(rows), "raw_triggers": sum(r["raw_trigger"] for r in rows),
            "group_candidates": sum(r["group_candidate"] for r in rows),
            "grouped_raw_triggers": sum(r["raw_trigger"] and not r["group_candidate"] for r in rows),
            "positive_token_observations": positive, "eligible_token_scores": eligible,
            "cold_start_token_scores": positive - eligible if semantic else None,
            "transactions_with_positive_outflow": sum(r["positive_token_count"] > 0 for r in rows) if semantic else None,
            "transactions_with_eligible_token_score": sum(r["eligible_token_count"] > 0 for r in rows) if semantic else None,
            "candidate_transaction_hashes": [r["transaction"]["transaction_hash"] for r in rows if r["group_candidate"]]}


def cell_summary(day, method, policy, budget, rows):
    emitted = [r for r in rows if r["notification_emitted"]]
    require(len(emitted) <= budget, "sealed decisions exceed daily budget")
    return {"day_utc": day, "method": method, "policy": policy, "daily_budget": budget,
            "transactions": len(rows), "notifications": len(emitted),
            "unused_daily_slots": budget - len(emitted), "hard_cap_exceeded": False,
            "raw_triggers": sum(r["raw_trigger"] for r in rows),
            "group_candidates": sum(r["group_candidate"] for r in rows),
            "suppression_counts": dict(sorted(Counter(r["suppression_reason"] for r in rows).items())),
            "notification_transaction_hashes": [r["transaction"]["transaction_hash"] for r in emitted],
            "first_notification_time_ns": emitted[0]["transaction"]["event_time_ns"] if emitted else None,
            "last_notification_time_ns": emitted[-1]["transaction"]["event_time_ns"] if emitted else None}


def load_run(entry, folder):
    config_path = binding(entry["config"], folder)
    config = driver.validate_config(read(config_path))
    require(config["case_id"] == entry["case_id"], "case/config differs")
    # The only admitted study scopes are the two immutable Phase16 configs.
    name = "lifi" if entry["case_id"] == CASES[0] else "revest"
    require(frozen.canonical(config) == frozen.canonical(read(PAPER / "phase16" / "protocol" / "configs" / (name + ".json"))),
            "config differs from frozen Phase16 case")
    acceptance_path = binding(entry["measurement_acceptance"], folder)
    acceptance = driver.validate_freeze(acceptance_path, config_path,
                          expected_freeze_sha256=entry["measurement_acceptance"]["sha256"])
    result = {"case_id": config["case_id"], "config": config, "status": entry["status"],
              "observations": {}, "methods": {}, "decisions": {}, "summaries": []}
    if entry["status"] == "UNAVAILABLE":
        require(entry.get("run_manifest") is None and entry.get("input_manifest") is None,
                "unavailable case must not supply detector inputs/results")
        failure = read(binding(entry["failure_report"], folder))
        require(failure["schema_version"] == "article2_phase16_closed_source_failure_v1"
                and failure["status"] == "SOURCE_STAGE_CLOSED_UNAVAILABLE"
                and failure["case_id"] == config["case_id"]
                and failure["config_sha256"] == entry["config"]["sha256"]
                and failure["detector_metrics_available"] is False, "invalid unavailable stage closure")
        nonempty(failure["reason"], "source failure reason")
        result.update(closed_utc=utc(failure["closed_utc"]), unavailable_reason=failure["reason"])
        return result
    require(entry["status"] == "COMPLETE", "unknown study case status")
    run_path = binding(entry["run_manifest"], folder)
    run = read(run_path)
    require(run["schema_version"] == "fixed_address_replay_run_v1" and run["status"] == "COMPLETE",
            "replay incomplete: unavailable cannot become zero")
    for key in ("case_id", "chain_id", "window", "state_initialization"):
        require(frozen.canonical(run[key]) == frozen.canonical(config[key]), "run/config scope mismatch")
    require(run["labels_used"] is False and run["label_join_performed"] is False,
            "decisions must precede labels")
    require(utc(run["completed_utc"]) >= utc(run["started_utc"]) >= utc(acceptance["accepted_utc"]),
            "replay ordering differs from measurement acceptance")
    require(run["days"] == 30 and run["cells"] == 810 and run["driver_sha256"] == frozen.file_digest(driver.__file__)
            and run["dependency_sha256"] == driver.DEPENDENCIES, "run dimensions/code differ")
    require(run["config_sha256"] == entry["config"]["sha256"]
            and run["measurement_acceptance_sha256"] == entry["measurement_acceptance"]["sha256"]
            and run["input_manifest_sha256"] == entry["input_manifest"]["sha256"], "run seal binding differs")
    input_path = binding(entry["input_manifest"], folder)
    manifest, observations = driver.load_inputs(config, input_path,
        expected_manifest_sha256=entry["input_manifest"]["sha256"], expected_config_sha256=entry["config"]["sha256"])
    expected_files = set()
    for day in driver.expected_days(config):
        expected_files.update(day + "/" + method + "__methods.jsonl.gz" for method in config["methods"])
        expected_files.update(day + "/" + "__".join(map(str, (method, policy, budget))) + "__decisions.jsonl.gz"
                              for method in config["methods"] for policy in config["policies"] for budget in config["budgets"])
        expected_files.update(day + "/" + name + ".json" for name in
                              ("method_summaries", "cell_summaries", "final_method_states", "final_policy_states"))
    artifacts = run["artifacts"]
    require(len(artifacts) == len(expected_files) and {a["path"] for a in artifacts} == expected_files,
            "run missing/repeated/extra sealed artifacts")
    for artifact in artifacts:
        path = driver.bound_file({k: artifact[k] for k in ("path", "sha256")}, run_path.parent)
        require(type(artifact["bytes"]) is int and path.stat().st_size == artifact["bytes"], "artifact bytes differ")
    all_summaries = []
    for day, obs in observations.items():
        day_folder = run_path.parent / day
        for observation in obs:
            key = identity(observation["transaction"])
            require(key not in result["observations"], "repeated selected identity")
            result["observations"][key] = observation
        recomputed_methods, day_summaries = {}, []
        for method in config["methods"]:
            rows = list(row_stream(day_folder / (method + "__methods.jsonl.gz")))
            require(len(rows) == len(obs), "selected transaction missing method decision")
            for row, observation in zip(rows, obs):
                require(row["schema_version"] == "semantic_flow_method_decision_v1" and row["method"] == method
                        and row["day_utc"] == day and row["label_used"] is False, "method decision scope differs")
                require(row["transaction"] == observation["transaction"]
                        and row["observation_sha256"] == frozen.digest(observation)
                        and row["archived_core_log_count"] == observation["archived_core_log_count"],
                        "method/observation identity or binding differs")
                for field in ("raw_trigger", "group_candidate"):
                    require(type(row[field]) is bool, "method boolean required")
                require(not row["group_candidate"] or row["raw_trigger"], "candidate without trigger")
                if method != frozen.METHODS[0]:
                    positive = frozen.integer(row["positive_token_count"], "positive token count")
                    eligible = frozen.integer(row["eligible_token_count"], "eligible token count")
                    require(eligible <= positive and (not row["raw_trigger"] or eligible > 0), "semantic funnel inconsistent")
                result["methods"][(method, identity(row["transaction"]))] = row
            recomputed_methods[method] = method_summary(rows, method != frozen.METHODS[0])
            for policy in config["policies"]:
                for budget in config["budgets"]:
                    key = method, policy, budget
                    decisions = list(row_stream(day_folder / ("__".join(map(str, key)) + "__decisions.jsonl.gz")))
                    require(len(decisions) == len(obs), "selected transaction missing admission decision")
                    emitted_count = 0
                    for decision, method_row in zip(decisions, rows):
                        require(decision["schema_version"] == "semantic_flow_admission_decision_v1"
                                and decision["day_utc"] == day and decision["method"] == method
                                and decision["policy"] == policy and type(decision["daily_budget"]) is int
                                and decision["daily_budget"] == budget and decision["label_used"] is False,
                                "admission decision scope differs")
                        for field in ("transaction", "observation_sha256", "raw_trigger", "group_candidate", "grouping_reason"):
                            require(frozen.canonical(decision[field]) == frozen.canonical(method_row[field]), "admission/method differs")
                        require(decision["method_decision_sha256"] == frozen.digest(method_row), "method decision seal differs")
                        require(type(decision["notification_emitted"]) is bool, "notification boolean required")
                        if decision["notification_emitted"]:
                            require(decision["group_candidate"] and decision["suppression_reason"] == "emitted"
                                    and decision["notification_time_ns"] == decision["transaction"]["event_time_ns"],
                                    "emitted decision inconsistent")
                            emitted_count += 1
                        else:
                            require(decision["suppression_reason"] in ("not_candidate", "hard_daily_cap", "paced_quota", "token_shortage")
                                    and decision["notification_time_ns"] is None, "suppressed decision inconsistent")
                        require(type(decision["notifications_on_day"]) is int
                                and decision["notifications_on_day"] == emitted_count, "notification count inconsistent")
                        result["decisions"][(key, identity(decision["transaction"]))] = decision
                    day_summaries.append(cell_summary(day, *key, decisions))
        require(frozen.canonical(read(day_folder / "method_summaries.json")) == frozen.canonical(recomputed_methods),
                "sealed method summary differs from decisions")
        require(frozen.canonical(read(day_folder / "cell_summaries.json")) == frozen.canonical(day_summaries),
                "sealed cell summary differs from decisions")
        all_summaries.extend(day_summaries)
    require(frozen.canonical(run["summaries"]) == frozen.canonical(all_summaries), "run summaries differ")
    require(run["decision_rows"] == sum(s["transactions"] for s in all_summaries), "run decision count differs")
    result.update(summaries=all_summaries, closed_utc=utc(run["completed_utc"]), source_audit=manifest["source_audit"])
    return result


def load_study(path, expected_sha256):
    study = pinned(path, expected_sha256)
    require(study["schema_version"] == "article2_phase16_decision_study_seal_v1"
            and study["status"] == "BOTH_CASE_DECISION_STAGES_CLOSED", "both decision stages must be sealed")
    require(study["reference_join_code_sha256"] == frozen.file_digest(__file__),
            "join implementation differs from pre-reference study seal")
    require([x["case_id"] for x in study["cases"]] == list(CASES), "both fixed cases required in order")
    cases = [load_run(entry, Path(path).parent) for entry in study["cases"]]
    require(utc(study["sealed_utc"]) >= max(case["closed_utc"] for case in cases), "study seal predates closed decisions")
    return study, cases


def load_inventory(path, expected_sha256, study, study_sha256, runs):
    inventory = pinned(path, expected_sha256)
    base = Path(path).parent
    require(inventory["schema_version"] == "article2_phase16_reference_inventory_v1"
            and inventory["status"] == "SEALED_AFTER_DECISIONS_INDEPENDENTLY_ADJUDICATED"
            and inventory["decision_study_sha256"] == study_sha256, "reference inventory stage binding differs")
    require(utc(inventory["reference_acquisition_started_utc"]) >= utc(study["sealed_utc"])
            and utc(inventory["sealed_utc"]) >= utc(inventory["reference_acquisition_started_utc"]),
            "reference acquisition must follow both sealed decisions")
    nonempty(inventory["prepared_by"], "reference preparer")
    review = read(binding(inventory["independent_review"], base))
    require(review["schema_version"] == "article2_phase16_reference_review_v1"
            and review["status"] == "APPROVED_FOR_EXACT_REFERENCE_JOIN"
            and review["decision_study_sha256"] == study_sha256
            and review["reference_cases_sha256"] == frozen.digest(inventory["cases"]), "independent review seal differs")
    nonempty(review["reviewer"], "independent reviewer")
    require(review["reviewer"] != inventory["prepared_by"], "separate independent reviewer required")
    require(utc(review["reviewed_utc"]) >= utc(inventory["reference_acquisition_started_utc"])
            and utc(inventory["sealed_utc"]) >= utc(review["reviewed_utc"]), "reference review ordering differs")
    for field in ("primary_roles_checked", "identity_status_window_checked", "source_coverage_checked", "inventory_completeness_checked"):
        require(review[field] is True, "independent review incomplete: " + field)
    require([x["case_id"] for x in inventory["cases"]] == list(CASES), "reference inventory case set differs")
    for case, run in zip(inventory["cases"], runs):
        status = case["execution_inventory_status"]
        require(status in INVENTORY_STATUSES, "unknown execution inventory status")
        nonempty(case["completeness_rationale"], "inventory completeness rationale")
        closure = case["completeness_evidence"]
        require(type(closure) is list, "completeness evidence list required")
        for evidence in closure:
            binding(evidence, base)
        if status == "COMPLETE_WITH_POSITIVE_CLOSURE_EVIDENCE":
            require(bool(closure), "complete inventory requires positive closure evidence")
        seen, positives = set(), 0
        for ref in case["references"]:
            key = ref["chain_id"], ref["transaction_hash"]
            require(type(ref["chain_id"]) is int and ref["chain_id"] == 1
                    and type(ref["transaction_hash"]) is str and frozen.HEX32.fullmatch(ref["transaction_hash"]),
                    "invalid canonical candidate identity")
            require(key not in seen, "duplicate reference identity")
            seen.add(key)
            require(ref["adjudication_status"] in ADJUDICATIONS, "unknown reference adjudication")
            nonempty(ref["reported_role"], "reported role")
            nonempty(ref["reviewer_rationale"], "reference rationale")
            require(type(ref["primary_source_locations_and_hashes"]) is list, "primary source locations list required")
            for source in ref["primary_source_locations_and_hashes"]:
                binding(source["artifact"], base)
                nonempty(source["url"], "primary source URL")
                nonempty(source["location"], "primary source location")
            audit_path = binding(ref["source_coverage_audit_binding"], base)
            audit = read(audit_path)
            require(audit["schema_version"] == "article2_phase16_reference_source_audit_v1"
                    and audit["case_id"] == case["case_id"]
                    and (audit["chain_id"], audit["transaction_hash"]) == key, "reference audit scope differs")
            require(audit["identity_status"] in ("VERIFIED", "UNAVAILABLE")
                    and audit["success_status"] == ref["success_status_or_unavailable"]
                    and audit["success_status"] in ("SUCCESS", "FAILED", "UNAVAILABLE")
                    and audit["core_selection_status"] in ("SELECTED", "OBSERVED_NO_CORE_EMITTER", "UNAVAILABLE"),
                    "reference audit statuses differ")
            require(type(audit["full_core_scan_or_terminal_logs_complete"]) is bool, "coverage boolean required")
            require(audit["evidence_tier"] in ("ENUMERATED_SOURCE_ARCHIVE", "BLOCKSCOUT_INDEXER", "UNAVAILABLE"),
                    "unsupported reference evidence tier")
            nonempty(audit["rationale"], "source audit rationale")
            for evidence in audit["identity_evidence"] + audit["selection_evidence"]:
                binding(evidence, audit_path.parent)
            tx = ref["actual_identity_or_unavailable"]
            if tx is not None:
                require(identity(tx) == key and audit["identity_status"] == "VERIFIED"
                        and bool(audit["identity_evidence"]), "actual identity lacks verified evidence")
                in_window = frozen.day_start(run["config"]["window"]["start_date_utc"]) <= tx["event_time_ns"] < frozen.day_start(run["config"]["window"]["end_date_utc_exclusive"])
                require(type(ref["in_fixed_window"]) is bool and ref["in_fixed_window"] == in_window,
                        "reference date/window mismatch")
            else:
                require(audit["identity_status"] == "UNAVAILABLE" and ref["in_fixed_window"] is None,
                        "unavailable identity cannot supply verified date")
            if ref["adjudication_status"] == "VERIFIED_APPLICABLE_EXECUTION":
                require(tx is not None and ref["in_fixed_window"] is True
                        and ref["success_status_or_unavailable"] == "SUCCESS"
                        and ref["reported_role"] == "SUCCESSFUL_UNAUTHORIZED_EXECUTION"
                        and bool(ref["primary_source_locations_and_hashes"]), "positive reference not independently established")
                positives += 1
            if ref["adjudication_status"] == "VERIFIED_OUTSIDE_WINDOW":
                require(tx is not None and ref["in_fixed_window"] is False, "outside-window disposition differs")
            selected = run["observations"].get(key)
            if selected is not None:
                if tx is not None:
                    require(tx == selected["transaction"], "selected reference actual identity mismatch")
                require(audit["core_selection_status"] != "OBSERVED_NO_CORE_EMITTER", "no-core contradicts selected record")
            if audit["core_selection_status"] == "SELECTED":
                require(selected is not None and type(audit["core_log_count"]) is int
                        and audit["core_log_count"] == selected["archived_core_log_count"]
                        and bool(audit["selection_evidence"]), "selected reference proof missing")
            elif audit["core_selection_status"] == "OBSERVED_NO_CORE_EMITTER":
                require(tx is not None and selected is None and type(audit["core_log_count"]) is int
                        and audit["core_log_count"] == 0 and audit["full_core_scan_or_terminal_logs_complete"] is True
                        and bool(audit["selection_evidence"]), "no-core absence requires complete scan or terminal log evidence")
            else:
                require(audit["core_log_count"] is None, "unavailable core coverage cannot become zero")
            ref["_audit"] = audit
        if status == "NO_VERIFIED_EXECUTION_UNDER_CAP":
            require(positives == 0, "no-verified status contradicts positives")
        if status == "COMPLETE_WITH_POSITIVE_CLOSURE_EVIDENCE":
            require(positives > 0 and all(r["adjudication_status"] not in ("UNRESOLVED", "UNVERIFIED_DUE_TO_CAP") for r in case["references"]),
                    "complete realized inventory cannot be empty or unresolved")
    return inventory


def terminal(run, ref, cell):
    method = cell[0]
    key = ref["chain_id"], ref["transaction_hash"]
    audit = ref["_audit"]
    if run["status"] != "COMPLETE":
        return CATEGORIES[0], None
    # A verified selected input already includes complete bundle/status/source
    # evidence. An unavailable extra reference audit does not erase that evidence.
    if audit["core_selection_status"] == "UNAVAILABLE" and key not in run["observations"]:
        return CATEGORIES[0], None
    if audit["core_selection_status"] == "OBSERVED_NO_CORE_EMITTER":
        return CATEGORIES[1], None
    # Missing selected decisions are invalid sealed input, never a measured miss.
    require(key in run["observations"] and (method, key) in run["methods"]
            and (cell, key) in run["decisions"], "selected reference decision unavailable")
    score, admission = run["methods"][(method, key)], run["decisions"][(cell, key)]
    if method != frozen.METHODS[0]:
        if score["positive_token_count"] == 0:
            return CATEGORIES[2], admission["suppression_reason"]
        if score["eligible_token_count"] == 0:
            return CATEGORIES[3], admission["suppression_reason"]
    if not score["raw_trigger"]:
        return CATEGORIES[4], admission["suppression_reason"]
    if not score["group_candidate"]:
        return CATEGORIES[5], admission["suppression_reason"]
    return (CATEGORIES[7] if admission["notification_emitted"] else CATEGORIES[6]), admission["suppression_reason"]


def fraction(numerator, denominator):
    return {"numerator": numerator, "denominator": denominator,
            "value": numerator / denominator if denominator else None}


def join_case(run, reference):
    positives = [r for r in reference["references"] if r["adjudication_status"] == "VERIFIED_APPLICABLE_EXECUTION"]
    pkeys = {(r["chain_id"], r["transaction_hash"]) for r in positives}
    output, rows = [], []
    for method in run["config"]["methods"]:
        for policy in run["config"]["policies"]:
            for budget in run["config"]["budgets"]:
                cell = method, policy, budget
                counts = Counter({category: 0 for category in CATEGORIES})
                for ref in positives:
                    category, reason = terminal(run, ref, cell)
                    counts[category] += 1
                    rows.append({"case_id": run["case_id"], "method": method, "policy": policy, "daily_budget": budget,
                                 "chain_id": ref["chain_id"], "transaction_hash": ref["transaction_hash"],
                                 "category": category, "original_suppression_reason": reason})
                n, u, total = counts[CATEGORIES[-1]], counts[CATEGORIES[0]], len(positives)
                complete_inventory = reference["execution_inventory_status"] == "COMPLETE_WITH_POSITIVE_CLOSURE_EVIDENCE"
                if n:
                    incident = "HIT"
                elif run["status"] != "COMPLETE":
                    incident = "UNAVAILABLE"
                elif complete_inventory and total and not u:
                    incident = "VERIFIED_COMPLETE_MISS"
                else:
                    incident = "INDETERMINATE_INCIDENT_COVERAGE"
                load = []
                if run["status"] == "COMPLETE":
                    for summary in run["summaries"]:
                        if (summary["method"], summary["policy"], summary["daily_budget"]) == cell:
                            known = sum((1, h) in pkeys for h in summary["notification_transaction_hashes"])
                            load.append({"day_utc": summary["day_utc"], "offered_daily_cap": budget,
                                         "notifications": summary["notifications"], "unused_daily_slots": summary["unused_daily_slots"],
                                         "verified_reference_notifications": known,
                                         "unknown_nonreference_notifications": summary["notifications"] - known,
                                         "suppression_counts": summary["suppression_counts"]})
                    notifications = sum(x["notifications"] for x in load)
                    known_notifications = sum(x["verified_reference_notifications"] for x in load)
                else:
                    load = [{"day_utc": day, "offered_daily_cap": budget, "notifications": None,
                             "unused_daily_slots": None, "verified_reference_notifications": None,
                             "unknown_nonreference_notifications": None, "suppression_counts": None}
                            for day in driver.expected_days(run["config"])]
                    notifications = known_notifications = None
                observed = total - u
                selected = observed - counts[CATEGORIES[1]]
                semantic = method != frozen.METHODS[0]
                positive = selected - counts[CATEGORIES[2]] if semantic else None
                eligible = positive - counts[CATEGORIES[3]] if semantic else None
                output.append({"case_id": run["case_id"], "method": method, "policy": policy, "daily_budget": budget,
                    "comparison_role": "PRIMARY_B5_ALL_POLICIES" if budget == 5 and method != "outflow_rank_1_10" else "PREDECLARED_SENSITIVITY",
                    "execution_inventory_status": reference["execution_inventory_status"],
                    "coverage_scope": "COMPLETE_INCIDENT_EXECUTION_INVENTORY" if complete_inventory else "KNOWN_SUBSET_ONLY",
                    "verified_applicable_executions": total, "exact_notified": n, "known_unnotified": total - n - u, "unknown": u,
                    "point_coverage": fraction(n, total) if total and not u else None,
                    "known_set_lower_bound": fraction(n, total), "known_set_upper_bound": fraction(n + u, total),
                    "incident_status": incident, "terminal_categories": dict(counts),
                    "funnel": {"verified_references": total, "source_evidence_available": observed, "selected": selected,
                               "positive_core_outflow_semantic_only": positive, "history_eligible_semantic_only": eligible,
                               "raw_trigger": sum(counts[CATEGORIES[i]] for i in (5, 6, 7)),
                               "group_candidate": counts[CATEGORIES[6]] + n, "emitted_notification": n},
                    "load": {"days": 30, "offered_slots": 30 * budget, "notifications": notifications,
                             "verified_reference_notifications": known_notifications,
                             "unknown_nonreference_notifications": notifications - known_notifications if notifications is not None else None,
                             "daily": load}})
    return {"case_id": run["case_id"], "run_status": run["status"],
            "reference_dispositions": dict(sorted(Counter(r["adjudication_status"] for r in reference["references"]).items())),
            "candidate_count": len(reference["references"]), "cells": output}, rows


def execute(study_path, study_sha256, inventory_path, inventory_sha256, output):
    study, runs = load_study(study_path, study_sha256)
    inventory = load_inventory(inventory_path, inventory_sha256, study, study_sha256, runs)
    cases, references, candidates = [], [], []
    for run, ref in zip(runs, inventory["cases"]):
        case, rows = join_case(run, ref)
        cases.append(case)
        references.extend(rows)
        candidates.extend({"case_id": ref["case_id"], "execution_inventory_status": ref["execution_inventory_status"],
                           **{k: r[k] for k in ("chain_id", "transaction_hash", "reported_role",
                              "actual_identity_or_unavailable", "success_status_or_unavailable", "in_fixed_window",
                              "adjudication_status", "reviewer_rationale", "source_coverage_audit_binding")},
                           "source_identity_status": r["_audit"]["identity_status"],
                           "source_core_selection_status": r["_audit"]["core_selection_status"]}
                          for r in ref["references"])
    across = []
    for pair in zip(*(case["cells"] for case in cases)):
        statuses = [cell["incident_status"] for cell in pair]
        hits = statuses.count("HIT")
        unknown = sum(s not in ("HIT", "VERIFIED_COMPLETE_MISS") for s in statuses)
        across.append({**{k: pair[0][k] for k in ("method", "policy", "daily_budget")},
                       "intended_incidents": 2, "incident_statuses": dict(zip(CASES, statuses)),
                       "point_incident_coverage": fraction(hits, 2) if not unknown else None,
                       "incident_coverage_lower_bound": fraction(hits, 2),
                       "incident_coverage_upper_bound": fraction(hits + unknown, 2)})
    # All scientific validation completes before any output becomes available.
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    result = {"schema_version": "article2_phase16_exact_reference_join_v1", "status": "COMPLETE",
              "created_utc": datetime.now(timezone.utc).isoformat(),
              "decision_study_sha256": study_sha256, "reference_inventory_sha256": inventory_sha256,
              "join_code_sha256": frozen.file_digest(__file__), "cases": cases, "across_cases": across,
              "interpretation": "Source-limited two-incident cohort. Exact chain/hash execution notification attribution; no causal detection, prevention, saved loss, precision or false-positive-rate inference. Nonreference notifications are UNKNOWN. Missing evidence is not zero. Hash checks bind audit assertions; they do not independently establish source or primary-report truth."}
    frozen.write_json(output / "coverage.json", result)
    frozen.write_jsonl_gzip(output / "reference_funnel.jsonl.gz", references)
    frozen.write_jsonl_gzip(output / "candidate_adjudications.jsonl.gz", candidates)
    frozen.write_json(output / "join_receipt.json", {"schema_version": "article2_phase16_join_receipt_v1", "status": "COMPLETE",
        "decision_study_sha256": study_sha256, "reference_inventory_sha256": inventory_sha256,
        "join_code_sha256": result["join_code_sha256"], "artifacts": [
            {"path": name, "sha256": frozen.file_digest(output / name), "bytes": (output / name).stat().st_size}
            for name in ("coverage.json", "reference_funnel.jsonl.gz", "candidate_adjudications.jsonl.gz")]})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study-manifest", type=Path, required=True)
    parser.add_argument("--expected-study-sha256", required=True)
    parser.add_argument("--reference-inventory", type=Path, required=True)
    parser.add_argument("--expected-reference-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = execute(args.study_manifest, args.expected_study_sha256,
                     args.reference_inventory, args.expected_reference_sha256, args.output)
    print(f"COMPLETE: {len(result['cases'])} cases, 54 method/policy/budget aggregates; no acquisition or replay performed")


if __name__ == "__main__":
    main()
