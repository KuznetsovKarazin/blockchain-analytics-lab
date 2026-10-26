"""Thirty-day, fixed-address Ethereum replay using the frozen Phase8 algorithms.

This controller validates externally audited inputs. It does not acquire data,
prove source completeness, nominate addresses, admit cases or read attack labels.
"""
from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sys

PAPER = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PAPER))
import semantic_flow_replay as frozen
from semantic_flow_monitor import validate_observation

DEPENDENCIES = {
    "semantic_flow_replay.py": "49597dfa39c6f1fa65be47d107bdf60696f8d26b82b13876bf1d587a593ac16a",
    "semantic_flow_monitor.py": "10ac4a7bc81b76c49be07ff8125136910cbacf2782708271d057b2094bfa60ad",
    "transfer_observation.py": "eb905fdbdc44033424066e4baebbbc1f6724bd68bd9e0573676f39e4908f429c",
    "semantic_flow_study_config.json": "4a3e038584158ba8b39b582291c18097f98a0fa67e70c46346c280b5cbb0cf3a",
}
METHOD_KEYS = ("methods", "semantic", "primary_semantic_method", "sensitivity_method",
               "count_baseline", "grouping_ns", "policies", "budgets", "primary_budget")
CONFIG_KEYS = {"schema_version", "case_id", "chain_id", "population_addresses", "window",
               "state_initialization", "source_scope", "source_tier", *METHOD_KEYS}
OBSERVATION_KEYS = {"schema_version", "status", "dataset_execution_status", "transaction",
                    "population_addresses", "counts", "archived_core_log_count",
                    "raw_amount_encoding", "token_flows", "evidence", "unavailable_fields"}
EVIDENCE_KEYS = {"tier", "source_kind", "source_audit_manifest_sha256", "selection_manifest_sha256",
                 "raw_receipt_acquired", "receipt_root_verified", "historical_deployed_abi_verified",
                 "token_erc20_compliance_verified", "observed_time", "full_chain_completeness_verified"}
UNAVAILABLE_FIELDS = ["actual_balance_change", "native_asset_flow", "token_decimals", "token_price",
                      "economic_loss", "historical_observed_time", "attack_label"]
TX_KEYS = {"chain_id", "block_number", "block_hash", "transaction_hash",
           "transaction_index", "event_time_ns"}
SELECTED_KEYS = TX_KEYS | {"archived_core_log_count", "archived_core_payload_sha256"}
COVERAGE_HASHES = ("partition_manifest_sha256", "header_chain_sha256", "address_scan_manifest_sha256")
COVERAGE_CHECKS = ("all_parts_enumerated", "all_address_row_groups_scanned",
                   "complete_headers_checked", "all_selected_log_bundles_checked",
                   "all_selected_statuses_checked")
GATE_NAMES = {"frame_dispositions", "cohort_selection", "core_nomination", "source_plan",
              "label_join_protocol", "denominators"}
SOURCE_SCOPE = frozen.SOURCE_SCOPE
EVIDENCE_TIER = frozen.EVIDENCE_TIER


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact_keys(value, names, name):
    require(type(value) is dict and set(value) == set(names), "invalid " + name + " fields")


def bound_file(binding, parent):
    """Paths are portable relative members of a retained input/gate directory."""
    exact_keys(binding, ("path", "sha256"), "file binding")
    require(type(binding["path"]) is str and bool(binding["path"]), "empty binding path")
    relative = Path(binding["path"])
    require(not relative.is_absolute() and ".." not in relative.parts, "binding path must stay relative")
    path = Path(parent) / relative
    require(frozen.file_digest(path) == frozen.sha(binding["sha256"], "bound file"), "bound file digest mismatch")
    return path


def check_dependencies():
    for name, expected in DEPENDENCIES.items():
        require(frozen.file_digest(PAPER / name) == expected, "frozen dependency changed: " + name)


def validate_config(config):
    check_dependencies()
    exact_keys(config, CONFIG_KEYS, "config")
    require(config["schema_version"] == "fixed_address_replay_config_v1", "unsupported config schema")
    require(type(config["case_id"]) is str and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,79}", config["case_id"]), "invalid case_id")
    require(type(config["chain_id"]) is int and config["chain_id"] == 1,
            "v1 supports Ethereum chain 1 only; frozen count/admission guards remain unchanged")
    addresses = config["population_addresses"]
    require(type(addresses) is list and bool(addresses), "nonempty fixed core required")
    require(all(type(a) is str and re.fullmatch(r"0x[0-9a-f]{40}", a)
                and a != "0x" + "0" * 40 for a in addresses), "invalid fixed core address")
    require(addresses == sorted(set(addresses)), "core addresses must be sorted and unique")
    original = frozen.strict_json((PAPER / "semantic_flow_study_config.json").read_bytes())
    for key in METHOD_KEYS:
        # Canonical JSON comparison also rejects bool/int and int/float substitutions.
        require(frozen.canonical(config[key]) == frozen.canonical(original[key]), "frozen method parameter differs: " + key)
    require(config["state_initialization"] == "independent_utc_day_reset", "daily reset is required")
    require(config["source_scope"] == SOURCE_SCOPE and config["source_tier"] == EVIDENCE_TIER,
            "unsupported source scope/tier")
    window = config["window"]
    exact_keys(window, ("execution_date_utc", "start_date_utc", "end_date_utc_exclusive"), "window")
    for value in window.values():
        frozen.day_start(value)
    incident = date.fromisoformat(window["execution_date_utc"])
    require(window["start_date_utc"] == (incident - timedelta(days=29)).isoformat()
            and window["end_date_utc_exclusive"] == (incident + timedelta(days=1)).isoformat(),
            "window must be [D-29,D+1), exactly 30 complete UTC days")
    return config


def expected_days(config):
    first = date.fromisoformat(config["window"]["start_date_utc"])
    return [(first + timedelta(days=n)).isoformat() for n in range(30)]


def validate_freeze(freeze_path, config_path, *, expected_freeze_sha256):
    """Verify an explicit root acceptance, not infer admission from valid inputs.

    The caller supplies the root receipt digest independently. These hashes bind
    the recorded scientific acceptance; they do not adjudicate its conclusions.
    """
    path = Path(freeze_path)
    require(frozen.file_digest(path) == frozen.sha(expected_freeze_sha256, "root acceptance"), "root acceptance digest mismatch")
    freeze = frozen.strict_json(path.read_bytes())
    exact_keys(freeze, ("schema_version", "status", "accepted_utc", "accepted_before_affected_payload",
                       "all_frame_dispositions_completed", "config_sha256", "driver_sha256",
                       "dependency_sha256", "gate_bindings"), "root acceptance")
    require(freeze["schema_version"] == "fixed_address_measurement_acceptance_v1"
            and freeze["status"] == "ACCEPTED_FOR_DECLARED_FIXED_ADDRESS_MEASUREMENT", "measurement is not explicitly accepted")
    require(freeze["accepted_before_affected_payload"] is True and freeze["all_frame_dispositions_completed"] is True,
            "prospective acceptance/all-frame disposition missing")
    accepted = datetime.fromisoformat(freeze["accepted_utc"].replace("Z", "+00:00"))
    require(accepted.utcoffset() == timedelta(0), "acceptance must have explicit UTC time")
    require(freeze["config_sha256"] == frozen.file_digest(config_path), "config changed after acceptance")
    require(freeze["driver_sha256"] == frozen.file_digest(__file__), "driver changed after acceptance")
    require(freeze["dependency_sha256"] == DEPENDENCIES, "dependency acceptance differs")
    check_dependencies()
    gates = freeze["gate_bindings"]
    exact_keys(gates, GATE_NAMES, "gate bindings")
    for binding in gates.values():
        bound_file(binding, path.parent)
    return freeze


def validate_day_sequence(items, days, name):
    require(type(items) is list and len(items) == len(days), "missing, repeated or extra " + name + " day")
    require([item.get("day_utc") for item in items] == days, "missing, repeated or unordered " + name + " day")


def load_inputs(config, manifest_path, *, expected_manifest_sha256, expected_config_sha256):
    """Validate the entire window before any score is computed.

    A source auditor must produce the coverage records from real acquisition
    evidence. This reader binds that audit and validates membership and arithmetic;
    it does not turn an asserted PASS or a digest into source completeness proof.
    """
    validate_config(config)
    path = Path(manifest_path)
    require(frozen.file_digest(path) == frozen.sha(expected_manifest_sha256, "input manifest"), "input manifest digest mismatch")
    manifest = frozen.strict_json(path.read_bytes())
    exact_keys(manifest, ("schema_version", "status", "case_id", "chain_id", "population_addresses",
                          "config_sha256", "source_scope", "source_tier", "source_audit", "selection", "days"), "input manifest")
    require(manifest["schema_version"] == "fixed_address_observation_manifest_v1" and manifest["status"] == "COMPLETE",
            "input collection unavailable or incomplete")
    require(manifest["config_sha256"] == frozen.sha(expected_config_sha256, "config digest"), "manifest config binding differs")
    for key in ("case_id", "chain_id", "population_addresses", "source_scope", "source_tier"):
        require(frozen.canonical(manifest[key]) == frozen.canonical(config[key]), "manifest scope differs: " + key)
    selection_path = bound_file(manifest["selection"], path.parent)
    audit_path = bound_file(manifest["source_audit"], path.parent)
    selection = frozen.strict_json(selection_path.read_bytes())
    audit = frozen.strict_json(audit_path.read_bytes())
    selection_digest = manifest["selection"]["sha256"]
    audit_digest = manifest["source_audit"]["sha256"]
    exact_keys(selection, ("schema_version", "status", "config_sha256", "rule", "days"), "selection")
    require(selection["schema_version"] == "fixed_address_transaction_selection_v1"
            and selection["status"] == "SEALED_BEFORE_SCORING"
            and selection["config_sha256"] == expected_config_sha256
            and selection["rule"] == "at_least_one_core_emitter_log_no_topic_filter", "selection contract differs")
    exact_keys(audit, ("schema_version", "status", "config_sha256", "selection_manifest_sha256", "tier",
                      "cross_day_header_links_checked", "endpoint_anchors_checked", "days"), "source audit")
    require(audit["schema_version"] == "fixed_address_source_audit_v1" and audit["status"] == "PASS"
            and audit["config_sha256"] == expected_config_sha256
            and audit["selection_manifest_sha256"] == selection_digest
            and audit["tier"] == EVIDENCE_TIER, "source audit does not bind accepted scope/selection")
    require(audit["cross_day_header_links_checked"] is True and audit["endpoint_anchors_checked"] is True,
            "window-wide header checks missing")
    days = expected_days(config)
    for items, name in ((manifest["days"], "input"), (selection["days"], "selection"), (audit["days"], "audit")):
        validate_day_sequence(items, days, name)
    result, previous_key, previous_time, previous_tx, seen = {}, None, None, None, set()
    blocks_by_hash = {}
    for day, item, chosen, coverage in zip(days, manifest["days"], selection["days"], audit["days"]):
        exact_keys(item, ("day_utc", "coverage_status", "observation_file", "bytes", "transaction_count",
                          "core_log_count", "observation_sha256"), "observation day")
        exact_keys(chosen, ("day_utc", "transactions"), "selection day")
        exact_keys(coverage, ("day_utc", "status", "selected_transactions", "core_log_count",
                              *COVERAGE_HASHES, *COVERAGE_CHECKS), "coverage day")
        require(item["coverage_status"] == "COVERED" and coverage["status"] == "COVERED",
                "unavailable/partial day cannot become zero")
        for key in COVERAGE_CHECKS:
            require(coverage[key] is True, "source coverage check missing: " + key)
        for key in COVERAGE_HASHES:
            frozen.sha(coverage[key], key)
        count = frozen.integer(item["transaction_count"], "day transaction count")
        core_sum_expected = frozen.integer(item["core_log_count"], "day core count")
        require(type(coverage["selected_transactions"]) is int and coverage["selected_transactions"] == count
                and type(coverage["core_log_count"]) is int and coverage["core_log_count"] == core_sum_expected,
                "audit day counts differ")
        selected, row_hashes = chosen["transactions"], item["observation_sha256"]
        require(type(selected) is list and len(selected) == count, "selection count differs")
        require(type(row_hashes) is list and len(row_hashes) == count, "observation anchor count differs")
        source = bound_file(item["observation_file"], path.parent)
        require(source.stat().st_size == frozen.integer(item["bytes"], "input bytes"), "input byte count differs")
        observations, core_sum = [], 0
        with source.open("rb") as handle:
            for raw in handle:
                require(raw.endswith(b"\n") and raw != b"\n", "partial/empty JSONL row")
                observation = frozen.strict_json(raw)
                require(frozen.canonical(observation) + b"\n" == raw, "noncanonical JSONL row")
                exact_keys(observation, OBSERVATION_KEYS, "observation")
                exact_keys(observation["evidence"], EVIDENCE_KEYS, "observation evidence")
                require(observation["unavailable_fields"] == UNAVAILABLE_FIELDS, "unsupported/unexpected observation fields")
                index = len(observations)
                require(index < count, "extra observation")
                expected_row = frozen.sha(row_hashes[index], "observation row")
                validate_observation(observation, expected_observation_sha256=expected_row,
                                     config=frozen.semantic_config(config, 20),
                                     source_audit_sha256=audit_digest, source_scope=SOURCE_SCOPE)
                require(observation["schema_version"] == "archive_transfer_observation_v1"
                        and observation["status"] == "observed_success", "unsupported observation source/status")
                require(observation["evidence"].get("source_kind") == SOURCE_SCOPE
                        and observation["evidence"]["selection_manifest_sha256"] == selection_digest,
                        "observation selection/source differs")
                member = selected[index]
                exact_keys(member, SELECTED_KEYS, "selected transaction")
                frozen.sha(member["archived_core_payload_sha256"], "selected core payload")
                tx = observation["transaction"]
                require(frozen.canonical(tx) == frozen.canonical({key: member[key] for key in TX_KEYS}),
                        "observation identity differs from selection")
                core_count = frozen.integer(member["archived_core_log_count"], "selected core count", 1)
                require(observation["archived_core_log_count"] == core_count, "selected core count differs")
                key, timestamp = frozen.transaction_identity(tx)
                start = frozen.day_start(day)
                require(start <= timestamp < start + frozen.DAY_NS, "observation outside declared UTC day")
                require(previous_key is None or key > previous_key, "global transaction order violation")
                require(previous_time is None or timestamp >= previous_time, "global timestamp decreases")
                if previous_tx and tx["block_number"] == previous_tx["block_number"]:
                    require(tx["block_hash"] == previous_tx["block_hash"] and timestamp == previous_time,
                            "conflicting block identity/time")
                require(tx["transaction_hash"] not in seen, "duplicate transaction across window")
                require(tx["block_hash"] not in blocks_by_hash or blocks_by_hash[tx["block_hash"]] == tx["block_number"],
                        "block hash reused at another height")
                blocks_by_hash[tx["block_hash"]] = tx["block_number"]
                seen.add(tx["transaction_hash"])
                previous_key, previous_time, previous_tx = key, timestamp, tx
                core_sum += core_count
                observations.append(observation)
        require(len(observations) == count and core_sum == core_sum_expected, "actual observation/core counts differ")
        # An empty file is valid only after all explicit coverage checks above.
        result[day] = observations
    return manifest, result


def replay_loaded(config, manifest, days):
    """Controller only: each call to frozen.replay_day creates fresh day state."""
    validate_config(config)
    require(list(days) == expected_days(config), "replay days differ from exact window")
    for day, observations in days.items():
        yield day, frozen.replay_day(config, day, observations,
                                    source_audit_sha256=manifest["source_audit"]["sha256"],
                                    source_scope=config["source_scope"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--measurement-acceptance", type=Path, required=True)
    parser.add_argument("--expected-acceptance-sha256", required=True)
    parser.add_argument("--input-manifest", type=Path, required=True)
    parser.add_argument("--expected-input-manifest-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    try:
        config = validate_config(frozen.strict_json(args.config.read_bytes()))
        config_digest = frozen.file_digest(args.config)
        freeze = validate_freeze(args.measurement_acceptance, args.config,
                                 expected_freeze_sha256=args.expected_acceptance_sha256)
        manifest, observations = load_inputs(config, args.input_manifest,
            expected_manifest_sha256=args.expected_input_manifest_sha256, expected_config_sha256=config_digest)
        summaries = []
        for day, run in replay_loaded(config, manifest, observations):
            folder = args.output / day
            folder.mkdir()
            for method, rows in run["methods"].items():
                frozen.write_jsonl_gzip(folder / (method + "__methods.jsonl.gz"), rows)
            for key, rows in run["decisions"].items():
                frozen.write_jsonl_gzip(folder / ("__".join(map(str, key)) + "__decisions.jsonl.gz"), rows)
            for key in ("method_summaries", "cell_summaries", "final_method_states", "final_policy_states"):
                frozen.write_json(folder / (key + ".json"), run[key])
            summaries.extend(run["cell_summaries"])
        validate_freeze(args.measurement_acceptance, args.config,
                        expected_freeze_sha256=args.expected_acceptance_sha256)
        require(frozen.file_digest(args.input_manifest) == args.expected_input_manifest_sha256, "input manifest changed during replay")
        artifacts = [{"path": str(p.relative_to(args.output)), "bytes": p.stat().st_size,
                      "sha256": frozen.file_digest(p)} for p in sorted(args.output.rglob("*")) if p.is_file()]
        result = {"schema_version": "fixed_address_replay_run_v1", "status": "COMPLETE",
                  "started_utc": started, "completed_utc": datetime.now(timezone.utc).isoformat(),
                  "case_id": config["case_id"], "chain_id": config["chain_id"], "window": config["window"],
                  "state_initialization": "independent_utc_day_reset", "days": 30, "cells": len(summaries),
                  "config_sha256": config_digest, "measurement_acceptance_sha256": args.expected_acceptance_sha256,
                  "input_manifest_sha256": args.expected_input_manifest_sha256,
                  "driver_sha256": freeze["driver_sha256"], "dependency_sha256": DEPENDENCIES,
                  "decision_rows": sum(x["transactions"] for x in summaries), "summaries": summaries,
                  "artifacts": artifacts, "labels_used": False, "label_join_performed": False,
                  "clock": "historical_event_time_ns_logical_simulation",
                  "scope": "Declared fixed-address Ethereum workload, externally audited enumerated-source tier. No independent case admission, receipt-root proof, label coverage or live-performance inference from this controller."}
        frozen.write_json(args.output / "run_manifest.json", result)
        print(json.dumps({"status": "COMPLETE", "cells": len(summaries), "decision_rows": result["decision_rows"]}))
    except Exception as error:
        frozen.write_json(args.output / "failure.json", {"status": "FAILED", "started_utc": started,
            "failed_utc": datetime.now(timezone.utc).isoformat(), "error_type": type(error).__name__,
            "error": str(error), "accepted_result": False, "labels_used": False})
        raise


if __name__ == "__main__":
    main()
