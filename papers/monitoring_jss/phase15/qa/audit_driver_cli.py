"""Independent synthetic CLI smoke check; no acquired chain rows or old suites."""
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

PAPER = Path(__file__).resolve().parents[2]
DRIVER = PAPER / "phase15/driver/fixed_address_replay.py"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def put(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    return sha(path)


def run():
    old = json.loads((PAPER / "semantic_flow_study_config.json").read_text())
    keys = ("methods", "semantic", "primary_semantic_method", "sensitivity_method",
            "count_baseline", "grouping_ns", "policies", "budgets", "primary_budget")
    deps = {name: sha(PAPER / name) for name in
            ("semantic_flow_replay.py", "semantic_flow_monitor.py", "transfer_observation.py",
             "semantic_flow_study_config.json")}
    with tempfile.TemporaryDirectory(prefix="phase15-independent-cli-") as folder:
        p = Path(folder)
        config = {"schema_version": "fixed_address_replay_config_v1", "case_id": "synthetic-review-only",
                  "chain_id": 1, "population_addresses": ["0x" + "bc" * 20],
                  "window": {"execution_date_utc": "2022-03-20", "start_date_utc": "2022-02-19",
                             "end_date_utc_exclusive": "2022-03-21"},
                  "state_initialization": "independent_utc_day_reset",
                  "source_scope": "aws_public_blockchain_parquet_transaction_subset",
                  "source_tier": "enumerated_daily_partition_and_transaction_metadata_checked",
                  **{key: old[key] for key in keys}}
        cfg = put(p / "config.json", config)
        days = [(date(2022, 2, 19) + timedelta(days=i)).isoformat() for i in range(30)]
        selected = put(p / "selection.json", {
            "schema_version": "fixed_address_transaction_selection_v1", "status": "SEALED_BEFORE_SCORING",
            "config_sha256": cfg, "rule": "at_least_one_core_emitter_log_no_topic_filter",
            "days": [{"day_utc": day, "transactions": []} for day in days]})
        coverage = [{"day_utc": day, "status": "COVERED", "selected_transactions": 0, "core_log_count": 0,
                     **{key: "a" * 64 for key in ("partition_manifest_sha256", "header_chain_sha256",
                                                  "address_scan_manifest_sha256")},
                     **{key: True for key in ("all_parts_enumerated", "all_address_row_groups_scanned",
                                             "complete_headers_checked", "all_selected_log_bundles_checked",
                                             "all_selected_statuses_checked")}} for day in days]
        audit = put(p / "audit.json", {"schema_version": "fixed_address_source_audit_v1", "status": "PASS",
            "config_sha256": cfg, "selection_manifest_sha256": selected, "tier": config["source_tier"],
            "cross_day_header_links_checked": True, "endpoint_anchors_checked": True, "days": coverage})
        observed_days = []
        for day in days:
            f = p / (day + ".jsonl")
            f.write_bytes(b"")
            observed_days.append({"day_utc": day, "coverage_status": "COVERED",
                "observation_file": {"path": f.name, "sha256": sha(f)}, "bytes": 0,
                "transaction_count": 0, "core_log_count": 0, "observation_sha256": []})
        manifest = put(p / "manifest.json", {"schema_version": "fixed_address_observation_manifest_v1",
            "status": "COMPLETE", "config_sha256": cfg,
            **{key: config[key] for key in ("case_id", "chain_id", "population_addresses", "source_scope", "source_tier")},
            "source_audit": {"path": "audit.json", "sha256": audit},
            "selection": {"path": "selection.json", "sha256": selected}, "days": observed_days})
        gates = {}
        for key in ("frame_dispositions", "cohort_selection", "core_nomination", "source_plan",
                    "label_join_protocol", "denominators"):
            path = p / (key + ".json")
            gates[key] = {"path": path.name, "sha256": put(path, {"kind": "SYNTHETIC_AUDIT_ONLY", "gate": key})}
        acceptance = {"schema_version": "fixed_address_measurement_acceptance_v1",
            "status": "ACCEPTED_FOR_DECLARED_FIXED_ADDRESS_MEASUREMENT",
            "accepted_utc": datetime.now(timezone.utc).isoformat(),
            "accepted_before_affected_payload": True, "all_frame_dispositions_completed": True,
            "config_sha256": cfg, "driver_sha256": sha(DRIVER), "dependency_sha256": deps,
            "gate_bindings": gates}
        accepted = put(p / "acceptance.json", acceptance)
        command = [sys.executable, str(DRIVER), "--config", str(p / "config.json"),
            "--measurement-acceptance", str(p / "acceptance.json"), "--expected-acceptance-sha256", accepted,
            "--input-manifest", str(p / "manifest.json"), "--expected-input-manifest-sha256", manifest]
        good = subprocess.run(command + ["--output", str(p / "accepted")], capture_output=True, text=True)
        assert good.returncode == 0, good.stderr
        result = json.loads((p / "accepted/run_manifest.json").read_text())
        assert result["status"] == "COMPLETE" and result["cells"] == 810 and result["days"] == 30
        assert result["decision_rows"] == 0 and result["label_join_performed"] is False
        assert len(result["summaries"]) == 810
        assert all(x["notifications"] == x["transactions"] == 0 for x in result["summaries"])
        for item in result["artifacts"]:
            path = p / "accepted" / item["path"]
            assert sha(path) == item["sha256"] and path.stat().st_size == item["bytes"]
        bad_command = command.copy()
        bad_command[bad_command.index("--expected-acceptance-sha256") + 1] = "0" * 64
        bad = subprocess.run(bad_command + ["--output", str(p / "rejected")], capture_output=True, text=True)
        assert bad.returncode != 0 and not (p / "rejected/run_manifest.json").exists()
        failure = json.loads((p / "rejected/failure.json").read_text())
        assert failure["accepted_result"] is False and "acceptance digest mismatch" in failure["error"]
        return {"schema_version": "phase15_independent_driver_cli_review_v1", "status": "PASS",
            "completed_utc": datetime.now(timezone.utc).isoformat(), "driver_sha256": sha(DRIVER),
            "auditor_sha256": sha(__file__), "independent_cli_cases": 2,
            "cases": ["Synthetic thirty-day covered empty window produces exactly810zero cells and valid output seals",
                      "Mismatched independent acceptance digest fails with preserved failure marker and no accepted run"],
            "accepted_output_artifacts_checked": len(result["artifacts"]),
            "producer_tests_rerun": 0, "old_suites_rerun": 0, "new_network_requests": 0,
            "real_case_inputs_scores_or_labels": 0,
            "limits": "Invented coverage attestations exercise CLI integrity only. This is not a real empty-chain observation, independent algorithm oracle or case admission. Bare load_inputs API requires callers to bind parsed config to the supplied config-file digest; the scientific CLI handles that binding."}


if __name__ == "__main__":
    report = run()
    output = Path(__file__).with_name("driver_cli_review.json")
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "cases": report["independent_cli_cases"],
                      "output_artifacts_checked": report["accepted_output_artifacts_checked"]}))
