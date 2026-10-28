"""New candidate adapter gate tests; row validation remains the exact frozen code.

The successful orchestration test uses a plainly labeled synthetic row-auditor
stub. It tests lineage and assembly, not source validity, and reads no dataset.
"""
import argparse
from datetime import date, timedelta
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch


def load():
    path = Path(__file__).with_name("audit_sources.py")
    spec = importlib.util.spec_from_file_location("candidate_continuation_source_audit", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def fixture(module, root, dependencies):
    collection = root / "collection"; collection.mkdir()
    objects, manifests, verified = [], [], []
    for day in module.days("2022-02-18", "2022-03-29"):
        kinds = ["blocks"] if day in ("2022-02-18", "2022-03-28") else ["blocks", "logs", "transactions"]
        for kind in kinds:
            key = day + "/" + kind
            source = {"key": key, "day_utc": day, "table": kind}
            objects.append(source); manifests.append({"source": source}); verified.append({"source_key": key})
    inv = root / "inventory.json"; inv_sha = module.write(inv, {"objects": objects})
    configs = []
    for short in ("lifi", "revest"):
        path = root / (short + ".json")
        path.write_bytes((module.PAPER / "phase16/protocol/configs" / (short + ".json")).read_bytes())
        configs.append({"path": path.name, "sha256": module.file_sha(path)})
    plan = {"schema_version": "article2_phase16_continuation_source_plan_v1",
            "original_plan_binding": {"path": "original.json", "sha256": "1" * 64},
            "source_union": {"path": inv.name, "sha256": inv_sha}, "case_configs": configs,
            "pyarrow_version": "26.0.0", "numpy_version": "2.3.5", "study_start": "2022-02-19",
            "study_end_exclusive": "2022-03-28", "accepted_header_anchors": []}
    plan_path = root / "newplan.json"; plan_sha = module.write(plan_path, plan)
    parent = root / "parent"; parent.mkdir()
    seal_path = root / "a1seal.json"
    seal_sha = module.write(seal_path, {"parent_root": str(parent), "completed_days": [], "partial_core_selection_seals": []})
    amendment_path = root / "amendment.json"
    amendment_sha = module.write(amendment_path, {"first_attempt_seal": {"path": str(seal_path), "sha256": seal_sha}})
    comparison_sha = module.write(collection / "prior_completed_day_comparisons.json", {
        "status": "PASS_EXACT_REPREPARATION_OF_ALL_ORIGINAL_COMPLETED_DAYS", "days": [],
        "completed_day_count": 0, "partial_core_selection_count": 0, "detector_scores_compared": False})
    cfgs = [module.read_json(root / bind["path"]) for bind in configs]
    prep_records, prepared = [], {}
    for day in module.days(plan["study_start"], plan["study_end_exclusive"]):
        folder = collection / "days" / day; folder.mkdir(parents=True)
        core_sha = module.write(folder / "core_selection.json", {"day_utc": day, "cases": {}, "synthetic_core_seal": True})
        prep = {"day_utc": day, "cases": {cfg["case_id"]: {"selected_transactions": []}
            for cfg in cfgs if day in module.frozen_driver.expected_days(cfg)},
            "core_selection_file_sha256": core_sha,
            **{key: "a" * 64 for key in module.frozen_driver.COVERAGE_HASHES}}
        path = folder / "prepared.json"; prep_records.append({"path": str(path.relative_to(collection)), "sha256": module.write(path, prep)})
        prepared[day] = prep
    selections = {}
    for cfg, binding in zip(cfgs, configs):
        selection = {"schema_version": "fixed_address_transaction_selection_v1", "status": "SEALED_BEFORE_SCORING",
            "config_sha256": binding["sha256"], "rule": "at_least_one_core_emitter_log_no_topic_filter",
            "days": [{"day_utc": day, "transactions": []} for day in module.frozen_driver.expected_days(cfg)]}
        path = collection / (cfg["case_id"] + "_selection.json")
        selections[cfg["case_id"]] = {"path": path.name, "sha256": module.write(path, selection)}
    previous, comparisons = [], []
    for index, day in enumerate(list(prepared)[:2]):
        old_folder = parent / "days" / day; old_folder.mkdir(parents=True)
        new_folder = collection / "days" / day
        (old_folder / "core_selection.json").write_bytes((new_folder / "core_selection.json").read_bytes())
        item = {"day_utc": day, "core_selection": {"path": f"days/{day}/core_selection.json",
                "sha256": module.file_sha(old_folder / "core_selection.json")}}
        if index == 0:
            (old_folder / "prepared.json").write_bytes((new_folder / "prepared.json").read_bytes())
            item["prepared"] = {"path": f"days/{day}/prepared.json", "sha256": module.file_sha(old_folder / "prepared.json")}
        previous.append(item)
        comparisons.append({"day_utc": day, "original_prepared_sha256": item["prepared"]["sha256"] if index == 0 else None,
            "new_prepared_sha256": module.file_sha(new_folder / "prepared.json"),
            "original_core_selection_sha256": item["core_selection"]["sha256"],
            "new_core_selection_sha256": module.file_sha(new_folder / "core_selection.json"),
            "canonical_cases_sha256": module.value_sha(prepared[day]["cases"]), "exact_core_selection_match": True,
            "exact_cases_and_payload_match": True if index == 0 else None,
            "comparison_scope": "selection_and_completed_payload" if index == 0 else "selection_only_for_incomplete_day",
            "source_sidecars_expected_to_reflect_new_transport_lineage": True})
    seal_sha = module.write(seal_path, {"parent_root": str(parent), "completed_days": previous[:1], "partial_core_selection_seals": previous[1:]})
    amendment_sha = module.write(amendment_path, {"first_attempt_seal": {"path": str(seal_path), "sha256": seal_sha}})
    comparison_sha = module.write(collection / "prior_completed_day_comparisons.json", {
        "status": "PASS_EXACT_REPREPARATION_OF_ALL_ORIGINAL_COMPLETED_DAYS", "days": comparisons,
        "completed_day_count": 1, "partial_core_selection_count": 1, "detector_scores_compared": False})
    result = {"schema_version": "phase16_continuation_collection_result_v1", "continuation_number": 1,
        "continuation_amendment_sha256": amendment_sha, "original_plan_binding": plan["original_plan_binding"],
        "status": "COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT", "plan_sha256": plan_sha,
        "transfer_decoding_performed": False, "detector_scoring_performed": False, "labels_used": False,
        "prepared_days": prep_records, "selection_manifests": selections,
        "prior_completed_day_comparisons_sha256": comparison_sha}
    result_sha = module.write(collection / "collection_result.json", result)
    manifest_sha = module.write(collection / "transport_sources.json", {"sources": manifests})
    transport = {"status": "PASS_CONTINUATION_TRANSPORT_ORIGINAL_BYTES", "plan_sha256": plan_sha,
        "continuation_amendment_sha256": amendment_sha, "original_source_plan_sha256": "1" * 64,
        "continuation_amendment_path": str(amendment_path), "first_attempt_seal_path": str(seal_path),
        "first_attempt_seal_sha256": seal_sha, "parent_root": str(parent),
        "collection_result_sha256": result_sha, "transport_sources_sha256": manifest_sha, "verified_sources": verified}
    transport_path = root / "transport.json"; transport_sha = module.write(transport_path, transport)
    args = SimpleNamespace(plan=plan_path, expected_plan_sha256=plan_sha, transport_audit=transport_path,
        expected_transport_audit_sha256=transport_sha, expected_amendment_sha256=amendment_sha,
        expected_original_plan_sha256="1" * 64, collection=collection, dependencies=Path(dependencies), output=root / "audit")
    return args, transport


def run(dependencies):
    module = load(); checks = []
    assert module.audit_day is module.original.audit_day and module.OfflineSource is module.original.OfflineSource
    checks.append("exact_original_row_validation_functions_reused_without_copy_or_mutation")
    with tempfile.TemporaryDirectory(prefix="continuation_source_adapter_synthetic_") as directory:
        root = Path(directory); args, transport = fixture(module, root, dependencies)
        def bad_transport(change, expected_error):
            altered = transport | change
            args.expected_transport_audit_sha256 = module.write(args.transport_audit, altered)
            try:
                module.run(args)
            except ValueError as exc:
                assert expected_error in str(exc), str(exc)
            else:
                raise AssertionError("invalid continuation lineage accepted")
        bad_transport({"status": "PASS_TRANSPORT_ORIGINAL_BYTES"}, "transport audit missing")
        checks.append("original_attempt_transport_status_cannot_masquerade_as_continuation_pass")
        bad_transport({"continuation_amendment_sha256": "3" * 64}, "amendment differs")
        checks.append("wrong_prospective_amendment_hash_rejected_before_source_decode")
        bad_transport({"original_source_plan_sha256": "4" * 64}, "original-plan lineage differs")
        checks.append("wrong_original_plan_lineage_rejected_before_source_decode")
        args.expected_transport_audit_sha256 = module.write(args.transport_audit, transport)
        calls = []
        def fake_headers(sources, day, pa, pc):
            number = (date.fromisoformat(day) - date(2022, 2, 18)).days + 1
            row = {"block_number": number, "block_hash": str(number), "parent_hash": str(number - 1),
                   "event_time_ns": module.midnight(day), "transaction_count": 0}
            return object(), [row]
        def fake_day(day, sources, headers, previous, following, configs, folder, pa, pc, np):
            calls.append(day)
            return module.read_json(folder / "prepared.json"), {"day_utc": day, "synthetic_row_stub": True, "cases": {}}
        with patch.object(module, "REPO", root), patch.object(module, "OfflineSource", lambda *a: object()), \
             patch.object(module, "header_rows", fake_headers), patch.object(module, "audit_day", fake_day), patch("builtins.print"):
            result = module.run(args)
        assert len(calls) == 37 and len(result["case_audits"]) == 2
        assert result["continuation_amendment_sha256"] == args.expected_amendment_sha256
        assert result["original_source_plan_sha256"] == "1" * 64
        assert result["original_row_auditor_sha256"] == module.ORIGINAL_ROW_AUDITOR_SHA256
        assert result["reviewer_sha256"] == module.file_sha(module.__file__)
        checks.append("synthetic_stub_orchestration_preserves37days_2case_audits_and_explicit_dual_plan_lineage")
        assert result["prior_exposure_comparison"]["completed_days"] == 1
        assert result["prior_exposure_comparison"]["partial_core_selection_days"] == 1
        checks.append("completed_payload_and_partial_day_core_selection_independently_compared")
        collection = module.read_json(args.collection / "collection_result.json")
        prepared = {item["path"].split("/")[1]: module.read_json(args.collection / item["path"])
                    for item in collection["prepared_days"]}
        prepared["2022-02-19"]["cases"]["lifi_20220320"]["selected_transactions"] = [{"invented": "changed"}]
        try:
            module.compare_prior_exposure(args.collection, collection, transport, args.expected_amendment_sha256, prepared)
        except ValueError as exc:
            assert "completed selected payload changed" in str(exc)
        else:
            raise AssertionError("changed prior complete payload accepted")
        checks.append("prior_completed_cases_change_rejected_independently_of_producer_pass_assertion")
        prepared["2022-02-19"] = module.read_json(args.collection / "days/2022-02-19/prepared.json")
        partial_path = args.collection / "days/2022-02-20/core_selection.json"
        prepared["2022-02-20"]["core_selection_file_sha256"] = module.write(partial_path,
            {"day_utc": "2022-02-20", "cases": {"changed": True}, "synthetic_core_seal": True})
        try:
            module.compare_prior_exposure(args.collection, collection, transport, args.expected_amendment_sha256, prepared)
        except ValueError as exc:
            assert "exposed core selection changed" in str(exc)
        else:
            raise AssertionError("changed prior partial selection accepted")
        checks.append("prior_partial_day_core_selection_change_rejected_without_prepared_parent")
    return {"status": "PASS_CANDIDATE_ADAPTER_SYNTHETIC_ONLY", "checks": checks, "checks_passed": len(checks),
        "adapter_sha256": module.file_sha(module.__file__), "test_sha256": module.file_sha(__file__),
        "real_source_or_capture_rows_read": 0, "network_requests": 0, "original_bound_files_changed": False,
        "actual_continuation_executed": False, "success_fixture_uses_explicit_row_validation_stub": True}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dependencies", required=True); p.add_argument("--report", type=Path, required=True)
    args = p.parse_args(); report = run(args.dependencies); args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "checks_passed": report["checks_passed"]}))
