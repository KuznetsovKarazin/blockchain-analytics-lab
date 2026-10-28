"""Candidate-only explicit storage-recovery source-audit adapter.

The exact original independent row-validation functions are reused unchanged.
This adapter accepts the separately authenticated storage-recovery transport status
and binds the actual new execution plan and amendment; it never relabels the
original attempt as passed. Case audits keep the frozen driver's schema.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import date, timedelta, datetime, timezone
from pathlib import Path
import argparse
import hashlib
import json
import sys

PAPER = Path(__file__).resolve().parents[2]
REPO = PAPER.parents[1]
ORIGINAL_ROW_AUDITOR_SHA256 = "385bff732afac356bf890193153b08d3751b5a3fbfd4788dab500176a0a03a62"
_original_path = PAPER / "phase16/qa/audit_prepared_sources.py"
if hashlib.sha256(_original_path.read_bytes()).hexdigest() != ORIGINAL_ROW_AUDITOR_SHA256:
    raise ValueError("frozen original source auditor changed before import")
sys.path.insert(0, str(_original_path.parent))
import audit_prepared_sources as original
from audit_prepared_sources import (FROZEN, DAY_NS, require, file_sha, bound, read_json, write,
    canonical, value_sha, days, midnight, header_rows, link, audit_day,
    frozen_driver)


sys.path.insert(0, str(Path(__file__).resolve().parent))
from independent_compact_reader import IndependentCompactSource as OfflineSource
import independent_compact_reader


def compare_prior_exposure(collection_root, collection, transport, amendment_sha, prepared):
    """Independently compare all previously exposed membership/payload seals."""
    amendment = bound(transport["storage_recovery_amendment_path"], amendment_sha)
    seal = bound(transport["first_attempt_seal_path"], transport["first_attempt_seal_sha256"])
    require(amendment["first_attempt_seal"]["sha256"] == transport["first_attempt_seal_sha256"],
            "transport amendment/parent seal binding differs")
    parent = Path(seal["parent_root"]).resolve()
    require(parent == Path(transport["parent_root"]).resolve(), "transport parent root differs")
    report = bound(collection_root / "prior_completed_day_comparisons.json",
                   collection["prior_completed_day_comparisons_sha256"])
    complete, partial = seal["completed_days"], seal["partial_core_selection_seals"]
    require([x["day_utc"] for x in complete] == list(prepared)[:len(complete)], "A1 complete days not exact study prefix")
    require(len(partial) <= 1 and (not partial or len(complete) < len(prepared)
            and partial[0]["day_utc"] == list(prepared)[len(complete)]), "A1 partial selection not next study day")
    compared = []
    for item in [*complete, *partial]:
        day = item["day_utc"]
        core_binding = item["core_selection"]
        require(core_binding["path"] == f"days/{day}/core_selection.json", "A1 core seal path differs")
        old_core = bound(parent / core_binding["path"], core_binding["sha256"])
        new_folder = collection_root / "days" / day
        new_core = bound(new_folder / "core_selection.json", prepared[day]["core_selection_file_sha256"])
        require(canonical(old_core) == canonical(new_core), "A1 exposed core selection changed during storage recovery")
        is_complete = "prepared" in item
        if is_complete:
            require(item["prepared"]["path"] == f"days/{day}/prepared.json", "A1 prepared path differs")
            old = bound(parent / item["prepared"]["path"], item["prepared"]["sha256"])
            require(canonical(old["cases"]) == canonical(prepared[day]["cases"]), "A1 completed selected payload changed during storage recovery")
        compared.append({"day_utc": day, "original_prepared_sha256": item["prepared"]["sha256"] if is_complete else None,
            "new_prepared_sha256": file_sha(new_folder / "prepared.json"),
            "original_core_selection_sha256": core_binding["sha256"],
            "new_core_selection_sha256": file_sha(new_folder / "core_selection.json"),
            "canonical_cases_sha256": value_sha(prepared[day]["cases"]), "exact_core_selection_match": True,
            "exact_cases_and_payload_match": True if is_complete else None,
            "comparison_scope": "selection_and_completed_payload" if is_complete else "selection_only_for_incomplete_day",
            "source_sidecars_expected_to_reflect_new_transport_lineage": True})
    require(report == {"status": "PASS_EXACT_REPREPARATION_OF_ALL_ORIGINAL_COMPLETED_DAYS", "days": compared,
        "completed_day_count": len(complete), "partial_core_selection_count": len(partial), "detector_scores_compared": False},
        "producer A1 comparison differs from independent exact comparison")
    return {"status": "PASS_INDEPENDENT_PRIOR_EXPOSURE_COMPARISON", "completed_days": len(complete),
            "partial_core_selection_days": len(partial), "first_attempt_seal_sha256": transport["first_attempt_seal_sha256"],
            "comparison_report_sha256": collection["prior_completed_day_comparisons_sha256"]}


def run(args):
    require(file_sha(original.__file__) == ORIGINAL_ROW_AUDITOR_SHA256, "frozen original row auditor changed")
    for relative, expected in FROZEN.items():
        require(file_sha(PAPER / relative) == expected, "frozen reviewer dependency changed")
    require(not args.output.exists(), "fresh audit output directory required")
    start_sha = file_sha(__file__)
    reader_sha = file_sha(independent_compact_reader.__file__)
    plan = bound(args.plan, args.expected_plan_sha256)
    require(plan["schema_version"] == "article2_phase16_storage_recovery_source_plan_v1"
            and plan["original_plan_binding"]["sha256"] == args.expected_original_plan_sha256,
            "new execution-plan original lineage differs")
    execution = plan["storage_recovery_execution_bindings"]
    code = {Path(item["path"]).name: item for item in execution}
    require(len(code) == len(execution) == 6 and set(code) == {
        "protocol.py", "compact_collector.py", "pipeline.py", "independent_transport_audit.py",
        "independent_compact_reader.py", "audit_sources.py"}, "storage execution code population differs")
    for name in ("audit_sources.py", "independent_compact_reader.py", "independent_transport_audit.py"):
        path = Path(__file__).parent / name
        require((REPO / code[name]["path"]).resolve() == path.resolve()
                and file_sha(path) == code[name]["sha256"], "accepted reviewer code binding differs")
    transport = bound(args.transport_audit, args.expected_transport_audit_sha256)
    require(transport["status"] == "PASS_STORAGE_RECOVERY_TRANSPORT_ORIGINAL_BYTES" and transport["plan_sha256"] == args.expected_plan_sha256,
            "independent original-byte transport audit missing")
    require(transport["storage_recovery_amendment_sha256"] == args.expected_amendment_sha256,
            "storage-recovery transport amendment differs")
    require(transport["original_source_plan_sha256"] == args.expected_original_plan_sha256,
            "storage-recovery transport original-plan lineage differs")
    require(transport["auditor_sha256"] == code["independent_transport_audit.py"]["sha256"],
            "transport audit reviewer differs from prospective storage acceptance")
    collection = bound(args.collection / "collection_result.json", transport["collection_result_sha256"])
    require(collection["schema_version"] == "phase16_storage_recovery_collection_result_v1"
            and collection["storage_recovery_number"] == 1
            and collection["storage_recovery_amendment_sha256"] == args.expected_amendment_sha256
            and collection["original_plan_binding"] == plan["original_plan_binding"],
            "storage recovery collection lineage differs")
    require(collection["status"] == "COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT"
            and collection["plan_sha256"] == args.expected_plan_sha256 and collection["transfer_decoding_performed"] is False
            and collection["detector_scoring_performed"] is False and collection["labels_used"] is False, "collection not complete/unscored")
    manifests = bound(args.collection / "transport_sources.json", transport["transport_sources_sha256"])
    storage = bound(args.collection / "runtime_source_storage.json", transport["runtime_source_storage_sha256"])
    require(collection["runtime_source_storage_sha256"] == transport["runtime_source_storage_sha256"],
            "collection storage map binding differs")
    inventory = bound(REPO / plan["source_union"]["path"], plan["source_union"]["sha256"])
    sys.path.insert(0, str(args.dependencies.resolve()))
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.parquet as pq
    import numpy as np
    require(pa.__version__ == plan["pyarrow_version"] == "26.0.0" and Path(pa.__file__).resolve().is_relative_to(args.dependencies.resolve()), "wrong parser")
    require(np.__version__ == plan["numpy_version"] == "2.3.5", "wrong NumPy runtime")
    configs = {}
    for binding in plan["case_configs"]:
        cfg = bound(REPO / binding["path"], binding["sha256"])
        frozen_driver.validate_config(cfg)
        configs[cfg["case_id"]] = (cfg, binding["sha256"])
    verified = {x["source_key"]: x for x in transport["verified_sources"]}
    # transport_sources.json is an ordered list of final SourceReader manifests.
    if isinstance(manifests, dict):
        manifests = manifests["sources"]
    mm = {x["source"]["key"]: x for x in manifests}
    expected_keys = {x["key"] for x in inventory["objects"]}
    require(len(expected_keys) == len(mm) == len(verified) == len(storage) == 113
            and set(mm) == set(verified) == set(storage) == expected_keys,
            "transport audit/source population differs")
    sources = defaultdict(lambda: defaultdict(list))
    for source in inventory["objects"]:
        proof = verified[source["key"]]
        path = proof["descriptor_path"] if proof["storage_kind"] == "compact_descriptor" else proof["path"]
        require(storage[source["key"]] == {"storage_kind": proof["storage_kind"], "path": path},
                "runtime source storage differs from independently audited location")
        reader = OfflineSource(source, mm[source["key"]], verified[source["key"]], pa, pq)
        sources[source["day_utc"]][source["table"]].append(reader)
    timeline = {}
    for day in sorted(sources):
        timeline[day] = header_rows(sources[day]["blocks"], day, pa, pc)
    for left, right in zip(sorted(timeline), sorted(timeline)[1:]):
        require(midnight(right) - midnight(left) == DAY_NS, "missing calendar day")
        link(timeline[left][1][-1], timeline[right][1][0])
    for anchor in plan["accepted_header_anchors"]:
        found = [row for _, rows in timeline.values() for row in rows if row["block_number"] == anchor["block_number"]]
        require(len(found) == 1 and all(found[0][k] == v for k, v in anchor.items()), "retained independent anchor differs")
    args.output.mkdir(parents=True)
    prepared, summaries = {}, []
    for item in collection["prepared_days"]:
        path = args.collection / item["path"]
        value = bound(path, item["sha256"])
        day = value["day_utc"]
        prior = (date.fromisoformat(day) - timedelta(days=1)).isoformat()
        following = (date.fromisoformat(day) + timedelta(days=1)).isoformat()
        active = {k: cfg for k, (cfg, _) in configs.items() if day in frozen_driver.expected_days(cfg)}
        prep, summary = audit_day(day, sources[day], timeline[day][0], timeline[prior][1][-1], timeline[following][1][0],
                                  active, path.parent, pa, pc, np)
        prepared[day] = prep; summaries.append(summary)
        write(args.output / "progress.json", {"status": "AUDIT_IN_PROGRESS_NOT_PASS", "completed_days": summaries})
        print(json.dumps({"independently_audited_day": day, "cases": summary["cases"]}), flush=True)
    require(list(prepared) == days(plan["study_start"], plan["study_end_exclusive"]), "not exactly37 ordered study days")
    prior_exposure_comparison = compare_prior_exposure(args.collection, collection, transport,
                                                       args.expected_amendment_sha256, prepared)
    case_audits = {}
    for case, (config, config_sha) in configs.items():
        selection_bind = collection["selection_manifests"][case]
        selection = bound(args.collection / selection_bind["path"], selection_bind["sha256"])
        expected = {"schema_version": "fixed_address_transaction_selection_v1", "status": "SEALED_BEFORE_SCORING",
                    "config_sha256": config_sha, "rule": "at_least_one_core_emitter_log_no_topic_filter",
                    "days": [{"day_utc": d, "transactions": prepared[d]["cases"][case]["selected_transactions"]}
                             for d in frozen_driver.expected_days(config)]}
        require(selection == expected, "full-window selection differs")
        audit = {"schema_version": "fixed_address_source_audit_v1", "status": "PASS", "config_sha256": config_sha,
                 "selection_manifest_sha256": selection_bind["sha256"], "tier": config["source_tier"],
                 "cross_day_header_links_checked": True, "endpoint_anchors_checked": True, "days": []}
        for day in frozen_driver.expected_days(config):
            prep = prepared[day]; records = prep["cases"][case]["selected_transactions"]
            audit["days"].append({"day_utc": day, "status": "COVERED", "selected_transactions": len(records),
                "core_log_count": sum(x["archived_core_log_count"] for x in records),
                **{k: prep[k] for k in frozen_driver.COVERAGE_HASHES}, **{k: True for k in frozen_driver.COVERAGE_CHECKS}})
        path = args.output / (case + "_source_audit.json")
        case_audits[case] = {"path": str(path.resolve()), "sha256": write(path, audit)}
    require(file_sha(__file__) == start_sha and file_sha(args.transport_audit) == args.expected_transport_audit_sha256,
            "reviewer inputs changed during audit")
    result = {"schema_version": "phase16_independent_actual_source_review_v1", "status": "PASS_SOURCE_SELECTION_AND_RAW_BUNDLES",
              "completed_utc": datetime.now(timezone.utc).isoformat(), "reviewer_sha256": start_sha,
              "plan_sha256": args.expected_plan_sha256, "transport_audit_sha256": args.expected_transport_audit_sha256,
              "collection_result_sha256": transport["collection_result_sha256"], "case_audits": case_audits,
              "days": summaries, "source_objects": 113, "study_days": 37,
              "endpoint_tier": "Source-adjacent complete header boundaries for every case; additionally actual retained independent LiFi RPC header anchors. No independent Revest endpoint anchor inferred.",
              "limitations": ["No receipt-root authentication or proof of archive correctness against full canonical chain.",
                              "All identity/address/hash/status/header projections audited; nonselected topics/data not required or validated.",
                              "Fixed nominated component sets only; source audit does not adjudicate incident labels or detector effectiveness."],
              "network_requests": 0, "transfer_decoding_performed": False, "detector_scores_computed": 0}
    result.update(storage_recovery_amendment_sha256=args.expected_amendment_sha256,
                  original_source_plan_sha256=args.expected_original_plan_sha256,
                  original_row_auditor_sha256=ORIGINAL_ROW_AUDITOR_SHA256,
                  compact_reader_sha256=reader_sha,
                  prior_exposure_comparison=prior_exposure_comparison,
                  audit_scope="Final combined source bytes under one explicitly accepted storage recovery; original A1 ENOSPC closure remains recorded separately.")
    require(file_sha(original.__file__) == ORIGINAL_ROW_AUDITOR_SHA256 and file_sha(independent_compact_reader.__file__) == reader_sha, "frozen original row auditor or independent reader changed during audit")
    write(args.output / "source_review.json", result)
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("plan", "collection", "transport-audit", "dependencies", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--expected-plan-sha256", required=True)
    p.add_argument("--expected-transport-audit-sha256", required=True)
    p.add_argument("--expected-amendment-sha256", required=True)
    p.add_argument("--expected-original-plan-sha256", required=True)
    args = p.parse_args()
    result = run(args)
    print(json.dumps({"status": result["status"], "case_audits": result["case_audits"]}), flush=True)
