"""Candidate-only orchestration for one explicitly accepted operational continuation.

The original scientific preparation and assembly functions remain hash-bound and
unchanged. An immutable original attempt and a prospective continuation amendment
are mandatory. No automatic retries or implicit continuation authorization exist.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from datetime import date, timedelta
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

PAPER = Path(__file__).resolve().parents[2]
REPO = PAPER.parents[1]
ORIGINAL_PIPELINE_SHA256 = "56c086e4af2d65e863a4dc53a31bf24e79f1a2ccd3ab0c4915e19ff823f64f46"
ORIGINAL_COLLECTOR_SHA256 = "13e15e7b770ad40c2e8d286abceb8f7e380d946626b35d0186f43f0001be563f"


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def value_sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_sha(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            result.update(chunk)
    return result.hexdigest()


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(Path(path).read_bytes(), object_pairs_hook=pairs)


def write(path, value):
    Path(path).write_bytes(canonical(value) + b"\n")
    return file_sha(path)


def inside(base, relative):
    path = Path(relative)
    require(not path.is_absolute() and path.parts and ".." not in path.parts, "unsafe relative binding")
    destination = Path(base) / path
    require(destination.resolve().is_relative_to(Path(base).resolve()), "binding leaves root")
    return destination


def bound_json(base, binding):
    require(type(binding) is dict and set(binding) == {"path", "sha256"}, "invalid file binding")
    path = inside(base, binding["path"])
    require(file_sha(path) == binding["sha256"], "bound file changed: " + binding["path"])
    return path, read_json(path)


def load_module(path, expected_sha, name):
    require(file_sha(path) == expected_sha, "execution source digest differs: " + str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def original_pipeline():
    pipeline = load_module(PAPER / "phase16/pipeline/streaming_pipeline.py", ORIGINAL_PIPELINE_SHA256,
                           "phase16_frozen_original_pipeline")
    require(file_sha(PAPER / "phase16/collector/range_collector.py") == ORIGINAL_COLLECTOR_SHA256,
            "original collector changed")
    pipeline.check_dependencies()
    return pipeline


def scientific_scope_unchanged(plan, original):
    """The continuation cannot change any key of the accepted scientific plan."""
    require(plan["schema_version"] == "article2_phase16_continuation_source_plan_v1", "continuation plan schema")
    require(original["schema_version"] == "article2_phase16_streaming_pipeline_plan_v1", "original plan schema")
    for key, value in original.items():
        if key != "schema_version":
            require(key in plan and canonical(plan[key]) == canonical(value),
                    "continuation changed original plan field: " + key)
    require(original["pipeline_sha256"] == ORIGINAL_PIPELINE_SHA256
            and original["collector_sha256"] == ORIGINAL_COLLECTOR_SHA256, "original execution identity differs")
    require(plan["study_start"] == "2022-02-19" and plan["study_end_exclusive"] == "2022-03-28",
            "study union changed")
    return True


def sealed_prior_days(parent, records, expected_days, partial_seals=()):
    """Read prior prepared payloads only after the prospective amendment gate."""
    require(type(records) is list, "prior completed-day records absent")
    require([x["day_utc"] for x in records] == expected_days[:len(records)],
            "prior completed days are not an exact study prefix")
    result = {}
    for item in records:
        day = item["day_utc"]
        require(item["prepared"]["path"] == f"days/{day}/prepared.json"
                and item["core_selection"]["path"] == f"days/{day}/core_selection.json",
                "prior day binding path differs")
        _, prepared = bound_json(parent, item["prepared"])
        _, selection = bound_json(parent, item["core_selection"])
        require(prepared["day_utc"] == day and selection["day_utc"] == day,
                "prior day identity differs")
        require(prepared["status"] == "PRODUCER_CHECKED_AWAITING_INDEPENDENT_SOURCE_AUDIT"
                and prepared["transfer_decoding_performed"] is False and prepared["labels_used"] is False,
                "prior completed day scope differs")
        require(prepared["core_selection_file_sha256"] == item["core_selection"]["sha256"],
                "prior prepared selection binding differs")
        result[day] = {"binding": item, "prepared": prepared, "core_selection": selection}
    require(type(partial_seals) in (list, tuple) and len(partial_seals) <= 1, "too many partial core seals")
    for item in partial_seals:
        day = item["day_utc"]
        require(len(records) < len(expected_days) and day == expected_days[len(records)], "partial seal is not next study day")
        require(item["core_selection"]["path"] == f"days/{day}/core_selection.json", "partial core seal path differs")
        require(not (parent / "days" / day / "prepared.json").exists(), "partial day already has prepared payload")
        _, selection = bound_json(parent, item["core_selection"])
        require(selection["day_utc"] == day, "partial seal day identity differs")
        result[day] = {"binding": item, "prepared": None, "core_selection": selection}
    return result


def compare_prior_day(prior, prepared, new_folder):
    """Byte provenance may change; selected membership and every payload must not."""
    selection = read_json(new_folder / "core_selection.json")
    require(canonical(prior["core_selection"]) == canonical(selection),
            "reprepared core selection differs from sealed original attempt")
    complete = prior["prepared"] is not None
    if complete:
        require(canonical(prior["prepared"]["cases"]) == canonical(prepared["cases"]),
                "reprepared selected cases/payload differ from sealed original attempt")
    return {
        "day_utc": prepared["day_utc"],
        "original_prepared_sha256": prior["binding"]["prepared"]["sha256"] if complete else None,
        "new_prepared_sha256": file_sha(new_folder / "prepared.json"),
        "original_core_selection_sha256": prior["binding"]["core_selection"]["sha256"],
        "new_core_selection_sha256": file_sha(new_folder / "core_selection.json"),
        "canonical_cases_sha256": value_sha(prepared["cases"]),
        "exact_core_selection_match": True,
        "exact_cases_and_payload_match": True if complete else None,
        "comparison_scope": "selection_and_completed_payload" if complete else "selection_only_for_incomplete_day",
        "source_sidecars_expected_to_reflect_new_transport_lineage": True,
    }


def recheck_parent_bindings(parent, bindings):
    for relative, expected in bindings.items():
        path = inside(parent, relative)
        if expected is None:
            require(not path.exists(), "formerly absent parent artifact appeared: " + relative)
        else:
            require(file_sha(path) == expected, "immutable parent artifact changed: " + relative)


def prepare_sources(plan, inventory, configs, config_shas, open_source, output, prior_days, p, pa, pc, np):
    """Rebuild every source day through the unchanged preparation implementation."""
    study = p.days_between(plan["study_start"], plan["study_end_exclusive"])
    require(len(study) == 37 and set(study) == set(d for c in configs.values() for d in p.driver.expected_days(c)),
            "case window union differs")
    sources = inventory["objects"]
    require(len(sources) == len({x["key"] for x in sources}) == 113, "source population changed")
    grouped = defaultdict(lambda: defaultdict(list))
    for source in sources:
        grouped[source["day_utc"]][source["table"]].append(source)
    all_days = p.days_between((date.fromisoformat(study[0]) - timedelta(days=1)).isoformat(),
                              (date.fromisoformat(study[-1]) + timedelta(days=2)).isoformat())
    require(sorted(grouped) == all_days, "source day coverage differs")
    readers, source_paths, headers = {}, {}, {}

    def reader(source):
        if source["key"] not in readers:
            instance = open_source(source)
            readers[source["key"]] = instance
            source_paths[source["key"]] = str(instance.path.resolve())
            write(output / "runtime_source_paths.json", source_paths)
        return readers[source["key"]]

    for day in all_days:
        rs = [reader(x) for x in grouped[day]["blocks"]]
        raw, _ = p.projection(rs, p.BLOCK_COLUMNS, pa)
        headers[day] = p.check_headers(raw, day, pa, pc, np)
    for left, right in zip(all_days, all_days[1:]):
        p.check_header_pair(headers[left].slice(len(headers[left]) - 1, 1).to_pylist()[0],
                            headers[right].slice(0, 1).to_pylist()[0])
    for anchor in plan["accepted_header_anchors"]:
        found = []
        for table in headers.values():
            found.extend(table.filter(pc.equal(table["block_number"], anchor["block_number"])).to_pylist())
        require(len(found) == 1 and all(found[0][key] == value for key, value in anchor.items()),
                "retained independent header anchor differs")
    write(output / "header_timeline.json", {
        "days": [{"day_utc": day, "first": headers[day].slice(0, 1).to_pylist()[0],
                  "last": headers[day].slice(len(headers[day]) - 1, 1).to_pylist()[0],
                  "count": len(headers[day]), "canonical_headers_sha256": p.digest(headers[day].to_pylist())}
                 for day in all_days], "accepted_header_anchors": plan["accepted_header_anchors"]})
    prepared, comparisons = [], []
    for day in study:
        require(set(grouped[day]) == {"blocks", "logs", "transactions"}, "missing daily source table")
        active = {case: cfg for case, cfg in configs.items() if day in p.driver.expected_days(cfg)}
        rs = {table: [reader(source) for source in grouped[day][table]]
              for table in ("blocks", "logs", "transactions")}
        previous = (date.fromisoformat(day) - timedelta(days=1)).isoformat()
        following = (date.fromisoformat(day) + timedelta(days=1)).isoformat()
        folder = output / "days" / day
        current = p.prepare_day(day, rs, headers[day],
                                headers[previous].slice(len(headers[previous]) - 1, 1).to_pylist()[0],
                                headers[following].slice(0, 1).to_pylist()[0], active, folder,
                                pa, pc, np, plan["limits"])
        if day in prior_days:
            comparisons.append(compare_prior_day(prior_days[day], current, folder))
            write(output / "prior_completed_day_comparisons.json", {
                "status": "EXACT_REPREPARATION_COMPARISONS_IN_PROGRESS", "days": comparisons})
        prepared.append(current)
        write(output / "progress.json", {"status": "CONTINUATION_IN_PROGRESS_NO_SCORING",
                                          "completed_days": [x["day_utc"] for x in prepared],
                                          "last_completed_day": day})
        print(json.dumps({"continuation_completed_day": day,
                          "compared_with_original_attempt": day in prior_days,
                          "cases": {key: len(value["selected_transactions"]) for key, value in current["cases"].items()}}),
              flush=True)
    require(len(comparisons) == len(prior_days), "prior completed-day comparison missing")
    comparison_sha = write(output / "prior_completed_day_comparisons.json", {
        "status": "PASS_EXACT_REPREPARATION_OF_ALL_ORIGINAL_COMPLETED_DAYS", "days": comparisons,
        "completed_day_count": sum(x["prepared"] is not None for x in prior_days.values()),
        "partial_core_selection_count": sum(x["prepared"] is None for x in prior_days.values()),
        "detector_scores_compared": False})
    selections = {}
    for case, cfg in configs.items():
        chosen = [x for x in prepared if x["day_utc"] in p.driver.expected_days(cfg)]
        folder = output / "cases" / case
        folder.mkdir(parents=True)
        selection = p.selection_for_case(cfg, config_shas[case], chosen)
        selection_sha = write(folder / "selection.json", selection)
        selections[case] = {"path": str((folder / "selection.json").relative_to(output)),
                            "sha256": selection_sha, "config_sha256": config_shas[case], "days": 30,
                            "transactions": sum(len(x["transactions"]) for x in selection["days"])}
    write(output / "transport_sources.json", {"sources": [x.manifest() for x in readers.values()]})
    return {"selection_manifests": selections,
            "prepared_days": [{"path": f"days/{day}/prepared.json", "sha256": file_sha(output / "days" / day / "prepared.json")}
                              for day in study],
            "prior_completed_day_comparisons_sha256": comparison_sha,
            "transport_sources": len(readers), "study_days": 37}


def execution_sources(plan, repo, expected_protocol_sha):
    bindings = plan["continuation_execution_bindings"]
    require(type(bindings) is list and bindings, "continuation execution bindings absent")
    by_path = {}
    for item in bindings:
        require(type(item) is dict and set(item) == {"path", "sha256"}, "invalid execution binding")
        require(item["path"] not in by_path, "duplicate execution binding")
        path = inside(repo, item["path"])
        require(file_sha(path) == item["sha256"], "continuation execution source changed: " + item["path"])
        by_path[item["path"]] = item["sha256"]
    for name in ("continue_pipeline.py", "collector.py", "protocol.py"):
        relative = str((Path(__file__).parent / name).resolve().relative_to(repo.resolve()))
        require(relative in by_path, "required continuation execution source absent: " + name)
    protocol_key = str((Path(__file__).parent / "protocol.py").resolve().relative_to(repo.resolve()))
    require(by_path[protocol_key] == expected_protocol_sha, "protocol import differs from execution plan")
    collector_key = str((Path(__file__).parent / "collector.py").resolve().relative_to(repo.resolve()))
    return by_path[collector_key]


def collect(args):
    # Only local candidate code and the amendment's sealed metadata are consulted
    # until this gate validates the prospective continuation authorization.
    helper = load_module(Path(__file__).parent / "protocol.py", args.expected_protocol_sha256,
                         "phase16_continuation_protocol")
    context = helper.validate_amendment(args.amendment, args.expected_amendment_sha256, for_execution=True)
    plan, original = context["plan"], context["original_plan"]
    plan_sha = context["plan_sha256"]
    require(file_sha(context["plan_path"]) == plan_sha, "continuation plan file changed")
    scientific_scope_unchanged(plan, original)
    repo = args.repo.resolve()
    require(repo == REPO.resolve(), "execution repository differs from imported source tree")
    collector_sha = execution_sources(plan, repo, args.expected_protocol_sha256)
    p = original_pipeline()
    require(file_sha(args.wheel) == plan["pyarrow_wheel_sha256"], "dependency wheel changed")
    sys.path.insert(0, str(args.dependencies.resolve()))
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.parquet as pq
    import numpy as np
    require(pa.__version__ == plan["pyarrow_version"] == "26.0.0"
            and Path(pa.__file__).resolve().is_relative_to(args.dependencies.resolve()), "parser origin/version differs")
    require(np.__version__ == plan["numpy_version"] == "2.3.5", "NumPy version differs")
    _, inventory = p.read_binding(plan["source_union"], repo)
    require(plan["source_union"] == plan["inventory_binding"], "inventory bindings differ")
    _, retained_reuse = p.read_binding(plan["reuse_expectations_binding"], repo)
    p.validate_reuse_expectations_binding(plan["whole_object_reuse_expectations"], retained_reuse, repo)
    reuse = read_json(args.reuse_map) if args.reuse_map else {}
    p.validate_reuse(reuse, plan["whole_object_reuse_expectations"], inventory["objects"], repo)
    configs, config_shas = {}, {}
    for binding in plan["case_configs"]:
        _, cfg = p.read_binding(binding, repo)
        p.driver.validate_config(cfg)
        require(cfg["case_id"] not in configs, "duplicate case config")
        configs[cfg["case_id"]] = cfg
        config_shas[cfg["case_id"]] = binding["sha256"]
    require(len(configs) == 2, "case population changed")
    parent = Path(context["parent_root"]).resolve()
    output = args.output.resolve()
    require(output == Path(context["continuation_output_root"]).resolve(), "output differs from single accepted continuation destination")
    require(not output.exists() and not output.is_relative_to(parent) and not parent.is_relative_to(output),
            "continuation requires a fresh output outside original attempt")
    recheck_parent_bindings(parent, context["parent_bindings"])
    study = p.days_between(plan["study_start"], plan["study_end_exclusive"])
    seal = context["first_attempt_seal"]
    prior = sealed_prior_days(parent, seal["completed_days"], study, seal["partial_core_selection_seals"])
    module = load_module(Path(__file__).parent / "collector.py", collector_sha,
                         "phase16_continuation_collector")
    output.mkdir(parents=True)
    (output / "frozen_plan.json").write_bytes(Path(context["plan_path"]).read_bytes())
    (output / "continuation_amendment.json").write_bytes(args.amendment.read_bytes())
    write(output / "lineage.json", {
        "schema_version": "phase16_operational_continuation_lineage_v1", "continuation_number": 1,
        "continuation_plan_sha256": plan_sha, "original_plan_binding": plan["original_plan_binding"],
        "amendment_sha256": args.expected_amendment_sha256,
        "parent_evidence_bindings": context["parent_bindings"],
        "absolute_deadline_utc": context["absolute_deadline_utc"],
        "source_payload_previously_exposed": True, "accepted_before_continuation_requests": True,
        "original_acceptances_unchanged": True, "scientific_scope_unchanged": True})
    session = None
    try:
        session = module.ContinuationSession(
            original["collector"], output / "transport", parent,
            parent_bindings=context["parent_bindings"], continuation_plan_sha256=plan_sha,
            original_plan_sha256=plan["original_plan_binding"]["sha256"],
            manual_reacquisition=context["manual_reacquisition"], repo=repo)
        if context["manual_reacquisition"] is not None:
            # One explicit request has its own prospective amendment descriptor;
            # failed bytes and their original cost remain in the A1 ledger.
            session.reacquire_final_failed_range()

        def open_source(source):
            reader = module.SourceReader(source, session, output / "cache", pa, pq, reuse=reuse.get(source["key"]))
            reader.open()
            return reader

        payload = prepare_sources(plan, inventory, configs, config_shas, open_source, output, prior, p, pa, pc, np)
        session.assert_parent_unchanged()
        recheck_parent_bindings(parent, context["parent_bindings"])
        for item in seal["completed_days"]:
            bound_json(parent, item["prepared"])
            bound_json(parent, item["core_selection"])
        for item in seal["partial_core_selection_seals"]:
            bound_json(parent, item["core_selection"])
        for binding in plan["case_configs"]:
            p.read_binding(binding, repo)
        execution_sources(plan, repo, args.expected_protocol_sha256)
        require(file_sha(context["plan_path"]) == plan_sha
                and file_sha(args.amendment) == args.expected_amendment_sha256, "continuation gate changed during execution")
        session.close("COMPLETE")
        result = {
            "schema_version": "phase16_continuation_collection_result_v1",
            "status": "COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT",
            "plan_sha256": plan_sha, "original_plan_binding": plan["original_plan_binding"],
            "continuation_amendment_sha256": args.expected_amendment_sha256,
            "continuation_number": 1, "source_payload_previously_exposed": True,
            "prepared_with_original_pipeline_sha256": ORIGINAL_PIPELINE_SHA256,
            "continuation_pipeline_sha256": file_sha(__file__), "continuation_collector_sha256": collector_sha,
            "prior_attempt_immutable_after_repreparation": True, **payload,
            "transfer_decoding_performed": False, "detector_scoring_performed": False, "labels_used": False,
            "pyarrow_version": pa.__version__, "numpy_version": np.__version__,
            "audit_requirement": "New independent multi-attempt transport audit, then unchanged independent source-row audit; no producer PASS."}
        write(output / "collection_result.json", result)
        print(json.dumps({"status": result["status"], "continuation_plan_sha256": plan_sha,
                          "cases": payload["selection_manifests"]}), flush=True)
        return result
    except Exception as exc:
        close_error = None
        if session is not None:
            try:
                session.close("FAILED")
            except Exception as closing:
                close_error = type(closing).__name__ + ": " + str(closing)
        progress = read_json(output / "progress.json") if (output / "progress.json").exists() else {}
        write(output / "failure.json", {
            "schema_version": "phase16_continuation_failure_v1", "status": "FAILED_NOT_ACCEPTED",
            "continuation_plan_sha256": plan_sha, "original_plan_binding": plan["original_plan_binding"],
            "continuation_amendment_sha256": args.expected_amendment_sha256,
            "error_type": type(exc).__name__, "error": str(exc), "close_error": close_error,
            "completed_days": progress.get("completed_days", []),
            "transfer_decoding_performed": False, "detector_scoring_performed": False,
            "automatic_retry_or_second_continuation": False})
        raise


def assemble(args):
    """Decode only after the new independent transport and full-source PASS gates."""
    helper = load_module(Path(__file__).parent / "protocol.py", args.expected_protocol_sha256,
                         "phase16_continuation_protocol")
    bindings = {
        "transport_audit": {"path": str(args.transport_audit.resolve()), "sha256": args.expected_transport_audit_sha256},
        "source_review": {"path": str(args.source_review.resolve()), "sha256": args.expected_source_review_sha256},
        "multiattempt_ledger": {"path": str(args.multiattempt_ledger.resolve()), "sha256": args.expected_multiattempt_ledger_sha256}}
    context = helper.validate_amended_source_ready(
        args.amendment, args.expected_amendment_sha256, **bindings, binding_parent=args.amendment.parent)
    plan, original = context["plan"], context["original_plan"]
    scientific_scope_unchanged(plan, original)
    require(args.repo.resolve() == REPO.resolve(), "assembly repository differs")
    execution_sources(plan, args.repo.resolve(), args.expected_protocol_sha256)
    source = read_json(args.source_review)
    transport = read_json(args.transport_audit)
    require(args.collection.resolve() == Path(context["continuation_output_root"]).resolve(),
            "assembly collection differs from accepted continuation destination")
    collection_path = args.collection / "collection_result.json"
    collection_sha = file_sha(collection_path)
    require(collection_sha == source["collection_result_sha256"] == transport["collection_result_sha256"],
            "actual collection differs from independent source/transport audits")
    collection = read_json(collection_path)
    require(collection["schema_version"] == "phase16_continuation_collection_result_v1"
            and collection["status"] == "COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT"
            and collection["plan_sha256"] == context["plan_sha256"]
            and collection["continuation_amendment_sha256"] == args.expected_amendment_sha256
            and collection["original_plan_binding"] == plan["original_plan_binding"],
            "collection continuation lineage differs")
    require(collection["transfer_decoding_performed"] is False and collection["detector_scoring_performed"] is False
            and collection["labels_used"] is False, "preassembly source stage contains downstream results")
    comparison_path = args.collection / "prior_completed_day_comparisons.json"
    require(file_sha(comparison_path) == collection["prior_completed_day_comparisons_sha256"],
            "original-attempt comparison binding differs")
    comparison = read_json(comparison_path)
    require(comparison["status"] == "PASS_EXACT_REPREPARATION_OF_ALL_ORIGINAL_COMPLETED_DAYS",
            "original-attempt reproduction incomplete")
    p = original_pipeline()
    configs = {}
    for binding in plan["case_configs"]:
        path, config = p.read_binding(binding, args.repo)
        p.driver.validate_config(config)
        configs[config["case_id"]] = (path, config)
    require(len(configs) == 2 and set(source["case_audits"]) == set(configs), "case source audits incomplete")
    audits = {}
    for case, item in source["case_audits"].items():
        audit_path = Path(item["path"])
        if not audit_path.is_absolute():
            audit_path = inside(args.source_review.parent, item["path"])
        require(file_sha(audit_path) == item["sha256"], "independent case audit changed")
        audits[case] = (audit_path, item["sha256"])
    require(not args.output.exists(), "fresh assembly output required")
    args.output.mkdir(parents=True)
    assembled = {}
    for case, (config_path, config) in configs.items():
        paths = [args.collection / "days" / day / "prepared.json" for day in p.driver.expected_days(config)]
        audit_path, audit_sha = audits[case]
        result = p.assemble_case(config_path, config, paths, audit_path, audit_sha, args.output / case)
        assembled[case] = {"path": str((args.output / case / "manifest.json").resolve()),
                           "sha256": result["manifest_sha256"]}
    require(file_sha(args.amendment) == args.expected_amendment_sha256
            and file_sha(context["plan_path"]) == context["plan_sha256"], "assembly acceptance changed")
    for name, binding in bindings.items():
        require(file_sha(binding["path"]) == binding["sha256"], "assembly audit input changed: " + name)
    result = {"schema_version": "phase16_continuation_observation_assembly_v1",
              "status": "COMPLETE_OBSERVATIONS_AWAITING_CURRENT_PRE_REPLAY_AUTHORIZATION",
              "plan_sha256": context["plan_sha256"], "original_plan_binding": plan["original_plan_binding"],
              "continuation_amendment_sha256": args.expected_amendment_sha256,
              "collection_result_sha256": collection_sha, "input_manifests": assembled,
              "source_review_sha256": args.expected_source_review_sha256,
              "transport_audit_sha256": args.expected_transport_audit_sha256,
              "multiattempt_ledger_sha256": args.expected_multiattempt_ledger_sha256,
              "original_assembler_sha256": ORIGINAL_PIPELINE_SHA256,
              "transfer_decoding_performed": True, "detector_scoring_performed": False, "labels_used": False}
    write(args.output / "assembly_result.json", result)
    print(json.dumps({"status": result["status"], "input_manifests": assembled}), flush=True)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect_parser = subparsers.add_parser("collect")
    assemble_parser = subparsers.add_parser("assemble")
    for sub in (collect_parser, assemble_parser):
        for name in ("amendment", "output"):
            sub.add_argument("--" + name, type=Path, required=True)
        sub.add_argument("--expected-amendment-sha256", required=True)
        sub.add_argument("--expected-protocol-sha256", required=True)
        sub.add_argument("--repo", type=Path, default=REPO)
    for name in ("dependencies", "wheel"):
        collect_parser.add_argument("--" + name, type=Path, required=True)
    collect_parser.add_argument("--reuse-map", type=Path)
    for name in ("transport-audit", "source-review", "multiattempt-ledger", "collection"):
        assemble_parser.add_argument("--" + name, type=Path, required=True)
    for name in ("transport-audit", "source-review", "multiattempt-ledger"):
        assemble_parser.add_argument("--expected-" + name + "-sha256", required=True)
    args = parser.parse_args(argv)
    return collect(args) if args.command == "collect" else assemble(args)


if __name__ == "__main__":
    main()
