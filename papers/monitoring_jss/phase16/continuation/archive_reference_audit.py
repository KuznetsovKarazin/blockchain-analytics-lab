"""Continuation-aware, post-decision archive reference facts; no retrieval/labels.

The pinned original source-fact engine remains untouched. The complete A1/A2
cost ledger stays bound; only its independently audited successful-byte view is
passed to the original reader. No original-plan or original-attempt substitution.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import importlib.util
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
PAPER = HERE.parents[1]
REPO = PAPER.parents[1]
ENGINE_SHA256 = "347bf76e162cf995e0b3c30ce6a3e72a75a1e78008d120ce8d51137667409955"
JOIN_SHA256 = "deaf7e58715cda8e701ec31bc2f4fcd7e85db5f9199fe23a0b55e195519b1cee"
PROTOCOL_SHA256 = "7afb6398fcf4f10f0db6f92bc18a8f1949e13b411f19241443c86d8d0d811fff"


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024**2), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_pinned(name, path, expected):
    if sha(path) != expected:
        raise ValueError("pinned reference dependency changed: " + str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if sha(PAPER / "phase16/reference/exact_reference_join.py") != JOIN_SHA256:
    raise ValueError("frozen exact join changed")
engine = load_pinned("phase16_original_archive_source_facts", PAPER / "phase16/reference/archive_reference_audit.py", ENGINE_SHA256)
protocol = load_pinned("phase16_reference_continuation_protocol", HERE / "protocol.py", PROTOCOL_SHA256)
join, frozen, need = engine.join, engine.frozen, engine.need
independent = engine.independent


def validate_successful_view(ledger, evidence, inherited, new, session, transport, manifests):
    """Keep the entire charged ledger; derive only a byte-reader success view."""
    need(ledger["schema_version"] == "article2_phase16_full_multiattempt_transport_ledger_v1"
         and ledger["original_requests"] == inherited and ledger["continuation_requests"] == new,
         "full original/new charged ledgers differ")
    need(ledger["parent_attempt_id"] == session["parent_attempt_id"]
         and ledger["continuation_attempt_id"] == session["attempt_id"], "ledger attempt identities differ")
    records = inherited + new
    need([r["ordinal"] for r in records] == list(range(1, len(records) + 1)), "full ledger ordinals differ")
    for record in records:
        need(type(record["transport_ok"]) is bool and type(record["length"]) is int
             and type(record["response_bytes"]) is int and 0 <= record["response_bytes"] <= record["length"],
             "full ledger response accounting invalid")
    expected = [{"origin_attempt_id": session["parent_attempt_id"] if i < len(inherited) else session["attempt_id"],
                 "origin_ordinal": record["ordinal"], "receipt": record}
                for i, record in enumerate(records) if record["transport_ok"] is True]
    need(evidence["schema_version"] == "article2_phase16_continuation_accepted_ranges_v1"
         and frozen.canonical(evidence["ranges"]) == frozen.canonical(expected),
         "accepted byte evidence must equal every successful full-ledger record with exact origin")
    parent_bytes = sum(r["response_bytes"] for r in inherited)
    new_bytes = sum(r["response_bytes"] for r in new)
    reserved_parent = sum(r["length"] - r["response_bytes"] for r in inherited if not r["transport_ok"])
    reserved_new = sum(r["length"] - r["response_bytes"] for r in new if not r["transport_ok"])
    rejected_bytes = sum(r["response_bytes"] for r in records if not r["transport_ok"])
    accounting = ledger["accounting"]
    totals = {"inherited_request_count": len(inherited), "new_request_count": len(new),
        "cumulative_request_count": len(records), "inherited_response_bytes": parent_bytes,
        "new_response_bytes": new_bytes, "cumulative_response_bytes": parent_bytes + new_bytes,
        "reserved_parent_failed_response_bytes": reserved_parent,
        "reserved_new_failed_or_pending_response_bytes": reserved_new,
        "inherited_charged_response_bytes": parent_bytes + reserved_parent,
        "new_charged_response_bytes": new_bytes + reserved_new,
        "cumulative_charged_response_bytes": parent_bytes + new_bytes + reserved_parent + reserved_new}
    need(all(type(accounting[k]) is int and accounting[k] == v and session[k] == v for k, v in totals.items()),
         "failed/full cumulative costs cannot be filtered from accounting")
    need(accounting["unaccepted_response_bytes"] == rejected_bytes and accounting["new_failed_request_count"] == 0
         and not any(not r["transport_ok"] for r in new), "complete continuation has failed new responses")
    need(ledger["all_failed_response_bytes_charged"] is True and ledger["failed_original_bytes_promoted"] is False
         and ledger["automatic_retries"] == 0 and accounting["wire_bytes_measured"] is False,
         "failed-byte provenance/charge claims differ")
    need(totals["cumulative_request_count"] <= protocol.LIMITS["cumulative_get_limit"]
         and totals["cumulative_charged_response_bytes"] <= protocol.LIMITS["cumulative_response_byte_limit"],
         "cumulative continuation cap exceeded")
    for field, value in (("request_count", len(records)), ("retained_response_bytes", parent_bytes + new_bytes),
            ("reserved_parent_failed_response_bytes", reserved_parent), ("unaccepted_response_bytes", rejected_bytes),
            ("cumulative_charged_response_bytes", totals["cumulative_charged_response_bytes"])):
        need(transport[field] == value, "transport/full ledger accounting differs")
    grouped = defaultdict(list)
    for origin in expected:
        grouped[origin["receipt"]["source"]["key"]].append(origin)
    verified = {source["source_key"]: source for source in transport["verified_sources"]}
    need(len(verified) == len(transport["verified_sources"]) and set(grouped) <= set(verified), "receipt source outside verified population")
    for key, source in verified.items():
        origins = grouped[key]
        successful = [origin["receipt"] for origin in origins]
        need(source["successful_receipt_origins"] == origins
             and source["range_receipts_canonical_sha256"] == frozen.digest(successful)
             and manifests[key]["successful_original_ranges"] == successful
             and manifests[key]["evidence_origins"] == origins, "source successful-origin view differs from full ledger")
    return {key: [origin["receipt"] for origin in grouped[key]] for key in verified}


def normalized_binding(value, base):
    return {"path": str(join.binding(value, base).resolve()), "sha256": value["sha256"]}


def normalized_cases(cases, base):
    need([entry["case_id"] for entry in cases] == list(join.CASES), "launcher case order differs")
    result = []
    for entry in cases:
        need(entry["status"] == "COMPLETE", "launcher case incomplete")
        result.append({"case_id": entry["case_id"], "status": entry["status"], **{
            field: normalized_binding(entry[field], base) for field in
            ("config", "measurement_acceptance", "input_manifest", "run_manifest")}})
    return result


def validate_launcher(receipt_path, study, study_base, auth, expected_bindings):
    receipt = join.read(receipt_path)
    need(receipt["schema_version"] == "article2_phase16_continuation_replay_launcher_receipt_v1"
         and receipt["status"] == "COMPLETE_BOTH_CASES_SEALED"
         and receipt["labels_used"] is False and receipt["reference_acquisition_performed"] is False,
         "both-case unlabelled authorized replay receipt missing")
    need(receipt["replay_launcher_sha256"] == auth["replay_launcher_sha256"] == sha(HERE / "run_replays.py")
         and receipt["original_driver_sha256"] == sha(join.driver.__file__), "replay launcher/driver code differs")
    need(Path(auth["replay_output_root"]).is_absolute()
         and receipt_path.parent.resolve() == Path(auth["replay_output_root"]).resolve(), "launcher receipt outside authorized output")
    for field, expected in expected_bindings.items():
        need(normalized_binding(receipt[field], receipt_path.parent) == expected, "launcher authorization/audit lineage differs: " + field)
    need(normalized_cases(receipt["cases"], receipt_path.parent) == normalized_cases(study["cases"], study_base),
         "launcher/study exact case bindings differ")
    need(join.utc(auth["accepted_utc"]) <= join.utc(receipt["started_utc"]) <= join.utc(receipt["completed_utc"])
         <= join.utc(study["sealed_utc"]), "launcher/study chronology differs")
    return receipt


def load_context(args):
    study, runs = join.load_study(args.study_manifest, args.expected_study_sha256)
    need(study.get("reference_archive_auditor_sha256") == sha(__file__)
         and study.get("reference_archive_source_engine_sha256") == ENGINE_SHA256,
         "continuation reference wrapper/engine not pinned before references")
    need(all(run["status"] == "COMPLETE" for run in runs), "archive route requires both complete runs")
    base = args.study_manifest.parent
    auth_binding = study["continuation_pre_replay_authorization"]
    auth_path = join.binding(auth_binding, base)
    context = protocol.validate_pre_replay_authorization(auth_path, auth_binding["sha256"])
    amendment_binding = study["continuation_amendment"]
    amendment_path = join.binding(amendment_binding, base)
    need(amendment_binding["sha256"] == context["amendment_sha256"]
         and amendment_path.resolve() == context["amendment_path"].resolve(), "study/pre-replay amendment differs")
    ledger_path = join.binding(study["multiattempt_ledger"], base)
    need(ledger_path.resolve() == context["multiattempt_ledger_path"].resolve(), "study/pre-replay full ledger differs")
    ledger = join.read(ledger_path)
    auth = context["pre_replay_authorization"]
    expected_bindings = {"pre_replay_authorization": engine.file_binding(auth_path),
        "continuation_amendment": engine.file_binding(amendment_path), "multiattempt_ledger": engine.file_binding(ledger_path),
        "source_review": normalized_binding(auth["source_review"], auth_path.parent),
        "transport_audit": normalized_binding(auth["transport_audit"], auth_path.parent)}
    launcher_path = join.binding(study["replay_launcher_receipt"], base)
    launcher = validate_launcher(launcher_path, study, base, auth, expected_bindings)
    for entry in study["cases"]:
        need(entry["input_manifest"]["sha256"] == auth["input_manifests"][entry["case_id"]]["sha256"],
             "scored inputs differ from pre-replay authorization")
        run_manifest = join.read(join.binding(entry["run_manifest"], base))
        need(join.utc(auth["accepted_utc"]) <= join.utc(run_manifest["started_utc"])
             <= join.utc(run_manifest["completed_utc"]) <= join.utc(launcher["completed_utc"]), "authorized replay chronology differs")
    transport = join.pinned(args.transport_audit, args.expected_transport_audit_sha256)
    source_review = join.pinned(args.source_review, args.expected_source_review_sha256)
    need(auth["transport_audit"]["sha256"] == args.expected_transport_audit_sha256
         and auth["source_review"]["sha256"] == args.expected_source_review_sha256
         and transport["schema_version"] == "article2_phase16_independent_continuation_transport_audit_v1"
         and transport["status"] == "PASS_CONTINUATION_TRANSPORT_ORIGINAL_BYTES"
         and transport["multiattempt_ledger_sha256"] == study["multiattempt_ledger"]["sha256"], "continuation audit lineage differs")
    need(frozen.canonical(transport) == frozen.canonical(context["transport_audit"])
         and frozen.canonical(source_review) == frozen.canonical(context["source_review"]), "pre-replay/reference audits differ")
    plan = context["plan"]
    need(args.collection.resolve() == context["continuation_output_root"].resolve(), "reference collection differs from single amended output")
    collection = join.pinned(args.collection / "collection_result.json", transport["collection_result_sha256"])
    need(collection["schema_version"] == "phase16_continuation_collection_result_v1"
         and collection["status"] == "COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT"
         and collection["plan_sha256"] == context["plan_sha256"]
         and collection["continuation_amendment_sha256"] == amendment_binding["sha256"]
         and collection["original_plan_binding"] == plan["original_plan_binding"]
         and source_review["collection_result_sha256"] == transport["collection_result_sha256"],
         "continuation collection identity differs; original-plan substitution prohibited")
    need(frozen.canonical(join.read(args.collection / "frozen_plan.json")) == frozen.canonical(plan)
         and sha(args.collection / "continuation_amendment.json") == amendment_binding["sha256"], "runtime continuation plan/amendment changed")
    manifests_raw = join.pinned(args.collection / "transport_sources.json", transport["transport_sources_sha256"])
    paths = join.pinned(args.collection / "runtime_source_paths.json", transport["runtime_source_paths_sha256"])
    session = join.pinned(args.collection / "transport/session.json", transport["session_sha256"])
    inherited = join.pinned(args.collection / "transport/inherited_requests.json", transport["inherited_requests_sha256"])
    new = join.pinned(args.collection / "transport/requests.json", transport["requests_sha256"])
    accepted = join.pinned(args.collection / "transport/accepted_range_evidence.json", transport["accepted_range_evidence_sha256"])
    need(session["schema_version"] == "article2_phase16_continuation_capture_v1" and session["status"] == "COMPLETE"
         and session["continuation_plan_sha256"] == context["plan_sha256"], "continuation session not complete/bound")
    need(ledger["continuation_amendment_sha256"] == amendment_binding["sha256"]
         and ledger["plan_sha256"] == context["plan_sha256"]
         and ledger["original_source_plan_sha256"] == plan["original_plan_binding"]["sha256"]
         and ledger["inherited_requests_sha256"] == transport["inherited_requests_sha256"]
         and ledger["new_requests_sha256"] == transport["requests_sha256"]
         and ledger["original_requests_sha256"] == context["parent_bindings"]["transport/requests.json"],
         "complete ledger hashes/plan lineage differ")
    inventory = join.read(join.binding(plan["source_union"], REPO))
    manifests_list = manifests_raw["sources"]
    manifests = {item["source"]["key"]: item for item in manifests_list}
    sources = {item["key"]: item for item in inventory["objects"]}
    verified = {item["source_key"]: item for item in transport["verified_sources"]}
    need(len(sources) == len(inventory["objects"]) == len(manifests) == len(manifests_list)
         == len(verified) == len(transport["verified_sources"]) == 113
         and set(sources) == set(manifests) == set(verified) == set(paths), "113-source continuation population differs")
    need(all(Path(paths[key]).resolve() == Path(verified[key]["path"]).resolve() for key in sources), "current source path map differs")
    requests = validate_successful_view(ledger, accepted, inherited, new, session, transport, manifests)
    review_days = {item["day_utc"]: item for item in source_review["days"]}
    days = independent.days(plan["study_start"], plan["study_end_exclusive"])
    need(len(days) == len(review_days) == len(source_review["days"]) == 37 and list(review_days) == days
         and set(days) == {day for run in runs for day in join.driver.expected_days(run["config"])}, "audited full-window union differs")
    for run in runs:
        audit = join.binding(source_review["case_audits"][run["case_id"]], args.source_review.parent)
        need(sha(audit) == run["source_audit"]["sha256"], "reference source review differs from scored case audit")
    candidates = engine.select_candidates(join.pinned(args.candidates, args.expected_candidates_sha256),
                                          args.expected_study_sha256, study["sealed_utc"])
    retained_bindings = [engine.file_binding(path) for path in (args.study_manifest, auth_path,
        amendment_path, ledger_path, launcher_path, args.transport_audit, args.source_review)]
    return {"runs": runs, "candidates": candidates, "plan": plan, "sources": sources,
            "manifests": manifests, "verified": verified, "requests": requests, "review_days": review_days,
            "context_bindings": retained_bindings, "ledger": ledger, "ledger_binding": engine.file_binding(ledger_path),
            "amendment_sha256": amendment_binding["sha256"], "authorization_sha256": auth_binding["sha256"]}


def run(args):
    need(not args.output.exists(), "fresh continuation reference audit output required")
    context = load_context(args)
    sys.path.insert(0, str(args.dependencies.resolve()))
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.parquet as pq
    import numpy as np
    plan = context["plan"]
    need(pa.__version__ == plan["pyarrow_version"] == "26.0.0"
         and Path(pa.__file__).resolve().is_relative_to(args.dependencies.resolve())
         and np.__version__ == plan["numpy_version"] == "2.3.5", "reference parser/runtime differs")
    started = time.monotonic()
    deadline = started + engine.WALL_SECONDS
    by_day = defaultdict(lambda: defaultdict(list))
    for source in context["sources"].values():
        by_day[source["day_utc"]][source["table"]].append(source)
    readers = {}
    def open_sources(day, kind):
        need(bool(by_day[day][kind]), "required continuation source day/table missing")
        result = []
        for source in by_day[day][kind]:
            key = source["key"]
            if key not in readers:
                engine.check_deadline(deadline)
                engine.verify_current_source(source, context["manifests"][key], context["verified"][key], context["requests"][key], deadline)
                reader = independent.OfflineSource(source, context["manifests"][key], context["verified"][key], pa, pq)
                engine.check_deadline(deadline)
                original_read = reader.read
                def bounded(group, columns, original=original_read):
                    engine.check_deadline(deadline)
                    value = original(group, columns)
                    engine.check_deadline(deadline)
                    return value
                reader.read = bounded
                readers[key] = reader
            result.append(readers[key])
        return result
    keys = {(candidate["chain_id"], candidate["transaction_hash"]) for case in context["candidates"]
            for candidate in case["candidates"] if candidate["within_cap"]}
    wanted = pa.array(sorted({txhash for _, txhash in keys}), type=pa.string())
    headers, matches, days = {}, {}, []
    capped = False
    try:
        for day in sorted(by_day):
            headers[day] = independent.header_rows(open_sources(day, "blocks"), day, pa, pc)[0]
            engine.check_deadline(deadline)
        for left, right in zip(sorted(headers), sorted(headers)[1:]):
            need(frozen.day_start(right) - frozen.day_start(left) == engine.DAY_NS, "header calendar gap")
            independent.link(headers[left].slice(len(headers[left]) - 1, 1).to_pylist()[0], headers[right].slice(0, 1).to_pylist()[0])
        for day, reviewed in context["review_days"].items():
            tx, tx_groups = independent.full_projection(open_sources(day, "transactions"), "transactions", pa, pc)
            need(len(tx) == reviewed["all_transaction_rows"], "TX scan differs from independent source review")
            engine.validate_tx_metadata(tx, headers[day], pa, pc, np)
            engine.check_deadline(deadline)
            found, log_groups, logs_read = {}, [], False
            if len(tx.filter(pc.is_in(tx["transaction_hash"], value_set=wanted))):
                logs, log_groups = independent.full_projection(open_sources(day, "logs"), "logs", pa, pc)
                active = {run["case_id"]: run for run in context["runs"] if day in join.driver.expected_days(run["config"])}
                found = engine.inspect_day(day, tx, logs, headers[day], active, keys, reviewed, pa, pc, np)
                engine.check_deadline(deadline)
                need(not set(found).intersection(matches), "candidate hash repeated across source days")
                matches.update(found)
                logs_read = True
            days.append({"day_utc": day, "full_transaction_rows": len(tx), "transaction_row_groups": tx_groups,
                "all_log_identity_address_rows_scanned": logs_read,
                "full_log_identity_rows": reviewed["all_log_identity_rows"] if logs_read else None,
                "log_identity_row_groups": log_groups, "candidate_matches": found})
            print(f"Continuation reference scan {day}: {len(found)} candidate hashes; no attack-role adjudication", flush=True)
        engine.check_deadline(deadline)
    except engine.AuditDeadlineExceeded:
        capped, matches = True, {}
    elapsed = time.monotonic() - started
    args.output.mkdir(parents=True)
    evidence = {"schema_version": "article2_phase16_continuation_archive_reference_projection_evidence_v1",
        "status": "CLOSED_UNAVAILABLE_TIME_CAP" if capped else "PASS", "created_utc": datetime.now(timezone.utc).isoformat(),
        "decision_study_sha256": args.expected_study_sha256, "candidate_inventory_sha256": args.expected_candidates_sha256,
        "archive_auditor_sha256": sha(__file__), "archive_source_engine_sha256": ENGINE_SHA256,
        "continuation_protocol_sha256": PROTOCOL_SHA256, "context_bindings": context["context_bindings"],
        "full_multiattempt_ledger": context["ledger_binding"], "full_cost_accounting": context["ledger"]["accounting"],
        "continuation_amendment_sha256": context["amendment_sha256"], "pre_replay_authorization_sha256": context["authorization_sha256"],
        "shared_execution_wall_cap_seconds": engine.WALL_SECONDS, "execution_wall_seconds": elapsed,
        "time_cap_reached": capped, "complete_declared_union_scan": not capped,
        "independently_transport_checked_source_objects": 113, "sources_reauthenticated_and_opened": len(readers),
        "days": days, "network_requests": 0, "nonselected_topics_or_data_decoded": False,
        "detector_scores_computed": 0, "attack_roles_adjudicated": 0,
        "scope": "Source facts under explicit one-continuation authorization; original A1 disposition and every failed cost retained. No receipt-root proof, attack-role inference, or nonexistent-transaction claim."}
    frozen.write_json(args.output / "projection_evidence.json", evidence)
    evidence_binding = engine.file_binding(args.output / "projection_evidence.json")
    runs = {run["case_id"]: run for run in context["runs"]}
    output_cases = []
    for case in context["candidates"]:
        folder = args.output / case["case_id"]
        folder.mkdir()
        facts = []
        for candidate in case["candidates"]:
            audit, fact = engine.make_record(case["case_id"], candidate, matches.get(candidate["transaction_hash"]),
                runs[case["case_id"]], evidence_binding, context["context_bindings"], scan_complete=not capped)
            target = folder / (candidate["transaction_hash"] + ".json")
            frozen.write_json(target, audit)
            fact["source_coverage_audit_binding"] = engine.file_binding(target)
            facts.append(fact)
        output_cases.append({"case_id": case["case_id"], "candidates": facts, "candidate_count": len(facts),
                             "audit_cap": engine.CAP, "over_cap_count": sum(not fact["within_cap"] for fact in facts)})
    result = {"schema_version": "article2_phase16_continuation_archive_reference_audit_result_v1",
        "status": "CLOSED_UNAVAILABLE_TIME_CAP" if capped else "COMPLETE_SOURCE_FACTS_ONLY",
        "decision_study_sha256": args.expected_study_sha256, "candidate_inventory_sha256": args.expected_candidates_sha256,
        "archive_auditor_sha256": sha(__file__), "archive_source_engine_sha256": ENGINE_SHA256,
        "projection_evidence": evidence_binding, "context_bindings": context["context_bindings"],
        "full_multiattempt_ledger": context["ledger_binding"], "time_cap_reached": capped,
        "shared_execution_wall_cap_seconds": engine.WALL_SECONDS, "execution_wall_seconds": elapsed,
        "cases": output_cases, "primary_reference_adjudication_performed": False,
        "reference_inventory_completeness_established": False, "network_requests": 0}
    frozen.write_json(args.output / "archive_reference_result.json", result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("study-manifest", "candidates", "collection", "transport-audit", "source-review", "dependencies", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("study", "candidates", "transport-audit", "source-review"):
        parser.add_argument("--expected-" + name + "-sha256", required=True)
    result = run(parser.parse_args(argv))
    print(result["status"] + ": " + str(sum(case["candidate_count"] for case in result["cases"])) + " retained candidates")


if __name__ == "__main__":
    main()
