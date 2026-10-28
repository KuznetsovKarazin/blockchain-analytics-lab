"""Candidate gates for one explicit Phase16 source-only continuation.

Nothing here authorizes continuation merely by existing or passing self-tests.
Root acceptance must follow a naturally closed original wall-limited attempt.
Original measurement acceptances and source plans remain immutable historical
records. This module performs no acquisition, source-row decode or replay.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile

PAPER = Path(__file__).resolve().parents[2]
REPO = PAPER.parents[1]
sys.path.insert(0, str(PAPER / "phase15" / "driver"))
import fixed_address_replay as driver

frozen = driver.frozen
need = driver.require
CASES = ("lifi_20220320", "revest_20220327")
ORIGINAL_WALL = 7200
LIMITS = {"absolute_deadline_seconds_from_a1_start": 14400,
          "cumulative_get_limit": 5000, "cumulative_response_byte_limit": 17179869184,
          "automatic_retries": 0, "maximum_explicit_manual_reacquisitions": 1,
          "failed_get_byte_charge": "FULL_DECLARED_RANGE_LENGTH"}
EXTRA_PLAN = {"original_plan_binding", "continuation_transport", "continuation_execution_bindings"}
REQUIRED_CODE = {"protocol.py", "collector.py", "continue_pipeline.py", "independent_transport_audit.py", "audit_sources.py"}
ORIGINAL_ROW_AUDITOR_SHA256 = "385bff732afac356bf890193153b08d3751b5a3fbfd4788dab500176a0a03a62"
WALL_ERRORS = {"wall cap during range", "wall cap after range read", "wall cap after response close"}
TIMEOUT_MESSAGES = {"timed out", "The read operation timed out"}
TIMEOUT_ERRORS = ({("TimeoutError", message) for message in TIMEOUT_MESSAGES}
                  | {("URLError", "<urlopen error " + message + ">") for message in TIMEOUT_MESSAGES})
TIMEOUT_CLASS = "DEADLINE_ASSOCIATED_TIMEOUT_CAUSALITY_UNRESOLVED"
REQUIRED_PARENT = {"frozen_plan.json", "runtime_acceptances.json", "transport/plan.json",
                   "transport/session.json", "transport/requests.json", "runtime_source_paths.json",
                   "failure.json", "collection_result.json"}


def read(path):
    return frozen.strict_json(Path(path).read_bytes())


def utc(value):
    need(type(value) is str, "explicit UTC timestamp required")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    need(result.utcoffset() == timedelta(0), "explicit UTC timestamp required")
    return result


def stamp():
    return datetime.now(timezone.utc).isoformat()


def file_binding(path):
    path = Path(path).resolve()
    return {"path": str(path), "sha256": frozen.file_digest(path)}


def bound(binding, parent):
    driver.exact_keys(binding, ("path", "sha256"), "continuation binding")
    need(type(binding["path"]) is str and bool(binding["path"]), "empty binding path")
    path = Path(binding["path"])
    path = path if path.is_absolute() else Path(parent) / path
    need(path.is_file() and frozen.file_digest(path) == frozen.sha(binding["sha256"], "continuation binding"),
         "bound continuation file changed: " + str(path))
    return path


def put_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    frozen.write_json(path, value)
    return file_binding(path)


def parent_path(root, name):
    path = Path(name)
    need(type(name) is str and bool(name) and not path.is_absolute() and ".." not in path.parts,
         "parent evidence must be an internal relative path")
    result = (Path(root) / path).resolve()
    need(result.is_relative_to(Path(root).resolve()), "parent evidence escapes immutable attempt")
    return result


def failed_reservation(requests):
    """Conservative budget charge, not a measurement of consumed wire bytes."""
    result = 0
    for request in requests:
        need(type(request["length"]) is int and 0 <= request["response_bytes"] <= request["length"], "failed response byte bounds differ")
        if request.get("transport_ok") is not True:
            result += request["length"] - request["response_bytes"]
    return result


def deadline_timeout(record, failure, start, closed):
    deadline = start + timedelta(seconds=ORIGINAL_WALL)
    if not ((failure.get("error_type"), failure.get("error")) in TIMEOUT_ERRORS
            and record.get("failure") == failure["error_type"] + ": " + failure["error"]
            and deadline - timedelta(seconds=60) <= utc(record["started_utc"]) < deadline
            and deadline <= utc(record["completed_utc"]) <= closed):
        return False
    names = {"http_status", "response_url", "etag", "content_range", "content_length", "content_encoding"}
    present = names & set(record)
    if not present:
        return record["response_bytes"] == 0
    if present != names:
        return False
    source, offset, length = record["source"], record["start"], record["length"]
    declared = record["content_length"]
    return (record["http_status"] == 206 and record["response_url"] == source["url"]
            and record["etag"] == source["etag_opaque"]
            and record["content_range"] == f"bytes {offset}-{offset + length - 1}/{source['size_bytes']}"
            and type(declared) is str and declared.isdigit() and int(declared) == length
            and record["content_encoding"] in (None, "identity"))


def closure_class(session, requests, failure, collection):
    """Wall guards or narrowly associated late TimeoutError; no causal rewrite."""
    start, closed = utc(session["started_utc"]), utc(session["updated_utc"])
    elapsed = session["wall_seconds_elapsed"]
    need(type(elapsed) in (int, float) and elapsed >= ORIGINAL_WALL
         and abs((closed - start).total_seconds() - elapsed) <= 2,
         "original wall exhaustion not established or clocks inconsistent")
    need(session["request_count"] == len(requests) <= LIMITS["cumulative_get_limit"], "original request ledger differs")
    need([r["ordinal"] for r in requests] == list(range(1, len(requests) + 1)), "original request ordinals differ")
    need(all(type(r["response_bytes"]) is int and r["response_bytes"] >= 0 for r in requests), "original byte count invalid")
    need(session["retained_response_bytes"] == sum(r["response_bytes"] for r in requests)
         <= LIMITS["cumulative_response_byte_limit"], "original cumulative byte ledger differs")
    need(session["retained_response_bytes"] + failed_reservation(requests) <= LIMITS["cumulative_response_byte_limit"],
         "original failed-range reservation exceeds cumulative byte cap")
    need(session["retries"] == 0, "original retry policy differs")
    unsuccessful = [r for r in requests if r.get("transport_ok") is not True]
    deadline = start + timedelta(seconds=ORIGINAL_WALL)
    for r in requests:
        need(r.get("completed_utc") is not None and start <= utc(r["started_utc"]) <= utc(r["completed_utc"]) <= closed,
             "pending/out-of-order original request cannot be sealed")
        if r.get("transport_ok") is True:
            need(r["response_bytes"] == r["length"] and "failure" not in r
                 and utc(r["completed_utc"]) <= deadline, "accepted original GET exceeds original bound")
    if session["status"] == "COMPLETE":
        need(elapsed > ORIGINAL_WALL and failure is None and collection is not None and not unsuccessful
             and collection["status"] == "COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT",
             "complete-overwall condition not established")
        return "COMPLETE_OVER_ORIGINAL_WALL_LIMIT"
    need(session["status"] == "FAILED" and failure is not None and collection is None,
         "original attempt must naturally close FAILED or COMPLETE-overwall")
    error = failure.get("error")
    if not unsuccessful:
        need(failure.get("error_type") == "ValueError" and error == "wall/request cap"
             and len(requests) < LIMITS["cumulative_get_limit"],
             "wall-only pre-request failure not established")
    else:
        need(len(unsuccessful) == 1 and unsuccessful[0] is requests[-1], "only one final unsuccessful GET is eligible")
        if deadline_timeout(unsuccessful[0], failure, start, closed):
            return TIMEOUT_CLASS
        need(failure.get("error_type") == "ValueError" and error in WALL_ERRORS
             and unsuccessful[0].get("failure") == "ValueError: " + error,
             "failure is neither an explicit wall guard nor the narrow deadline-associated TimeoutError")
    return "WALL_LIMIT_FAILED"


def day_seals(root):
    completed, partial = [], []
    days_root = Path(root) / "days"
    if days_root.exists():
        for folder in sorted(days_root.iterdir()):
            need(folder.is_dir() and re.fullmatch(r"\d{4}-\d{2}-\d{2}", folder.name), "unexpected daily source entry")
            frozen.day_start(folder.name)
            prepared, core = folder / "prepared.json", folder / "core_selection.json"
            def local(path):
                return {"path": str(path.relative_to(root)), "sha256": frozen.file_digest(path)}
            if prepared.exists():
                need(core.exists(), "completed day lacks prior core selection seal")
                completed.append({"day_utc": folder.name, "prepared": local(prepared), "core_selection": local(core)})
            elif core.exists():
                partial.append({"day_utc": folder.name, "core_selection": local(core)})
    need(len(partial) <= 1, "more than one incomplete sequential core-selection day")
    if partial and completed:
        need(partial[0]["day_utc"] > completed[-1]["day_utc"], "partial core seal precedes completed days")
    return completed, partial


def make_first_attempt_seal(parent_root, original_plan_path, expected_original_plan_sha256, output):
    """Future root operation after closure; never call on the active A1 attempt."""
    root = Path(parent_root).resolve()
    need(not Path(output).resolve().is_relative_to(root), "closure seal must be outside immutable A1 directory")
    plan_path = bound({"path": str(Path(original_plan_path).resolve()), "sha256": expected_original_plan_sha256}, root)
    plan = read(plan_path)
    need(frozen.canonical(read(root / "frozen_plan.json")) == frozen.canonical(plan), "A1 original plan differs")
    need(frozen.canonical(read(root / "transport" / "plan.json")) == frozen.canonical(plan["collector"]), "A1 collector plan differs")
    session, requests = read(root / "transport" / "session.json"), read(root / "transport" / "requests.json")
    failure = read(root / "failure.json") if (root / "failure.json").exists() else None
    collection = read(root / "collection_result.json") if (root / "collection_result.json").exists() else None
    kind = closure_class(session, requests, failure, collection)
    files = {str(p.relative_to(root)): frozen.file_digest(p) for p in sorted(root.rglob("*.json")) if p.is_file()}
    for name in REQUIRED_PARENT:
        files.setdefault(name, None)
    completed, partial = day_seals(root)
    seal = {"schema_version": "article2_phase16_first_attempt_closure_seal_v1",
            "status": "CLOSED_ORIGINAL_ATTEMPT_PRESERVED", "sealed_utc": stamp(),
            "parent_root": str(root), "original_plan_sha256": expected_original_plan_sha256,
            "attempt_id": session["attempt_id"], "started_utc": session["started_utc"],
            "closed_utc": session["updated_utc"], "closure_class": kind,
            "parent_evidence_bindings": files, "completed_days": completed,
            "partial_core_selection_seals": partial, "original_request_count": len(requests),
            "original_response_bytes": session["retained_response_bytes"],
            "original_wall_seconds_elapsed": session["wall_seconds_elapsed"],
            "producer_status": session["status"], "original_wall_contract_status": "FAILED",
            "timeout_causality_unresolved": kind == TIMEOUT_CLASS,
            "reserved_parent_failed_response_bytes": failed_reservation(requests),
            "inherited_charged_response_bytes": session["retained_response_bytes"] + failed_reservation(requests),
            "original_attempt_compliant_completion": False,
            "note": "Original outcome and exposures remain preserved; this seal is not continuation acceptance."}
    put_new(output, seal)
    return seal


def validate_first_attempt_seal(seal, original_plan, original_sha):
    need(seal["schema_version"] == "article2_phase16_first_attempt_closure_seal_v1"
         and seal["status"] == "CLOSED_ORIGINAL_ATTEMPT_PRESERVED"
         and seal["original_plan_sha256"] == original_sha
         and seal["original_attempt_compliant_completion"] is False, "first-attempt closure seal differs")
    root = Path(seal["parent_root"]).resolve()
    evidence = seal["parent_evidence_bindings"]
    need(type(evidence) is dict and REQUIRED_PARENT <= set(evidence), "required A1 evidence bindings absent")
    actual_names = {str(p.relative_to(root)) for p in root.rglob("*.json") if p.is_file()}
    need(actual_names == {name for name, value in evidence.items() if value is not None}, "A1 JSON artifact inventory changed")
    for name, expected in evidence.items():
        path = parent_path(root, name)
        if expected is None:
            need(not path.exists(), "explicitly absent A1 evidence appeared")
        else:
            need(path.is_file() and frozen.file_digest(path) == frozen.sha(expected, "A1 evidence"), "A1 evidence changed: " + name)
    need(frozen.canonical(read(root / "frozen_plan.json")) == frozen.canonical(original_plan)
         and frozen.canonical(read(root / "transport" / "plan.json")) == frozen.canonical(original_plan["collector"]),
         "A1 plan lineage differs")
    session, requests = read(root / "transport" / "session.json"), read(root / "transport" / "requests.json")
    failure = read(root / "failure.json") if evidence["failure.json"] is not None else None
    collection = read(root / "collection_result.json") if evidence["collection_result.json"] is not None else None
    need(closure_class(session, requests, failure, collection) == seal["closure_class"], "original wall closure classification differs")
    need(seal["producer_status"] == session["status"] and seal["original_wall_contract_status"] == "FAILED",
         "original producer/wall-contract distinction missing")
    need(seal["timeout_causality_unresolved"] is (seal["closure_class"] == TIMEOUT_CLASS), "timeout causal ambiguity must be explicit")
    need(seal["reserved_parent_failed_response_bytes"] == failed_reservation(requests)
         and seal["inherited_charged_response_bytes"] == session["retained_response_bytes"] + failed_reservation(requests),
         "failed-range conservative reservation differs")
    for report in (failure, collection):
        if report is not None:
            need(report.get("transfer_decoding_performed") is False and report.get("detector_scoring_performed") is False,
                 "original collection no longer source-only")
    need(session["attempt_id"] == seal["attempt_id"] == frozen.digest({"plan": frozen.digest(original_plan["collector"]), "started_utc": session["started_utc"]}),
         "A1 attempt identity differs")
    need(seal["started_utc"] == session["started_utc"] and seal["closed_utc"] == session["updated_utc"]
         and utc(seal["sealed_utc"]) >= utc(seal["closed_utc"]), "closure seal ordering differs")
    need((seal["original_request_count"], seal["original_response_bytes"], seal["original_wall_seconds_elapsed"])
         == (len(requests), session["retained_response_bytes"], session["wall_seconds_elapsed"]), "A1 resource exposure differs")
    completed, partial = day_seals(root)
    need(seal["completed_days"] == completed and seal["partial_core_selection_seals"] == partial,
         "completed or partially exposed core-selection inventory differs")
    return root, session, requests


def validate_plan(plan, base):
    need(plan["schema_version"] == "article2_phase16_continuation_source_plan_v1", "continuation plan schema differs")
    need(EXTRA_PLAN <= set(plan), "continuation envelope incomplete")
    baseline = {key: value for key, value in plan.items() if key not in EXTRA_PLAN}
    baseline["schema_version"] = base["schema_version"]
    need(frozen.canonical(baseline) == frozen.canonical(base), "continuation changed original source/science/implementation fields")
    need(frozen.canonical(plan["continuation_transport"]) == frozen.canonical(LIMITS), "continuation limits differ")
    caps = base["collector"]["caps"]
    need(caps["wall_seconds"] == ORIGINAL_WALL and caps["requests"] == LIMITS["cumulative_get_limit"]
         and caps["total_response_bytes"] == LIMITS["cumulative_response_byte_limit"]
         and caps["request_timeout_seconds"] == 60
         and caps["retries"] == 0 and caps["concurrency"] == 1, "original transport bounds differ")


def validate_manual_reacquisition(value, requests, *, closure_kind=None):
    if value is None:
        need(closure_kind != TIMEOUT_CLASS, "deadline-associated timeout requires explicit exact manual reacquisition")
        return
    driver.exact_keys(value, ("parent_request_ordinal", "source_key", "start", "length"), "manual reacquisition")
    need(bool(requests), "manual reacquisition lacks original request")
    last = requests[-1]
    allowed = {"ValueError: " + e for e in WALL_ERRORS}
    if closure_kind == TIMEOUT_CLASS:
        allowed |= {kind + ": " + message for kind, message in TIMEOUT_ERRORS}
    need(last.get("transport_ok") is False and last.get("failure") in allowed,
         "manual reacquisition must be the last explicitly wall-failed GET")
    expected = {"parent_request_ordinal": last["ordinal"], "source_key": last["source"]["key"], "start": last["start"], "length": last["length"]}
    need(frozen.canonical(value) == frozen.canonical(expected), "manual reacquisition descriptor differs")


def validate_amendment(amendment_path, expected_sha256, *, now_utc=None, for_execution=True):
    path = bound({"path": str(Path(amendment_path).resolve()), "sha256": expected_sha256}, Path.cwd())
    amendment = read(path)
    need(amendment["schema_version"] == "article2_phase16_source_continuation_acceptance_v1"
         and amendment["status"] == "ACCEPTED_BEFORE_CONTINUATION_ONLY", "root has not accepted continuation")
    need("accepted_before_affected_payload" not in amendment, "new before-payload assertion is prohibited after A1 exposure")
    need(amendment["accepted_before_continuation_requests"] is True and amendment["source_payload_previously_exposed"] is True,
         "continuation/exposure chronology must be explicit")
    plan_path = bound(amendment["continuation_plan"], path.parent)
    plan = read(plan_path)
    original_path = bound(plan["original_plan_binding"], plan_path.parent)
    original = read(original_path)
    validate_plan(plan, original)
    code_paths = []
    for binding in plan["continuation_execution_bindings"]:
        relative = Path(binding["path"])
        need(not relative.is_absolute() and ".." not in relative.parts, "execution bindings must be repository-relative")
        code_paths.append(bound(binding, REPO).resolve())
    required_paths = {Path(__file__).parent / name for name in REQUIRED_CODE}
    need(required_paths <= set(code_paths) and len(set(code_paths)) == len(code_paths), "required continuation implementation/auditors missing or duplicated")
    seal_path = bound(amendment["first_attempt_seal"], path.parent)
    seal = read(seal_path)
    root, session, requests = validate_first_attempt_seal(seal, original, plan["original_plan_binding"]["sha256"])
    continuation_root = Path(amendment["continuation_output_root"])
    need(continuation_root.is_absolute(), "single continuation output must be an absolute fixed directory")
    continuation_root = continuation_root.resolve()
    need(not continuation_root.is_relative_to(root), "continuation must not mutate the sealed original attempt")
    if for_execution:
        need(not continuation_root.exists(), "accepted continuation destination already used; a second A2 attempt is not authorized")
    need(amendment["parent_evidence_bindings"] == seal["parent_evidence_bindings"], "amendment parent evidence map differs")
    exposure_path = bound(amendment["exposure_report"], path.parent)
    exposure = read(exposure_path)
    need(exposure["schema_version"] == "article2_phase16_source_only_exposure_report_v1"
         and exposure["status"] == "ROOT_REVIEWED_SOURCE_ONLY_EXPOSURE"
         and exposure["first_attempt_seal_sha256"] == amendment["first_attempt_seal"]["sha256"], "source-only exposure report not bound/reviewed")
    need(exposure["source_payload_exposed"] is True
         and exposure["detector_scoring_started"] is False
         and exposure["new_reference_acquisition_started"] is False
         and exposure["performance_or_reference_results_examined"] is False, "amendment not eligible after scores/new labels")
    need(exposure["completed_days"] == [x["day_utc"] for x in seal["completed_days"]]
         and exposure["partial_core_selection_days"] == [x["day_utc"] for x in seal["partial_core_selection_seals"]],
         "exposure report omits already exposed selection")
    need(type(exposure["reviewer"]) is str and bool(exposure["reviewer"].strip())
         and type(exposure["exposure_description"]) is str and bool(exposure["exposure_description"].strip()),
         "root exposure reviewer/description missing")
    accepted = utc(amendment["accepted_utc"])
    need(utc(seal["closed_utc"]) <= utc(seal["sealed_utc"]) <= utc(exposure["reviewed_utc"]) <= accepted,
         "prospective amendment predates original closure/exposure review")
    eligibility_binding = amendment["complete_overwall_source_validity_review"]
    if seal["closure_class"] == "COMPLETE_OVER_ORIGINAL_WALL_LIMIT":
        eligibility_path = bound(eligibility_binding, path.parent)
        eligibility = read(eligibility_path)
        need(eligibility["schema_version"] == "article2_phase16_complete_overwall_eligibility_review_v1"
             and eligibility["status"] == "PASS_SOURCE_VALIDITY_ONLY_ORIGINAL_WALL_CONTRACT_FAILED"
             and eligibility["first_attempt_seal_sha256"] == amendment["first_attempt_seal"]["sha256"]
             and eligibility["original_plan_sha256"] == plan["original_plan_binding"]["sha256"]
             and eligibility["original_collection_result_sha256"] == seal["parent_evidence_bindings"]["collection_result.json"],
             "complete-overwall independent source-validity review not bound")
        need(eligibility["producer_status"] == "COMPLETE" and eligibility["original_wall_contract_status"] == "FAILED"
             and eligibility["all_http_gets_within_original_deadline"] is True
             and eligibility["all_source_parts_and_projection_integrity_valid"] is True
             and eligibility["selection_and_prepared_bundles_valid"] is True
             and eligibility["source_identity_schema_validation_errors"] is False
             and type(eligibility["source_objects"]) is int and eligibility["source_objects"] == 113
             and type(eligibility["study_days"]) is int and eligibility["study_days"] == 37,
             "complete-overwall source validity not independently established")
        need(type(eligibility["reviewer"]) is str and bool(eligibility["reviewer"].strip())
             and utc(seal["sealed_utc"]) <= utc(eligibility["reviewed_utc"]) <= accepted
             and bool(eligibility["evidence_bindings"]), "complete-overwall eligibility review chronology/evidence missing")
        for binding in eligibility["evidence_bindings"]:
            bound(binding, eligibility_path.parent)
    else:
        need(eligibility_binding is None, "ordinary failed-wall branch must not masquerade as complete-source validity")
    deadline = utc(session["started_utc"]) + timedelta(seconds=LIMITS["absolute_deadline_seconds_from_a1_start"])
    need(accepted < deadline, "amendment accepted after absolute cumulative deadline")
    current = utc(now_utc) if now_utc is not None else datetime.now(timezone.utc)
    need(current >= accepted, "amendment timestamp is in the future")
    if for_execution:
        need(current < deadline, "absolute cumulative continuation deadline elapsed")
    originals = amendment["original_measurement_acceptances"]
    need(set(originals) == set(CASES), "both original case acceptances required")
    need(frozen.canonical(read(root / "runtime_acceptances.json")) == frozen.canonical(originals), "original A1 runtime acceptances changed")
    configs = {}
    for cfg_binding in original["case_configs"]:
        cfg_path = bound(cfg_binding, REPO)
        config = driver.validate_config(read(cfg_path))
        configs[config["case_id"]] = (cfg_path, config)
    need(set(configs) == set(CASES), "original case population differs")
    for case, acceptance_binding in originals.items():
        acceptance_path = bound(acceptance_binding, path.parent)
        cfg_path, _ = configs[case]
        acceptance = driver.validate_freeze(acceptance_path, cfg_path, expected_freeze_sha256=acceptance_binding["sha256"])
        wrapper_path = driver.bound_file(acceptance["gate_bindings"]["source_plan"], acceptance_path.parent)
        wrapper = read(wrapper_path)
        need(wrapper["schema_version"] == "article2_phase16_bound_source_execution_gate_v1"
             and wrapper["source_plan"]["sha256"] == plan["original_plan_binding"]["sha256"], "original acceptance/source plan lineage differs")
        driver.bound_file(wrapper["source_plan"], wrapper_path.parent)
        for binding in wrapper["execution_source_bindings"]:
            bound(binding, REPO)
        need(utc(acceptance["accepted_utc"]) <= utc(session["started_utc"]), "original measurement acceptance not before A1")
    validate_manual_reacquisition(amendment["manual_reacquisition"], requests, closure_kind=seal["closure_class"])
    return {"amendment": amendment, "amendment_path": path, "amendment_sha256": expected_sha256,
            "plan": plan, "plan_path": plan_path, "plan_sha256": amendment["continuation_plan"]["sha256"],
            "original_plan": original, "original_plan_path": original_path,
            "first_attempt_seal": seal, "exposure": exposure, "parent_root": root,
            "continuation_output_root": continuation_root,
            "reserved_parent_failed_response_bytes": seal["reserved_parent_failed_response_bytes"],
            "inherited_charged_response_bytes": seal["inherited_charged_response_bytes"],
            "parent_bindings": seal["parent_evidence_bindings"], "manual_reacquisition": amendment["manual_reacquisition"],
            "absolute_deadline_utc": deadline.isoformat(), "original_acceptances": originals}


def validate_amended_source_ready(amendment_path, expected_amendment_sha256, *, transport_audit,
                                  source_review, multiattempt_ledger, binding_parent, now_utc=None):
    """Source gate before assembly; final input manifests do not yet exist."""
    context = validate_amendment(amendment_path, expected_amendment_sha256, now_utc=now_utc, for_execution=False)
    transport_path = bound(transport_audit, binding_parent)
    transport = read(transport_path)
    need(transport["status"] == "PASS_CONTINUATION_TRANSPORT_ORIGINAL_BYTES"
         and transport["continuation_amendment_sha256"] == expected_amendment_sha256
         and transport["plan_sha256"] == context["plan_sha256"]
         and transport["auditor_sha256"] == frozen.file_digest(Path(__file__).parent / "independent_transport_audit.py"),
         "amended transport audit not passed/bound")
    ledger_path = bound(multiattempt_ledger, binding_parent)
    need(frozen.file_digest(ledger_path) == transport["multiattempt_ledger_sha256"], "full multi-attempt cost/failure ledger differs")
    source_path = bound(source_review, binding_parent)
    source = read(source_path)
    need(source["status"] == "PASS_SOURCE_SELECTION_AND_RAW_BUNDLES"
         and source["transport_audit_sha256"] == transport_audit["sha256"]
         and source["continuation_amendment_sha256"] == expected_amendment_sha256
         and source["original_source_plan_sha256"] == context["plan"]["original_plan_binding"]["sha256"]
         and source["plan_sha256"] == context["plan_sha256"]
         and source["reviewer_sha256"] == frozen.file_digest(Path(__file__).parent / "audit_sources.py")
         and source["original_row_auditor_sha256"] == ORIGINAL_ROW_AUDITOR_SHA256
             == frozen.file_digest(PAPER / "phase16" / "qa" / "audit_prepared_sources.py"),
         "amended full source audit not passed/bound")
    prior = source["prior_exposure_comparison"]
    need(prior["status"] == "PASS_INDEPENDENT_PRIOR_EXPOSURE_COMPARISON"
         and prior["first_attempt_seal_sha256"] == context["amendment"]["first_attempt_seal"]["sha256"]
         and prior["completed_days"] == len(context["first_attempt_seal"]["completed_days"])
         and prior["partial_core_selection_days"] == len(context["first_attempt_seal"]["partial_core_selection_seals"]),
         "source reviewer did not preserve exposed original membership/bundles")
    need(set(source["case_audits"]) == set(CASES), "both amended case source audits required")
    for binding in source["case_audits"].values():
        case_audit = read(bound(binding, source_path.parent))
        need(case_audit["status"] == "PASS", "case source audit unavailable")
    return context | {"transport_audit": transport, "source_review": source, "multiattempt_ledger_path": ledger_path}


def validate_pre_replay_authorization(receipt_path, expected_sha256, *, now_utc=None):
    """Current-dated authorization after amended source PASS, before any scores."""
    path = bound({"path": str(Path(receipt_path).resolve()), "sha256": expected_sha256}, Path.cwd())
    receipt = read(path)
    need(receipt["schema_version"] == "article2_phase16_continuation_pre_replay_authorization_v1"
         and receipt["status"] == "ACCEPTED_FOR_FROZEN_REPLAY_AFTER_AMENDED_SOURCE_AUDIT"
         and receipt["accepted_before_replay"] is True
         and receipt["detector_scoring_started"] is False
         and receipt["new_reference_acquisition_started"] is False, "pre-replay authorization missing or exposed")
    need("accepted_before_affected_payload" not in receipt, "pre-replay receipt cannot backdate payload acceptance")
    amendment_path = bound(receipt["continuation_amendment"], path.parent)
    context = validate_amended_source_ready(amendment_path, receipt["continuation_amendment"]["sha256"],
        transport_audit=receipt["transport_audit"], source_review=receipt["source_review"],
        multiattempt_ledger=receipt["multiattempt_ledger"], binding_parent=path.parent, now_utc=now_utc)
    source = context["source_review"]
    accepted = utc(receipt["accepted_utc"])
    current = utc(now_utc) if now_utc is not None else datetime.now(timezone.utc)
    need(current >= accepted, "pre-replay authorization timestamp is in the future")
    need(accepted >= utc(source["completed_utc"]) and accepted >= utc(context["amendment"]["accepted_utc"]), "pre-replay authorization ordering differs")
    need(set(receipt["input_manifests"]) == set(CASES), "both complete case inputs required before replay")
    for cfg_binding in context["original_plan"]["case_configs"]:
        cfg_path = bound(cfg_binding, REPO)
        config = driver.validate_config(read(cfg_path))
        manifest_binding = receipt["input_manifests"][config["case_id"]]
        manifest_path = bound(manifest_binding, path.parent)
        manifest, _ = driver.load_inputs(config, manifest_path, expected_manifest_sha256=manifest_binding["sha256"], expected_config_sha256=cfg_binding["sha256"])
        need(manifest["source_audit"]["sha256"] == source["case_audits"][config["case_id"]]["sha256"], "scored input not bound to amended source review")
    return context | {"pre_replay_authorization": receipt, "pre_replay_authorization_sha256": expected_sha256}


def self_test():
    """New tiny synthetic gate checks only; no real A1 inspection or old suite."""
    checks = []
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    session = {"started_utc": start.isoformat(), "updated_utc": (start + timedelta(seconds=7201)).isoformat(),
               "wall_seconds_elapsed": 7201, "request_count": 0, "retained_response_bytes": 0, "retries": 0, "status": "FAILED"}
    failure = {"error_type": "ValueError", "error": "wall/request cap"}
    need(closure_class(session, [], failure, None) == "WALL_LIMIT_FAILED", "synthetic wall closure")
    checks.append("natural_wall_failure_accepted")
    def reject(fn, label):
        try:
            fn()
        except (ValueError, KeyError):
            checks.append(label)
        else:
            raise AssertionError(label)
    reject(lambda: closure_class(session | {"status": "OPEN"}, [], failure, None), "active_attempt_rejected")
    reject(lambda: closure_class(session | {"wall_seconds_elapsed": 60}, [], failure, None), "early_nonwall_failure_rejected")
    reject(lambda: closure_class(session, [], {"error_type": "TimeoutError", "error": "timed out"}, None), "generic_timeout_rejected")
    reject(lambda: closure_class(session, [], {"error_type": "ValueError", "error": "malformed selected bundle"}, None), "data_integrity_failure_rejected")
    collection = {"status": "COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT"}
    need(closure_class(session | {"status": "COMPLETE"}, [], None, collection) == "COMPLETE_OVER_ORIGINAL_WALL_LIMIT", "synthetic complete-overwall")
    checks.append("complete_overwall_preserves_original_noncompliance")
    last = {"ordinal": 1, "source": {"key": "invented"}, "start": 4, "length": 8,
            "transport_ok": False, "failure": "ValueError: wall cap during range"}
    manual = {"parent_request_ordinal": 1, "source_key": "invented", "start": 4, "length": 8}
    validate_manual_reacquisition(manual, [last]); checks.append("exact_last_wall_get_manual_reacquisition_allowed")
    reject(lambda: validate_manual_reacquisition(manual | {"length": 9}, [last]), "manual_reacquisition_cannot_expand_range")
    reject(lambda: validate_manual_reacquisition(manual, [last | {"failure": "TimeoutError: timed out"}]), "manual_reacquisition_cannot_hide_timeout_retry")
    late = {"ordinal": 1, "source": {"key": "invented", "url": "https://example.invalid/invented", "etag_opaque": '"invented"', "size_bytes": 100},
            "start": 4, "length": 8, "transport_ok": False, "response_bytes": 0,
            "started_utc": (start + timedelta(seconds=7195)).isoformat(),
            "completed_utc": (start + timedelta(seconds=7201)).isoformat(), "failure": "TimeoutError: timed out"}
    timed_session = session | {"request_count": 1}
    timed_failure = {"error_type": "TimeoutError", "error": "timed out"}
    need(closure_class(timed_session, [late], timed_failure, None) == TIMEOUT_CLASS, "narrow timeout association")
    checks.append("late_timeout_allowed_only_with_causal_uncertainty")
    second_message = "The read operation timed out"
    need(closure_class(timed_session, [late | {"failure": "TimeoutError: " + second_message}],
         {"error_type": "TimeoutError", "error": second_message}, None) == TIMEOUT_CLASS, "read timeout whitelist")
    checks.append("exact_read_timeout_whitelist_preserves_verbatim_exception")
    for message in TIMEOUT_MESSAGES:
        wrapped = "<urlopen error " + message + ">"
        need(closure_class(timed_session, [late | {"failure": "URLError: " + wrapped}],
             {"error_type": "URLError", "error": wrapped}, None) == TIMEOUT_CLASS, "exact urlopen timeout wrapper")
    checks.append("only_two_exact_urlopen_timeout_wrappers_are_recognized")
    dns = "<urlopen error [Errno -3] Temporary failure in name resolution>"
    reject(lambda: closure_class(timed_session, [late | {"failure": "URLError: " + dns}],
           {"error_type": "URLError", "error": dns}, None), "generic_urlerror_dns_failure_rejected")
    ssl = "<urlopen error _ssl.c:989: The handshake operation timed out>"
    reject(lambda: closure_class(timed_session, [late | {"failure": "URLError: " + ssl}],
           {"error_type": "URLError", "error": ssl}, None), "ssl_handshake_wrapper_not_authorized")
    reject(lambda: closure_class(timed_session, [late | {"started_utc": (start + timedelta(seconds=7139)).isoformat()}], timed_failure, None),
           "earlier_network_timeout_cannot_be_retried")
    reject(lambda: closure_class(timed_session, [late | {"completed_utc": (start + timedelta(seconds=7199)).isoformat()}], timed_failure, None),
           "timeout_before_deadline_not_eligible")
    reject(lambda: closure_class(timed_session, [late | {"http_status": 206}], timed_failure, None),
           "partial_response_headers_not_promoted_to_valid_timeout")
    reject(lambda: closure_class(timed_session | {"retained_response_bytes": 1}, [late | {"response_bytes": 1}], timed_failure, None),
           "unknown_headers_with_retained_body_not_eligible")
    with_headers = late | {"http_status": 206, "response_url": late["source"]["url"], "etag": '"invented"',
                          "content_range": "bytes 4-11/100", "content_length": "8", "content_encoding": None, "response_bytes": 3}
    need(closure_class(timed_session | {"retained_response_bytes": 3}, [with_headers], timed_failure, None) == TIMEOUT_CLASS,
         "valid partial body timeout association")
    need(failed_reservation([with_headers]) == 5 and with_headers["response_bytes"] == 3, "retained/reserved distinction")
    checks.append("failed_range_charged_in_full_without_rewriting_retained_bytes")
    reject(lambda: closure_class(timed_session | {"retained_response_bytes": 3}, [with_headers | {"http_status": 403}], timed_failure, None),
           "observed_bad_headers_ineligible_even_at_deadline")
    reject(lambda: validate_manual_reacquisition(None, [late], closure_kind=TIMEOUT_CLASS), "late_timeout_requires_explicit_manual_reacquisition")
    validate_manual_reacquisition(manual, [late], closure_kind=TIMEOUT_CLASS)
    checks.append("exact_late_timeout_manual_reacquisition_is_separately_declared")
    reject(lambda: closure_class(timed_session, [late | {"length": LIMITS["cumulative_response_byte_limit"] + 1}], timed_failure, None),
           "full_failed_range_reservation_cannot_exceed_original_budget")
    baseline = {"schema_version": "original", "collector": {"caps": {"wall_seconds": 7200, "requests": 5000,
        "total_response_bytes": 17179869184, "request_timeout_seconds": 60, "retries": 0, "concurrency": 1}}, "science": "invented fixed values"}
    plan = baseline | {"schema_version": "article2_phase16_continuation_source_plan_v1", "original_plan_binding": {},
                       "continuation_transport": LIMITS.copy(), "continuation_execution_bindings": []}
    validate_plan(plan, baseline); checks.append("only_explicit_continuation_envelope_added")
    reject(lambda: validate_plan(plan | {"science": "changed"}, baseline), "science_field_change_rejected")
    reject(lambda: validate_plan(plan | {"continuation_transport": LIMITS | {"cumulative_get_limit": 5001}}, baseline), "cumulative_budget_expansion_rejected")
    with tempfile.TemporaryDirectory(prefix="phase16_continuation_gate_synthetic_") as folder:
        root = Path(folder)
        (root / "days" / "2022-02-19").mkdir(parents=True)
        (root / "days" / "2022-02-19" / "core_selection.json").write_text('{"synthetic_only":true}\n')
        completed, partial = day_seals(root)
        need(not completed and len(partial) == 1, "partial selection exposure lost")
        checks.append("partial_day_core_selection_sealed_before_prepared_day")
        reject(lambda: parent_path(root, "../outside.json"), "parent_evidence_path_escape_rejected")
    return {"status": "PASS_CANDIDATE_SYNTHETIC_GATES_ONLY", "checks_passed": len(checks), "checks": checks,
            "protocol_sha256": frozen.file_digest(__file__), "real_attempts_read": 0, "acquisition_requests": 0,
            "root_continuation_accepted": False, "old_suites_run": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("self-test")
    seal = sub.add_parser("seal-first-attempt")
    for name in ("parent-root", "original-plan", "output"):
        seal.add_argument("--" + name, type=Path, required=True)
    seal.add_argument("--expected-original-plan-sha256", required=True)
    check = sub.add_parser("validate-amendment")
    check.add_argument("--amendment", type=Path, required=True)
    check.add_argument("--expected-amendment-sha256", required=True)
    args = parser.parse_args(argv)
    if args.command == "self-test":
        print(json.dumps(self_test(), sort_keys=True))
    elif args.command == "seal-first-attempt":
        result = make_first_attempt_seal(args.parent_root, args.original_plan, args.expected_original_plan_sha256, args.output)
        print(json.dumps({"status": result["status"], "closure_class": result["closure_class"]}))
    else:
        result = validate_amendment(args.amendment, args.expected_amendment_sha256)
        print(json.dumps({"status": "VALID_PROSPECTIVE_CONTINUATION_GATE", "absolute_deadline_utc": result["absolute_deadline_utc"]}))


if __name__ == "__main__":
    main()
