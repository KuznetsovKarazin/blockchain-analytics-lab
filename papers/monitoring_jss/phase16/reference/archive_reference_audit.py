"""Offline post-decision candidate identity/coverage audit from retained sources.

Reads only authenticated block/TX/log identity/address projections, never topics,
data, transfers, scores or primary attack roles. Emits join-compatible source
audit records and separate identity facts; primary adjudication remains external.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
PAPER = HERE.parents[1]
REPO = PAPER.parents[1]
sys.path.insert(0, str(HERE))
import exact_reference_join as join
sys.path.insert(0, str(PAPER / "phase16" / "qa"))
import audit_prepared_sources as independent

need = join.require
frozen = join.frozen
CAP = 64
WALL_SECONDS = 20 * 60
DAY_NS = frozen.DAY_NS


class AuditDeadlineExceeded(TimeoutError):
    pass


def check_deadline(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise AuditDeadlineExceeded("fixed archive execution-audit wall cap reached")


def ranged_sha(path, start, length, deadline=None):
    result = hashlib.sha256()
    with Path(path).open("rb") as handle:
        handle.seek(start)
        remaining = length
        while remaining:
            check_deadline(deadline)
            data = handle.read(min(4 * 1024**2, remaining))
            need(bool(data), "truncated retained source range")
            result.update(data)
            remaining -= len(data)
    check_deadline(deadline)
    return result.hexdigest()


def file_binding(path):
    path = Path(path).resolve()
    return {"path": str(path), "sha256": frozen.file_digest(path)}


def select_candidates(document, expected_study_sha, study_sealed_utc):
    need(document["schema_version"] == "article2_phase16_primary_candidate_inventory_v1"
         and document["status"] == "PRIMARY_CANDIDATES_EXTRACTED_NOT_ADJUDICATED"
         and document["decision_study_sha256"] == expected_study_sha, "candidate stage/study binding differs")
    need(join.utc(document["created_utc"]) >= join.utc(study_sealed_utc), "candidate extraction precedes sealed decisions")
    need([case["case_id"] for case in document["cases"]] == list(join.CASES), "candidate case set/order differs")
    result = []
    for case in document["cases"]:
        seen = set()
        for candidate in case["candidates"]:
            key = candidate["chain_id"], candidate["transaction_hash"]
            need(type(key[0]) is int and key[0] == 1 and type(key[1]) is str
                 and frozen.HEX32.fullmatch(key[1]), "canonical Ethereum candidate identity required")
            need(key not in seen, "duplicate candidate identity; resolve source roles before audit")
            seen.add(key)
        # Sorting is independent of source selection, decisions and scores.
        ordered = sorted(case["candidates"], key=lambda c: (c["chain_id"], c["transaction_hash"]))
        result.append({"case_id": case["case_id"], "candidates": [
            {**value, "audit_rank": index, "within_cap": index <= CAP}
            for index, value in enumerate(ordered, 1)]})
    return result


def verify_current_source(source, manifest, transport_entry, request_records, deadline=None):
    """Re-authenticate bytes before OfflineSource may parse any metadata/rows."""
    identity = {k: source[k] for k in ("table", "day_utc", "key", "size_bytes", "etag_opaque", "url")}
    need(manifest["source"] == identity and transport_entry["source"] == identity
         and transport_entry["source_key"] == source["key"], "current source identity differs")
    path = Path(transport_entry["path"])
    need(path.is_file() and path.stat().st_size == source["size_bytes"], "retained source size differs")
    spans = transport_entry["available_ranges"]
    if transport_entry["whole_source_sha256_verified"] is True:
        need(not request_records and spans == [[0, source["size_bytes"]]], "whole reuse/range evidence inconsistent")
        need(ranged_sha(path, 0, source["size_bytes"], deadline) == transport_entry["whole_source_sha256"], "current whole source bytes changed")
    else:
        need(transport_entry["whole_source_sha256_verified"] is False and bool(request_records), "range evidence missing")
        need(frozen.digest(request_records) == transport_entry["range_receipts_canonical_sha256"], "range receipt binding differs")
        intervals = []
        for record in request_records:
            need(record["source"] == identity and record["transport_ok"] is True, "range source/status differs")
            start, length = record["start"], record["length"]
            need(type(start) is int and type(length) is int and 0 <= start < start + length <= source["size_bytes"], "range bounds differ")
            need(ranged_sha(path, start, length, deadline) == record["response_sha256"], "current original range bytes changed")
            intervals.append([start, start + length])
        merged = []
        for start, end in sorted(intervals):
            if merged and start <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        need(merged == spans, "available interval evidence differs")
    footer = transport_entry["original_footer_evidence"]
    size = source["size_bytes"]
    need(independent.covered(0, 4, spans) and independent.covered(size - 8, size, spans), "footer envelope not retained")
    with path.open("rb") as handle:
        need(handle.read(4) == b"PAR1", "leading Parquet magic differs")
        handle.seek(size - 8)
        trailer = handle.read(8)
    length = int.from_bytes(trailer[:4], "little")
    start = size - 8 - length
    need(trailer[4:] == b"PAR1" and 4 <= start < size - 8
         and independent.covered(start, size, spans), "footer contains unacquired bytes")
    need(footer["footer_start"] == start and footer["footer_length"] == length
         and footer["leading_magic_sha256"] == ranged_sha(path, 0, 4, deadline)
         and footer["footer_and_trailer_sha256"] == ranged_sha(path, start, size - start, deadline), "audited footer bytes changed")


def validate_tx_metadata(tx, headers, pa, pc, np):
    need(pc.count_distinct(tx["transaction_hash"]).as_py() == len(tx), "duplicate candidate-source TX hash")
    need(independent.all_true(pc.is_in(tx["dataset_execution_status"], value_set=pa.array([0, 1], type=pa.int64())), pc),
         "unknown archive transaction status")
    positions = pc.index_in(tx["block_number"], value_set=headers["block_number"])
    need(positions.null_count == 0, "candidate-source TX header missing")
    for name in ("block_hash", "event_time_ns"):
        need(independent.all_true(pc.equal(tx[name], pc.take(headers[name], positions)), pc), "candidate-source TX/header differs")
    need(independent.all_true(pc.less(tx["transaction_index"], pc.take(headers["transaction_count"], positions)), pc),
         "candidate-source transaction index outside block")
    ordered = tx.select(["block_number", "transaction_index"]).take(pc.sort_indices(tx, sort_keys=[
        ("block_number", "ascending"), ("transaction_index", "ascending")]))
    blocks, indices = (ordered[name].to_numpy() for name in ordered.column_names)
    need(not bool(np.any((blocks[1:] == blocks[:-1]) & (indices[1:] == indices[:-1]))), "duplicate candidate-source TX position")
    counts = np.bincount(positions.to_numpy(), minlength=len(headers))
    need(bool(np.array_equal(counts, headers["transaction_count"].to_numpy())), "candidate-source TX table incomplete")


def inspect_day(day, tx, logs, headers, active_case_runs, candidate_keys, expected_counts, pa, pc, np):
    """Read-normalized whole projections only; reviewed counts forbid filtering."""
    need(len(tx) == expected_counts["all_transaction_rows"] and len(logs) == expected_counts["all_log_identity_rows"],
         "reference scan incomplete against independently reviewed row totals")
    independent.metadata_and_identities(tx, logs, headers, pa, pc, np)
    need(independent.all_true(pc.and_(pc.greater_equal(tx["event_time_ns"], frozen.day_start(day)),
         pc.less(tx["event_time_ns"], frozen.day_start(day) + DAY_NS)), pc), "candidate-source TX outside scanned UTC day")
    counts_by_case = {}
    for case_id, run in active_case_runs.items():
        addresses = pa.array(run["config"]["population_addresses"], type=pa.string())
        core = logs.filter(pc.is_in(logs["address"], value_set=addresses))
        counts = defaultdict(int)
        for txhash in core["transaction_hash"].to_pylist():
            counts[txhash] += 1
        expected = {key[1]: obs for key, obs in run["observations"].items()
                    if frozen.day_start(day) <= obs["transaction"]["event_time_ns"] < frozen.day_start(day) + DAY_NS}
        need(set(counts) == set(expected), "complete core scan differs from sealed selection membership")
        need(all(expected[h]["archived_core_log_count"] == n for h, n in counts.items()), "complete core scan count differs from sealed selection")
        counts_by_case[case_id] = counts
    wanted = pa.array(sorted({h for chain, h in candidate_keys if chain == 1}), type=pa.string())
    found = tx.filter(pc.is_in(tx["transaction_hash"], value_set=wanted)).to_pylist()
    result = {}
    for row in found:
        identity = {key: 1 if key == "chain_id" else row[key] for key in join.driver.TX_KEYS}
        join.identity(identity)
        for case_id, run in active_case_runs.items():
            selected = run["observations"].get((1, row["transaction_hash"]))
            if selected is not None:
                need(identity == selected["transaction"], "candidate exact identity differs from selected observation")
        result[row["transaction_hash"]] = {"day_utc": day, "transaction": identity,
            "dataset_execution_status": row["dataset_execution_status"],
            "core_counts": {case: counts.get(row["transaction_hash"], 0) for case, counts in counts_by_case.items()}}
    return result


def load_context(args):
    # This validates both complete run seals and every selected row. The frozen
    # join itself is pinned by the supplied study seal before references exist.
    study, runs = join.load_study(args.study_manifest, args.expected_study_sha256)
    need(study.get("reference_archive_auditor_sha256") == frozen.file_digest(__file__),
         "archive auditor differs from pre-reference study seal")
    need(all(run["status"] == "COMPLETE" for run in runs), "archive route requires both complete audited source/run stages")
    document = join.pinned(args.candidates, args.expected_candidates_sha256)
    candidates = select_candidates(document, args.expected_study_sha256, study["sealed_utc"])
    transport = join.pinned(args.transport_audit, args.expected_transport_audit_sha256)
    source_review = join.pinned(args.source_review, args.expected_source_review_sha256)
    need(transport["schema_version"] == "article2_phase16_independent_transport_audit_v1"
         and transport["status"] == "PASS_TRANSPORT_ORIGINAL_BYTES", "independent transport audit not passed")
    need(source_review["schema_version"] == "phase16_independent_actual_source_review_v1"
         and source_review["status"] == "PASS_SOURCE_SELECTION_AND_RAW_BUNDLES"
         and source_review["transport_audit_sha256"] == args.expected_transport_audit_sha256
         and source_review["reviewer_sha256"] == frozen.file_digest(independent.__file__), "independent source review not passed/bound")
    plans = []
    for entry, run in zip(study["cases"], runs):
        acceptance_path = join.binding(entry["measurement_acceptance"], args.study_manifest.parent)
        acceptance = join.read(acceptance_path)
        wrapper_path = join.driver.bound_file(acceptance["gate_bindings"]["source_plan"], acceptance_path.parent)
        wrapper = join.read(wrapper_path)
        need(wrapper["schema_version"] == "article2_phase16_bound_source_execution_gate_v1", "source execution gate differs")
        plan_path = join.driver.bound_file(wrapper["source_plan"], wrapper_path.parent)
        need(frozen.file_digest(plan_path) == transport["plan_sha256"] == source_review["plan_sha256"], "case/source plan seals differ")
        for code in wrapper["execution_source_bindings"]:
            join.binding(code, REPO)
        plans.append(join.read(plan_path))
        audit_path = join.binding(source_review["case_audits"][entry["case_id"]], args.source_review.parent)
        need(frozen.file_digest(audit_path) == run["source_audit"]["sha256"], "source review does not bind scored case audit")
    need(frozen.canonical(plans[0]) == frozen.canonical(plans[1]), "case plans differ")
    plan = plans[0]
    collection = join.pinned(args.collection / "collection_result.json", transport["collection_result_sha256"])
    need(collection["plan_sha256"] == transport["plan_sha256"]
         and collection["status"] == "COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT"
         and source_review["collection_result_sha256"] == transport["collection_result_sha256"], "audits bind different collection")
    need(frozen.canonical(join.read(args.collection / "frozen_plan.json")) == frozen.canonical(plan), "runtime plan differs")
    manifests = join.pinned(args.collection / "transport_sources.json", transport["transport_sources_sha256"])
    paths = join.pinned(args.collection / "runtime_source_paths.json", transport["runtime_source_paths_sha256"])
    join.pinned(args.collection / "transport" / "session.json", transport["session_sha256"])
    requests = join.pinned(args.collection / "transport" / "requests.json", transport["requests_sha256"])
    inventory = join.read(join.binding(plan["source_union"], REPO))
    verified = {item["source_key"]: item for item in transport["verified_sources"]}
    manifests = manifests["sources"] if type(manifests) is dict else manifests
    manifests_by_key = {item["source"]["key"]: item for item in manifests}
    sources = {item["key"]: item for item in inventory["objects"]}
    need(len(sources) == len(inventory["objects"]) == len(verified) == len(transport["verified_sources"])
         == len(manifests_by_key) == len(manifests) == 113
         and set(sources) == set(verified) == set(manifests_by_key) == set(paths), "113-source population differs")
    need(all(Path(paths[key]).resolve() == Path(verified[key]["path"]).resolve() for key in sources), "retained source path map differs")
    review_days = {item["day_utc"]: item for item in source_review["days"]}
    study_days = independent.days(plan["study_start"], plan["study_end_exclusive"])
    need(len(study_days) == len(review_days) == len(source_review["days"]) == 37
         and list(review_days) == study_days, "independently reviewed study-day coverage differs")
    need(set(study_days) == {day for run in runs for day in join.driver.expected_days(run["config"])}, "case windows/source union differ")
    request_map = defaultdict(list)
    for record in requests:
        need(record["source"]["key"] in sources, "request outside declared source union")
        request_map[record["source"]["key"]].append(record)
    return study, runs, candidates, plan, sources, manifests_by_key, verified, request_map, review_days


def make_record(case, candidate, match, run, evidence, context_bindings, *, scan_complete=True):
    """Produce source facts only; never promote a candidate to an attack label."""
    txhash = candidate["transaction_hash"]
    audit = {"schema_version": "article2_phase16_reference_source_audit_v1", "case_id": case,
        "chain_id": 1, "transaction_hash": txhash, "identity_status": "UNAVAILABLE",
        "success_status": "UNAVAILABLE", "core_selection_status": "UNAVAILABLE", "core_log_count": None,
        "full_core_scan_or_terminal_logs_complete": False, "identity_evidence": [], "selection_evidence": [],
        "evidence_tier": "UNAVAILABLE", "rationale": ""}
    facts = {"case_id": case, "chain_id": 1, "transaction_hash": txhash,
             "audit_rank": candidate["audit_rank"], "within_cap": candidate["within_cap"],
             "actual_identity_or_unavailable": None, "success_status_or_unavailable": "UNAVAILABLE",
             "in_fixed_window": None, "attack_role_adjudicated": False}
    if not candidate["within_cap"]:
        facts["archive_disposition"] = "UNVERIFIED_DUE_TO_CAP"
        audit["rationale"] = "Beyond frozen 64-candidate per-case canonical-order archive audit cap; identity/status/coverage unavailable."
    elif not scan_complete:
        facts["archive_disposition"] = "UNVERIFIED_DUE_TO_CAP"
        audit["rationale"] = "Shared conservative 20-minute archive execution-audit deadline reached before complete declared-union verification; no partial scan or selected-file absence promoted to an identity/coverage claim."
    elif match is None:
        facts["archive_disposition"] = "UNAVAILABLE_NOT_LOCATED_IN_DECLARED_SOURCE_UNION"
        audit["rationale"] = "Exact hash not located in the complete declared 37-day TX metadata projections. This does not establish nonexistence or a date outside the fixed window; provider fallback or unresolved adjudication remains separate."
    else:
        tx = match["transaction"]
        inside = frozen.day_start(run["config"]["window"]["start_date_utc"]) <= tx["event_time_ns"] < frozen.day_start(run["config"]["window"]["end_date_utc_exclusive"])
        success = "SUCCESS" if match["dataset_execution_status"] == 1 else "FAILED"
        facts.update(actual_identity_or_unavailable=tx, success_status_or_unavailable=success, in_fixed_window=inside,
                     archive_disposition="VERIFIED_ARCHIVE_IDENTITY" if inside else "VERIFIED_OUTSIDE_FIXED_WINDOW")
        audit.update(identity_status="VERIFIED", success_status=success, identity_evidence=[evidence, *context_bindings],
                     evidence_tier="ENUMERATED_SOURCE_ARCHIVE")
        if inside:
            count = match["core_counts"][case]
            selected = run["observations"].get((1, txhash))
            need((count > 0) == (selected is not None), "candidate core/selection membership mismatch")
            audit.update(core_selection_status="SELECTED" if count else "OBSERVED_NO_CORE_EMITTER", core_log_count=count,
                         full_core_scan_or_terminal_logs_complete=True, selection_evidence=[evidence, *context_bindings])
            audit["rationale"] = "Exact archive TX identity/status/header checked; every declared day log identity/address row group reread under passed independent source/transport audits. Core-emitter count matched sealed selection. Nonselected topics/data were neither required nor decoded; no receipt-root/full-chain proof or attack-role inference."
        else:
            audit["rationale"] = "Exact archive TX identity/status/header verified within the shared source union but outside this case's fixed 30-day window. No within-window selection or detector outcome assigned."
    return audit, facts


def run(args):
    need(not args.output.exists(), "fresh reference audit output required")
    context = load_context(args)
    study, runs, candidates, plan, sources, manifests, verified, requests, review_days = context
    sys.path.insert(0, str(args.dependencies.resolve()))
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.parquet as pq
    import numpy as np
    need(pa.__version__ == plan["pyarrow_version"] == "26.0.0"
         and Path(pa.__file__).resolve().is_relative_to(args.dependencies.resolve()), "archive auditor parser/version differs")
    need(np.__version__ == plan["numpy_version"] == "2.3.5", "archive auditor NumPy differs")
    started = time.monotonic()
    deadline = started + WALL_SECONDS
    by_day = defaultdict(lambda: defaultdict(list))
    for source in sources.values():
        by_day[source["day_utc"]][source["table"]].append(source)
    readers = {}
    def open_sources(day, kind):
        need(bool(by_day[day][kind]), "required source day/table missing")
        values = []
        for source in by_day[day][kind]:
            key = source["key"]
            if key not in readers:
                check_deadline(deadline)
                verify_current_source(source, manifests[key], verified[key], requests[key], deadline)
                reader = independent.OfflineSource(source, manifests[key], verified[key], pa, pq)
                check_deadline(deadline)
                original_read = reader.read
                def bounded_read(group, columns, original=original_read):
                    check_deadline(deadline)
                    value = original(group, columns)
                    check_deadline(deadline)
                    return value
                reader.read = bounded_read
                readers[key] = reader
            values.append(readers[key])
        return values
    # Every boundary header source is already in the 113-object frozen union.
    headers = {}
    keys = {(c["chain_id"], c["transaction_hash"]) for case in candidates for c in case["candidates"] if c["within_cap"]}
    wanted = pa.array(sorted({h for _, h in keys}), type=pa.string())
    matches, day_evidence = {}, []
    time_cap_reached = False
    try:
        for day in sorted(by_day):
            headers[day] = independent.header_rows(open_sources(day, "blocks"), day, pa, pc)[0]
            check_deadline(deadline)
        for left, right in zip(sorted(headers), sorted(headers)[1:]):
            need(frozen.day_start(right) - frozen.day_start(left) == DAY_NS, "missing calendar header day")
            independent.link(headers[left].slice(len(headers[left]) - 1, 1).to_pylist()[0], headers[right].slice(0, 1).to_pylist()[0])
        for day, reviewed in review_days.items():
            tx, tx_records = independent.full_projection(open_sources(day, "transactions"), "transactions", pa, pc)
            need(len(tx) == reviewed["all_transaction_rows"], "TX scan row total differs from independent review")
            validate_tx_metadata(tx, headers[day], pa, pc, np)
            check_deadline(deadline)
            candidates_in_day = tx.filter(pc.is_in(tx["transaction_hash"], value_set=wanted))
            logs_read, log_records = False, []
            found = {}
            if len(candidates_in_day):
                logs, log_records = independent.full_projection(open_sources(day, "logs"), "logs", pa, pc)
                active = {run["case_id"]: run for run in runs if day in join.driver.expected_days(run["config"])}
                found = inspect_day(day, tx, logs, headers[day], active, keys, reviewed, pa, pc, np)
                check_deadline(deadline)
                need(not (set(found) & set(matches)), "candidate hash occurs in multiple declared source days")
                matches.update(found)
                logs_read = True
            day_evidence.append({"day_utc": day, "full_transaction_rows": len(tx), "transaction_row_groups": tx_records,
                "all_log_identity_address_rows_scanned": logs_read,
                "full_log_identity_rows": reviewed["all_log_identity_rows"] if logs_read else None,
                "log_identity_row_groups": log_records, "candidate_matches": found})
            print(f"Reference identity scan {day}: {len(found)} bounded candidate hashes; no attack-role adjudication", flush=True)
        check_deadline(deadline)
    except AuditDeadlineExceeded:
        time_cap_reached = True
        matches = {}  # Conservative: partial union scan yields no accepted facts.
    elapsed = time.monotonic() - started
    context_bindings = [file_binding(args.study_manifest), file_binding(args.transport_audit), file_binding(args.source_review)]
    # Output is created only after all referenced sources/gates pass. Originals
    # remain untouched; these are reference-side artifacts, never replay inputs.
    args.output.mkdir(parents=True)
    evidence = {"schema_version": "article2_phase16_archive_reference_projection_evidence_v1",
        "status": "CLOSED_UNAVAILABLE_TIME_CAP" if time_cap_reached else "PASS",
        "created_utc": datetime.now(timezone.utc).isoformat(), "decision_study_sha256": args.expected_study_sha256,
        "candidate_inventory_sha256": args.expected_candidates_sha256, "context_bindings": context_bindings,
        "archive_auditor_sha256": frozen.file_digest(__file__), "offline_reader_sha256": frozen.file_digest(independent.__file__),
        "independently_transport_checked_source_objects": 113, "sources_reauthenticated_and_opened": len(readers),
        "shared_execution_wall_cap_seconds": WALL_SECONDS, "execution_wall_seconds": elapsed,
        "time_cap_reached": time_cap_reached, "complete_declared_union_scan": not time_cap_reached,
        "days": day_evidence, "network_requests": 0, "nonselected_topics_or_data_decoded": False,
        "detector_scores_computed": 0, "attack_roles_adjudicated": 0,
        "scope": "Exact identities/status and full-day core emitter coverage at enumerated archive-source tier. Missing hash stays unavailable; no chain-wide nonexistence, receipt-root authentication or primary attack attribution."}
    frozen.write_json(args.output / "projection_evidence.json", evidence)
    evidence_binding = file_binding(args.output / "projection_evidence.json")
    output_cases = []
    run_by_case = {run["case_id"]: run for run in runs}
    for case in candidates:
        facts = []
        folder = args.output / case["case_id"]
        folder.mkdir()
        for candidate in case["candidates"]:
            audit, fact = make_record(case["case_id"], candidate,
                matches.get(candidate["transaction_hash"]), run_by_case[case["case_id"]], evidence_binding, context_bindings,
                scan_complete=not time_cap_reached)
            target = folder / (candidate["transaction_hash"] + ".json")
            frozen.write_json(target, audit)
            fact["source_coverage_audit_binding"] = file_binding(target)
            facts.append(fact)
        output_cases.append({"case_id": case["case_id"], "candidates": facts,
                             "candidate_count": len(facts), "audit_cap": CAP,
                             "over_cap_count": sum(not f["within_cap"] for f in facts)})
    result = {"schema_version": "article2_phase16_archive_reference_audit_result_v1",
        "status": "CLOSED_UNAVAILABLE_TIME_CAP" if time_cap_reached else "COMPLETE_SOURCE_FACTS_ONLY",
        "decision_study_sha256": args.expected_study_sha256, "candidate_inventory_sha256": args.expected_candidates_sha256,
        "archive_auditor_sha256": frozen.file_digest(__file__), "projection_evidence": evidence_binding,
        "time_cap_reached": time_cap_reached, "shared_execution_wall_cap_seconds": WALL_SECONDS,
        "execution_wall_seconds": elapsed,
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
    print(result["status"] + ": " + str(sum(c["candidate_count"] for c in result["cases"])) + " retained candidate records")


if __name__ == "__main__":
    main()
