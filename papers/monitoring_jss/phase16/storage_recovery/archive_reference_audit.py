"""Storage recovery-aware, post-decision archive reference facts; no retrieval/labels.

The pinned original source-fact engine remains untouched. The complete A1/A2
cost ledger stays bound; only its independently audited successful-byte view is
passed to the independent compact reader. No original-plan or attempt substitution.
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
PROTOCOL_SHA256 = "3b5003147d59cfd13f28adf614bb2859f8d6d1c6a3923ccd3c77e34944d261e0"


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
protocol = load_pinned("phase16_reference_storage_recovery_protocol", HERE / "protocol.py", PROTOCOL_SHA256)
join, frozen, need = engine.join, engine.frozen, engine.need
independent = engine.independent


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
    need(receipt["schema_version"] == "article2_phase16_storage_recovery_replay_launcher_receipt_v1"
         and receipt["status"] == "COMPLETE_BOTH_CASES_SEALED"
         and receipt["labels_used"] is False and receipt["reference_acquisition_performed"] is False,
         "both-case unlabelled authorized replay receipt missing")
    need(receipt["replay_launcher_sha256"] == auth["replay_launcher_sha256"] == sha(HERE / "run_replays.py")
         and receipt["original_driver_sha256"] == sha(join.driver.__file__), "replay launcher/driver code differs")
    need(receipt['protocol_sha256'] == PROTOCOL_SHA256 and receipt['driver_invocations'] == 2
         and receipt['retries'] == 0
         and receipt['reference_archive_source_engine_sha256'] == auth['reference_archive_source_engine_sha256'] == ENGINE_SHA256,
         'launcher execution or source-engine contract differs')
    for field in ('reference_archive_auditor', 'reference_compact_reader'):
        auth_base = Path(expected_bindings['pre_replay_authorization']['path']).parent
        need(normalized_binding(receipt[field], receipt_path.parent) == normalized_binding(auth[field], auth_base),
             'launcher future-reference implementation binding differs: ' + field)
    need(Path(auth["replay_output_root"]).is_absolute()
         and receipt_path.parent.resolve() == Path(auth["replay_output_root"]).resolve(), "launcher receipt outside authorized output")
    for field, expected in expected_bindings.items():
        need(normalized_binding(receipt[field], receipt_path.parent) == expected, "launcher authorization/audit lineage differs: " + field)
    need(normalized_cases(receipt["cases"], receipt_path.parent) == normalized_cases(study["cases"], study_base),
         "launcher/study exact case bindings differ")
    need(join.utc(auth["accepted_utc"]) <= join.utc(receipt["started_utc"]) <= join.utc(receipt["completed_utc"])
         <= join.utc(study["sealed_utc"]), "launcher/study chronology differs")
    return receipt


def validate_successful_view(ledger, accepted, inherited, new, session, transport, context, sources, auditor):
    """Retain the unresolved parent GET in every complete cost ledger."""
    need(ledger['schema_version'] == 'article2_phase16_storage_recovery_multiattempt_ledger_v1'
         and ledger['status'] == 'VERIFIED_RECORDED_COSTS_WITH_FULL_UNRESOLVED_PENDING_RESERVATION'
         and ledger['inherited_requests'] == inherited and ledger['new_requests'] == new
         and ledger['limits'] == protocol.LIMITS, 'full unresolved/original/new cost ledger differs')
    parent_session = protocol.read(context['parent_root'] / 'transport/session.json')
    need(sha(context['parent_root'] / 'transport/requests.json') == transport['inherited_requests_sha256'],
         'accepted original request prefix has been filtered or changed')
    costs = auditor.validate_cost_ledgers(inherited, new, parent_session, session, sources,
        context['original_plan']['collector']['caps'], context['amendment']['accepted_utc'], context['manual_reacquisition'])
    origins = costs.pop('accepted_origins')
    need(all(ledger.get(k) == value and transport.get(k) == value for k, value in costs.items()),
         'reported cumulative known/unknown/reserved costs differ')
    need(costs['parent_pending_response_bytes'] is None and costs['actual_cumulative_response_bytes_complete'] is False
         and costs['wire_bytes_measured'] is False and costs['new_failed_requests'] == 0,
         'unknown parent bytes or failed recovery were promoted into complete evidence')
    need(accepted['schema_version'] == 'article2_phase16_compact_accepted_ranges_v1'
         and [{k: v for k, v in row.items() if k != 'blob'} for row in accepted['ranges']] == origins,
         'accepted ranges must be the exact successful-origin view of the full ledger')
    grouped = defaultdict(list)
    for row in accepted['ranges']:
        grouped[row['receipt']['source']['key']].append(row)
    return grouped, costs


def verify_source_metadata(source, manifest, verified, ranges, collection, provenance):
    """Match byte proofs to original receipts before the independent reader opens."""
    need(manifest['source'] == verified['source'] == source
         and verified['source_key'] == source['key']
         and manifest['storage_kind'] == verified['storage_kind'], 'archive source identity/storage differs')
    receipts = [row['receipt'] for row in ranges]
    need(manifest['successful_original_ranges'] == receipts and manifest['evidence_origins'] == ranges
         and verified['range_receipts_canonical_sha256'] == frozen.digest(receipts),
         'source accepted ranges omit, alter or promote a request')
    if verified['storage_kind'] == 'compact_descriptor':
        descriptor = Path(verified['descriptor_path'])
        need(descriptor.resolve().is_relative_to(collection.resolve()) and sha(descriptor) == verified['descriptor_sha256']
             == manifest['descriptor_sha256'], 'audited compact descriptor changed')
        expected = []
        for row in ranges:
            receipt, blob = row['receipt'], row['blob']
            path = protocol.parent_path(collection, blob['path'])
            need(blob['size_bytes'] == receipt['length'] == receipt['response_bytes']
                 and blob['sha256'] == receipt['response_sha256'] and receipt['transport_ok'] is True,
                 'blob does not represent an exact successful original response')
            expected.append({'start': receipt['start'], 'length': receipt['length'], 'path': str(path),
                             'sha256': blob['sha256'], 'origin_attempt_id': row['origin_attempt_id'],
                             'origin_ordinal': row['origin_ordinal'], 'receipt_sha256': frozen.digest(receipt)})
        expected.sort(key=lambda row: row['start'])
        need(expected == verified['verified_blobs']
             and verified['available_ranges'] == [[r['start'], r['start'] + r['length']] for r in expected]
             and manifest['whole_source_sha256_verified'] is False and manifest['whole_source_sha256'] is None,
             'compact bytes differ from accepted-range proof; holes cannot become source bytes')
    else:
        need(verified['storage_kind'] == 'verified_whole_object' and ranges == [], 'whole object replaced acquired range evidence')
        expectation = provenance['expected'][source['key']]
        origin = verified['whole_object_origin']
        need(verified['sha256'] == expectation['expected_whole_object_sha256'] == manifest['whole_source_sha256']
             and verified['available_ranges'] == [[0, source['size_bytes']]]
             and manifest['whole_source_sha256_verified'] is True
             and origin['recovery_receipt_sha256'] == provenance['recovery_receipt_sha256']
             and origin['original_manifest_sha256'] == provenance['original_manifest_sha256']
             and origin['prior_independent_acquisition_review_sha256'] == provenance['prior_independent_acquisition_review_sha256']
             and origin['prior_verified_archive_sha256'] == expectation['expected_archive_sha256']
             and origin['fresh_zip_reads'] == 0, 'prior whole-object provenance differs')


def load_context(args):
    study, runs = join.load_study(args.study_manifest, args.expected_study_sha256)
    need(study.get('reference_archive_auditor_sha256') == sha(__file__)
         and study.get('reference_archive_source_engine_sha256') == ENGINE_SHA256,
         'storage archive code/engine not pinned before reference acquisition')
    need(all(run['status'] == 'COMPLETE' for run in runs), 'archive facts require both complete sealed decisions')
    base = args.study_manifest.parent
    auth_binding = study['storage_recovery_pre_replay_authorization']
    auth_path = join.binding(auth_binding, base)
    context = protocol.validate_pre_replay_authorization(auth_path, auth_binding['sha256'])
    auth = context['pre_replay_authorization']
    amendment_binding = study['storage_recovery_amendment']
    amendment_path = join.binding(amendment_binding, base)
    need(amendment_binding['sha256'] == context['amendment_sha256']
         and amendment_path.resolve() == context['amendment_path'].resolve(), 'study/pre-replay amendment differs')
    ledger_path = join.binding(study['multiattempt_ledger'], base)
    need(ledger_path.resolve() == context['multiattempt_ledger_path'].resolve(), 'study/pre-replay ledger differs')
    expected_bindings = {'pre_replay_authorization': engine.file_binding(auth_path),
        'storage_recovery_amendment': engine.file_binding(amendment_path), 'multiattempt_ledger': engine.file_binding(ledger_path),
        'source_review': normalized_binding(auth['source_review'], auth_path.parent),
        'transport_audit': normalized_binding(auth['transport_audit'], auth_path.parent)}
    launcher_path = join.binding(study['replay_launcher_receipt'], base)
    launcher = validate_launcher(launcher_path, study, base, auth, expected_bindings)
    need(auth['reference_archive_auditor']['sha256'] == study['reference_archive_auditor_sha256']
         and normalized_binding(auth['reference_archive_auditor'], auth_path.parent)['path'] == str(Path(__file__).resolve()),
         'archive implementation differs from prospective replay authorization')
    compact_binding = normalized_binding(auth['reference_compact_reader'], auth_path.parent)
    need(compact_binding['sha256'] == study['reference_compact_reader_sha256']
         and compact_binding['path'] == str((HERE / 'independent_compact_reader.py').resolve()), 'compact reader pin differs')
    compact = load_pinned('phase16_archive_independent_compact_reader', HERE / 'independent_compact_reader.py', compact_binding['sha256'])
    for entry in study['cases']:
        need(entry['input_manifest']['sha256'] == auth['input_manifests'][entry['case_id']]['sha256'], 'scored input differs from authorized input')
        run_manifest = join.read(join.binding(entry['run_manifest'], base))
        need(join.utc(auth['accepted_utc']) <= join.utc(run_manifest['started_utc'])
             <= join.utc(run_manifest['completed_utc']) <= join.utc(launcher['completed_utc']), 'authorized replay chronology differs')
    transport = join.pinned(args.transport_audit, args.expected_transport_audit_sha256)
    review = join.pinned(args.source_review, args.expected_source_review_sha256)
    need(auth['transport_audit']['sha256'] == args.expected_transport_audit_sha256
         and auth['source_review']['sha256'] == args.expected_source_review_sha256
         and transport['schema_version'] == 'article2_phase16_independent_storage_recovery_transport_audit_v1'
         and transport['status'] == 'PASS_STORAGE_RECOVERY_TRANSPORT_ORIGINAL_BYTES'
         and transport['multiattempt_ledger_sha256'] == study['multiattempt_ledger']['sha256']
         and transport['fresh_zip_reads'] == 0, 'storage audit provenance differs')
    need(frozen.canonical(transport) == frozen.canonical(context['transport_audit'])
         and frozen.canonical(review) == frozen.canonical(context['source_review']), 'pre-replay/reference audits differ')
    auditor = load_pinned('phase16_archive_independent_transport_functions', HERE / 'independent_transport_audit.py', transport['auditor_sha256'])
    plan = context['plan']
    need(args.collection.resolve() == context['recovery_output_root'].resolve(), 'archive collection differs from accepted A2')
    collection = join.pinned(args.collection / 'collection_result.json', transport['collection_result_sha256'])
    need(collection['schema_version'] == 'phase16_storage_recovery_collection_result_v1'
         and collection['status'] == 'COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT'
         and collection['plan_sha256'] == context['plan_sha256']
         and collection['storage_recovery_amendment_sha256'] == amendment_binding['sha256']
         and collection['original_plan_binding'] == plan['original_plan_binding']
         and review['collection_result_sha256'] == transport['collection_result_sha256'], 'recovered collection differs')
    need(sha(args.collection / 'frozen_plan.json') == context['plan_sha256']
         and sha(args.collection / 'storage_recovery_amendment.json') == amendment_binding['sha256'], 'runtime recovery plan/amendment changed')
    manifests_raw = join.pinned(args.collection / 'transport_sources.json', transport['transport_sources_sha256'])
    locations = join.pinned(args.collection / 'runtime_source_storage.json', transport['runtime_source_storage_sha256'])
    session = join.pinned(args.collection / 'transport/session.json', transport['session_sha256'])
    inherited = join.pinned(args.collection / 'transport/inherited_requests.json', transport['inherited_requests_sha256'])
    new = join.pinned(args.collection / 'transport/requests.json', transport['requests_sha256'])
    accepted = join.pinned(args.collection / 'transport/accepted_range_evidence.json', transport['accepted_range_evidence_sha256'])
    need(session['schema_version'] == 'article2_phase16_storage_recovery_capture_v1' and session['status'] == 'COMPLETE'
         and session['recovery_plan_sha256'] == context['plan_sha256'], 'recovery session not complete/bound')
    ledger = join.read(ledger_path)
    need(ledger['storage_recovery_amendment_sha256'] == amendment_binding['sha256']
         and ledger['plan_sha256'] == context['plan_sha256']
         and ledger['original_source_plan_sha256'] == plan['original_plan_binding']['sha256']
         and ledger['inherited_requests_sha256'] == transport['inherited_requests_sha256']
         and ledger['new_requests_sha256'] == transport['requests_sha256'], 'full ledger identities differ')
    inventory = join.read(join.binding(plan['source_union'], REPO))
    sources = {item['key']: auditor.identity(item) for item in inventory['objects']}
    manifests = {item['source']['key']: item for item in manifests_raw['sources']}
    verified = {item['source_key']: item for item in transport['verified_sources']}
    need(len(sources) == len(inventory['objects']) == len(manifests) == len(manifests_raw['sources'])
         == len(verified) == len(transport['verified_sources']) == 113
         and set(sources) == set(manifests) == set(verified) == set(locations), '113-source population differs')
    ranges, costs = validate_successful_view(ledger, accepted, inherited, new, session, transport, context, sources, auditor)
    need(args.expected_recovery_receipt_sha256 == transport['recovery_receipt_sha256'], 'whole-source recovery receipt differs')
    provenance = auditor.prepare_whole_provenance(plan, REPO, args.recovery_receipt, args.expected_recovery_receipt_sha256)
    for key, source in sources.items():
        v = verified[key]
        path_field = 'descriptor_path' if v['storage_kind'] == 'compact_descriptor' else 'path'
        need(locations[key]['storage_kind'] == v['storage_kind']
             and Path(locations[key]['path']).resolve() == Path(v[path_field]).resolve(), 'typed source location differs')
        verify_source_metadata(source, manifests[key], v, ranges[key], args.collection, provenance)
    review_days = {item['day_utc']: item for item in review['days']}
    days = independent.days(plan['study_start'], plan['study_end_exclusive'])
    need(len(days) == len(review_days) == len(review['days']) == 37 and list(review_days) == days
         and set(days) == {day for run in runs for day in join.driver.expected_days(run['config'])}, 'full audited day union differs')
    for run in runs:
        audit = join.binding(review['case_audits'][run['case_id']], args.source_review.parent)
        need(sha(audit) == run['source_audit']['sha256'], 'archive source review differs from scored source audit')
    candidates = engine.select_candidates(join.pinned(args.candidates, args.expected_candidates_sha256),
        args.expected_study_sha256, study['sealed_utc'])
    retained = [engine.file_binding(path) for path in (args.study_manifest, auth_path, amendment_path, ledger_path,
        launcher_path, args.transport_audit, args.source_review, args.recovery_receipt)]
    return {'runs': runs, 'candidates': candidates, 'plan': plan, 'sources': sources, 'manifests': manifests,
            'verified': verified, 'ranges': ranges, 'review_days': review_days, 'context_bindings': retained,
            'ledger': ledger, 'costs': costs, 'ledger_binding': engine.file_binding(ledger_path),
            'amendment_sha256': amendment_binding['sha256'], 'authorization_sha256': auth_binding['sha256'],
            'compact': compact, 'provenance': provenance}


def make_source_reader(compact, source, manifest, verified, pa, pq, deadline):
    """Add the archive deadline to identical SHA checks in this private import.

    The frozen reader file is unchanged. Its constructor resolves the module's
    hash function at runtime; the wrapper streams the same complete bytes with
    the frozen archive engine's per-chunk deadline checks, then restores it.
    This operation is sequential and affects only this private imported module.
    """
    original_sha = compact.sha
    def bounded_sha(path):
        return engine.ranged_sha(Path(path), 0, Path(path).stat().st_size, deadline)
    compact.sha = bounded_sha
    try:
        engine.check_deadline(deadline)
        reader = compact.IndependentCompactSource(source, manifest, verified, pa, pq)
        engine.check_deadline(deadline)
        return reader
    finally:
        compact.sha = original_sha


def run(args):
    need(not args.output.exists(), "fresh storage_recovery reference audit output required")
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
        need(bool(by_day[day][kind]), "required storage_recovery source day/table missing")
        result = []
        for source in by_day[day][kind]:
            key = source["key"]
            if key not in readers:
                engine.check_deadline(deadline)
                verify_source_metadata(source, context["manifests"][key], context["verified"][key], context["ranges"][key], args.collection, context["provenance"])
                reader = make_source_reader(context["compact"], source, context["manifests"][key], context["verified"][key], pa, pq, deadline)
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
            print(f"Storage recovery reference scan {day}: {len(found)} candidate hashes; no attack-role adjudication", flush=True)
        engine.check_deadline(deadline)
    except engine.AuditDeadlineExceeded:
        capped, matches = True, {}
    elapsed = time.monotonic() - started
    args.output.mkdir(parents=True)
    evidence = {"schema_version": "article2_phase16_storage_recovery_archive_reference_projection_evidence_v1",
        "status": "CLOSED_UNAVAILABLE_TIME_CAP" if capped else "PASS", "created_utc": datetime.now(timezone.utc).isoformat(),
        "decision_study_sha256": args.expected_study_sha256, "candidate_inventory_sha256": args.expected_candidates_sha256,
        "archive_auditor_sha256": sha(__file__), "archive_source_engine_sha256": ENGINE_SHA256,
        "storage_recovery_protocol_sha256": PROTOCOL_SHA256, "context_bindings": context["context_bindings"],
        "full_multiattempt_ledger": context["ledger_binding"], "full_cost_accounting": context["costs"],
        "storage_recovery_amendment_sha256": context["amendment_sha256"], "pre_replay_authorization_sha256": context["authorization_sha256"],
        "shared_execution_wall_cap_seconds": engine.WALL_SECONDS, "execution_wall_seconds": elapsed,
        "time_cap_reached": capped, "complete_declared_union_scan": not capped,
        "independently_transport_checked_source_objects": 113, "sources_reauthenticated_and_opened": len(readers),
        "days": days, "network_requests": 0, "nonselected_topics_or_data_decoded": False,
        "detector_scores_computed": 0, "attack_roles_adjudicated": 0,
        "scope": "Source facts under explicit one-storage-recovery authorization; original A1 disposition and every failed cost retained. No receipt-root proof, attack-role inference, or nonexistent-transaction claim."}
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
    result = {"schema_version": "article2_phase16_storage_recovery_archive_reference_audit_result_v1",
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
    for name in ("study-manifest", "candidates", "collection", "transport-audit", "source-review", "recovery-receipt", "dependencies", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("study", "candidates", "transport-audit", "source-review", "recovery-receipt"):
        parser.add_argument("--expected-" + name + "-sha256", required=True)
    result = run(parser.parse_args(argv))
    print(result["status"] + ": " + str(sum(case["candidate_count"] for case in result["cases"])) + " retained candidates")


if __name__ == "__main__":
    main()
