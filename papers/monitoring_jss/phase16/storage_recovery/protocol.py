"""Prospective storage/resource recovery gate; never treats ENOSPC as wall closure.
Only metadata are read here. Existing source exposure remains explicit; all A1
checkpoints and the unused wall-continuation candidate remain unchanged.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

PAPER = Path(__file__).resolve().parents[2]
REPO = PAPER.parents[1]
DRIVER_SHA256 = "591a8e09cd1920496ad0acc8fb13a1f4c62a0a224b3d8925ec364fff91ed293d"
_driver = PAPER / "phase15" / "driver" / "fixed_address_replay.py"
if hashlib.sha256(_driver.read_bytes()).hexdigest() != DRIVER_SHA256:
    raise ValueError("frozen driver changed before gate import")
sys.path.insert(0, str(_driver.parent))
import fixed_address_replay as driver
frozen = driver.frozen
need = driver.require
CASES = ("lifi_20220320", "revest_20220327")
ORIGINAL_WALL = 7200
RUNTIME_ROOT = Path("/tmp/article2_phase16_runtime_159bf77d8682")
LIMITS = {"absolute_deadline_seconds_from_a1_start": 14400,
          "cumulative_get_limit": 5000, "cumulative_response_byte_limit": 17179869184,
          "automatic_retries": 0, "maximum_explicit_manual_reacquisitions": 1,
          "pending_get_byte_charge": "FULL_DECLARED_RANGE_LENGTH",
          "source_storage": "IMMUTABLE_RANGE_BLOBS_STRICT_ARROW_VIEW",
          "pending_parent_range_accepted": False}
EXTRA_PLAN = {"original_plan_binding", "storage_recovery_transport", "storage_recovery_execution_bindings"}
REQUIRED_CODE = {"protocol.py", "compact_collector.py", "pipeline.py", "independent_transport_audit.py",
                 "independent_compact_reader.py", "audit_sources.py"}
FORENSIC_NAMES = {"metadata_inventory", "allocation_review", "path_relocation",
                  "external_resource_failure_attestation", "accepted_range_review"}
REQUIRED_PARENT = {"frozen_plan.json", "runtime_acceptances.json", "transport/plan.json",
                   "transport/session.json", "transport/requests.json", "runtime_source_paths.json",
                   "transport/requests.json.pending", "failure.json", "collection_result.json"}
ORIGINAL_ROW_AUDITOR_SHA256 = "385bff732afac356bf890193153b08d3751b5a3fbfd4788dab500176a0a03a62"

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
    driver.exact_keys(binding, ("path", "sha256"), "recovery binding")
    need(type(binding["path"]) is str and bool(binding["path"]), "empty binding path")
    path = Path(binding["path"])
    path = path if path.is_absolute() else Path(parent) / path
    need(path.is_file() and frozen.file_digest(path) == frozen.sha(binding["sha256"], "recovery binding"),
         "bound recovery file changed: " + str(path))
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


def validate_pending_checkpoint(session, requests):
    """The final persisted zero is a placeholder, never a measured byte count."""
    need(session['status'] == 'OPEN_REQUEST_PENDING' and session['retries'] == 0,
         'resource recovery requires preserved pending checkpoint, not synthesized failure')
    need(type(requests) is list and len(requests) >= 1
         and session['request_count'] == len(requests) < LIMITS['cumulative_get_limit']
         and [r['ordinal'] for r in requests] == list(range(1, len(requests) + 1)),
         'committed request prefix incomplete or request cap exhausted')
    start, updated = utc(session['started_utc']), utc(session['updated_utc'])
    need(abs((updated - start).total_seconds() - session['wall_seconds_elapsed']) <= 2,
         'last committed monotonic/UTC clocks inconsistent')
    previous = start
    for r in requests[:-1]:
        need(r.get('transport_ok') is True and 'failure' not in r
             and type(r['response_bytes']) is int and r['response_bytes'] == r['length'] > 0
             and previous <= utc(r['started_utc']) <= utc(r['completed_utc']) <= updated
             and utc(r['completed_utc']) <= start + timedelta(seconds=ORIGINAL_WALL),
             'successful request prefix invalid or already over original wall')
        frozen.sha(r['response_sha256'], 'accepted response')
        previous = utc(r['completed_utc'])
    pending = requests[-1]
    need(utc(pending['started_utc']) < start + timedelta(seconds=ORIGINAL_WALL),
         'pending GET was not started inside the original wall deadline')
    need(pending.get('transport_ok') is False and pending.get('response_bytes') == 0
         and pending.get('completed_utc') is None and 'failure' not in pending
         and pending.get('response_sha256') is None
         and previous <= utc(pending['started_utc']) <= updated
         and type(pending['length']) is int and pending['length'] > 0
         and type(pending['start']) is int and pending['start'] >= 0
         and pending['start'] + pending['length'] <= pending['source']['size_bytes'],
         'last record is not the exact unresolved pending GET')
    need(not ({'http_status', 'response_url', 'etag', 'content_range', 'content_length', 'content_encoding'} & set(pending)),
         'pending checkpoint unexpectedly contains final response evidence')
    known = sum(r['response_bytes'] for r in requests[:-1])
    need(session['retained_response_bytes'] == known
         and known + pending['length'] <= LIMITS['cumulative_response_byte_limit'],
         'known prefix plus full pending-range charge exceeds original byte budget')
    return known, pending


def validate_manual_reacquisition(value, requests):
    driver.exact_keys(value, ('parent_request_ordinal', 'source_key', 'start', 'length'), 'pending reacquisition')
    last = requests[-1]
    expected = {'parent_request_ordinal': last['ordinal'], 'source_key': last['source']['key'],
                'start': last['start'], 'length': last['length']}
    need(value == expected and last.get('transport_ok') is False,
         'only the exact unresolved final pending range may be reacquired once')


def forensic_documents(bindings, parent):
    need(type(bindings) is dict and set(bindings) == FORENSIC_NAMES, 'forensic binding set differs')
    need(all(Path(b['path']).is_absolute() for b in bindings.values()), 'forensic bindings must use explicit absolute paths')
    return {name: read(bound(binding, parent)) for name, binding in bindings.items()}


def validate_external_evidence(documents, bindings, root, session, requests, parent):
    known, pending = validate_pending_checkpoint(session, requests)
    att = documents['external_resource_failure_attestation']
    need(att['schema_version'] == 'article2_phase16_external_resource_failure_attestation_v1'
         and att['status'] == 'ROOT_OBSERVED_TERMINATED_ENOSPC_ORIGINAL_CHECKPOINT_UNCHANGED',
         'external ENOSPC termination attestation missing')
    terminal, observation, checkpoint = att['terminal_observation'], att['process_observation'], att['original_checkpoint']
    need(terminal['exit_code'] == 1
         and terminal['reported_primary_exception'] == 'OSError: [Errno 28] No space left on device'
         and bool(terminal['tool_output_chunk_id']) and bool(terminal['source_of_attestation']),
         'external terminal observation does not establish requested ENOSPC failure')
    lower, upper = utc(observation['last_observed_running_utc']), utc(observation['first_observed_ended_utc'])
    need(utc(session['updated_utc']) <= lower <= upper <= utc(att['attested_utc'])
         and observation['exact_failure_time_known'] is False, 'external closure bracket/order differs')
    bound(observation['runtime_observer_log'], parent)
    for field, expected in {'status': session['status'], 'attempt_id': session['attempt_id'],
                            'started_utc': session['started_utc'], 'last_updated_utc': session['updated_utc'],
                            'wall_seconds_elapsed': session['wall_seconds_elapsed'],
                            'request_count': len(requests), 'successful_request_count': len(requests)-1,
                            'committed_successful_response_bytes': known}.items():
        need(checkpoint[field] == expected, 'external attestation checkpoint differs: ' + field)
    terminal_request = checkpoint['failed_terminal_request']
    expected_pending = {'ordinal': pending['ordinal'], 'source_key': pending['source']['key'],
                        'start': pending['start'], 'length': pending['length'],
                        'persisted_response_bytes_placeholder': 0, 'actual_terminal_received_bytes': None,
                        'actual_terminal_written_bytes': None,
                        'response_completion_and_identity_headers_persisted': False,
                        'accepted_for_source_use': False, 'conservative_charge_bytes': pending['length']}
    need(terminal_request == expected_pending, 'unresolved pending exposure has been promoted or altered')
    need(att['conservative_parent_response_byte_charge'] == known + pending['length']
         and att['producer_failure_json_exists'] is False and att['producer_collection_result_exists'] is False
         and att['committed_metadata_rewritten'] is False and att['canonical_source_bytes_changed_by_root'] is False
         and att['source_payload_decoded_by_original_collection'] is True
         and att['new_detector_scores_computed'] == 0 and att['new_reference_requests'] == 0
         and att['wall_continuation_eligible'] is False, 'external source-only resource closure conditions differ')
    supported = {binding['sha256'] for binding in att['supporting_evidence']}
    need({bindings[k]['sha256'] for k in FORENSIC_NAMES - {'external_resource_failure_attestation'}} <= supported,
         'attestation does not bind all forensic evidence')
    for binding in att['supporting_evidence']:
        bound(binding, parent)
    inventory = documents['metadata_inventory']
    summary = inventory['summary']
    need(inventory['schema_version'] == 'article2_phase16_readonly_a1_metadata_forensics_v1'
         and summary['all_files_stable_during_read'] is True
         and all(session.get(k) == v for k, v in summary['session'].items())
         and summary['committed_request_records'] == len(requests)
         and summary['committed_successful_requests'] == len(requests)-1
         and summary['committed_response_bytes_sum'] == known
         and summary['committed_incomplete_ordinals'] == [pending['ordinal']]
         and summary['cache_successful_range_records'] == len(requests)-1
         and summary['cache_accepted_response_bytes_sum'] == known
         and summary['session_counts_match_committed_requests'] is True
         and summary['complete_attempt_costs_established'] is False
         and summary['failure_json_exists'] is False and summary['collection_result_json_exists'] is False,
         'metadata forensic prefix/completeness evidence differs')
    for key in ('cache_receipt_mismatch_ordinals', 'cache_non_successful_ordinals',
                'duplicate_cache_ordinals', 'successful_committed_requests_missing_cache'):
        need(summary[key] == [], 'forensic successful prefix not uniquely authenticated: ' + key)
    for item in inventory['files']:
        path = parent_path(root, item['path'])
        need(path.is_file() and path.stat().st_size == item['size_bytes']
             and frozen.file_digest(path) == item['sha256'], 'forensic metadata changed: ' + item['path'])
    allocation = documents['allocation_review']
    need(allocation['schema_version'] == 'phase16_enospc_allocation_review_v1'
         and allocation['status'] == 'FORENSIC_METADATA_ONLY_NO_SCIENTIFIC_ADMISSION'
         and allocation['capture_mutations_by_this_reviewer'] is False
         and allocation['source_payload_read_by_this_report'] is False
         and allocation['metadata_inventory']['sha256'] == bindings['metadata_inventory']['sha256'],
         'allocation review provenance differs')
    relocation = documents['path_relocation']
    need(relocation['schema_version'] == 'article2_phase16_forensic_path_relocation_v1'
         and relocation['capture_file_contents_modified'] is False
         and Path(relocation['current_physical_root']).resolve() == root
         and Path(relocation['old_logical_root']).is_symlink()
         and Path(relocation['old_logical_root']).resolve() == root,
         'original logical/physical path relocation differs')
    mapped = relocation['metadata_sha256_before_and_after']
    expected = {item['path']: item['sha256'] for item in inventory['files'] if item['checkpoint_kind'] == 'COMMITTED_FILENAME'}
    need(mapped == expected, 'relocation did not preserve every committed metadata hash')
    for name, digest in mapped.items():
        need(frozen.file_digest(parent_path(root, name)) == digest, 'relocated metadata changed')
    accepted = documents['accepted_range_review']
    need(accepted['status'] == 'CANONICAL_ACCEPTED_RANGES_HASH_VERIFIED_AUXILIARY_COPIES_REMOVED'
         and accepted['verified_successful_requests'] == len(requests)-1
         and accepted['verified_response_bytes'] == known
         and accepted['canonical_capture_files_changed'] is False
         and accepted['pending_request_not_promoted'] is True,
         'accepted original ranges not independently hash reviewed')
    return known, pending, lower, upper


def evidence_inventory(root):
    files = {str(p.relative_to(root)): frozen.file_digest(p) for p in sorted(root.rglob('*'))
             if p.is_file() and (p.name.endswith('.json') or p.name.endswith('.json.pending'))}
    for name in REQUIRED_PARENT:
        files.setdefault(name, None)
    return files


def make_external_closure_seal(parent_root, original_plan_path, expected_original_plan_sha256,
                               forensic_bindings, output, *, binding_parent=None):
    root = Path(parent_root).resolve()
    need(root == RUNTIME_ROOT / 'attempt1', 'A1 recovery parent must be the fixed relocated capture')
    need(not Path(output).resolve().is_relative_to(root), 'external seal must remain outside A1')
    parent = Path(binding_parent or Path.cwd())
    plan = read(bound({'path': str(Path(original_plan_path).resolve()), 'sha256': expected_original_plan_sha256}, parent))
    session, requests = read(root / 'transport/session.json'), read(root / 'transport/requests.json')
    docs = forensic_documents(forensic_bindings, parent)
    known, pending, lower, upper = validate_external_evidence(docs, forensic_bindings, root, session, requests, parent)
    need(frozen.canonical(read(root / 'frozen_plan.json')) == frozen.canonical(plan)
         and frozen.canonical(read(root / 'transport/plan.json')) == frozen.canonical(plan['collector']),
         'original A1 plan changed')
    evidence = evidence_inventory(root)
    need(evidence['failure.json'] is None and evidence['collection_result.json'] is None,
         'external closure cannot overwrite producer closure evidence')
    completed, partial = day_seals(root)
    seal = {'schema_version': 'article2_phase16_external_resource_closure_seal_v1',
            'status': 'EXTERNALLY_CLOSED_ENOSPC_CHECKPOINT_PRESERVED', 'sealed_utc': stamp(),
            'parent_root': str(root), 'original_plan_sha256': expected_original_plan_sha256,
            'attempt_id': session['attempt_id'], 'started_utc': session['started_utc'],
            'process_end_lower_bound_utc': lower.isoformat(), 'process_end_upper_bound_utc': upper.isoformat(),
            'producer_status': session['status'], 'closure_class': 'EXTERNAL_ENOSPC_TERMINATION',
            'original_attempt_compliant_completion': False, 'parent_evidence_bindings': evidence,
            'completed_days': completed, 'partial_core_selection_seals': partial,
            'forensic_bindings': forensic_bindings, 'original_request_count': len(requests),
            'original_successful_request_count': len(requests)-1, 'known_parent_response_bytes': known,
            'pending_received_bytes': None, 'reserved_parent_pending_response_bytes': pending['length'],
            'inherited_charged_response_bytes': known + pending['length'],
            'actual_parent_response_bytes_complete': False}
    validate_external_closure_seal(seal, plan, expected_original_plan_sha256, parent)
    put_new(output, seal)
    return seal


def validate_external_closure_seal(seal, original_plan, original_sha, parent):
    need(seal['schema_version'] == 'article2_phase16_external_resource_closure_seal_v1'
         and seal['status'] == 'EXTERNALLY_CLOSED_ENOSPC_CHECKPOINT_PRESERVED'
         and seal['closure_class'] == 'EXTERNAL_ENOSPC_TERMINATION'
         and seal['original_plan_sha256'] == original_sha
         and seal['original_attempt_compliant_completion'] is False,
         'external resource closure seal differs')
    root = Path(seal['parent_root']).resolve()
    need(root == RUNTIME_ROOT / 'attempt1', 'unexpected original capture location')
    evidence = seal['parent_evidence_bindings']
    need(evidence == evidence_inventory(root) and REQUIRED_PARENT <= set(evidence), 'A1 metadata inventory changed')
    need(evidence['failure.json'] is None and evidence['collection_result.json'] is None,
         'producer status was rewritten after external resource closure')
    need(evidence['transport/requests.json.pending'] == hashlib.sha256(b'').hexdigest(),
         'original empty failed checkpoint changed or promoted')
    need(frozen.canonical(read(root / 'frozen_plan.json')) == frozen.canonical(original_plan)
         and frozen.canonical(read(root / 'transport/plan.json')) == frozen.canonical(original_plan['collector']),
         'original plan lineage changed')
    session, requests = read(root / 'transport/session.json'), read(root / 'transport/requests.json')
    docs = forensic_documents(seal['forensic_bindings'], parent)
    known, pending, lower, upper = validate_external_evidence(docs, seal['forensic_bindings'], root, session, requests, parent)
    expected = {'producer_status': 'OPEN_REQUEST_PENDING', 'attempt_id': session['attempt_id'],
                'started_utc': session['started_utc'], 'original_request_count': len(requests),
                'original_successful_request_count': len(requests)-1, 'known_parent_response_bytes': known,
                'pending_received_bytes': None, 'reserved_parent_pending_response_bytes': pending['length'],
                'inherited_charged_response_bytes': known + pending['length'],
                'actual_parent_response_bytes_complete': False}
    need(all(seal[k] == v for k, v in expected.items()), 'external closure resource exposure differs')
    need(session['attempt_id'] == frozen.digest({'plan': frozen.digest(original_plan['collector']), 'started_utc': session['started_utc']}),
         'original attempt identity differs')
    need(utc(seal['process_end_lower_bound_utc']) == lower and utc(seal['process_end_upper_bound_utc']) == upper
         and utc(docs['external_resource_failure_attestation']['attested_utc']) <= utc(seal['sealed_utc']),
         'external seal chronology differs')
    complete, partial = day_seals(root)
    need(seal['completed_days'] == complete and seal['partial_core_selection_seals'] == partial,
         'already exposed selection/prepared inventory changed')
    return root, session, requests




def validate_plan(plan, base):
    need(plan["schema_version"] == "article2_phase16_storage_recovery_source_plan_v1", "recovery plan schema differs")
    need(EXTRA_PLAN <= set(plan), "recovery envelope incomplete")
    baseline = {key: value for key, value in plan.items() if key not in EXTRA_PLAN}
    baseline["schema_version"] = base["schema_version"]
    need(frozen.canonical(baseline) == frozen.canonical(base), "recovery changed original source/science/implementation fields")
    need(frozen.canonical(plan["storage_recovery_transport"]) == frozen.canonical(LIMITS), "recovery limits differ")
    caps = base["collector"]["caps"]
    need(caps["wall_seconds"] == ORIGINAL_WALL and caps["requests"] == LIMITS["cumulative_get_limit"]
         and caps["total_response_bytes"] == LIMITS["cumulative_response_byte_limit"]
         and caps["request_timeout_seconds"] == 60
         and caps["retries"] == 0 and caps["concurrency"] == 1, "original transport bounds differ")


def make_candidate_recovery_plan(original_plan_path, expected_original_plan_sha256, output):
    original_path = bound({'path': str(Path(original_plan_path).resolve()), 'sha256': expected_original_plan_sha256}, Path.cwd())
    original = read(original_path)
    bindings = [{'path': str((Path(__file__).parent / name).relative_to(REPO)),
                 'sha256': frozen.file_digest(Path(__file__).parent / name)} for name in sorted(REQUIRED_CODE)]
    plan = original | {'schema_version': 'article2_phase16_storage_recovery_source_plan_v1',
                       'original_plan_binding': file_binding(original_path),
                       'storage_recovery_transport': LIMITS.copy(),
                       'storage_recovery_execution_bindings': bindings}
    validate_plan(plan, original)
    put_new(output, plan)
    return plan



def validate_recovery_amendment(amendment_path, expected_sha256, *, now_utc=None, for_execution=True):
    path = bound({"path": str(Path(amendment_path).resolve()), "sha256": expected_sha256}, Path.cwd())
    amendment = read(path)
    need(amendment["schema_version"] == "article2_phase16_storage_recovery_acceptance_v1"
         and amendment["status"] == "ACCEPTED_BEFORE_RECOVERY_IMPORT_AND_REQUESTS_ONLY", "root has not accepted recovery")
    need("accepted_before_affected_payload" not in amendment, "new before-payload assertion is prohibited after A1 exposure")
    need(amendment["accepted_before_recovery_requests"] is True
         and amendment["accepted_before_recovery_source_import"] is True
         and amendment["source_payload_previously_exposed"] is True,
         "recovery/exposure chronology must be explicit")
    plan_path = bound(amendment["recovery_plan"], path.parent)
    plan = read(plan_path)
    original_path = bound(plan["original_plan_binding"], plan_path.parent)
    original = read(original_path)
    validate_plan(plan, original)
    code_paths = []
    for binding in plan["storage_recovery_execution_bindings"]:
        relative = Path(binding["path"])
        need(not relative.is_absolute() and ".." not in relative.parts, "execution bindings must be repository-relative")
        code_paths.append(bound(binding, REPO).resolve())
    required_paths = {Path(__file__).parent / name for name in REQUIRED_CODE}
    need(required_paths == set(code_paths) and len(set(code_paths)) == len(code_paths), "required six recovery implementation/auditors missing, extra or duplicated")
    seal_path = bound(amendment["first_attempt_seal"], path.parent)
    seal = read(seal_path)
    root, session, requests = validate_external_closure_seal(seal, original, plan["original_plan_binding"]["sha256"], path.parent)
    recovery_root = Path(amendment["recovery_output_root"])
    need(recovery_root.is_absolute(), "single recovery output must be an absolute fixed directory")
    recovery_root = recovery_root.resolve()
    need(recovery_root == RUNTIME_ROOT / 'attempt2' and not recovery_root.is_relative_to(root),
         "recovery must use the exact fixed A2 destination without mutating A1")
    if for_execution:
        need(not recovery_root.exists(), "accepted recovery destination already used; a second A2 attempt is not authorized")
    need(amendment["parent_evidence_bindings"] == seal["parent_evidence_bindings"], "amendment parent evidence map differs")
    need(amendment['forensic_bindings'] == seal['forensic_bindings'], 'amendment forensic evidence map differs')
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
    need(utc(seal["process_end_upper_bound_utc"]) <= utc(seal["sealed_utc"]) <= utc(exposure["reviewed_utc"]) <= accepted,
         "prospective amendment predates original closure/exposure review")
    deadline = utc(session["started_utc"]) + timedelta(seconds=LIMITS["absolute_deadline_seconds_from_a1_start"])
    need(accepted < deadline, "amendment accepted after absolute cumulative deadline")
    current = utc(now_utc) if now_utc is not None else datetime.now(timezone.utc)
    need(current >= accepted, "amendment timestamp is in the future")
    if for_execution:
        need(current < deadline, "absolute cumulative recovery deadline elapsed")
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
    validate_manual_reacquisition(amendment["manual_reacquisition"], requests)
    return {"amendment": amendment, "amendment_path": path, "amendment_sha256": expected_sha256,
            "plan": plan, "plan_path": plan_path, "plan_sha256": amendment["recovery_plan"]["sha256"],
            "original_plan": original, "original_plan_path": original_path,
            "first_attempt_seal": seal, "exposure": exposure, "parent_root": root,
            "recovery_output_root": recovery_root,
            "reserved_parent_pending_response_bytes": seal["reserved_parent_pending_response_bytes"],
            "known_parent_response_bytes": seal["known_parent_response_bytes"],
            "forensic_bindings": amendment["forensic_bindings"], "pinned_runtime_root": recovery_root,
            "inherited_charged_response_bytes": seal["inherited_charged_response_bytes"],
            "parent_bindings": seal["parent_evidence_bindings"], "manual_reacquisition": amendment["manual_reacquisition"],
            "absolute_deadline_utc": deadline.isoformat(), "original_acceptances": originals}



def validate_recovered_source_ready(amendment_path, expected_amendment_sha256, *, transport_audit,
                                  source_review, multiattempt_ledger, binding_parent, now_utc=None):
    """Source gate before assembly; final input manifests do not yet exist."""
    context = validate_recovery_amendment(amendment_path, expected_amendment_sha256, now_utc=now_utc, for_execution=False)
    transport_path = bound(transport_audit, binding_parent)
    transport = read(transport_path)
    need(transport["status"] == "PASS_STORAGE_RECOVERY_TRANSPORT_ORIGINAL_BYTES"
         and transport["storage_recovery_amendment_sha256"] == expected_amendment_sha256
         and transport["plan_sha256"] == context["plan_sha256"]
         and transport["auditor_sha256"] == frozen.file_digest(Path(__file__).parent / "independent_transport_audit.py"),
         "amended transport audit not passed/bound")
    ledger_path = bound(multiattempt_ledger, binding_parent)
    need(frozen.file_digest(ledger_path) == transport["multiattempt_ledger_sha256"], "full multi-attempt cost/failure ledger differs")
    source_path = bound(source_review, binding_parent)
    source = read(source_path)
    need(source["status"] == "PASS_SOURCE_SELECTION_AND_RAW_BUNDLES"
         and source["transport_audit_sha256"] == transport_audit["sha256"]
         and source["storage_recovery_amendment_sha256"] == expected_amendment_sha256
         and source["original_source_plan_sha256"] == context["plan"]["original_plan_binding"]["sha256"]
         and source["plan_sha256"] == context["plan_sha256"]
         and source["reviewer_sha256"] == frozen.file_digest(Path(__file__).parent / "audit_sources.py")
         and source['compact_reader_sha256'] == frozen.file_digest(Path(__file__).parent / 'independent_compact_reader.py')
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
    need(receipt["schema_version"] == "article2_phase16_storage_recovery_pre_replay_authorization_v1"
         and receipt["status"] == "ACCEPTED_FOR_FROZEN_REPLAY_AFTER_AMENDED_SOURCE_AUDIT"
         and receipt["accepted_before_replay"] is True
         and receipt["detector_scoring_started"] is False
         and receipt["new_reference_acquisition_started"] is False, "pre-replay authorization missing or exposed")
    need("accepted_before_affected_payload" not in receipt, "pre-replay receipt cannot backdate payload acceptance")
    amendment_path = bound(receipt["storage_recovery_amendment"], path.parent)
    context = validate_recovered_source_ready(amendment_path, receipt["storage_recovery_amendment"]["sha256"],
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    plan = commands.add_parser('prepare-candidate-plan')
    plan.add_argument('--original-plan', type=Path, required=True)
    plan.add_argument('--expected-original-plan-sha256', required=True)
    plan.add_argument('--output', type=Path, required=True)
    seal = commands.add_parser('seal-external-resource-closure')
    for name in ('parent-root', 'original-plan', 'forensic-bindings', 'output'):
        seal.add_argument('--' + name, type=Path, required=True)
    seal.add_argument('--expected-original-plan-sha256', required=True)
    seal.add_argument('--expected-forensic-bindings-sha256', required=True)
    check = commands.add_parser('validate-amendment')
    check.add_argument('--amendment', type=Path, required=True)
    check.add_argument('--expected-amendment-sha256', required=True)
    check.add_argument('--historical', action='store_true', help='Validate lineage after execution; never an acquisition authorization')
    args = parser.parse_args(argv)
    if args.command == 'prepare-candidate-plan':
        make_candidate_recovery_plan(args.original_plan, args.expected_original_plan_sha256, args.output)
        print(json.dumps({'status': 'CANDIDATE_ONLY_NOT_ACCEPTED', 'output': file_binding(args.output)}))
    elif args.command == 'seal-external-resource-closure':
        manifest = bound({'path': str(args.forensic_bindings.resolve()), 'sha256': args.expected_forensic_bindings_sha256}, Path.cwd())
        result = make_external_closure_seal(args.parent_root, args.original_plan,
            args.expected_original_plan_sha256, read(manifest), args.output, binding_parent=manifest.parent)
        print(json.dumps({'status': result['status'], 'output': file_binding(args.output)}))
    else:
        result = validate_recovery_amendment(args.amendment, args.expected_amendment_sha256, for_execution=not args.historical)
        print(json.dumps({'status': 'VALID_HISTORICAL_RECOVERY_LINEAGE' if args.historical else 'VALID_PROSPECTIVE_STORAGE_RECOVERY_GATE',
                          'absolute_deadline_utc': result['absolute_deadline_utc']}))


if __name__ == '__main__':
    main()


