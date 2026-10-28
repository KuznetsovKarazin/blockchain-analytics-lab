"""Run each frozen Phase16 case once after the new storage-source gate passes.

No scoring occurs on import. Only the explicitly pinned pre-replay receipt can
admit invocation; a failed or interrupted output directory is never resumed.
Both original case acceptances remain unchanged historical records.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAPER = HERE.parents[1]
REPO = PAPER.parents[1]
PROTOCOL_SHA256 = '3b5003147d59cfd13f28adf614bb2859f8d6d1c6a3923ccd3c77e34944d261e0'
DRIVER_SHA256 = '591a8e09cd1920496ad0acc8fb13a1f4c62a0a224b3d8925ec364fff91ed293d'
JOIN_SHA256 = 'deaf7e58715cda8e701ec31bc2f4fcd7e85db5f9199fe23a0b55e195519b1cee'
ENGINE_SHA256 = '347bf76e162cf995e0b3c30ce6a3e72a75a1e78008d120ce8d51137667409955'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def pinned_module(name, path, expected):
    if sha(path) != expected:
        raise ValueError('pinned replay dependency changed: ' + str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


protocol = pinned_module('phase16_storage_replay_protocol', HERE / 'protocol.py', PROTOCOL_SHA256)
join = pinned_module('phase16_storage_replay_seal_validator', PAPER / 'phase16/reference/exact_reference_join.py', JOIN_SHA256)
frozen, need = protocol.frozen, protocol.need


def stamp():
    return datetime.now(timezone.utc).isoformat()


def normalized(binding, base):
    return protocol.file_binding(protocol.bound(binding, base))


def run(args, *, driver_main=None, run_validator=None):
    """Injected callables exist only for inert synthetic orchestration tests."""
    auth_path = Path(args.pre_replay_authorization).resolve()
    context = protocol.validate_pre_replay_authorization(auth_path, args.expected_authorization_sha256)
    auth = context['pre_replay_authorization']
    need(auth['replay_launcher_sha256'] == sha(__file__), 'launcher is not pinned in pre-replay authorization')
    need(sha(protocol.driver.__file__) == DRIVER_SHA256, 'original replay driver changed')
    output = Path(auth['replay_output_root'])
    need(output.is_absolute() and output.resolve() == Path(args.output).resolve(), 'replay output differs from exact authorized destination')
    output = output.resolve()
    need(not output.exists() and not output.is_relative_to(context['parent_root']), 'fresh replay output outside immutable A1 required')
    archive = normalized(auth['reference_archive_auditor'], auth_path.parent)
    need(Path(archive['path']) == HERE / 'archive_reference_audit.py', 'wrong storage archive auditor selected')
    need(auth['reference_archive_source_engine_sha256'] == ENGINE_SHA256
         and sha(PAPER / 'phase16/reference/archive_reference_audit.py') == ENGINE_SHA256,
         'original archive source-fact engine changed')
    compact = normalized(auth['reference_compact_reader'], auth_path.parent)
    need(Path(compact['path']) == HERE / 'independent_compact_reader.py', 'wrong compact archive reader selected')
    configs = {}
    for binding in context['original_plan']['case_configs']:
        path = protocol.bound(binding, REPO)
        config = protocol.driver.validate_config(protocol.read(path))
        configs[config['case_id']] = protocol.file_binding(path)
    need(set(configs) == set(protocol.CASES) == set(auth['input_manifests']) == set(context['original_acceptances']),
         'both exact frozen cases must be authorized before either replay')
    entries = [{'case_id': case, 'status': 'COMPLETE', 'config': configs[case],
                'measurement_acceptance': normalized(context['original_acceptances'][case], context['amendment_path'].parent),
                'input_manifest': normalized(auth['input_manifests'][case], auth_path.parent)} for case in protocol.CASES]
    lineage = {'pre_replay_authorization': protocol.file_binding(auth_path),
               'storage_recovery_amendment': protocol.file_binding(context['amendment_path']),
               'multiattempt_ledger': protocol.file_binding(context['multiattempt_ledger_path']),
               'source_review': normalized(auth['source_review'], auth_path.parent),
               'transport_audit': normalized(auth['transport_audit'], auth_path.parent)}
    driver_main = driver_main or protocol.driver.main
    run_validator = run_validator or join.load_run
    started = stamp()
    need(protocol.utc(auth['accepted_utc']) <= protocol.utc(started), 'replay cannot predate authorization')
    output.mkdir(parents=True, exist_ok=False)
    completed, started_cases = [], []
    try:
        for entry in entries:
            case = entry['case_id']
            destination = output / case
            need(not destination.exists(), 'case replay already attempted')
            started_cases.append(case)
            driver_main(['--config', entry['config']['path'],
                         '--measurement-acceptance', entry['measurement_acceptance']['path'],
                         '--expected-acceptance-sha256', entry['measurement_acceptance']['sha256'],
                         '--input-manifest', entry['input_manifest']['path'],
                         '--expected-input-manifest-sha256', entry['input_manifest']['sha256'],
                         '--output', str(destination)])
            entry = entry | {'run_manifest': protocol.file_binding(destination / 'run_manifest.json')}
            validated = run_validator(entry, output)
            need(validated['status'] == 'COMPLETE' and validated['case_id'] == case, 'replay did not produce a valid complete sealed case')
            manifest = protocol.read(destination / 'run_manifest.json')
            need(protocol.utc(auth['accepted_utc']) <= protocol.utc(manifest['started_utc'])
                 <= protocol.utc(manifest['completed_utc']), 'case replay chronology differs')
            completed.append(entry)
            del validated
        need([e['case_id'] for e in completed] == list(protocol.CASES), 'both cases did not close')
        # Pin integrity again after the two calls; a changed gate or input cannot
        # receive the complete-study receipt even if one replay already ran.
        need(sha(HERE / 'protocol.py') == PROTOCOL_SHA256 and sha(__file__) == auth['replay_launcher_sha256']
             and sha(protocol.driver.__file__) == DRIVER_SHA256, 'execution implementation changed during replay')
        for binding in (archive, compact, *lineage.values()):
            protocol.bound(binding, output)
        for entry in completed:
            for field in ('config', 'measurement_acceptance', 'input_manifest', 'run_manifest'):
                protocol.bound(entry[field], output)
        closed = stamp()
        receipt = {'schema_version': 'article2_phase16_storage_recovery_replay_launcher_receipt_v1',
                   'status': 'COMPLETE_BOTH_CASES_SEALED', 'started_utc': started, 'completed_utc': closed,
                   'replay_launcher_sha256': sha(__file__), 'original_driver_sha256': DRIVER_SHA256,
                   'protocol_sha256': PROTOCOL_SHA256, **lineage, 'cases': completed,
                   'reference_archive_auditor': archive, 'reference_compact_reader': compact,
                   'reference_archive_source_engine_sha256': ENGINE_SHA256,
                   'labels_used': False, 'reference_acquisition_performed': False,
                   'driver_invocations': len(started_cases), 'retries': 0}
        frozen.write_json(output / 'replay_launcher_receipt.json', receipt)
        study = {'schema_version': 'article2_phase16_decision_study_seal_v1',
                 'status': 'BOTH_CASE_DECISION_STAGES_CLOSED', 'sealed_utc': stamp(),
                 'reference_join_code_sha256': JOIN_SHA256, 'cases': completed,
                 'reference_archive_auditor_sha256': archive['sha256'],
                 'reference_archive_source_engine_sha256': ENGINE_SHA256,
                 'reference_compact_reader_sha256': compact['sha256'],
                 'storage_recovery_pre_replay_authorization': lineage['pre_replay_authorization'],
                 'storage_recovery_amendment': lineage['storage_recovery_amendment'],
                 'multiattempt_ledger': lineage['multiattempt_ledger'],
                 'replay_launcher_receipt': protocol.file_binding(output / 'replay_launcher_receipt.json'),
                 'labels_used': False, 'reference_acquisition_started': False}
        frozen.write_json(output / 'decision_study_seal.json', study)
        return {'status': receipt['status'], 'study_seal': protocol.file_binding(output / 'decision_study_seal.json'),
                'replay_launcher_receipt': protocol.file_binding(output / 'replay_launcher_receipt.json')}
    except BaseException as error:
        failure = {'schema_version': 'article2_phase16_storage_recovery_replay_launcher_failure_v1',
                   'status': 'FAILED_NO_COMPLETE_STUDY_SEAL', 'started_utc': started, 'failed_utc': stamp(),
                   'error_type': type(error).__name__, 'error': str(error), **lineage,
                   'started_cases': started_cases, 'verified_completed_cases': completed,
                   'automatic_retry_performed': False, 'reference_acquisition_performed': False}
        try:
            frozen.write_json(output / 'launcher_failure.json', failure)
        except OSError:
            pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pre-replay-authorization', type=Path, required=True)
    parser.add_argument('--expected-authorization-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    result = run(parser.parse_args(argv))
    import json
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
