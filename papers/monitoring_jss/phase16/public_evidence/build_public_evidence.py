"""Build an exact-byte review capsule from the verified recovered metadata tree.

This maintainer utility copies a narrow, explicit evidence selection. It does
not acquire sources, change historical records, or calculate detector scores.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import zipfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
OLD_REPO = '/workspace/scratch/159bf77d8682/monitoring-work/'
OLD_RUNTIME = '/tmp/article2_phase16_runtime_159bf77d8682/'
OLD_WORKSPACE = '/workspace/scratch/159bf77d8682/'
RUNTIME_PREFIXES = ('attempt2/observations/', 'replays/', 'reference_work/',
                    'reference_archive_audit/', 'reference_join/',
                    'independent_source_audit/', 'decision_audits/', 'scientific_results/')
EXTRAS = ('original_sources/recovery_receipt.json',)
WORKSPACE_FILES = ('phase16_storage_recovery_audit/transport_audit.json',
                   'phase16_storage_recovery_audit/multiattempt_ledger.json')


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def bindings(value):
    if isinstance(value, dict):
        if isinstance(value.get('path'), str) and re.fullmatch(r'[a-f0-9]{64}', str(value.get('sha256', ''))):
            yield value
        for child in value.values():
            yield from bindings(child)
    elif isinstance(value, list):
        for child in value:
            yield from bindings(child)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recovered-root', type=Path, required=True)
    args = parser.parse_args(argv)
    mapping = json.loads((args.recovered_root / 'recovery_mapping.json').read_bytes())
    selected = {}
    for row in mapping:
        old = row['original_path'] or (OLD_RUNTIME + row['member'] if row['member'].startswith('attempt2/') else None)
        if not old:
            continue
        target = None
        if old.startswith(OLD_RUNTIME):
            suffix = old[len(OLD_RUNTIME):]
            if suffix.startswith(RUNTIME_PREFIXES) or suffix in EXTRAS:
                target = 'runtime/' + suffix
        elif old.startswith(OLD_WORKSPACE):
            suffix = old[len(OLD_WORKSPACE):]
            if suffix in WORKSPACE_FILES:
                target = 'workspace/' + suffix
        if target is None:
            continue
        need('/internal_raw/' not in old, 'full primary text excluded')
        body = Path(row['extracted_path']).read_bytes()
        need(len(body) == row['bytes'] and sha(body) == row['sha256'], 'recovery mapping does not match exact bytes')
        if target.endswith(('.json', '.jsonl', '.md', '.txt')):
            text = body.decode('utf-8')
            need(not re.search(r'libfile_[A-Za-z0-9_-]+|[?&](?:X-Amz-Signature|sig)=|BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY', text),
                 'private identity, signed URL or credential marker in public evidence: ' + target)
        need(old not in selected, 'duplicate original path')
        selected[old] = {'path': target, 'original_path': old, 'sha256': sha(body), 'bytes': len(body), 'body': body}
    study_old = OLD_RUNTIME + 'replays/decision_study_seal.json'
    study = json.loads(selected[study_old]['body'])
    repository = {}

    def add_repo(old, expected=None):
        need(old.startswith(OLD_REPO), 'repository binding outside original repository')
        rel = old[len(OLD_REPO):]
        path = REPO / rel
        need(path.is_file(), 'repository dependency missing: ' + rel)
        body = path.read_bytes()
        if expected:
            need(sha(body) == expected, 'repository dependency hash mismatch: ' + rel)
        repository[old] = {'path': rel, 'original_path': old, 'sha256': sha(body), 'bytes': len(body)}

    join_path = REPO / 'papers/monitoring_jss/phase16/reference/exact_reference_join.py'
    spec = importlib.util.spec_from_file_location('phase16_capsule_build_join', join_path)
    join = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(join)
    add_repo(OLD_REPO + str(join_path.relative_to(REPO)), study['reference_join_code_sha256'])
    driver_path = Path(join.driver.__file__).resolve()
    add_repo(OLD_REPO + str(driver_path.relative_to(REPO)))
    for name, expected in join.driver.DEPENDENCIES.items():
        add_repo(OLD_REPO + 'papers/monitoring_jss/' + name, expected)
    for case in study['cases']:
        for name in ('config', 'measurement_acceptance'):
            add_repo(case[name]['path'], case[name]['sha256'])
        accept_path = REPO / case['measurement_acceptance']['path'][len(OLD_REPO):]
        acceptance = json.loads(accept_path.read_bytes())
        for binding in acceptance['gate_bindings'].values():
            old = str(Path(case['measurement_acceptance']['path']).parent / binding['path'])
            add_repo(old, binding['sha256'])
    # Include exact available repository dependencies referenced by selected
    # records. Historical fields that are merely receipts remain historical.
    for row in selected.values():
        if row['path'].endswith('.json'):
            for binding in bindings(json.loads(row['body'])):
                if binding['path'].startswith(OLD_REPO):
                    path = REPO / binding['path'][len(OLD_REPO):]
                    if path.is_file() and sha(path.read_bytes()) == binding['sha256']:
                        add_repo(binding['path'], binding['sha256'])
    archive = HERE / 'sealed_evidence.zip'
    manifest_path = HERE / 'evidence_manifest.json'
    need(not archive.exists() and not manifest_path.exists(), 'fresh capsule targets required')
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for old, row in sorted(selected.items()):
            info = zipfile.ZipInfo(row['path'], (2026, 10, 28, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            z.writestr(info, row['body'], compresslevel=9)
    entrypoints = {}
    for key, suffix in [('study', 'replays/decision_study_seal.json'),
                        ('reference_inventory', 'reference_work/reference_inventory.json'),
                        ('archived_coverage', 'reference_join/coverage.json'),
                        ('reference_funnel.jsonl.gz', 'reference_join/reference_funnel.jsonl.gz'),
                        ('candidate_adjudications.jsonl.gz', 'reference_join/candidate_adjudications.jsonl.gz')]:
        row = selected[OLD_RUNTIME + suffix]
        entrypoints[key] = {k: row[k] for k in ('original_path', 'sha256')}
    manifest = {
        'schema_version': 'article2_phase16_public_evidence_manifest_v1',
        'capsule': {'path': archive.name, 'bytes': archive.stat().st_size, 'sha256': sha(archive.read_bytes())},
        'entrypoints': entrypoints,
        'files': [{k: v for k, v in row.items() if k != 'body'} for _, row in sorted(selected.items())],
        'repository_files': [row for _, row in sorted(repository.items())],
        'scope': 'Exact sealed selected observations, decisions, postdecision references and historical source/decision/interpretation audit records. Raw accepted response bodies and full primary retrieval text are not included.',
        'original_paths_are_historical_identifiers_not_write_targets': True,
        'source_rows_decoded': False, 'detector_scores_computed': False,
        'full_raw_chain_audit_reproduction_claimed': False}
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'capsule_bytes': manifest['capsule']['bytes'], 'capsule_sha256': manifest['capsule']['sha256'],
                      'manifest_sha256': sha(manifest_path.read_bytes()), 'file_count': len(selected),
                      'repository_files': len(repository)}))


if __name__ == '__main__':
    main()
