"""Verify the published capsule and rerun only the frozen exact-reference join.

The sole adapter resolves explicitly enumerated historical absolute bindings to
current files. Original bytes, hashes, relative-path checks and scientific
validators are unchanged. No source acquisition, detector scoring or replay.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import stat
import zipfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
JOIN_REL = 'papers/monitoring_jss/phase16/reference/exact_reference_join.py'
JOIN_SHA = 'deaf7e58715cda8e701ec31bc2f4fcd7e85db5f9199fe23a0b55e195519b1cee'


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def relative(value):
    need(type(value) is str and value and '\\' not in value and ':' not in value,
         'invalid portable member')
    path = PurePosixPath(value)
    need(not path.is_absolute() and '..' not in path.parts and str(path) == value and value != '.',
         'portable member must stay relative')
    return path


def inside(root, value):
    path = Path(root).joinpath(*relative(value).parts)
    need(path.resolve().is_relative_to(Path(root).resolve()), 'path escapes root')
    return path


def check_file(path, record):
    need(path.is_file() and not path.is_symlink(), 'missing, nonregular or symlink artifact')
    need(type(record['bytes']) is int and path.stat().st_size == record['bytes'], 'artifact size mismatch')
    need(digest(path) == record['sha256'], 'artifact SHA256 mismatch')


def extract_verified(capsule, manifest, output):
    check_file(capsule, manifest['capsule'])
    records = manifest['files']
    names = [str(relative(row['path'])) for row in records]
    need(len(names) == len(set(names)), 'duplicate manifest member')
    need(all(type(row['bytes']) is int and 0 <= row['bytes'] <= 128 * 1024 * 1024 for row in records),
         'invalid or oversized evidence member')
    need(sum(row['bytes'] for row in records) <= 256 * 1024 * 1024, 'oversized metadata capsule')
    by_name = {row['path']: row for row in records}
    need(not output.exists(), 'fresh output directory required')
    with zipfile.ZipFile(capsule) as archive:
        infos = archive.infolist()
        need(len(infos) == len(names) and {x.filename for x in infos} == set(names),
             'ZIP missing, duplicate or extra member')
        for info in infos:
            relative(info.filename)
            need(not info.is_dir() and not stat.S_ISLNK(info.external_attr >> 16),
                 'ZIP directory or symlink is not an evidence file')
            need(info.file_size == by_name[info.filename]['bytes'], 'ZIP header member size mismatch')
        output.mkdir(parents=True)
        for row in records:
            body = archive.read(row['path'])
            need(len(body) == row['bytes'] and hashlib.sha256(body).hexdigest() == row['sha256'],
                 'ZIP member SHA256 or size mismatch')
            path = inside(output, row['path'])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
    return records


def make_binding_adapter(join, targets, allowed_files):
    original = join.binding

    def relocated(value, folder):
        join.driver.exact_keys(value, ('path', 'sha256'), 'reference binding')
        join.nonempty(value['path'], 'binding path')
        path = Path(value['path'])
        if path.is_absolute():
            need(str(path) in targets, 'historical absolute binding is not enumerated: ' + str(path))
            need(targets[str(path)].resolve() in allowed_files, 'target is outside verified file set')
            rewritten = {'path': str(targets[str(path)]), 'sha256': value['sha256']}
            resolved = original(rewritten, folder)
        else:
            need((Path(folder) / path).resolve() in allowed_files, 'relative binding is outside verified file set')
            resolved = original(value, folder)
        need(resolved.resolve() in allowed_files, 'binding resolves outside verified file set')
        return resolved

    return original, relocated


def verify(args):
    manifest = read_json(args.manifest)
    need(manifest['schema_version'] == 'article2_phase16_public_evidence_manifest_v1', 'unsupported manifest')
    if args.expected_manifest_sha256:
        need(digest(args.manifest) == args.expected_manifest_sha256, 'manifest SHA256 mismatch')
    repo = Path(args.repo).resolve()
    output = Path(args.output).resolve()
    need(not output.exists() and not output.is_relative_to(repo), 'fresh output outside repository required')
    targets, allowed = {}, set()
    for record in manifest['repository_files']:
        path = inside(repo, record['path'])
        check_file(path, record)
        need(record['original_path'] not in targets, 'duplicate historical path')
        targets[record['original_path']] = path
        allowed.add(path.resolve())
    join_path = inside(repo, JOIN_REL)
    need(digest(join_path) == JOIN_SHA, 'frozen exact join changed')
    records = extract_verified(Path(args.capsule), manifest, output / 'payload')
    for record in records:
        path = inside(output / 'payload', record['path'])
        need(record['original_path'] not in targets, 'duplicate historical path')
        targets[record['original_path']] = path
        allowed.add(path.resolve())
    spec = importlib.util.spec_from_file_location('phase16_public_frozen_join', join_path)
    join = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(join)
    original_driver_binding = join.driver.bound_file
    original, adapter = make_binding_adapter(join, targets, allowed)
    study = manifest['entrypoints']['study']
    inventory = manifest['entrypoints']['reference_inventory']
    join.binding = adapter
    try:
        result = join.execute(targets[study['original_path']], study['sha256'],
                              targets[inventory['original_path']], inventory['sha256'],
                              output / 'recomputed_join')
    finally:
        join.binding = original
    need(join.driver.bound_file is original_driver_binding, 'driver binding unexpectedly changed')
    archived = read_json(targets[manifest['entrypoints']['archived_coverage']['original_path']])
    need({k: v for k, v in result.items() if k != 'created_utc'} ==
         {k: v for k, v in archived.items() if k != 'created_utc'},
         'recomputed coverage differs beyond generated UTC timestamp')
    row_checks = {}
    for name in ('reference_funnel.jsonl.gz', 'candidate_adjudications.jsonl.gz'):
        old = targets[manifest['entrypoints'][name]['original_path']]
        new = output / 'recomputed_join' / name
        with gzip.open(old, 'rb') as left, gzip.open(new, 'rb') as right:
            old_bytes, new_bytes = left.read(), right.read()
        need(old_bytes == new_bytes, 'exact joined rows differ: ' + name)
        row_checks[name] = {'decompressed_bytes_equal': True, 'rows': len(old_bytes.splitlines()),
                            'compressed_bytes_equal': digest(old) == digest(new)}
    report = {
        'schema_version': 'article2_phase16_public_evidence_verification_v1',
        'status': 'PASS_FROZEN_EXACT_JOIN_FROM_PUBLIC_SEALED_EVIDENCE',
        'completed_utc': datetime.now(timezone.utc).isoformat(),
        'verifier_sha256': digest(__file__), 'manifest_sha256': digest(args.manifest),
        'capsule_sha256': digest(args.capsule), 'frozen_join_sha256': JOIN_SHA,
        'capsule_files_verified': len(records), 'repository_files_verified': len(manifest['repository_files']),
        'case_count': len(result['cases']), 'aggregate_arm_cells': sum(len(c['cells']) for c in result['cases']),
        'across_case_cells': len(result['across_cases']),
        'coverage_equal_except_generated_utc': True, 'joined_row_checks': row_checks,
        'only_adapted_function': 'exact_reference_join.binding (explicit historical path relocation)',
        'driver_relative_path_binding_unchanged': True, 'frozen_scientific_source_bytes_unchanged': True,
        'detector_scoring_or_replay_performed': False, 'network_requests': 0,
        'raw_source_audit_repeated': False, 'reference_roles_readjudicated': False,
        'limits': 'Validates retained bytes and recomputes the exact reference join from sealed decisions. Historical source/role audits remain assertions supported by their retained evidence; this does not independently repeat raw-chain acquisition or prove those historical assertions.'}
    (output / 'verification_report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=REPO)
    parser.add_argument('--capsule', type=Path, default=HERE / 'sealed_evidence.zip')
    parser.add_argument('--manifest', type=Path, default=HERE / 'evidence_manifest.json')
    parser.add_argument('--expected-manifest-sha256')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    print(json.dumps(verify(args), sort_keys=True))


if __name__ == '__main__':
    main()
