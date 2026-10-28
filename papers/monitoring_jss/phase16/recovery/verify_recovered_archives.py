#!/usr/bin/env python3
"""Verify and extract canonical original sources after both case acceptances.

This program reads bytes, hashes and ZIP metadata only. It does not decode
Parquet rows, select detector transactions, obtain network data or compute scores.
Runtime source paths and Library identifiers must remain outside public results.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import zipfile

SHA = re.compile(r'[a-f0-9]{64}\Z')
CORES = {
    'lifi': ['0x5a9fd7c39a6c488e715437d7b1f3c823d5596ed1'],
    'revest': ['0x2320a28f52334d62622cc2eafa15de55f9987ed9', '0xa81bd16aa6f6b25e66965a2f842e9c806c0aa11f'],
}
DATES = {'lifi': '2022-03-20', 'revest': '2022-03-27'}
CASE_IDS = {'lifi': 'lifi_20220320', 'revest': 'revest_20220327'}


def need(value, message):
    if not value:
        raise ValueError(message)


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(4*1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def constant(value):
        raise ValueError('nonfinite JSON constant')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def checked_json(path, expected):
    need(type(expected) is str and SHA.fullmatch(expected), 'invalid expected SHA256')
    need(file_sha(path) == expected, 'bound file digest mismatch')
    return strict_json(Path(path).read_bytes())


def validate_acceptances(records, *, inventory_sha256, reuse_sha256):
    """Use the frozen scientific CLI's gate checks for both declared populations."""
    need(type(records) is dict and set(records) == set(CORES), 'both case acceptances required')
    driver_path = Path(__file__).resolve().parents[2]/'phase15/driver/fixed_address_replay.py'
    spec = importlib.util.spec_from_file_location('phase16_recovery_frozen_driver', driver_path)
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    result = {}
    for case, record in records.items():
        need(type(record) is dict and set(record) == {'config_path', 'acceptance_path', 'acceptance_sha256'}, 'acceptance record fields')
        config_path = Path(record['config_path'])
        config = strict_json(config_path.read_bytes())
        driver.validate_config(config)
        need(config['case_id'] == CASE_IDS[case] and config['population_addresses'] == CORES[case] and config['window']['execution_date_utc'] == DATES[case], 'wrong accepted case, core or window')
        acceptance = driver.validate_freeze(record['acceptance_path'], config_path, expected_freeze_sha256=record['acceptance_sha256'])
        gate_path = driver.bound_file(acceptance['gate_bindings']['source_plan'], Path(record['acceptance_path']).parent)
        gate = strict_json(gate_path.read_bytes())
        need(gate['schema_version'] == 'article2_phase16_bound_source_execution_gate_v1', 'source execution gate schema')
        source_plan = driver.bound_file(gate['source_plan'], gate_path.parent)
        plan = strict_json(source_plan.read_bytes())
        for name, filename, digest in [('inventory_binding', 'source_union.json', inventory_sha256),
                                        ('reuse_expectations_binding', 'reuse_expectations.json', reuse_sha256)]:
            need(type(digest) is str and SHA.fullmatch(digest), 'invalid expected recovery input SHA256')
            need(plan.get(name) == {'path': 'papers/monitoring_jss/phase16/recovery/'+filename, 'sha256': digest},
                 'recovery input not bound by shared source plan: '+name)
        bound_self = [x for x in gate['execution_source_bindings'] if x['path'].endswith('/phase16/recovery/verify_recovered_archives.py')]
        need(len(bound_self) == 1 and bound_self[0]['sha256'] == file_sha(__file__), 'recovery verifier not bound by root acceptance')
        result[case] = {'acceptance_sha256': record['acceptance_sha256'], 'config_sha256': file_sha(config_path), 'source_plan_sha256': file_sha(source_plan)}
    need(len({x['source_plan_sha256'] for x in result.values()}) == 1, 'case acceptances do not share exact source plan')
    return result


def validate_expectations(expectations, inventory):
    need(expectations['schema_version'] == 'phase16_retained_original_source_reuse_expectations_v1', 'reuse schema')
    need(inventory['schema_version'] == 'article2_phase16_transport_inventory_v1', 'inventory schema')
    need(expectations['archive_count'] == 9 and expectations['object_count'] == 18, 'reuse counts')
    need(len(expectations['archives']) == 9 and len(expectations['objects']) == 18, 'reuse actual counts')
    sources = {x['key']: x for x in inventory['objects']}
    need(len(sources) == len(inventory['objects']) == 113, 'transport inventory exact object count')
    archives = {x['day_utc']: x for x in expectations['archives']}
    need(len(archives) == 9, 'duplicate archive date')
    by_day = {}
    source_keys = set()
    for row in expectations['objects']:
        need(row['source_key'] in sources and row['source_key'] not in source_keys, 'unexpected or duplicate reuse object')
        source_keys.add(row['source_key'])
        source = sources[row['source_key']]
        need(row['table'] in ('blocks', 'logs') and row['day_utc'] in archives, 'invalid reuse table/date')
        need(source['day_utc'] == row['day_utc'] and source['table'] == row['table'], 'reuse table/date differs from source')
        need(source['size_bytes'] == row['size_bytes'] and source['etag_opaque'] == row['etag_opaque'] and source['url'] == row['source_url'], 'reuse source identity differs')
        need(row['expected_archive_sha256'] == archives[row['day_utc']]['sha256'], 'archive identity differs')
        member = 'headers.parquet' if row['table'] == 'blocks' else 'logs.parquet'
        need(row['expected_original_member_name'] == member, 'noncanonical reuse member')
        by_day.setdefault(row['day_utc'], []).append(row)
    need(set(by_day) == set(archives) and all({x['table'] for x in rows} == {'blocks', 'logs'} and len(rows) == 2 for rows in by_day.values()), 'missing or duplicate day members')
    return archives, by_day


def extract_one(archive_path, archive_record, member_records, directory):
    """Byte-only primitive; enclosing main validates both scientific acceptances."""
    archive_path = Path(archive_path)
    result = []
    with archive_path.open('rb') as archive:
        before = os.fstat(archive.fileno())
        need(before.st_size == archive_record['bytes'], 'archive size mismatch')
        archive.seek(0)
        archive_digest = hashlib.sha256()
        for block in iter(lambda: archive.read(4*1024*1024), b''):
            archive_digest.update(block)
        need(archive_digest.hexdigest() == archive_record['sha256'], 'archive SHA256 mismatch')
        with zipfile.ZipFile(archive) as z:
            names = z.namelist()
            need(len(names) == len(set(names)) == archive_record['members'], 'archive duplicate/member count')
            for name in names:
                path = PurePosixPath(name)
                need(not path.is_absolute() and '..' not in path.parts and '\\' not in name, 'unsafe archive member path')
            for row in member_records:
                name = row['expected_original_member_name']
                need(name in ('headers.parquet', 'logs.parquet') and name in names, 'canonical raw member missing')
                info = z.getinfo(name)
                need(not info.is_dir() and info.file_size == row['size_bytes'], 'member size/type mismatch')
                need((info.external_attr >> 16) & 0o170000 != 0o120000, 'symlink member forbidden')
                target = directory/(row['table']+'.parquet')
                partial = target.with_suffix('.partial')
                need(not target.exists() and not partial.exists(), 'refuse to overwrite recovered source')
                digest = hashlib.sha256(); count = 0
                with z.open(info) as src, partial.open('xb') as dst:
                    for block in iter(lambda: src.read(4*1024*1024), b''):
                        count += len(block)
                        need(count <= row['size_bytes'], 'member byte cap')
                        digest.update(block); dst.write(block)
                need(count == row['size_bytes'] and digest.hexdigest() == row['expected_whole_object_sha256'], 'member SHA256/length mismatch')
                partial.rename(target)
                result.append({'path': str(target.resolve()), 'sha256': digest.hexdigest(), 'source_key': row['source_key'], 'size_bytes': count, 'etag_opaque': row['etag_opaque']})
        after = os.fstat(archive.fileno())
        need((before.st_size, before.st_mtime_ns, before.st_ino) == (after.st_size, after.st_mtime_ns, after.st_ino), 'archive changed during verification')
    return result


def build_reuse_map(records):
    result = {row['source_key']: row for row in records}
    need(len(result) == len(records), 'duplicate recovered source key')
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--acceptances', type=Path, required=True, help='Runtime-only JSON mapping lifi/revest to config and acceptance paths/digests')
    ap.add_argument('--reuse-expectations', type=Path, required=True)
    ap.add_argument('--expected-reuse-sha256', required=True)
    ap.add_argument('--inventory', type=Path, required=True)
    ap.add_argument('--expected-inventory-sha256', required=True)
    ap.add_argument('--archive-paths', type=Path, required=True, help='Runtime-only JSON mapping each expected day to its materialized ZIP path')
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    accepted = validate_acceptances(strict_json(args.acceptances.read_bytes()),
                                    inventory_sha256=args.expected_inventory_sha256,
                                    reuse_sha256=args.expected_reuse_sha256)
    expectations = checked_json(args.reuse_expectations, args.expected_reuse_sha256)
    inventory = checked_json(args.inventory, args.expected_inventory_sha256)
    archives, by_day = validate_expectations(expectations, inventory)
    paths = strict_json(args.archive_paths.read_bytes())
    need(type(paths) is dict and set(paths) == set(archives) and all(type(x) is str for x in paths.values()), 'archive path map differs from nine dates')
    need(not args.output.exists(), 'fresh output directory required')
    args.output.mkdir(parents=True)
    receipt = {'schema_version': 'phase16_recovered_original_objects_v1', 'started_utc': datetime.now(timezone.utc).isoformat(), 'status': 'RUNNING', 'accepted_case_bindings': accepted,
               'reuse_expectations_sha256': args.expected_reuse_sha256, 'source_inventory_sha256': args.expected_inventory_sha256,
               'new_dataset_http_requests': 0, 'parquet_rows_decoded': 0, 'detector_scores': 0, 'completed_archives': [], 'objects': []}
    try:
        for day in sorted(archives):
            directory = args.output/day
            directory.mkdir()
            records = extract_one(paths[day], archives[day], by_day[day], directory)
            receipt['objects'].extend(records)
            receipt['completed_archives'].append({'day_utc': day, 'bytes': archives[day]['bytes'], 'sha256': archives[day]['sha256']})
            (args.output/'progress.json').write_text(json.dumps(receipt, indent=2)+'\n')
        need(len(receipt['objects']) == 18, 'recovered member count')
        receipt['status'] = 'VERIFIED_ORIGINAL_OBJECTS_READY_FOR_COLLECTOR_REUSE'
        receipt['whole_source_bytes_verified'] = sum(x['size_bytes'] for x in receipt['objects'])
        (args.output/'reuse_map.json').write_text(json.dumps(build_reuse_map(receipt['objects']), indent=2)+'\n')
    except Exception as exc:
        receipt['status'] = 'FAILED_PARTIAL_OUTPUT_NOT_ACCEPTED'
        receipt['failure_type'] = type(exc).__name__
        receipt['failure_message'] = str(exc)
        raise
    finally:
        receipt['completed_utc'] = datetime.now(timezone.utc).isoformat()
        (args.output/'recovery_receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps({'status': receipt['status'], 'archives': len(receipt['completed_archives']), 'objects': len(receipt['objects']), 'whole_source_bytes_verified': receipt['whole_source_bytes_verified']}))


if __name__ == '__main__':
    main()
