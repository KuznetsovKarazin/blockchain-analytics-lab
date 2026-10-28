#!/usr/bin/env python3
"""Build Phase16's transport inventory from exact retained listing bytes.

Metadata only. No network, Parquet decoding, source payload or scoring occurs.
The two boundary block objects support UTC boundary checks and are not study days.
"""
from __future__ import annotations
import argparse
from datetime import date, timedelta
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

N = '{http://s3.amazonaws.com/doc/2006-03-01/}'
ENDPOINT = 'https://aws-public-blockchain.s3.us-east-2.amazonaws.com/'
EXPECTED = [
    ('repo', 'papers/monitoring_jss/qa/phase4_common_window_feasibility_20261025T122103_763107Z/logs_2022-03_page1.xml', 'a4fa3ab3ca8f30a6a881306ca858a5ae4eee1105b57c94ad7804443874b8d000', 'logs', '2022-03'),
    ('repo', 'papers/monitoring_jss/qa/phase4_common_window_feasibility_20261025T122103_763107Z/blocks_2022-03_page1.xml', '28d13f4044f74d245a4de952ad3fb77eea9972e0bd82c6b70482fec34f319a50', 'blocks', '2022-03'),
    ('capture', '001_prefix0_page1_response.xml', '67a80f0bf7cb80a1ad6a8145066f19a345a613fc69dd8a416273283dc0953590', 'logs', '2022-02'),
    ('capture', '002_prefix1_page1_response.xml', 'c7391fb6aa9689d1207e3a41258a46172b6db315b6324f7a8e8f00b49278d159', 'blocks', '2022-02'),
    ('capture', '003_prefix2_page1_response.xml', 'ee134897927838d80e8e623f1d8a154cb0a017988e88e8af2dfc35725a6817f3', 'transactions', '2022-02'),
    ('capture', '004_prefix3_page1_response.xml', '87d8e89b52531d6d33dfee29909056e73598099b1e5b8a5cf632c8f4674a547b', 'transactions', '2022-03'),
]


def need(value, message):
    if not value:
        raise ValueError(message)


def hashed(path, expected):
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == expected, 'retained byte identity changed')
    return raw


def listing(raw, table, month):
    root = ET.fromstring(raw)
    need(root.tag == N+'ListBucketResult', 'wrong listing root')
    def single(node, name):
        found = node.findall(N+name)
        need(len(found) == 1 and found[0].text is not None, 'missing/duplicate XML '+name)
        return found[0].text
    need(single(root, 'Name') == 'aws-public-blockchain', 'wrong bucket')
    prefix = f'v1.0/eth/{table}/date={month}-'
    need(single(root, 'Prefix') == prefix, 'wrong prefix')
    need(single(root, 'IsTruncated') == 'false' and not root.findall(N+'NextContinuationToken'), 'listing unfinished')
    entries = root.findall(N+'Contents')
    need(single(root, 'KeyCount').isdigit() and int(single(root, 'KeyCount')) == len(entries) < 1000, 'listing count/cap')
    result = []
    for entry in entries:
        key = single(entry, 'Key')
        match = re.fullmatch(r'v1\.0/eth/'+table+r'/date=(\d{4}-\d{2}-\d{2})/[^/]+\.parquet', key)
        need(match is not None and key.startswith(prefix), 'wrong key')
        day = match.group(1)
        need(date.fromisoformat(day).isoformat() == day, 'noncanonical date')
        size = single(entry, 'Size')
        need(re.fullmatch(r'[1-9][0-9]*', size) is not None, 'invalid size')
        etag = single(entry, 'ETag')
        need(etag.startswith('"') and etag.endswith('"') and '\n' not in etag and '\r' not in etag, 'invalid opaque ETag')
        result.append({'table': table, 'day_utc': day, 'key': key, 'size_bytes': int(size), 'etag_opaque': etag, 'url': ENDPOINT+key,
                       'last_modified_metadata': single(entry, 'LastModified'), 'storage_class_metadata': single(entry, 'StorageClass')})
    need(len({x['key'] for x in result}) == len(result), 'duplicate object key')
    return result


def identity(o):
    return o['key'], o['size_bytes'], o['etag_opaque']


def build(repo, capture):
    objects, bindings = [], []
    for location, rel, sha, table, month in EXPECTED:
        path = (repo if location == 'repo' else capture)/rel
        raw = hashed(path, sha)
        parsed = listing(raw, table, month)
        artifact = ('retained_phase4/' if location == 'repo' else 'retained_phase14/')+path.name
        bindings.append({'artifact_id': artifact, 'sha256': sha, 'bytes': len(raw), 'table': table, 'month': month, 'listed_objects': len(parsed), 'listing_terminal': True})
        for obj in parsed:
            objects.append({**obj, 'source_listing_id': artifact, 'source_listing_sha256': sha})
    need(len({o['key'] for o in objects}) == len(objects), 'duplicate across source listings')
    study = [o for o in objects if '2022-02-19' <= o['day_utc'] < '2022-03-28']
    boundaries = [o for o in objects if o['table'] == 'blocks' and o['day_utc'] in ('2022-02-18', '2022-03-28')]
    days = [(date(2022, 2, 19)+timedelta(days=i)).isoformat() for i in range(37)]
    need(len(study) == 111 and len(boundaries) == 2, 'unexpected source population')
    for day in days:
        for table in ('blocks', 'logs', 'transactions'):
            need(len([o for o in study if o['day_utc'] == day and o['table'] == table]) == 1, 'retained single-part structure changed')
    need({o['day_utc'] for o in boundaries} == {'2022-02-18', '2022-03-28'}, 'missing boundary object')
    p14_raw = hashed(capture/'summary.json', '8b85676f2dbe50ff5e6f4d66d98cd9510017b906a3ba8249496624566ab4d26b')
    p15_raw = hashed(repo/'papers/monitoring_jss/phase15/source_readiness/revest_inventory.json', 'e557dd3951fac2e3365cc837cfece34e83f693f6d2a6941b46bf476984759dac')
    lifi = [o for c in json.loads(p14_raw)['day_table_cells'] for o in c['objects']]
    revest = [o for c in json.loads(p15_raw)['cells'] for o in c['objects']]
    actual = {o['key']: identity(o) for o in study}
    for expected in lifi+revest:
        need(actual[expected['key']] == identity(expected), 'prior case inventory identity mismatch')
    need(set(actual) == {o['key'] for o in lifi+revest}, 'study union differs from accepted inventories')
    result_objects = []
    for obj in study+boundaries:
        cases = []
        if '2022-02-19' <= obj['day_utc'] < '2022-03-21': cases.append('lifi')
        if '2022-02-26' <= obj['day_utc'] < '2022-03-28': cases.append('revest')
        result_objects.append({**obj, 'role': 'study' if cases else 'boundary_headers_only', 'case_ids': cases})
    result_objects.sort(key=lambda x: (x['day_utc'], ('blocks', 'logs', 'transactions').index(x['table']), x['key']))
    shared = {o['key'] for o in lifi}&{o['key'] for o in revest}
    return {
        'schema_version': 'article2_phase16_transport_inventory_v1',
        'status': 'COMPLETE_RETAINED_METADATA_NOT_PAYLOAD_AUTHORIZATION',
        'chain_id': 1, 'endpoint': ENDPOINT, 'study_window_utc': ['2022-02-19T00:00:00Z', '2022-03-28T00:00:00Z'],
        'study_days': 37, 'study_objects': len(study), 'boundary_block_objects': len(boundaries), 'transport_objects': len(result_objects),
        'study_declared_whole_object_bytes': sum(o['size_bytes'] for o in study),
        'boundary_declared_whole_object_bytes': sum(o['size_bytes'] for o in boundaries),
        'transport_declared_whole_object_bytes': sum(o['size_bytes'] for o in result_objects),
        'shared_case_objects': len(shared), 'original_case_inventory_records_checked': len(lifi)+len(revest),
        'object_order': ['day_utc_ascending', 'table_blocks_logs_transactions', 'key_ascending'],
        'objects': result_objects, 'source_bindings': bindings,
        'prior_inventory_bindings': [
            {'artifact_id': 'retained_phase14/measurement_inventory_summary.json', 'sha256': hashlib.sha256(p14_raw).hexdigest()},
            {'path': 'papers/monitoring_jss/phase15/source_readiness/revest_inventory.json', 'sha256': hashlib.sha256(p15_raw).hexdigest()}],
        'new_dataset_http_requests': 0, 'new_data_rows_read': 0, 'new_object_payload_bytes': 0, 'new_detector_scores': 0,
        'limits': [
            'Reuses original capture timestamps; no source metadata refresh.',
            'ETag is an opaque If-Match identity, not an object content SHA256.',
            'Declared object bytes are not transferred bytes or selected-column costs.',
            'The two boundary block objects support adjacent-header checks only; no extra study observation day is added.',
            'Nonempty listing metadata does not establish row readability, successful execution status, source completeness or receipt-root authentication.',
            'Exact root measurement acceptance is required before affected workload acquisition.']}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo', type=Path, required=True)
    ap.add_argument('--phase14-capture', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    value = build(args.repo, args.phase14_capture)
    args.output.write_text(json.dumps(value, indent=2)+'\n')
    print(json.dumps({k: v for k, v in value.items() if k in ('status', 'study_objects', 'boundary_block_objects', 'transport_objects', 'study_declared_whole_object_bytes', 'boundary_declared_whole_object_bytes', 'transport_declared_whole_object_bytes', 'shared_case_objects')}))


if __name__ == '__main__':
    main()
