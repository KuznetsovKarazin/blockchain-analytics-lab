#!/usr/bin/env python3
"""Allowlist a successful private byte-recovery receipt into public metadata.

This closure utility is not an acquisition/extraction/audit authorization gate.
It reads JSON metadata only and cannot replace the independent transport audit.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

SHA = re.compile(r'[a-f0-9]{64}\Z')


def need(value, message):
    if not value:
        raise ValueError(message)


def load_bound(path, digest):
    need(type(digest) is str and SHA.fullmatch(digest), 'invalid metadata digest')
    raw = Path(path).read_bytes()
    need(hashlib.sha256(raw).hexdigest() == digest, 'metadata digest mismatch')
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs)


def project(receipt, expectations, *, receipt_sha256, expectations_sha256):
    for digest in (receipt_sha256, expectations_sha256, receipt['source_inventory_sha256']):
        need(type(digest) is str and SHA.fullmatch(digest), 'invalid projection provenance digest')
    need(expectations['schema_version'] == 'phase16_retained_original_source_reuse_expectations_v1', 'expectations schema')
    need(receipt['schema_version'] == 'phase16_recovered_original_objects_v1', 'receipt schema')
    need(receipt['status'] == 'VERIFIED_ORIGINAL_OBJECTS_READY_FOR_COLLECTOR_REUSE', 'recovery incomplete')
    need(receipt['reuse_expectations_sha256'] == expectations_sha256, 'recovery expectation binding differs')
    for key in ('new_dataset_http_requests', 'parquet_rows_decoded', 'detector_scores'):
        need(type(receipt[key]) is int and receipt[key] == 0, 'byte-only recovery scope differs')
    accepted = receipt['accepted_case_bindings']
    need(set(accepted) == {'lifi', 'revest'}, 'both case bindings required')
    accepted_public = {}
    for case, record in accepted.items():
        accepted_public[case] = {}
        for key in ('acceptance_sha256', 'config_sha256', 'source_plan_sha256'):
            need(type(record[key]) is str and SHA.fullmatch(record[key]), 'invalid accepted binding digest')
            accepted_public[case][key] = record[key]
    need(len({x['source_plan_sha256'] for x in accepted_public.values()}) == 1, 'source plan mismatch')
    expected_archives = {r['day_utc']: r for r in expectations['archives']}
    archives = []
    for row in receipt['completed_archives']:
        need(row['day_utc'] in expected_archives, 'unexpected archive')
        expected = expected_archives[row['day_utc']]
        need(row['bytes'] == expected['bytes'] and row['sha256'] == expected['sha256'], 'archive identity differs')
        archives.append({key: row[key] for key in ('day_utc', 'bytes', 'sha256')})
    need(len(archives) == len({r['day_utc'] for r in archives}) == len(expected_archives) == 9, 'archive set differs')
    expected_objects = {r['source_key']: r for r in expectations['objects']}
    objects = []
    for row in receipt['objects']:
        need(row['source_key'] in expected_objects, 'unexpected source object')
        expected = expected_objects[row['source_key']]
        need(row['sha256'] == expected['expected_whole_object_sha256'] and
             row['size_bytes'] == expected['size_bytes'] and row['etag_opaque'] == expected['etag_opaque'],
             'source object identity differs')
        objects.append({**{key: row[key] for key in ('source_key', 'sha256', 'size_bytes', 'etag_opaque')},
                        **{key: expected[key] for key in ('day_utc', 'table', 'expected_archive_sha256', 'expected_original_member_name')}})
    need(len(objects) == len({r['source_key'] for r in objects}) == len(expected_objects) == 18, 'source object set differs')
    total = sum(r['size_bytes'] for r in objects)
    need(receipt['whole_source_bytes_verified'] == total == expectations['original_source_object_bytes_total'], 'source byte count differs')
    for key in ('started_utc', 'completed_utc'):
        need(datetime.fromisoformat(receipt[key]).utcoffset().total_seconds() == 0, 'receipt timestamp must be UTC')
    return {
        'schema_version': 'article2_phase16_public_original_object_recovery_v1',
        'status': 'RECOVERY_RECEIPT_VERIFIED_PENDING_INDEPENDENT_TRANSPORT_AUDIT',
        'private_recovery_receipt_sha256': receipt_sha256,
        'reuse_expectations_sha256': expectations_sha256,
        'source_inventory_sha256': receipt['source_inventory_sha256'],
        'accepted_case_bindings': accepted_public,
        'started_utc': receipt['started_utc'], 'completed_utc': receipt['completed_utc'],
        'archive_count': len(archives), 'archive_bytes_verified': sum(r['bytes'] for r in archives),
        'canonical_raw_source_object_count': len(objects), 'whole_source_bytes_verified': total,
        'archives': sorted(archives, key=lambda r: r['day_utc']),
        'objects': sorted(objects, key=lambda r: (r['day_utc'], r['table'])),
        'scope': 'Projection of completed extraction receipt; Library materialization traffic is accounted separately.',
        'new_dataset_http_requests_by_extractor': 0, 'parquet_rows_decoded_by_extractor': 0,
        'detector_scores_by_extractor': 0, 'independent_transport_audit_performed_by_projection': False,
        'projection_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'projected_utc': datetime.now(timezone.utc).isoformat(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--expected-receipt-sha256', required=True)
    parser.add_argument('--expectations', type=Path, required=True)
    parser.add_argument('--expected-expectations-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value = project(load_bound(args.receipt, args.expected_receipt_sha256),
                    load_bound(args.expectations, args.expected_expectations_sha256),
                    receipt_sha256=args.expected_receipt_sha256, expectations_sha256=args.expected_expectations_sha256)
    need(not args.output.exists(), 'projection output already exists')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n')
    print(json.dumps({k: value[k] for k in ('status', 'archive_count', 'canonical_raw_source_object_count', 'whole_source_bytes_verified')}))


if __name__ == '__main__':
    main()
