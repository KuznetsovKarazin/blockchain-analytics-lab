#!/usr/bin/env python3
"""Offline independent Phase20 source-listing and derived core-traffic audit.

Checks published capture receipts/derived results, not the original 381 MB
of range-response bodies, which were checked on the collecting runner.
"""
import argparse
import datetime as dt
import json
import re
import statistics
from pathlib import Path

SHA = re.compile(r'^[0-9a-f]{64}$')
CASES = {
    'bacon_20220305': {
        'start': '2022-02-04', 'end': '2022-03-06',
        'listing_id': 'bacon_20220305', 'cores': ('proxy',)},
    'rari_pool127_20220430': {
        'start': '2022-04-01', 'end': '2022-05-01',
        'listing_id': 'rari_fuse_pool127_20220430',
        'cores': ('fETH', 'fUSDC', 'comptroller')},
}
REF_MIN = {
    ('bacon_20220305', '2022-03-05'): {'proxy': 8},
    ('rari_pool127_20220430', '2022-04-30'):
        {'fETH': 7, 'fUSDC': 12, 'comptroller': 10},
}

def require(condition, reason):
    if not condition:
        raise ValueError(reason)

def days(start, end):
    current, stop = dt.date.fromisoformat(start), dt.date.fromisoformat(end)
    while current < stop:
        yield current.isoformat()
        current += dt.timedelta(days=1)

def verify(capture, listing):
    require(capture['schema'] == 'phase20_label_free_core_traffic_v1', 'capture schema')
    require(capture['status'] == 'COMPLETE_ADDRESS_ONLY_60_DAYS', 'capture incomplete')
    require(capture['new_incidents_admitted'] == 0
            and capture['detector_runs'] == 0
            and capture['transaction_hashes_downloaded'] == 0, 'scientific scope mismatch')
    require(capture['range_requests'] <= 450
            and capture['range_response_bytes'] <= 550_000_000, 'caps exceeded')
    require(len(capture['days']) == 60 and len(capture['source_audit']) == 60,
            'missing daily source')
    original_index = {(x['case'], x['date'], x['table']): x
                      for x in listing['partitions']}
    receipts = {(x['case'], x['day']): x for x in capture['source_audit']}
    require(len(receipts) == 60, 'duplicate source receipts')
    computed = {}
    bytes_total = requests_total = 0
    for case, spec in CASES.items():
        dates = list(days(spec['start'], spec['end']))
        require(len(dates) == 30, 'wrong UTC window')
        observed = [x for x in capture['days'] if x['case'] == case]
        require([x['day'] for x in observed] == dates, 'missing/out-of-order day '+case)
        values = {name: [] for name in spec['cores']}
        for row in observed:
            day = row['day']
            key = (case, day)
            require(row['status'] == 'FULL_ORIGINAL_ADDRESS_COLUMN_AUDIT',
                    'unavailable day '+repr(key))
            listing_row = original_index[(spec['listing_id'], day, 'logs')]
            require(listing_row['status'] == 'LISTED_METADATA_ONLY'
                    and len(listing_row['keys']) == 1, 'missing S3 source '+repr(key))
            require(row['source_key'] == listing_row['keys'][0]['key']
                    and row['source_declared_bytes'] ==
                    listing_row['keys'][0]['declared_bytes'], 'source mismatch '+repr(key))
            require(row['source_key'].startswith('v1.0/eth/logs/date='+day+'/')
                    and row['source_key'].endswith('.snappy.parquet'),
                    'invalid source key '+repr(key))
            require(row['rowgroups'] > 0 and row['source_log_rows'] > 0,
                    'invalid row groups '+repr(key))
            saved = receipts[key]
            require(saved['key'] == row['source_key']
                    and saved['declared_bytes'] == row['source_declared_bytes']
                    and saved['etag'] == row['source_etag'], 'source receipt mismatch '+repr(key))
            spans = []
            for part in saved['range_receipts']:
                start, length = part['start'], part['length']
                require(type(start) is int and type(length) is int
                        and start >= 0 and length > 0
                        and start+length <= row['source_declared_bytes'],
                        'invalid range '+repr(key))
                require(bool(SHA.fullmatch(part['sha256'])), 'invalid range SHA256')
                spans.append((start,start+length))
                bytes_total += length
                requests_total += 1
            spans.sort()
            require(all(spans[i][1] <= spans[i+1][0]
                        for i in range(len(spans)-1)),
                    'overlapping source ranges '+repr(key))
            require(len(spans) == row['range_requests']
                    and sum(b-a for a,b in spans) == row['range_response_bytes'],
                    'range accounting '+repr(key))
            require(set(row['core_log_counts']) == set(spec['cores']),
                    'unexpected monitored core '+repr(key))
            require(sum(row['core_log_counts'].values()) <= row['source_log_rows'],
                    'core logs exceed all logs '+repr(key))
            for name in spec['cores']:
                n = row['core_log_counts'][name]
                require(type(n) is int and 0 <= n <= row['source_log_rows'],
                        'invalid core count '+repr(key))
                values[name].append(n)
                if key in REF_MIN:
                    require(n >= REF_MIN[key][name],
                            'reference core logs exceed incident-day count '+repr(key))
        per_core = {}
        for name, v in values.items():
            per_core[name] = {
                'days': len(v), 'total_logs': sum(v),
                'days_below_20': sum(x < 20 for x in v),
                'days_at_least_20': sum(x >= 20 for x in v),
                'days_without_logs': v.count(0),
                'min_logs': min(v), 'median_logs': statistics.median(v),
                'max_logs': max(v)}
            prior = capture['summary'][case]['per_core'][name]
            require(prior['total_core_logs'] == sum(v)
                    and prior['days_impossible_history_eligibility_upper_bound']
                         == sum(x < 20 for x in v)
                    and prior['days_at_least_20_logs'] == sum(x >= 20 for x in v),
                    'stored daily summary mismatch '+case+'/'+name)
        computed[case] = per_core
    require(requests_total == capture['range_requests']
            and bytes_total == capture['range_response_bytes'],
            'global transfer accounting mismatch')
    return {
        'verification': 'PASS_OFFLINE_SUMMARY_AND_RECEIPTS',
        'date_source_scans': 60,
        'range_requests': requests_total,
        'retained_response_bytes': bytes_total,
        'new_incidents_admitted': 0,
        'per_core': computed,
        'limitations': 'Verifies stored S3 listing identities, source-range receipts and counts, not independent receipt roots or original source bytes.'}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('source_traffic_json')
    parser.add_argument('full_window_listing_json')
    parser.add_argument('--output')
    args = parser.parse_args()
    result = verify(json.loads(Path(args.source_traffic_json).read_text()),
                    json.loads(Path(args.full_window_listing_json).read_text()))
    output = json.dumps(result, sort_keys=True, indent=2)+'\n'
    if args.output:
        Path(args.output).write_text(output)
    print(output)

if __name__ == '__main__':
    main()
