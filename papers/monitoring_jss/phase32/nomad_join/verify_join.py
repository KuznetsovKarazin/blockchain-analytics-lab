#!/usr/bin/env python3
"""Offline documentary join of the immutable V7 Nomad count replay.

Uses only Python's standard library; imports no detector implementation.
The public labels are source assertions, not a closed attack ground truth.
"""
import argparse
from collections import Counter, deque
import csv
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
PAPER = HERE.parents[1]
CORE = '0x5d94309e5a0090b165fa4181519701637b6daeba'
PROCESS_TOPIC = '0xd42de95a9b26f1be134c8ecce389dc4fcfa18753d01661b7b361233569e8fe48'
PIN = 'ba9adb9323517e8e677c774fbfc58364566df43b'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def iso(ns):
    return datetime.fromtimestamp(ns // 1_000_000_000, timezone.utc).isoformat()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def build():
    protocol = read(HERE / 'PROTOCOL.json')
    assert protocol['source_commit'] == PIN
    assert protocol['core_address'] == CORE
    assert not protocol['detector_rules_changed'] and not protocol['boundary_or_window_changed']
    for name, expected in protocol['baseline_inputs_sha256'].items():
        assert sha((PAPER / name).read_bytes()) == expected, name
    identity = read(HERE / 'sources/source_identity.json')
    assert identity['commit'] == PIN and identity['repository'] == 'nomad-xyz/hack-data'
    for item in identity['files']:
        raw = (HERE / 'sources' / item['local']).read_bytes()
        assert sha(raw) == item['retained_sha256'], item['local']
        source = gzip.decompress(raw) if item['local'].endswith('.gz') else raw
        assert len(source) == item['size']
        assert sha(source) == item['source_sha256']
        assert hashlib.sha1(f'blob {len(source)}\0'.encode() + source).hexdigest() == item['sha']

    public = read(HERE / 'sources/transaction_hashes.json')
    assert len(public) == len(set(public)) == 960
    assert all(re.fullmatch(r'0x[0-9a-f]{64}', x) for x in public)
    public = set(public)
    events = json.loads(gzip.decompress((HERE / 'sources/process_events.json.gz').read_bytes()))
    assert len(events) == 1182
    assert {x['transactionHash'].lower() for x in events} == public
    assert all(x['success'] == 1 for x in events)
    by_source_core = {}
    for event in events:
        by_source_core.setdefault(event['contractAddress'].lower(), set()).add(event['transactionHash'].lower())
    assert len(by_source_core) == 3

    nomad = PAPER / 'phase31/nomad'
    accepted = read(nomad / 'ACCEPTED_DATA.json')
    data = nomad / accepted['relative_path']
    assert accepted['status'] == 'COMPLETE' and accepted['selected_transactions'] == 930
    assert sha((data / 'acquisition_manifest.json').read_bytes()) == accepted['manifest_sha256']
    with gzip.open(data / 'observations.jsonl.gz', 'rt') as f:
        observations = [json.loads(line) for line in f]
    with gzip.open(data / 'raw_selected_bundles.jsonl.gz', 'rt') as f:
        bundles = [json.loads(line) for line in f]
    order = lambda x: (x['transaction']['block_number'], x['transaction']['transaction_index'])
    assert observations == sorted(observations, key=order)
    index = {x['transaction']['transaction_hash']: x for x in observations}
    raw_index = {x['transaction']['transaction_hash']: x for x in bundles}
    assert len(observations) == len(index) == len(raw_index) == 930
    assert set(raw_index) == set(index)

    # Match documentary Process metadata and indexed topics, not merely hashes.
    event_matches = 0
    event_keys = {}
    duplicate_event_rows = 0
    for event in events:
        tx = event['transactionHash'].lower()
        key = (tx, event['logIndex'])
        normalized_source = {k: v for k, v in event.items() if k != 'index'}
        if key in event_keys:
            assert normalized_source == event_keys[key], 'Conflicting duplicate Process event'
            duplicate_event_rows += 1
            continue
        event_keys[key] = normalized_source
        if tx not in index:
            continue
        transaction = index[tx]['transaction']
        assert transaction['block_number'] == event['blockNumber']
        assert transaction['block_hash'] == event['blockHash'].lower()
        assert transaction['transaction_index'] == event['transactionIndex']
        matches = [x for x in raw_index[tx]['events'] if x['log_index'] == event['logIndex']]
        assert len(matches) == 1
        raw = matches[0]
        assert raw['address'] == event['contractAddress'].lower() == CORE
        assert raw['data'] == event['data']
        assert raw['topics'] == [PROCESS_TOPIC, event['messageHash'].lower(),
                                 '0x' + format(event['success'], '064x'), event['returnData'].lower()]
        event_matches += 1

    assert duplicate_event_rows == 7 and len(event_keys) == 1175

    # Independently reconstruct the fixed count rule and grouping from V7 inputs.
    traces = [x for x in read(nomad / 'results/method_traces.json')
              if x['method'] == 'core_count_60s_10']
    assert len(traces) == 930
    trace_index = {x['tx']: x for x in traces}
    queue = deque()
    rolling = 0
    previous_day = None
    anchor = None
    daily_sent = 0
    decisions = []
    for observation in observations:
        tx = observation['transaction']['transaction_hash']
        now = observation['transaction']['event_time_ns']
        day = observation['day_utc']
        if day != previous_day:
            anchor, daily_sent, previous_day = None, 0, day
        while queue and queue[0][0] <= now - 60_000_000_000:
            rolling -= queue.popleft()[1]
        count = sum(x['address'] == CORE for x in raw_index[tx]['events'])
        assert count == observation['core_log_counts']['fixed_core']
        queue.append((now, count))
        rolling += count
        raw_trigger = rolling >= 10
        candidate = raw_trigger and (anchor is None or now - anchor >= 300_000_000_000)
        if candidate:
            anchor = now
        delivered = candidate and daily_sent < 5
        if delivered:
            daily_sent += 1
        trace = trace_index[tx]
        assert trace['time_ns'] == now and trace['day'] == day
        assert trace['raw_trigger'] == raw_trigger and trace['group_candidate'] == candidate
        decisions.append({'transaction_hash': tx, 'timestamp_utc': iso(now), 'time_ns': now,
                          'block_number': observation['transaction']['block_number'],
                          'transaction_index': observation['transaction']['transaction_index'],
                          'core_logs_60s': rolling, 'protocol_listed_hash': tx in public,
                          'raw_trigger': raw_trigger, 'group_candidate': candidate,
                          'greedy_B5_notification': delivered,
                          'greedy_B5_hard_cap_rejection': candidate and not delivered})
    candidates = [x for x in decisions if x['group_candidate']]
    emitted = [x for x in candidates if x['greedy_B5_notification']]
    suppressed = [x for x in candidates if x['greedy_B5_hard_cap_rejection']]
    assert [len(candidates), len(emitted), len(suppressed)] == [12, 5, 7]
    assert all(x['protocol_listed_hash'] for x in candidates)
    score_rows = read(nomad / 'results/label_blind_replay.json')['case_score_rows']
    for budget, expected in [(5, emitted), (20, candidates)]:
        row = next(x for x in score_rows if x['method'] == 'core_count_60s_10'
                   and x['policy'] == 'greedy' and x['B'] == budget)
        assert row['notified_transactions'] == [x['transaction_hash'] for x in expected]
        assert row['raw_triggers'] == sum(x['raw_trigger'] for x in decisions) == 564
        assert row['group_candidates'] == 12

    joined = [x for x in decisions if x['protocol_listed_hash']]
    first = joined[0]
    earliest_source = min(events, key=lambda x: (x['blockNumber'], x['transactionIndex'], x['logIndex']))
    assert earliest_source['transactionHash'].lower() == first['transaction_hash']
    assert first['timestamp_utc'] == '2022-08-01T21:32:31+00:00'
    public_core = by_source_core[CORE]
    other_only = public - public_core
    core_later = public_core - set(index)
    last_block = max(x['transaction']['block_number'] for x in observations)
    assert len(public_core) == 921 and len(other_only) == 39 and len(core_later) == 44
    assert all(x['blockNumber'] > last_block for x in events if x['transactionHash'].lower() in core_later)
    assert len(joined) == 877
    assert sum(x['day_utc'] == '2022-08-01' for x in observations) == 884
    report = {
        'schema': 'article2_phase32_nomad_documentary_join_v1', 'status': 'PASS',
        'network_requests_during_verification': 0,
        'baseline_release': protocol['baseline_release'], 'baseline_commit': protocol['baseline_commit'],
        'reference_source_commit': PIN, 'source_license': 'Apache-2.0',
        'fixed_population': {'selected_transactions': 930, 'final_utc_day_transactions': 884,
                             'preceding_29_day_transactions': 46, 'core_address': CORE},
        'reference_reconciliation': {
            'protocol_published_unique_hashes': 960, 'protocol_published_process_event_rows': 1182,
            'unique_protocol_process_events': len(event_keys), 'duplicate_source_event_rows_differing_only_in_export_index': duplicate_event_rows,
            'protocol_published_replica_addresses': 3, 'fixed_replica_reference_hashes': 921,
            'selected_reference_hashes': 877, 'other_replica_only_reference_hashes': 39,
            'fixed_replica_reference_hashes_after_last_selected_block': 44,
            'source_process_events_matching_retained_AWS_payloads': event_matches,
            'unlisted_selected_transactions': 53},
        'count_funnel': {'raw_triggers': 564,
                        'protocol_listed_raw_triggers': sum(x['raw_trigger'] and x['protocol_listed_hash'] for x in decisions),
                        'grouped_candidates': 12, 'protocol_listed_grouped_candidates': 12,
                        'greedy_B5_notifications': 5, 'protocol_listed_greedy_B5_notifications': 5,
                        'greedy_B5_hard_cap_rejections': 7, 'protocol_listed_greedy_B5_hard_cap_rejections': 7,
                        'greedy_B20_notifications': 12},
        'timing': {
            'first_protocol_listed_transaction': first,
            'first_count_candidate': candidates[0], 'fifth_notification_exhausting_B5': emitted[-1],
            'first_hard_cap_rejection': suppressed[0],
            'seconds_first_reference_to_first_candidate': (candidates[0]['time_ns'] - first['time_ns']) // 1_000_000_000,
            'seconds_first_reference_to_budget_exhaustion': (emitted[-1]['time_ns'] - first['time_ns']) // 1_000_000_000,
            'seconds_first_candidate_to_budget_exhaustion': (emitted[-1]['time_ns'] - candidates[0]['time_ns']) // 1_000_000_000},
        'candidate_rows': candidates,
        'baseline_input_sha256': protocol['baseline_inputs_sha256'],
        'source_identity_sha256': sha((HERE / 'sources/source_identity.json').read_bytes()),
        'limits': ['Post-scoring exact documentary membership, not independent attack-role adjudication.',
                   'Protocol-listed hack transactions can include fund recovery or whitehat actors; no malicious-intent label is inferred.',
                   'The public list is not assumed to be an exhaustive incident inventory.',
                   'No recall or false-positive-rate estimate; reference hashes outside the fixed boundary/window are not monitor failures.',
                   'The first count notification is 71 minutes 1 second after the earliest listed transaction, not early warning.',
                   'Budget exhaustion occurs 105 minutes 2 seconds after the earliest listed transaction, not in the first minutes.',
                   'Agreement with retained source rows is not receipt-root authentication.']}
    assert report['count_funnel']['protocol_listed_raw_triggers'] == 564
    assert report['timing']['seconds_first_reference_to_first_candidate'] == 4261
    assert report['timing']['seconds_first_reference_to_budget_exhaustion'] == 6302
    assert report['timing']['seconds_first_candidate_to_budget_exhaustion'] == 2041
    table = io.StringIO(newline='')
    writer = csv.DictWriter(table, fieldnames=list(candidates[0]), lineterminator='\n')
    writer.writeheader()
    writer.writerows(candidates)
    return {'JOIN_REPORT.json': encoded(report),
            'CANDIDATE_DISPATCH.csv': table.getvalue().encode(),
            'SELECTED_REFERENCE_HASHES.json': encoded([x['transaction_hash'] for x in joined])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Compare retained outputs without modifying them.')
    parser.add_argument('--out', type=Path, default=HERE)
    args = parser.parse_args()
    outputs = build()
    for name, content in outputs.items():
        path = args.out / name
        if args.check:
            assert path.read_bytes() == content, name
        else:
            args.out.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    print('PASS: 930 fixed transactions; 877 documentary joins; 12/12 candidates listed; 5 sent and 7 hard-cap rejections.')


if __name__ == '__main__':
    main()
