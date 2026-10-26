#!/usr/bin/env python3
"""Descriptive source-free projection of one immutable event capture; no replay."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--attempt', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    source_raw = (args.attempt / 'summary.json').read_bytes()
    source = json.loads(source_raw)
    plan = json.loads((args.attempt / 'frozen_plan.json').read_bytes())
    ledger_raw = (args.attempt / 'requests.json').read_bytes()
    ledger = json.loads(ledger_raw)
    assert source['plan_sha256'] == sha((args.attempt / 'frozen_plan.json').read_bytes())
    assert source['http_gets'] == len(ledger)
    assert source['retained_response_bytes'] == sum(x['response_bytes'] for x in ledger)
    events, cuts, initializers = [], [], set()
    for event in source['events']:
        row = {key: event[key] for key in ('block_number', 'block_hash', 'transaction_index', 'transaction_hash', 'log_index', 'removed')}
        row['indexer_reported_timestamp_utc'] = datetime.fromtimestamp(event['timestamp_epoch_seconds'], timezone.utc).isoformat()
        row['decoded'] = dict(event['decoded'])
        if row['decoded']['event'] == 'DiamondCut':
            data = bytes.fromhex(row['decoded'].pop('initializer_calldata')[2:])
            row['decoded'].update(initializer_calldata_bytes=len(data), initializer_calldata_sha256=sha(data),
                                  initializer_calldata_selector=('0x' + data[:4].hex()) if len(data) >= 4 else None)
            cuts.extend(row['decoded']['cuts'])
            if row['decoded']['initializer_effects_unclosed']:
                initializers.add(row['decoded']['initializer'])
        events.append(row)
    names = {0: 'Add', 1: 'Replace', 2: 'Remove'}
    result = {'schema_version': 'article2_phase14_indexer_history_findings_v1',
        'disposition': source['disposition'], 'summary_sha256': sha(source_raw), 'requests_sha256': sha(ledger_raw),
        'plan_sha256': source['plan_sha256'], 'runner_sha256': source['runner_sha256'],
        'study_window_utc': plan['window_utc'], 'controls': source['controls'],
        'http_gets': source['http_gets'], 'retained_response_bytes': source['retained_response_bytes'],
        'elapsed_seconds': source['elapsed_seconds'], 'completed_window_topics': source['completed_window_topics'],
        'window_schedule_complete_unsaturated': source['window_schedule_complete_unsaturated'],
        'retained_window_records': len(events), 'event_type_counts': source['event_type_counts'],
        'distinct_returned_event_transactions': len({x['transaction_hash'] for x in events}),
        'distinct_returned_event_blocks': len({x['block_number'] for x in events}),
        'window_records_missing_block_hash': source['window_records_missing_block_hash'],
        'window_records_missing_removed_status': source['window_records_missing_removed_status'],
        'nominal_replay_performed': source['nominal_replay_performed'],
        'nominal_replay_events_applied': source.get('nominal_replay_events_applied'),
        'nominal_replay_error': source.get('nominal_replay_error'),
        'end_checkpoint_comparison': source.get('end_checkpoint_comparison'),
        'returned_cut_entries_by_action': dict(Counter(names[x['action']] for x in cuts)),
        'returned_selector_references_by_action': {name: sum(len(x['selectors']) for x in cuts if x['action'] == action) for action, name in names.items()},
        'nonzero_initializer_event_count': source['nonzero_initializer_event_count'],
        'returned_initializer_targets': sorted(initializers),
        'discovered_nonzero_facets': source['discovered_nonzero_facets'],
        'discovered_selectors': source['discovered_selectors'], 'events': events,
        'failure_detail': source.get('detail'), 'scientific_admissions': 0, 'detector_scores': 0,
        'new_network_requests_by_projection': 0, 'new_replay_executions_by_projection': 0,
        'index_completeness_proved': False, 'historical_routing_proved': False,
        'authenticated_chain_mapping': False,
        'limits': plan['limitations']}
    assert not args.output.exists(), 'Do not overwrite earlier findings'
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'path': str(args.output), 'sha256': sha(args.output.read_bytes()),
                      'disposition': result['disposition'], 'retained_records': len(events)}, indent=2))


if __name__ == '__main__':
    main()
