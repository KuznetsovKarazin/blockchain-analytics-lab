#!/usr/bin/env python3
"""Make a source-free account from one immutable continuation summary.

This is descriptive aggregation, not another network request or event replay.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_once(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    assert not path.exists(), 'Do not replace an earlier findings record'
    path.write_bytes(raw)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--attempt', required=True, type=Path)
    parser.add_argument('--prior-attempt', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    summary_raw = (args.attempt / 'summary.json').read_bytes()
    source = json.loads(summary_raw)
    prior_raw = (args.prior_attempt / 'summary.json').read_bytes()
    prior = json.loads(prior_raw)
    plan = json.loads((args.attempt / 'frozen_plan.json').read_bytes())
    ledger_raw = (args.attempt / 'requests.json').read_bytes()
    ledger = json.loads(ledger_raw)
    assert sha(prior_raw) == plan['prior_bindings']['phase13_failed_summary_sha256']
    assert sha((args.attempt / 'frozen_plan.json').read_bytes()) == source['plan_sha256']
    assert source['rpc_methods'] == len(ledger)
    assert sum(x['response_bytes'] for x in ledger) == source['retained_response_bytes']
    events, cuts, initializer_targets = [], [], set()
    action_names = {0: 'Add', 1: 'Replace', 2: 'Remove'}
    for index, row in enumerate(source['events']):
        event = row['decoded']
        projected = {key: row[key] for key in ('block_number', 'block_hash', 'transaction_index', 'transaction_hash', 'log_index')}
        projected.update(event_index=index, event=event['event'])
        if event['event'] == 'DiamondCut':
            data = bytes.fromhex(event['initializer_calldata'][2:])
            projected.update(initializer=event['initializer'], initializer_calldata_bytes=len(data),
                             initializer_calldata_sha256=sha(data),
                             initializer_calldata_selector=('0x' + data[:4].hex()) if len(data) >= 4 else None,
                             initializer_effects_unclosed=event['initializer_effects_unclosed'],
                             cuts=[{'facet': cut['facet'], 'action': action_names[cut['action']],
                                    'selectors': cut['selectors']} for cut in event['cuts']])
            if event['initializer_effects_unclosed']:
                initializer_targets.add(event['initializer'])
            cuts.extend(projected['cuts'])
        elif event['event'] == 'OwnershipTransferred':
            projected.update(previous_owner=event['previous_owner'], new_owner=event['new_owner'])
        else:
            projected.update(bridge=event['bridge'], chain_id=event['chain_id'],
                             facet_attribution='AMBIGUOUS_SHARED_EVENT_SIGNATURE')
        events.append(projected)
    failure = None
    if ledger and not ledger[-1].get('transport_json_ok', False):
        last = ledger[-1]
        raw = (args.attempt / last['response_file']).read_bytes()
        failure = {key: last[key] for key in ('ordinal', 'key', 'http_status', 'response_bytes', 'response_sha256') if key in last}
        failure['request_sha256'] = last['request_sha256']
        try:
            error = json.loads(raw).get('error', {})
            failure['rpc_error_code'] = error.get('code')
            failure['rpc_error_message'] = error.get('message')
        except (ValueError, AttributeError):
            failure['rpc_error_parseable'] = False
    complete = source['window_event_coverage_complete_under_query_schedule']
    result = {
        'schema_version': 'article2_phase13_publicnode_history_findings_v1',
        'disposition': source['disposition'],
        'summary_sha256': sha(summary_raw), 'requests_sha256': sha(ledger_raw),
        'plan_sha256': source['plan_sha256'], 'runner_sha256': source['runner_sha256'],
        'prior_attempt_summary_sha256': sha(prior_raw),
        'study_window_utc': plan['window_utc'],
        'window_blocks_inclusive': [plan['event_range']['from_block'], plan['event_range']['to_block']],
        'nominal_seed_block_end': plan['event_range']['seed_checkpoint_block'],
        'positive_control': source['positive_control'],
        'matched_reference_headers': source['headers'],
        'new_request_accounting': {key: source[key] for key in ('rpc_methods', 'retained_response_bytes', 'chain_id_queries',
            'fresh_headers', 'positive_control_log_queries', 'window_log_requests', 'completed_log_chunks')},
        'phase13_cumulative_rpc_methods': prior['rpc_methods'] + source['rpc_methods'],
        'phase13_cumulative_retained_response_bytes': prior['retained_response_bytes'] + source['retained_response_bytes'],
        'completed_all_39_window_chunks': complete,
        'retained_decoded_window_records': len(events),
        'returned_complete_window_event_count': len(events) if complete else None,
        'event_type_counts_in_retained_records': source['event_type_counts'],
        'nominal_replay_performed': source['nominal_replay_performed'],
        'nominal_replay_events_applied': source.get('nominal_replay_events_applied'),
        'nominal_replay_error': source.get('nominal_replay_error'),
        'end_checkpoint_comparison': source.get('end_checkpoint_comparison'),
        'retained_cut_entries_by_action': dict(Counter(cut['action'] for cut in cuts)),
        'retained_selector_references_by_action': {name: sum(len(cut['selectors']) for cut in cuts if cut['action'] == name)
                                                   for name in ('Add', 'Replace', 'Remove')},
        'retained_nonzero_initializer_event_count': source['nonzero_initializer_event_count'],
        'retained_initializer_targets': sorted(initializer_targets),
        'events': events, 'transport_failure': failure,
        'scientific_admissions': 0, 'detector_scores': 0,
        'new_network_requests_for_this_summary': 0, 'new_replay_executions_for_this_summary': 0,
        'historical_routing_proved': False, 'provider_index_completeness_proved': False,
        'limits': ['Positive control checks a known two-event subset at one earlier block, not complete study-window retrieval.',
            'Reference-header agreement is provider-data consistency, not cryptographic state or consensus authentication.',
            'A complete scheduled event list and matching nominal end state do not exclude unlogged writes or initializer effects.',
            'Unavailable event history is not an empty history; partial or absent records do not justify case exclusion.',
            'Inited-shaped events are not automatically attributable to one facet or effective bridge configuration.',
            'No new runtime, source, transaction-payload, detector-score or label acquisition follows from discovered targets.']}
    write_once(args.output, result)
    print(json.dumps({'output': str(args.output), 'sha256': sha(args.output.read_bytes()),
                      'disposition': result['disposition'], 'rpc_methods': source['rpc_methods'],
                      'decoded_window_records': len(events), 'complete_window': complete}, indent=2))


if __name__ == '__main__':
    main()
