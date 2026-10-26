#!/usr/bin/env python3
"""Independently inspect retained indexer records and nominal registry transitions.

Imports the separately written independent ABI/list model, never the acquisition
runner, RPC codec or producer replay. No network, compiler or EVM execution.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from urllib.parse import parse_qsl, urlsplit

sys.dont_write_bytecode = True


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path):
    def pairs(items):
        result = {}
        for key, value in items:
            assert key not in result, 'Duplicate JSON key'
            result[key] = value
        return result
    def constant(value):
        raise AssertionError('Nonfinite JSON: ' + value)
    return json.loads(path.read_bytes(), object_pairs_hook=pairs, parse_constant=constant)


def when(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def number(value):
    assert isinstance(value, str) and re.fullmatch(r'0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)?', value)
    return 0 if value == '0x' else int(value, 16)


def main():
    root = Path(__file__).resolve().parents[4]
    work, paper = root.parent, root / 'papers/monitoring_jss'
    phase = paper / 'phase14'
    attempt = work / 'phase14_lifi_private/blockscout_events_attempt1'
    plan_path = attempt / 'frozen_plan.json'
    summary_path, ledger_path = attempt / 'summary.json', attempt / 'requests.json'
    plan, summary, ledger = load(plan_path), load(summary_path), load(ledger_path)
    original_plan = phase / 'archive_access/blockscout_event_plan.json'
    runner = phase / 'archive_access/capture_blockscout_events.py'
    preflight = phase / 'qa/archive_access_preflight.json'
    freeze_path = phase / 'archive_access/root_archive_freeze.json'
    freeze, acceptance = load(freeze_path), load(attempt / 'acceptance.json')
    assert freeze['status'] == 'ACCEPTED_BEFORE_FIRST_REQUEST'
    assert sha(freeze_path.read_bytes()) == '781a68b573c4166525b06cafa68ce74fbeef7dcd419eddefe0fe9b156a43f2ac'
    for binding in freeze['bindings']:
        assert sha((paper / binding['path']).read_bytes()) == binding['sha256']
    assert plan_path.read_bytes() == original_plan.read_bytes()
    assert (attempt / 'runner_source.py').read_bytes() == runner.read_bytes()
    assert summary['plan_sha256'] == acceptance['plan_sha256'] == sha(plan_path.read_bytes())
    assert summary['runner_sha256'] == acceptance['runner_sha256'] == sha(runner.read_bytes())
    assert when(freeze['accepted_utc']) < when(acceptance['started_utc']) < when(ledger[0]['started_utc'])
    for row in plan['module_bindings'].values():
        assert sha((paper / row['path']).read_bytes()) == row['sha256']
    for row in plan['document_bindings']:
        assert sha((paper / row['path']).read_bytes()) == row['sha256']
    checkpoints_path = work / 'phase12_lifi_private/checkpoint_only_attempt1/summary.json'
    headers_path = work / 'phase12_lifi_private/admin_state_attempt1/summary.json'
    receipt_path = work / 'phase10_lifi_private/factory_continuation_attempt1/007_diamond_rpc_creation_receipt_response.bin'
    for key, path in [('checkpoint_summary_sha256', checkpoints_path), ('reference_headers_summary_sha256', headers_path),
                      ('constructor_receipt_sha256', receipt_path)]:
        assert sha(path.read_bytes()) == plan['prior_bindings'][key]
    for row, path in zip(plan['prior_failures_preserved'], [headers_path,
                        work / 'phase13_lifi_private/code_window_attempt1/summary.json',
                        work / 'phase13_lifi_private/publicnode_history_attempt1/summary.json']):
        assert sha(path.read_bytes()) == row['summary_sha256']
    checkpoint_data, headers = load(checkpoints_path), load(headers_path)['headers']
    states = {row['name']: row for row in checkpoint_data['states']}
    receipt = load(receipt_path)['result']
    known = {row['topics'][0].lower(): row for row in receipt['logs'] if row['address'].lower() == plan['diamond']}
    independent_path = paper / 'phase13/qa/independent_event_model.py'
    assert sha(independent_path.read_bytes()) == 'f0a681a4e5c5e8de35cd103b59328e88feda611f8d5e7fbfa9a37d655970379a'
    spec = importlib.util.spec_from_file_location('phase14_independent_event_model', independent_path)
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    signatures = {row['topic0']: row['name'] for row in plan['events']}
    quantities, controls, events, checked, returned = [], [], [], [], []
    contexts = {role: {'logs': set(), 'tx_by_position': {}, 'position_by_tx': {}, 'timestamps': {}, 'hashes': {}}
                for role in ('control', 'window')}

    def normalize(raw, query):
        assert isinstance(raw, dict)
        address = '0x' + model.raw_hex(raw['address'], 20).hex()
        topics = list(raw['topics'])
        assert 1 <= len(topics) <= 4
        while topics and topics[-1] is None:
            topics.pop()
        assert topics and None not in topics
        topics = ['0x' + model.raw_hex(t, 32).hex() for t in topics]
        assert address == plan['diamond'] and topics[0] == query['topic0']
        data = '0x' + model.raw_hex(raw['data']).hex()
        block, tx, index, timestamp = [number(raw[k]) for k in ('blockNumber', 'transactionIndex', 'logIndex', 'timeStamp')]
        quantities.extend(raw[k] for k in ('blockNumber', 'transactionIndex', 'logIndex', 'timeStamp'))
        tx_hash = '0x' + model.raw_hex(raw['transactionHash'], 32).hex()
        block_hash = None if raw.get('blockHash') is None else '0x' + model.raw_hex(raw['blockHash'], 32).hex()
        removed = raw.get('removed')
        assert removed is None or removed is False
        assert query['from_block'] <= block <= query['to_block']
        seen = contexts[query['role']]
        assert (block, index) not in seen['logs']
        assert (block, tx) not in seen['tx_by_position'] or seen['tx_by_position'][(block, tx)] == tx_hash
        assert tx_hash not in seen['position_by_tx'] or seen['position_by_tx'][tx_hash] == (block, tx)
        assert block not in seen['timestamps'] or seen['timestamps'][block] == timestamp
        for other, stamp in seen['timestamps'].items():
            assert other == block or (stamp < timestamp if other < block else stamp > timestamp)
        if block_hash is not None:
            assert block not in seen['hashes'] or seen['hashes'][block] == block_hash
            seen['hashes'][block] = block_hash
        for header in headers.values():
            if header['number'] == block:
                assert block_hash is None or block_hash == header['hash']
                assert header['transaction_hashes'][tx] == tx_hash
        if query['role'] == 'window':
            assert plan['window_epoch_seconds'][0] <= timestamp < plan['window_epoch_seconds'][1]
        decoded = model.decode(topics, data, signatures, plan['caps'])
        seen['logs'].add((block, index))
        seen['tx_by_position'][(block, tx)] = tx_hash
        seen['position_by_tx'][tx_hash] = (block, tx)
        seen['timestamps'][block] = timestamp
        return {'block_number': block, 'block_hash': block_hash, 'transaction_index': tx,
                'transaction_hash': tx_hash, 'log_index': index, 'timestamp_epoch_seconds': timestamp,
                'removed': removed, 'raw_data_sha256': sha(bytes.fromhex(data[2:])), 'decoded': decoded}, \
               {'address': address, 'topics': topics, 'data': data}

    assert len(ledger) == len(plan['queries']) == 5
    total = 0
    for i, (record, query) in enumerate(zip(ledger, plan['queries']), 1):
        assert record['ordinal'] == i and record['key'] == query['name'] and record['kind'] == 'blockscout_legacy_get'
        request_path, response_path = attempt / record['request_file'], attempt / record['response_file']
        request_raw, response_raw = request_path.read_bytes(), response_path.read_bytes()
        assert sha(request_raw) == record['request_sha256'] and sha(response_raw) == record['response_sha256']
        assert len(response_raw) == record['response_bytes'] < plan['caps']['per_response_bytes']
        assert record['http_status'] == 200 and record['transport_json_ok'] is True
        assert record['response_at_cap_eof_unproved'] is False
        request, body = load(request_path), load(response_path)
        params = {'module': 'logs', 'action': 'getLogs', 'fromBlock': str(query['from_block']),
                  'toBlock': str(query['to_block']), 'address': plan['diamond'], 'topic0': query['topic0']}
        assert set(request) == {'url', 'method', 'query'} and request['method'] == 'GET' and request['query'] == params
        split = urlsplit(request['url'])
        assert split.scheme + '://' + split.netloc + split.path == plan['api_endpoint'] and not split.fragment
        parsed = parse_qsl(split.query, keep_blank_values=True)
        assert len(parsed) == len(params) and dict(parsed) == params
        assert set(body) == {'status', 'message', 'result'}
        if body['status'] == '0':
            assert body['message'] == 'No logs found' and body['result'] == []
        else:
            assert body['status'] == '1' and body['message'] == 'OK' and isinstance(body['result'], list)
        assert len(body['result']) < plan['caps']['max_response_logs']
        normalized = [normalize(raw, query) for raw in body['result']]
        if query['role'] == 'control':
            expected = known[query['topic0']]
            matches = [(row, data) for row, data in normalized
                       if row['transaction_hash'] == receipt['transactionHash'].lower()
                       and row['log_index'] == int(expected['logIndex'], 16)]
            assert len(matches) == 1
            row, data = matches[0]
            assert row['block_number'] == int(expected['blockNumber'], 16)
            assert row['transaction_index'] == int(expected['transactionIndex'], 16)
            assert row['timestamp_epoch_seconds'] == int(expected['blockTimestamp'], 16)
            assert row['block_hash'] is None or row['block_hash'] == expected['blockHash'].lower()
            assert data == {'address': expected['address'].lower(), 'topics': [v.lower() for v in expected['topics']], 'data': expected['data'].lower()}
            controls.append({'topic': signatures[query['topic0']], 'returned_rows': len(normalized),
                             'known_log_matched': True, 'block_hash_available': row['block_hash'] is not None,
                             'removed_status_available': row['removed'] is not None})
        else:
            events.extend(row for row, _ in normalized)
        total += len(response_raw)
        assert when(record['started_utc']) < when(record['completed_utc'])
        if i > 1:
            assert (when(record['started_utc']) - when(ledger[i - 2]['completed_utc'])).total_seconds() >= plan['caps']['inter_request_pause_seconds']
        checked.append({'ordinal': i, 'role': query['role'], 'event': signatures[query['topic0']],
                        'request_sha256': sha(request_raw), 'response_sha256': sha(response_raw),
                        'response_bytes': len(response_raw), 'rows': len(normalized), 'empty_envelope': body['status'] == '0'})
    events.sort(key=lambda row: (row['block_number'], row['transaction_index'], row['log_index']))
    last = {}
    for row in events:
        assert row['log_index'] > last.get(row['block_number'], -1)
        last[row['block_number']] = row['log_index']
    seed = {'owner': states['start']['owner'], 'enumerated_facets': [
        {key: row[key] for key in ('address', 'facet_position', 'selectors')} for row in states['start']['facets']]}
    registry = model.Registry(seed, plan['diamond'], plan['caps']['max_facets'], plan['caps']['max_selectors'])
    facets, selectors = set(checkpoint_data['discovered_nonzero_facets']), set(checkpoint_data['discovered_selectors'])
    for row in events:
        event = row['decoded']
        if event['event'] == 'DiamondCut':
            facets.update(cut['facet'] for cut in event['cuts'] if cut['facet'] != model.ZERO)
            selectors.update(value for cut in event['cuts'] for value in cut['selectors'])
        assert len(facets) <= plan['caps']['max_facets'] and len(selectors) <= plan['caps']['max_selectors']
        registry.apply(event)
    target = {'owner': states['end']['owner'], 'facets': [
        {key: row[key] for key in ('address', 'facet_position', 'selectors')} for row in states['end']['facets']],
        'selector_map': states['end']['selector_map']}
    assert registry.snapshot() == target == summary['nominal_replay_end']
    assert summary['end_checkpoint_comparison'] == {'facets_equal': True, 'owner_equal': True, 'selector_map_equal': True}
    assert summary['events'] == events and summary['controls'] == controls
    assert summary['discovered_nonzero_facets'] == sorted(facets) and summary['discovered_selectors'] == sorted(selectors)
    assert summary['event_type_counts'] == dict(Counter(row['decoded']['event'] for row in events))
    assert summary['completed_window_topics'] == [signatures[q['topic0']] for q in plan['queries'][2:]]
    assert summary['http_gets'] == 5 and summary['retained_response_bytes'] == total <= plan['caps']['total_retained_response_bytes']
    assert summary['nominal_replay_performed'] is True and summary['nominal_replay_error'] is None
    assert summary['nominal_replay_events_applied'] == len(events) and summary['window_schedule_complete_unsaturated'] is True
    assert summary['disposition'] == 'INDEXER_EVENT_CHECKPOINT_CONSISTENCY_ROUTING_UNRESOLVED'
    initializers = [row for row in events if row['decoded'].get('initializer_effects_unclosed', False)]
    assert summary['nonzero_initializer_event_count'] == len(initializers)
    assert summary['window_records_missing_block_hash'] == sum(row['block_hash'] is None for row in events)
    assert summary['window_records_missing_removed_status'] == sum(row['removed'] is None for row in events)
    assert all(summary[k] is False for k in ('index_completeness_proved', 'historical_routing_proved', 'authenticated_chain_mapping'))
    assert summary['scientific_admissions'] == summary['detector_scores'] == 0
    elapsed = (when(summary['completed_utc']) - when(ledger[0]['started_utc'])).total_seconds()
    assert 0 <= elapsed <= plan['caps']['wall_seconds'] and abs(elapsed - summary['elapsed_seconds']) < 1
    output = {'schema_version': 'article2_phase14_archive_access_actual_audit_v1',
              'status': 'PASS_INDEPENDENT_INDEXER_RECORDS_AND_NOMINAL_REPLAY',
              'audited_utc': datetime.now(timezone.utc).isoformat(),
              'auditor_sha256': sha(Path(__file__).read_bytes()),
              'independent_model_sha256': sha(independent_path.read_bytes()),
              'freeze_sha256': sha(freeze_path.read_bytes()), 'plan_sha256': sha(plan_path.read_bytes()),
              'runner_sha256': sha(runner.read_bytes()), 'preflight_sha256': sha(preflight.read_bytes()),
              'summary_sha256': sha(summary_path.read_bytes()), 'requests_sha256': sha(ledger_path.read_bytes()),
              'requests': checked, 'new_http_gets': len(ledger), 'retained_response_bytes': total,
              'elapsed_first_request_to_summary_seconds': elapsed,
              'controls_matched': len(controls), 'window_topic_queries': 3,
              'window_event_counts': dict(Counter(row['decoded']['event'] for row in events)),
              'window_event_count': len(events), 'distinct_window_event_transactions': len({r['transaction_hash'] for r in events}),
              'all_queries_unsaturated': True, 'observed_empty_topic_responses': [r['event'] for r in checked if r['role'] == 'window' and r['rows'] == 0],
              'legacy_empty_hex_zero_quantity_count': quantities.count('0x'),
              'window_missing_block_hash': sum(row['block_hash'] is None for row in events),
              'window_missing_removed_status': sum(row['removed'] is None for row in events),
              'nominal_replay_applied_events': len(events),
              'endpoint_owner_facets_and_selector_map_equal': True,
              'nonzero_initializer_event_count': len(initializers),
              'initializer_observations': [{'block_number': r['block_number'], 'transaction_hash': r['transaction_hash'],
                  'log_index': r['log_index'], 'address': r['decoded']['initializer'],
                  'calldata_bytes': len(bytes.fromhex(r['decoded']['initializer_calldata'][2:])),
                  'calldata_sha256': sha(bytes.fromhex(r['decoded']['initializer_calldata'][2:]))} for r in initializers],
              'prior_failed_summaries_unchanged': True,
              'producer_modules_imported': False, 'network_requests_by_auditor': 0,
              'compiler_invocations': 0, 'old_suites_rerun': 0,
              'limitations': [
                  'This is an independently decoded indexer record list and nominal endpoint consistency result.',
                  'Missing block hashes and removed flags remain null; no cryptographic chain mapping is asserted.',
                  'Two known controls and unsaturated responses do not prove exhaustive canonical index coverage.',
                  'Three nonzero initializer events are not modeled; their effects and other writers remain unresolved.',
                  'Shared Inited records are not automatically attributed to CBridge or effective configuration.',
                  'No complete historical routing, case admission or detector-performance result follows.'
              ]}
    target = Path(__file__).with_name('archive_access_actual_review.json')
    assert not target.exists(), 'Preserve earlier actual audit'
    target.write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps({key: output[key] for key in ('status', 'new_http_gets', 'retained_response_bytes', 'window_event_counts', 'nonzero_initializer_event_count')}))


if __name__ == '__main__':
    main()
