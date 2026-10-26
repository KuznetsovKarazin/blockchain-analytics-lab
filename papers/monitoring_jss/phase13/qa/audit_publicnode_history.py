#!/usr/bin/env python3
"""Independent audit of the separately frozen PublicNode observation attempt."""
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import importlib.util
import json
import sys

sys.dont_write_bytecode = True
QA = Path(__file__).resolve().parent
ROOT = QA.parents[3]
WORK = ROOT.parent
PAPER = ROOT / 'papers/monitoring_jss'
PHASE = PAPER / 'phase13'


def imported(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


helpers = imported('independent_history_audit_helpers', QA / 'audit_code_and_window_events.py')
sha, read, when, quantity = helpers.sha, helpers.read, helpers.when, helpers.quantity
model = imported('independent_history_model', QA / 'independent_event_model.py')


def canonical(log):
    return {'address': '0x' + model.raw_hex(log['address'], 20).hex(),
        'topics': ['0x' + model.raw_hex(x, 32).hex() for x in log['topics']],
        'data': '0x' + model.raw_hex(log['data']).hex(),
        'blockHash': '0x' + model.raw_hex(log['blockHash'], 32).hex(),
        'transactionHash': '0x' + model.raw_hex(log['transactionHash'], 32).hex(),
        **{key: quantity(log[key]) for key in ('blockNumber', 'transactionIndex', 'logIndex')},
        'removed': log['removed']}


def decode_logs(logs, interval, plan, headers, seen):
    assert isinstance(logs, list)
    rows = []
    topics = {x['topic0']: x['name'] for x in plan['events']}
    for log in logs:
        value = canonical(log)
        assert value['address'] == plan['diamond'] and value['removed'] is False
        block, txindex, index = (value[k] for k in ('blockNumber', 'transactionIndex', 'logIndex'))
        blockhash, txhash = value['blockHash'], value['transactionHash']
        assert interval[0] <= block <= interval[1]
        assert (block, index) not in seen['ids']
        seen['ids'].add((block, index))
        assert block not in seen['blocks'] or seen['blocks'][block] == blockhash
        seen['blocks'][block] = blockhash
        assert (block, txindex) not in seen['positions'] or seen['positions'][(block, txindex)] == txhash
        seen['positions'][(block, txindex)] = txhash
        assert txhash not in seen['transactions'] or seen['transactions'][txhash] == (block, blockhash, txindex)
        seen['transactions'][txhash] = (block, blockhash, txindex)
        for header in headers.values():
            if header['number'] == block:
                assert header['hash'] == blockhash and header['transaction_hashes'][txindex] == txhash
        rows.append({'block_number': block, 'block_hash': blockhash, 'transaction_index': txindex,
            'transaction_hash': txhash, 'log_index': index,
            'raw_data_sha256': hashlib.sha256(model.raw_hex(log['data'])).hexdigest(),
            'decoded': model.decode(log['topics'], log['data'], topics, plan['caps'])})
    return rows


def new_seen():
    return {'ids': set(), 'blocks': {}, 'positions': {}, 'transactions': {}}


def main():
    attempt = WORK / 'phase13_lifi_private/publicnode_history_attempt1'
    folder = PHASE / 'history_continuation'
    freeze_path = folder / 'root_history_freeze.json'
    freeze = read(freeze_path)
    plan, summary = read(attempt / 'frozen_plan.json'), read(attempt / 'summary.json')
    acceptance, ledger = read(attempt / 'acceptance.json'), read(attempt / 'requests.json')
    assert sha(attempt / 'frozen_plan.json') == freeze['plan_sha256']
    assert sha(attempt / 'runner_source.py') == freeze['runner_sha256']
    assert sha(folder / 'capture_publicnode_history.py') == freeze['runner_sha256']
    assert all(summary[k] == acceptance[k] == freeze[k] for k in ('plan_sha256', 'runner_sha256'))
    assert when(freeze['accepted_utc']) < when(acceptance['started_utc'])
    for value in plan['module_bindings'].values():
        assert sha(PAPER / value['path']) == value['sha256']
    for value in plan['document_bindings']:
        assert sha(PAPER / value['path']) == value['sha256']
    prior = plan['prior_bindings']
    checkpoints_path = WORK / 'phase12_lifi_private/checkpoint_only_attempt1/summary.json'
    old12_path = WORK / 'phase12_lifi_private/admin_state_attempt1/summary.json'
    old13_path = WORK / 'phase13_lifi_private/code_window_attempt1/summary.json'
    receipt_path = WORK / 'phase10_lifi_private/factory_continuation_attempt1/007_diamond_rpc_creation_receipt_response.bin'
    for key, path in [('checkpoint_summary_sha256', checkpoints_path), ('phase12_failed_summary_sha256', old12_path),
        ('phase13_failed_summary_sha256', old13_path), ('constructor_receipt_sha256', receipt_path)]:
        assert sha(path) == prior[key]
    assert sha(PAPER / prior['original_plan_path']) == prior['original_plan_sha256']
    original_plan = read(PAPER / prior['original_plan_path'])
    assert all(plan[k] == original_plan[k] for k in ('diamond', 'events', 'window_utc', 'event_range'))
    old12, old13 = read(old12_path), read(old13_path)
    for old in (old12, old13):
        assert old['disposition'] == 'UNAVAILABLE_UNDER_FROZEN_CAP' and old['completed_log_chunks'] == 0
    assert old12['rpc_methods'] == 5 and old12['retained_response_bytes'] == 29835
    assert old13['rpc_methods'] == 19 and old13['retained_response_bytes'] == 154568
    checkpoints = read(checkpoints_path)
    headers, states = old12['headers'], {x['name']: x for x in checkpoints['states']}
    chunks = [{'from_block': n, 'to_block': min(n + 4999, 14426367)} for n in range(14233163, 14426368, 5000)]
    assert plan['event_range']['chunks'] == chunks and len(chunks) == 39
    assert plan['positive_control']['block_number'] == headers['creation']['number'] == 13984588
    assert plan['positive_control']['block_hash'] == headers['creation']['hash']
    assert plan['rpc_endpoint'] == 'https://ethereum-rpc.publicnode.com'
    topics = [x['topic0'] for x in plan['events']]
    expected = [('chain_id', 'eth_chainId', [])]
    expected.extend((name + '_header', 'eth_getBlockByNumber', [hex(headers[name]['number']), False]) for name in ('start', 'end'))
    expected.append(('creation_control_logs', 'eth_getLogs', [{'blockHash': headers['creation']['hash'],
        'address': plan['diamond'], 'topics': [topics]}]))
    expected.extend(('window_admin_logs_' + str(i), 'eth_getLogs', [{'fromBlock': hex(c['from_block']),
        'toBlock': hex(c['to_block']), 'address': plan['diamond'], 'topics': [topics]}]) for i, c in enumerate(chunks))
    assert len(expected) == plan['caps']['rpc_methods'] == 43
    assert 0 < len(ledger) <= 43
    previous, total, responses, inventory, failures = when(acceptance['started_utc']), 0, [], [], []
    for i, record in enumerate(ledger):
        ordinal = i + 1
        key, method, params = expected[i]
        assert record['ordinal'] == ordinal and record['key'] == key and record['kind'] == 'rpc'
        req, res = attempt / record['request_file'], attempt / record['response_file']
        assert req.name == f'{ordinal:03d}_{key}_request.json' and res.name == f'{ordinal:03d}_{key}_response.bin'
        assert sha(req) == record['request_sha256'] and sha(res) == record['response_sha256']
        assert res.stat().st_size == record['response_bytes'] <= plan['caps']['per_response_bytes']
        total += res.stat().st_size
        assert total <= plan['caps']['total_retained_response_bytes']
        assert previous <= when(record['started_utc']) <= when(record['completed_utc'])
        previous = when(record['completed_utc'])
        assert read(req) == {'url': plan['rpc_endpoint'], 'method': 'POST', 'json': {
            'jsonrpc': '2.0', 'id': ordinal, 'method': method, 'params': params}}
        response = read(res)
        assert response['jsonrpc'] == '2.0' and type(response['id']) is int and response['id'] == ordinal
        if record['transport_json_ok']:
            assert record['http_status'] == 200 and record['response_at_cap_eof_unproved'] is False
            assert 'result' in response and 'error' not in response
        else:
            assert ordinal == len(ledger) and 'failure' in record
            assert 'error' in response and 'result' not in response
            failures.append({'ordinal': ordinal, 'key': key, 'http_status': record.get('http_status'),
                'error': response['error'], 'response_sha256': sha(res)})
        responses.append(response)
        inventory.append({'ordinal': ordinal, 'key': key, 'method': method,
            'request_sha256': sha(req), 'response_sha256': sha(res), 'response_bytes': res.stat().st_size,
            'http_status': record.get('http_status'), 'transport_json_ok': record['transport_json_ok']})
    assert {p.name for p in attempt.glob('*_request.json')} == {r['request_file'] for r in ledger}
    assert {p.name for p in attempt.glob('*_response.bin')} == {r['response_file'] for r in ledger}
    assert summary['rpc_methods'] == len(ledger) and summary['retained_response_bytes'] == total
    assert previous <= when(summary['completed_utc'])
    elapsed = (when(summary['completed_utc']) - when(ledger[0]['started_utc'])).total_seconds()
    assert elapsed <= plan['caps']['wall_seconds'] + plan['caps']['request_timeout_seconds']
    assert ledger[0]['transport_json_ok'] and quantity(responses[0]['result']) == summary['chain_id'] == 1
    if len(ledger) < 4 or not all(row['transport_json_ok'] for row in ledger[:4]):
        assert len(ledger) == 2 and ledger[0]['response_bytes'] == 40
        assert ledger[1]['http_status'] == 200 and ledger[1]['response_bytes'] == 135
        assert responses[1]['error'] == {'code': 4444,
            'message': 'pruned history unavailable: requested 14233162, earliest available 15500000'}
        assert summary['disposition'] == 'UNAVAILABLE_UNDER_FROZEN_CAP'
        assert summary['headers'] == {} and summary['positive_control'] is None and summary['events'] == []
        assert summary['chain_id_queries'] == 1 and summary['fresh_headers'] == 1
        for key in ('positive_control_log_queries', 'window_log_requests', 'completed_log_chunks',
            'scientific_admissions', 'detector_scores', 'fresh_code_requests', 'new_compiler_invocations',
            'incident_transaction_payload_queries', 'nonzero_initializer_event_count'):
            assert summary[key] == 0
        for key in ('nominal_replay_performed', 'window_event_coverage_complete_under_query_schedule',
            'historical_routing_proved', 'index_completeness_proved', 'proofs_cryptographically_verified',
            'unlogged_mutation_paths_excluded'):
            assert summary[key] is False
        assert summary['event_type_counts'] == {}
        assert summary['discovered_nonzero_facets'] == checkpoints['discovered_nonzero_facets']
        assert summary['discovered_selectors'] == checkpoints['discovered_selectors']
        assert summary['prior_failed_attempts_preserved'] is True
        result = {'schema_version': 'article2_phase13_independent_publicnode_history_audit_v1',
            'status': 'PASS_PRESERVED_PUBLICNODE_HISTORY_UNAVAILABILITY',
            'audited_utc': datetime.now(timezone.utc).isoformat(), 'auditor_sha256': sha(Path(__file__)),
            'own_audit_helper_sha256': sha(QA / 'audit_code_and_window_events.py'),
            'independent_event_model_sha256': sha(QA / 'independent_event_model.py'),
            'root_freeze_sha256': sha(freeze_path), 'plan_sha256': freeze['plan_sha256'],
            'runner_sha256': freeze['runner_sha256'], 'summary_sha256': sha(attempt / 'summary.json'),
            'request_ledger_sha256': sha(attempt / 'requests.json'),
            'new_rpc_methods': 2, 'new_retained_response_bytes': total, 'requests': inventory,
            'elapsed_seconds_first_request_to_summary': elapsed, 'retained_provider_failures': failures,
            'chain_id_successful': 1, 'header_requests_attempted': 1, 'header_results_observed': 0,
            'positive_control_requests': 0, 'positive_control_passed': None,
            'window_log_requests': 0, 'completed_window_chunks': 0, 'window_events_observed': None,
            'nominal_replay_performed': False, 'end_checkpoint_comparison': None,
            'phase13_cumulative_rpc_methods': 21, 'phase13_cumulative_retained_response_bytes': 154568 + total,
            'prior_failures_unchanged': True, 'adaptive_retry_split_or_additional_targets_observed': False,
            'producer_modules_imported': False, 'new_network_requests_by_auditor': 0,
            'compiler_invocations_by_auditor': 0, 'old_test_suites_rerun': 0,
            'scientific_admissions': 0, 'detector_scores': 0,
            'limitations': ['A successful chain ID does not establish historical data access.',
                'The reported pruning boundary belongs to this response; no general provider SLA or all-endpoint limitation is inferred.',
                'The planned positive control and window event queries were never reached.',
                'No event absence, replay agreement, routing continuity or scientific case exclusion follows.',
                'The endpoint change is a disclosed separate retrieval adaptation preserving both prior refusals.']}
        assert total == 175
        output = QA / 'independent_history_review.json'
        output.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'status': result['status'], 'path': str(output), 'sha256': sha(output),
            'rpc_methods': 2, 'bytes': total, 'cumulative_rpc': 21, 'cumulative_bytes': 154568 + total}))
        return
    checked_headers = {}
    for i, name in enumerate(('start', 'end'), 1):
        assert ledger[i]['transport_json_ok']
        value, prior_header = responses[i]['result'], headers[name]
        assert quantity(value['number']) == prior_header['number']
        assert value['hash'] == prior_header['hash'] and value['stateRoot'] == prior_header['state_root']
        assert quantity(value['timestamp']) == int(when(prior_header['timestamp_utc']).timestamp())
        assert value['transactions'] == prior_header['transaction_hashes']
        checked_headers[name] = {'number': prior_header['number'], 'hash': prior_header['hash'],
            'state_root': prior_header['state_root'], 'timestamp_utc': when(prior_header['timestamp_utc']).isoformat(),
            'transaction_count': len(prior_header['transaction_hashes']), 'full_transaction_hash_list_equal': True}
    assert checked_headers == summary['headers']
    assert ledger[3]['transport_json_ok']
    control = responses[3]['result']
    assert isinstance(control, list) and len(control) <= plan['caps']['max_event_logs']
    control_rows = decode_logs(control, (13984588, 13984588), plan, headers, new_seen())
    retained_receipt = read(receipt_path)['result']
    reference = [canonical(x) for x in retained_receipt['logs'] if x['address'].lower() == plan['diamond']]
    returned = [canonical(x) for x in control]
    assert len(reference) == 2 and {x['logIndex'] for x in reference} == {122, 123}
    assert all(x in returned for x in reference)
    for row in control:
        if 'blockTimestamp' in row:
            assert quantity(row['blockTimestamp']) == int(when(headers['creation']['timestamp_utc']).timestamp())
    control_summary = {'status': 'PASS_RETAINED_CONSTRUCTOR_LOG_SUBSET', 'returned_logs': len(control),
        'expected_logs_matched': 2, 'additional_logs_allowed': len(control) - 2,
        'block_number': 13984588, 'block_hash': headers['creation']['hash'],
        'decoded_event_counts': dict(Counter(x['decoded']['event'] for x in control_rows)), 'included_in_window_replay': False}
    assert summary['positive_control'] == control_summary
    events, complete_chunks, seen = [], 0, new_seen()
    for index, (record, response) in enumerate(zip(ledger[4:], responses[4:])):
        if not record['transport_json_ok']:
            break
        logs, chunk = response['result'], chunks[index]
        assert isinstance(logs, list) and len(events) + len(logs) <= plan['caps']['max_event_logs']
        rows = decode_logs(logs, (chunk['from_block'], chunk['to_block']), plan, headers, seen)
        events.extend({**row, 'chunk_index': index} for row in rows)
        complete_chunks += 1
    complete = complete_chunks == 39
    if complete:
        events.sort(key=lambda x: (x['block_number'], x['transaction_index'], x['log_index']))
        last = {}
        for event in events:
            assert event['log_index'] > last.get(event['block_number'], -1)
            last[event['block_number']] = event['log_index']
    assert events == summary['events']
    assert summary['completed_log_chunks'] == complete_chunks
    assert summary['window_event_coverage_complete_under_query_schedule'] == complete
    counts = dict(Counter(x['decoded']['event'] for x in events))
    assert summary['event_type_counts'] == counts
    initializer_count = sum(x['decoded'].get('initializer_effects_unclosed', False) for x in events)
    assert summary['nonzero_initializer_event_count'] == initializer_count
    facets, selectors = set(checkpoints['discovered_nonzero_facets']), set(checkpoints['discovered_selectors'])
    for event in events:
        for cut in event['decoded'].get('cuts', []):
            if cut['facet'] != model.ZERO:
                facets.add(cut['facet'])
            selectors.update(cut['selectors'])
    assert sorted(facets) == summary['discovered_nonzero_facets']
    assert sorted(selectors) == summary['discovered_selectors']
    assert len(facets) <= plan['caps']['max_facets'] and len(selectors) <= plan['caps']['max_selectors']
    comparison, replay_error, applied = None, None, 0
    if complete:
        replay = model.Registry({'owner': states['start']['owner'], 'enumerated_facets': states['start']['facets']},
            plan['diamond'], plan['caps']['max_facets'], plan['caps']['max_selectors'])
        assert replay.snapshot()['selector_map'] == states['start']['selector_map']
        for i, event in enumerate(events):
            try:
                replay.apply(event['decoded'])
                applied += 1
            except (AssertionError, StopIteration):
                replay_error = {'event_index': i, 'block_number': event['block_number'], 'log_index': event['log_index']}
                break
        target = {'owner': states['end']['owner'], 'facets': [{k: x[k] for k in ('address', 'facet_position', 'selectors')}
            for x in states['end']['facets']], 'selector_map': states['end']['selector_map']}
        comparison = {key + '_equal': replay_error is None and replay.snapshot()[key] == value for key, value in target.items()}
        assert summary['nominal_replay_performed'] is True and summary['nominal_replay_events_applied'] == applied
        assert (summary['nominal_replay_error'] is None) == (replay_error is None)
        if replay_error:
            assert all(summary['nominal_replay_error'][k] == v for k, v in replay_error.items())
        assert summary['nominal_replay_end'] == (None if replay_error else replay.snapshot())
        assert summary['end_checkpoint_comparison'] == comparison
    else:
        assert summary['nominal_replay_performed'] is False
    assert summary['chain_id_queries'] == 1 and summary['fresh_headers'] == 2
    assert summary['positive_control_log_queries'] == 1 and summary['window_log_requests'] == len(ledger) - 4
    for key in ('scientific_admissions', 'detector_scores', 'fresh_code_requests', 'new_compiler_invocations', 'incident_transaction_payload_queries'):
        assert summary[key] == 0
    for key in ('historical_routing_proved', 'index_completeness_proved', 'proofs_cryptographically_verified', 'unlogged_mutation_paths_excluded'):
        assert summary[key] is False
    assert summary['prior_failed_attempts_preserved'] is True
    result = {'schema_version': 'article2_phase13_independent_publicnode_history_audit_v1',
        'status': 'PASS_INDEPENDENT_PUBLICNODE_HISTORY_AUDIT', 'audited_utc': datetime.now(timezone.utc).isoformat(),
        'auditor_sha256': sha(Path(__file__)), 'own_audit_helper_sha256': sha(QA / 'audit_code_and_window_events.py'),
        'independent_event_model_sha256': sha(QA / 'independent_event_model.py'),
        'root_freeze_sha256': sha(freeze_path), 'plan_sha256': freeze['plan_sha256'], 'runner_sha256': freeze['runner_sha256'],
        'summary_sha256': sha(attempt / 'summary.json'), 'request_ledger_sha256': sha(attempt / 'requests.json'),
        'new_rpc_methods': len(ledger), 'new_retained_response_bytes': total, 'requests': inventory,
        'elapsed_seconds_first_request_to_summary': elapsed, 'retained_provider_failures': failures,
        'headers_independently_matched': checked_headers, 'positive_control': control_summary,
        'completed_window_chunks': complete_chunks, 'window_events': len(events), 'window_event_type_counts': counts,
        'window_event_transaction_count': len({x['transaction_hash'] for x in events}),
        'nonzero_initializer_events': initializer_count, 'nominal_replay_events_applied': applied,
        'nominal_replay_error': replay_error, 'end_checkpoint_comparison': comparison,
        'phase13_cumulative_rpc_methods': 19 + len(ledger), 'phase13_cumulative_retained_response_bytes': 154568 + total,
        'new_window_event_facets': sorted(facets - set(checkpoints['discovered_nonzero_facets'])),
        'prior_failures_unchanged': True, 'positive_control_included_in_window_replay': False,
        'adaptive_retry_split_or_additional_targets_observed': False, 'producer_modules_imported': False,
        'new_network_requests_by_auditor': 0, 'compiler_invocations_by_auditor': 0,
        'old_test_suites_rerun': 0, 'scientific_admissions': 0, 'detector_scores': 0,
        'limitations': ['The provider change is a disclosed separate retrieval adaptation after prior refusals.',
            'Positive-control success does not prove completeness of the provider historical index.',
            'Nominal replay agreement does not exclude initializer effects or hidden intermediate state.',
            'Shared Inited events do not establish CBridge attribution or effective configuration.',
            'State proofs, exhaustive mapping membership and all reachable writers remain unclosed.',
            'No independent incident admission or detector-performance claim follows.']}
    output = QA / 'independent_history_review.json'
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'path': str(output), 'sha256': sha(output),
        'rpc_methods': len(ledger), 'bytes': total, 'events': len(events), 'comparison': comparison}))


if __name__ == '__main__':
    main()
