#!/usr/bin/env python3
"""Independent retained-evidence audit; no producer, transport or codec imports."""
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import importlib.util
import json
import re
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[4]
WORK = ROOT.parent
PAPER = ROOT / 'papers/monitoring_jss'
PHASE = PAPER / 'phase13'
QA = PHASE / 'qa'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    def pairs(values):
        result = {}
        for key, value in values:
            assert key not in result
            result[key] = value
        return result
    return json.loads(path.read_bytes(), object_pairs_hook=pairs)


def when(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def quantity(value):
    assert isinstance(value, str) and re.fullmatch(r'0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)', value)
    return int(value, 16)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    attempt = WORK / 'phase13_lifi_private/code_window_attempt1'
    freeze_path = PHASE / 'acquisition/root_acquisition_freeze.json'
    freeze = read(freeze_path)
    plan_path = PHASE / 'acquisition/code_and_window_events_plan.json'
    runner_path = PHASE / 'acquisition/capture_code_and_window_events.py'
    plan, summary = read(plan_path), read(attempt / 'summary.json')
    acceptance, ledger = read(attempt / 'acceptance.json'), read(attempt / 'requests.json')
    assert sha(plan_path) == sha(attempt / 'frozen_plan.json') == freeze['plan_sha256']
    assert sha(runner_path) == sha(attempt / 'runner_source.py') == freeze['runner_sha256']
    assert all(summary[k] == acceptance[k] == freeze[k] for k in ('plan_sha256', 'runner_sha256'))
    assert when(freeze['accepted_utc']) < when(acceptance['started_utc'])
    preflight = read(QA / 'acquisition_preflight.json')
    assert preflight['plan_sha256'] == sha(plan_path) and preflight['runner_sha256'] == sha(runner_path)
    assert sha(QA / 'acquisition_preflight.json') == freeze['independent_preflight_sha256']
    prior = plan['prior_bindings']
    checkpoint_path = WORK / 'phase12_lifi_private/checkpoint_only_attempt1/summary.json'
    failed_path = WORK / 'phase12_lifi_private/admin_state_attempt1/summary.json'
    assert sha(checkpoint_path) == prior['checkpoint_summary_sha256']
    assert sha(failed_path) == prior['failed_attempt_summary_sha256']
    for prefix in ('checkpoint_review', 'scope_review', 'phase13_scope_review', 'phase12_plan'):
        assert sha(PAPER / prior[prefix + '_path']) == prior[prefix + '_sha256']
    for binding in plan['module_bindings'].values():
        assert sha(PAPER / binding['path']) == binding['sha256']
    checkpoints, failed = read(checkpoint_path), read(failed_path)
    assert failed['disposition'] == 'UNAVAILABLE_UNDER_FROZEN_CAP' and failed['rpc_methods'] == 5
    assert failed['retained_response_bytes'] == 29835 and failed['completed_log_chunks'] == 0
    old_ledger = read(failed_path.parent / 'requests.json')
    for record in old_ledger:
        assert sha(failed_path.parent / record['request_file']) == record['request_sha256']
        assert sha(failed_path.parent / record['response_file']) == record['response_sha256']
    assert old_ledger[-1]['http_status'] == 400
    assert read(failed_path.parent / old_ledger[-1]['response_file'])['error']['code'] == 35
    states = {x['name']: x for x in checkpoints['states']}
    expected_pairs = [{'checkpoint': s['name'], 'block_number': s['block_number'], 'block_hash': s['block_hash'],
        'address': f['address']} for s in checkpoints['states'] for f in s['facets']]
    assert [{k: row[k] for k in expected_pairs[0]} for row in plan['code_observations']] == expected_pairs
    assert len(expected_pairs) == 19 and len({x['address'] for x in expected_pairs}) == 14
    chunks = [{'from_block': n, 'to_block': min(n + 4999, 14426367)} for n in range(14233163, 14426368, 5000)]
    assert plan['event_range']['chunks'] == chunks and len(chunks) == 39
    assert states['start']['block_number'] + 1 == chunks[0]['from_block']
    assert states['end']['block_number'] == chunks[-1]['to_block']
    kp = PAPER / 'phase9/qa/independent_keccak.py'
    assert sha(kp) == '360e723166844e065b2e07c446e634198cb6611499b758b4c90385b28e4e33c0'
    keccak = module('phase13_audit_keccak', kp).digest256
    model_path = QA / 'independent_event_model.py'
    model = module('phase13_audit_event_model', model_path)
    event_topics = {x['topic0']: x['name'] for x in plan['events']}
    for row in plan['events']:
        assert '0x' + keccak(row['signature'].encode()).hex() == row['topic0']
    expected = []
    for i, row in enumerate(plan['code_observations']):
        if row['mode'] == 'fresh':
            expected.append(('facet_code_' + str(i), 'eth_getCode', [row['address'], hex(row['block_number'])]))
    for i, chunk in enumerate(chunks):
        expected.append(('window_admin_logs_' + str(i), 'eth_getLogs', [{
            'fromBlock': hex(chunk['from_block']), 'toBlock': hex(chunk['to_block']),
            'address': plan['diamond'], 'topics': [list(event_topics)]}]))
    assert len(expected) == plan['caps']['rpc_methods'] == 57
    assert 0 < len(ledger) <= 57
    previous, total, responses, inventory, failures = when(acceptance['started_utc']), 0, [], [], []
    for i, record in enumerate(ledger):
        key, method, params = expected[i]
        ordinal = i + 1
        assert record['ordinal'] == ordinal and record['kind'] == 'rpc' and record['key'] == key
        req, res = attempt / record['request_file'], attempt / record['response_file']
        assert req.name == f'{ordinal:03d}_{key}_request.json'
        assert res.name == f'{ordinal:03d}_{key}_response.bin'
        assert sha(req) == record['request_sha256'] and sha(res) == record['response_sha256']
        length = res.stat().st_size
        assert length == record['response_bytes'] <= plan['caps']['per_response_bytes']
        total += length
        assert total <= plan['caps']['total_retained_response_bytes']
        assert previous <= when(record['started_utc']) <= when(record['completed_utc'])
        previous = when(record['completed_utc'])
        assert read(req) == {'url': plan['rpc_endpoint'], 'method': 'POST', 'json': {
            'jsonrpc': '2.0', 'id': ordinal, 'method': method, 'params': params}}
        if record['transport_json_ok']:
            response = read(res)
            assert record['http_status'] == 200 and record['response_at_cap_eof_unproved'] is False
            assert response['jsonrpc'] == '2.0' and type(response['id']) is int and response['id'] == ordinal
            assert 'result' in response and 'error' not in response and 'failure' not in record
        else:
            assert ordinal == len(ledger) and 'failure' in record
            response = None
            body = read(res)
            assert body['jsonrpc'] == '2.0' and type(body['id']) is int and body['id'] == ordinal
            assert 'error' in body and 'result' not in body
            assert type(body['error']['code']) is int and isinstance(body['error']['message'], str)
            failures.append({'ordinal': ordinal, 'method': method, 'params': params,
                'http_status': record.get('http_status'), 'jsonrpc_code': body['error']['code'],
                'message': body['error']['message'], 'response_bytes': length,
                'response_sha256': sha(res)})
        responses.append(response)
        inventory.append({'ordinal': ordinal, 'method': method, 'key': key, 'request_sha256': sha(req),
            'response_sha256': sha(res), 'response_bytes': length,
            'http_status': record.get('http_status'), 'transport_json_ok': record['transport_json_ok']})
    assert {p.name for p in attempt.glob('*_request.json')} == {r['request_file'] for r in ledger}
    assert {p.name for p in attempt.glob('*_response.bin')} == {r['response_file'] for r in ledger}
    assert previous <= when(summary['completed_utc'])
    elapsed = (when(summary['completed_utc']) - when(ledger[0]['started_utc'])).total_seconds()
    assert elapsed <= plan['caps']['wall_seconds'] + plan['caps']['request_timeout_seconds']
    assert summary['rpc_methods'] == len(ledger) and summary['retained_response_bytes'] == total
    assert summary['fresh_code_requests'] == min(len(ledger), 18)
    assert summary['window_log_requests'] == max(0, len(ledger) - 18)
    old10 = WORK / 'phase10_lifi_private/factory_continuation_attempt1'
    cursor, runtime, code_bytes = 0, [], {}
    for row in plan['code_observations']:
        if row['mode'] == 'fresh':
            if cursor >= len(ledger) or not ledger[cursor]['transport_json_ok']:
                break
            body = responses[cursor]['result']
            source = {'kind': 'fresh_phase13', 'request_ordinal': cursor + 1}
            cursor += 1
        else:
            record = row['reused_record']
            for kind in ('request', 'response'):
                assert sha(old10 / record[kind + '_file']) == record[kind + '_sha256']
            oldreq, oldres = read(old10 / record['request_file']), read(old10 / record['response_file'])
            assert oldreq['url'] == plan['rpc_endpoint'] and oldreq['json']['method'] == 'eth_getCode'
            assert oldreq['json']['params'] == [row['address'], hex(row['block_number'])]
            assert oldreq['json']['id'] == oldres['id'] and 'error' not in oldres
            body = oldres['result']
            source = {'kind': 'reused_phase10', 'response_sha256': record['response_sha256']}
        raw = model.raw_hex(body)
        code_bytes[(row['address'], row['block_number'])] = raw
        runtime.append({**{k: row[k] for k in expected_pairs[0]}, 'runtime_bytes': len(raw),
            'runtime_sha256': hashlib.sha256(raw).hexdigest(), 'runtime_keccak256': '0x' + keccak(raw).hex(),
            'code_empty': not bool(raw), 'evidence_source': source, 'source_semantics_newly_verified': False,
            'historical_block_mapping_cryptographically_verified': False})
    assert runtime == summary['runtime_observations']
    assert len(runtime) == summary['completed_runtime_observations']
    assert sum(x['code_empty'] for x in runtime) == summary['empty_runtime_observation_count']
    events, identities, block_hashes, tx_positions, tx_contexts = [], set(), {}, {}, {}
    complete_chunks = 0
    for chunk_index, (record, response) in enumerate(zip(ledger[18:], responses[18:])):
        if not record['transport_json_ok']:
            break
        logs = response['result']
        assert isinstance(logs, list) and len(events) + len(logs) <= plan['caps']['max_event_logs']
        chunk = chunks[chunk_index]
        for log in logs:
            assert isinstance(log, dict) and log['removed'] is False
            assert '0x' + model.raw_hex(log['address'], 20).hex() == plan['diamond']
            block, position, index = (quantity(log[k]) for k in ('blockNumber', 'transactionIndex', 'logIndex'))
            bh, th = ('0x' + model.raw_hex(log[k], 32).hex() for k in ('blockHash', 'transactionHash'))
            assert chunk['from_block'] <= block <= chunk['to_block']
            assert (block, index) not in identities
            identities.add((block, index))
            assert block not in block_hashes or block_hashes[block] == bh
            block_hashes[block] = bh
            assert (block, position) not in tx_positions or tx_positions[(block, position)] == th
            tx_positions[(block, position)] = th
            assert th not in tx_contexts or tx_contexts[th] == (block, bh, position)
            tx_contexts[th] = (block, bh, position)
            for header in failed['headers'].values():
                if header['number'] == block:
                    assert header['hash'] == bh and header['transaction_hashes'][position] == th
            event = model.decode(log['topics'], log['data'], event_topics, plan['caps'])
            events.append({'block_number': block, 'block_hash': bh, 'transaction_index': position,
                'transaction_hash': th, 'log_index': index,
                'raw_data_sha256': hashlib.sha256(model.raw_hex(log['data'])).hexdigest(),
                'decoded': event, 'chunk_index': chunk_index})
        complete_chunks += 1
    complete = complete_chunks == 39
    if complete:
        events.sort(key=lambda x: (x['block_number'], x['transaction_index'], x['log_index']))
        last = {}
        for row in events:
            assert row['log_index'] > last.get(row['block_number'], -1)
            last[row['block_number']] = row['log_index']
    assert events == summary['events'] and complete_chunks == summary['completed_log_chunks']
    assert summary['window_event_coverage_complete_under_query_schedule'] == complete
    counts = dict(Counter(x['decoded']['event'] for x in events))
    assert counts == summary['event_type_counts']
    initializers = [x for x in events if x['decoded'].get('initializer_effects_unclosed')]
    assert len(initializers) == summary['nonzero_initializer_event_count']
    discovered_facets = {x['address'] for x in expected_pairs}
    discovered_selectors = set(checkpoints['discovered_selectors'])
    for row in events:
        for cut in row['decoded'].get('cuts', []):
            if cut['facet'] != model.ZERO:
                discovered_facets.add(cut['facet'])
            discovered_selectors.update(cut['selectors'])
    assert sorted(discovered_facets) == summary['discovered_nonzero_facets']
    assert sorted(discovered_selectors) == summary['discovered_selectors']
    assert len(discovered_facets) <= plan['caps']['max_facets'] and len(discovered_selectors) <= plan['caps']['max_selectors']
    assert sorted(discovered_facets - {x['address'] for x in expected_pairs}) == summary['newly_nominated_event_facets_without_adaptive_code_query']
    comparison, replay_error, applied = None, None, 0
    seed = {'owner': states['start']['owner'], 'enumerated_facets': states['start']['facets']}
    replay = model.Registry(seed, plan['diamond'], plan['caps']['max_facets'], plan['caps']['max_selectors'])
    assert replay.snapshot()['selector_map'] == states['start']['selector_map']
    if complete:
        for i, row in enumerate(events):
            try:
                replay.apply(row['decoded'])
                applied += 1
            except (AssertionError, StopIteration):
                replay_error = {'event_index': i, 'block_number': row['block_number'], 'log_index': row['log_index']}
                break
        expected_end = {'owner': states['end']['owner'],
            'facets': [{k: x[k] for k in ('address', 'facet_position', 'selectors')} for x in states['end']['facets']],
            'selector_map': states['end']['selector_map']}
        comparison = {key + '_equal': replay_error is None and replay.snapshot()[key] == value for key, value in expected_end.items()}
        assert summary['nominal_replay_performed'] is True and summary['nominal_replay_events_applied'] == applied
        assert (summary['nominal_replay_error'] is None) == (replay_error is None)
        if replay_error:
            assert all(summary['nominal_replay_error'][k] == v for k, v in replay_error.items())
        assert summary['nominal_replay_end'] == (None if replay_error else replay.snapshot())
        assert summary['end_checkpoint_comparison'] == comparison
    else:
        assert summary['nominal_replay_performed'] is False
        assert summary['disposition'] == 'UNAVAILABLE_UNDER_FROZEN_CAP'
    for key in ('detector_scores', 'scientific_admissions', 'incident_transaction_payload_queries',
                'fresh_headers', 'chain_id_queries', 'new_source_runtime_recompilations'):
        assert summary[key] == 0
    for key in ('historical_routing_proved', 'index_completeness_proved', 'proofs_cryptographically_verified',
                'unlogged_mutation_paths_excluded', 'prewindow_event_history_acquired'):
        assert summary[key] is False
    assert summary['prior_failed_attempt_preserved'] is True
    grouped = {}
    for row in runtime:
        grouped.setdefault(row['address'], []).append(row)
    repeated = [{'address': address, 'observations': len(rows),
        'sampled_runtime_bytes_equal': len({code_bytes[(address, x['block_number'])] for x in rows}) == 1}
        for address, rows in sorted(grouped.items()) if len(rows) > 1]
    result = {'schema_version': 'article2_phase13_independent_actual_evidence_audit_v1',
        'status': 'PASS_INDEPENDENT_CODE_AND_WINDOW_EVENT_AUDIT', 'audited_utc': datetime.now(timezone.utc).isoformat(),
        'auditor_sha256': sha(Path(__file__)), 'independent_event_model_sha256': sha(model_path),
        'independent_keccak_sha256': sha(kp), 'root_freeze_sha256': sha(freeze_path),
        'plan_sha256': sha(plan_path), 'runner_sha256': sha(runner_path),
        'summary_sha256': sha(attempt / 'summary.json'), 'request_ledger_sha256': sha(attempt / 'requests.json'),
        'source_bindings_unchanged': True, 'requests': inventory,
        'new_rpc_methods': len(ledger), 'new_retained_response_bytes': total,
        'retained_provider_failures': failures,
        'event_history_available_under_completed_schedule': complete,
        'empty_event_history_established': False,
        'elapsed_seconds_first_request_to_summary': elapsed, 'code_observations': len(runtime),
        'exact_prior_code_observations_reused': 1, 'reused_code_response_bytes_not_charged_again': 11411,
        'distinct_sampled_facet_addresses': len(grouped), 'empty_runtime_observations': sum(x['code_empty'] for x in runtime),
        'distinct_sampled_runtime_sha256': len({x['runtime_sha256'] for x in runtime}),
        'repeated_address_comparisons': repeated, 'completed_log_chunks': complete_chunks,
        'decoded_event_count': len(events), 'event_type_counts': counts,
        'distinct_observed_event_transactions': len({x['transaction_hash'] for x in events}),
        'nonzero_initializer_events': len(initializers), 'nominal_replay_events_applied': applied,
        'nominal_replay_error': replay_error, 'end_checkpoint_comparison': comparison,
        'new_event_nominated_facets': summary['newly_nominated_event_facets_without_adaptive_code_query'],
        'prior_phase12_failed_attempt_preserved': True, 'retry_fallback_or_adaptive_requests_observed': False,
        'producer_modules_imported': False, 'new_network_requests_by_auditor': 0,
        'compiler_invocations_by_auditor': 0, 'old_suites_rerun': 0,
        'scientific_admissions': 0, 'detector_scores': 0,
        'limitations': ['Runtime bytes are sampled provider observations, not new source equivalence or continuity proof.',
            'Complete fixed-range responses do not prove provider log-index completeness.',
            'Nominal replay excludes initializer effects and unlogged state writers.',
            'Shared Inited signatures are not attributed to a unique facet.',
            'State-root authentication and orphan selector-key exclusion were not performed.',
            'No complete historical routing, detector-performance result or independent case admission follows.',
            'A refused log request is unavailable history, not an empty event result or an established general API limit.']}
    output = QA / 'independent_actual_review.json'
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'path': str(output), 'sha256': sha(output),
        'rpc_methods': len(ledger), 'bytes': total, 'events': len(events), 'comparison': comparison}))


if __name__ == '__main__':
    main()
