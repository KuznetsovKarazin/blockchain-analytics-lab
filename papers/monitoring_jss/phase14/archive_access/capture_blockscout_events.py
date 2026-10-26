#!/usr/bin/env python3
"""Five bounded legacy-indexer queries; unavailable chain fields stay unavailable.

This uses a Blockscout-specific normalizer, never the unchanged strict RPC-log
parser. Nominal replay does not prove index completeness or all storage writers.
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def quantity(value):
    need(isinstance(value, str) and re.fullmatch(r'0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)?', value),
         'Invalid indexer hexadecimal quantity')
    return 0 if value == '0x' else int(value, 16)


def rows_from_envelope(body, cap):
    need(isinstance(body, dict) and set(body) == {'status', 'message', 'result'}, 'Unexpected legacy envelope fields')
    if body['status'] == '0':
        need(body['message'] == 'No logs found' and body['result'] == [], 'Indexer error is not an empty result')
        return []
    need(body['status'] == '1' and body['message'] == 'OK' and isinstance(body['result'], list), 'Invalid success envelope')
    need(len(body['result']) < cap, 'Documented result cap reached; completeness unresolved')
    return body['result']


def normalized_topics(value, codec):
    need(isinstance(value, list) and 1 <= len(value) <= 4, 'Invalid topics list')
    out = list(value)
    while out and out[-1] is None:
        out.pop()
    need(bool(out) and all(x is not None for x in out), 'Missing or nontrailing null topic')
    return ['0x' + codec.hx(x, 32).hex() for x in out]


def normalize_log(log, query, plan, codec, signatures, seen, retained_headers):
    need(isinstance(log, dict), 'Log is not an object')
    topics = normalized_topics(log.get('topics'), codec)
    address = '0x' + codec.hx(log.get('address'), 20).hex()
    block, tx_index, log_index, timestamp = (quantity(log.get(k)) for k in ('blockNumber', 'transactionIndex', 'logIndex', 'timeStamp'))
    tx_hash = '0x' + codec.hx(log.get('transactionHash'), 32).hex()
    block_hash = None if log.get('blockHash') is None else '0x' + codec.hx(log['blockHash'], 32).hex()
    removed = log.get('removed')
    need(removed is None or removed is False, 'Removed or malformed removed-state log')
    data = '0x' + codec.hx(log.get('data')).hex()
    need(address == plan['diamond'] and topics[0] == query['topic0'], 'Returned emitter/topic differs from query')
    need(query['from_block'] <= block <= query['to_block'], 'Log outside fixed queried interval')
    need((block, log_index) not in seen['log_ids'], 'Duplicate block/log index')
    need((block, tx_index) not in seen['tx_positions'] or seen['tx_positions'][(block, tx_index)] == tx_hash,
         'Conflicting transaction at one block position')
    need(tx_hash not in seen['tx_contexts'] or seen['tx_contexts'][tx_hash] == (block, tx_index),
         'Transaction hash has conflicting block/position')
    need(block not in seen['timestamps'] or seen['timestamps'][block] == timestamp, 'Conflicting timestamp for block')
    for other_block, other_timestamp in seen['timestamps'].items():
        need(other_block == block or (other_timestamp < timestamp if other_block < block else other_timestamp > timestamp),
             'Timestamp ordering conflicts with distinct block ordering')
    if block_hash is not None:
        need(block not in seen['block_hashes'] or seen['block_hashes'][block] == block_hash, 'Conflicting known block hashes')
    for header in retained_headers.values():
        if header['number'] == block:
            need(block_hash is None or block_hash == header['hash'], 'Known block hash differs from retained header')
            need(tx_index < len(header['transaction_hashes']) and header['transaction_hashes'][tx_index] == tx_hash,
                 'Indexer transaction position differs from retained header')
    if query['role'] == 'window':
        need(plan['window_epoch_seconds'][0] <= timestamp < plan['window_epoch_seconds'][1], 'Window event timestamp outside fixed UTC window')
    decoded = codec.decode_event(topics, data, signatures, plan['caps'])
    seen['log_ids'].add((block, log_index))
    seen['tx_positions'][(block, tx_index)] = tx_hash
    seen['tx_contexts'][tx_hash] = (block, tx_index)
    seen['timestamps'][block] = timestamp
    if block_hash is not None:
        seen['block_hashes'][block] = block_hash
    return {'block_number': block, 'block_hash': block_hash, 'transaction_index': tx_index,
            'transaction_hash': tx_hash, 'log_index': log_index, 'timestamp_epoch_seconds': timestamp,
            'removed': removed, 'raw_data_sha256': sha(codec.hx(data)), 'decoded': decoded,
            'normalized_log': {'address': address, 'topics': topics, 'data': data}}


def verify_control(row, retained, codec):
    normalized = row['normalized_log']
    need(row['block_number'] == int(retained['blockNumber'], 16)
         and row['transaction_index'] == int(retained['transactionIndex'], 16)
         and row['transaction_hash'] == retained['transactionHash'].lower()
         and row['log_index'] == int(retained['logIndex'], 16), 'Known constructor log context not returned')
    need(row['block_hash'] is None or row['block_hash'] == retained['blockHash'].lower(), 'Known constructor hash differs')
    need(row['timestamp_epoch_seconds'] == int(retained['blockTimestamp'], 16), 'Constructor timestamp differs')
    need(normalized == {'address': retained['address'].lower(), 'topics': [x.lower() for x in retained['topics']],
                        'data': retained['data'].lower()}, 'Known constructor topic/data differs')


class Capture:
    def __init__(self, plan, output, transport):
        self.plan, self.output, self.transport = plan, output, transport
        self.started, self.records, self.bytes = time.monotonic(), [], 0
        self.opener = urllib.request.build_opener(transport.NoRedirect())

    def get(self, query):
        cap = self.plan['caps']
        remaining = cap['wall_seconds'] - (time.monotonic() - self.started)
        need(remaining > 0 and len(self.records) < cap['http_gets'] and self.bytes < cap['total_retained_response_bytes'], 'Acquisition cap closed')
        params = [('module', 'logs'), ('action', 'getLogs'), ('fromBlock', str(query['from_block'])),
                  ('toBlock', str(query['to_block'])), ('address', self.plan['diamond']), ('topic0', query['topic0'])]
        url = self.plan['api_endpoint'] + '?' + urllib.parse.urlencode(params)
        ordinal = len(self.records) + 1
        prefix = f'{ordinal:03d}_{query["name"]}'
        request_path = self.output / (prefix + '_request.json')
        self.transport.save(request_path, {'url': url, 'method': 'GET', 'query': dict(params)})
        record = {'ordinal': ordinal, 'key': query['name'], 'kind': 'blockscout_legacy_get',
                  'started_utc': self.transport.stamp(), 'request_file': request_path.name,
                  'request_sha256': sha(request_path.read_bytes())}
        self.records.append(record)
        self.transport.save(self.output / 'requests.json', self.records)
        raw = bytearray()
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'Article2-Blockscout-admin-history/1', 'Accept': 'application/json'})
            try:
                response = self.opener.open(request, timeout=min(cap['request_timeout_seconds'], remaining))
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                record['http_status'] = response.status
                record['content_type'] = response.headers.get('Content-Type')
                limit = min(cap['per_response_bytes'], cap['total_retained_response_bytes'] - self.bytes)
                while len(raw) < limit:
                    need(time.monotonic() - self.started < cap['wall_seconds'], 'Wall cap while reading')
                    chunk = response.read(min(65536, limit - len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
                record['response_at_cap_eof_unproved'] = len(raw) == limit
            need(not record['response_at_cap_eof_unproved'], 'Response cap reached without proved EOF')
            need(record['http_status'] == 200, 'HTTP response unsuccessful')
            value = self.transport.parse(bytes(raw))
            record['transport_json_ok'] = True
            return value
        except Exception as exc:
            record.update(transport_json_ok=False, failure=type(exc).__name__ + ': ' + str(exc))
            raise
        finally:
            self.bytes += len(raw)
            response_path = self.output / (prefix + '_response.bin')
            response_path.write_bytes(bytes(raw))
            record.update(completed_utc=self.transport.stamp(), response_file=response_path.name,
                          response_bytes=len(raw), response_sha256=sha(bytes(raw)))
            self.transport.save(self.output / 'requests.json', self.records)


def main():
    parser = argparse.ArgumentParser()
    for name in ('plan', 'checkpoints', 'reference-headers', 'constructor-receipt', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--accepted-plan-sha256', required=True)
    parser.add_argument('--accepted-runner-sha256', required=True)
    args = parser.parse_args()
    need(sha(args.plan.read_bytes()) == args.accepted_plan_sha256
         and sha(Path(__file__).read_bytes()) == args.accepted_runner_sha256, 'Accepted plan/runner differs')
    plan = json.loads(args.plan.read_bytes())
    paper = Path(__file__).resolve().parents[2]
    loaded = {}
    for key, item in plan['module_bindings'].items():
        path = paper / item['path']
        need(sha(path.read_bytes()) == item['sha256'], 'Dependency module differs')
        spec = importlib.util.spec_from_file_location('phase14_' + key, path)
        loaded[key] = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loaded[key])
    transport, codec, helper, history = (loaded[x] for x in ('transport', 'event_codec', 'window_helper', 'history_helper'))
    def read_bound(path, key):
        need(sha(path.read_bytes()) == plan['prior_bindings'][key], 'Retained input differs')
        return transport.parse(path.read_bytes())
    checkpoints = read_bound(args.checkpoints, 'checkpoint_summary_sha256')
    headers = read_bound(args.reference_headers, 'reference_headers_summary_sha256')['headers']
    receipt = read_bound(args.constructor_receipt, 'constructor_receipt_sha256')['result']
    for item in plan['document_bindings']:
        need(sha((paper / item['path']).read_bytes()) == item['sha256'], 'Document binding differs')
    need(plan['schema_version'] == 'article2_phase14_blockscout_event_plan_v1'
         and plan['api_endpoint'] == 'https://eth.blockscout.com/api', 'Wrong plan/endpoint')
    states = {x['name']: x for x in checkpoints['states']}
    helper.seed_registry(codec, states['start'], plan['diamond'], plan['caps'])
    queries = plan['queries']
    need(len(queries) == plan['caps']['http_gets'] == 5 and [x['role'] for x in queries] == ['control'] * 2 + ['window'] * 3,
         'Unexpected query count/roles')
    signatures = {x['topic0']: x['name'] for x in plan['events']}
    known_logs = {x['topics'][0].lower(): x for x in receipt['logs'] if x['address'].lower() == plan['diamond']}
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'frozen_plan.json').write_bytes(args.plan.read_bytes())
    (args.output / 'runner_source.py').write_bytes(Path(__file__).read_bytes())
    transport.save(args.output / 'acceptance.json', {'started_utc': transport.stamp(), 'plan_sha256': args.accepted_plan_sha256,
                   'runner_sha256': args.accepted_runner_sha256, 'authority': 'Root accepted exact plan and runner before first request.'})
    capture = Capture(plan, args.output, transport)
    result = {'schema_version': 'article2_phase14_blockscout_event_result_v1', 'plan_sha256': args.accepted_plan_sha256,
              'runner_sha256': args.accepted_runner_sha256, 'controls': [], 'events': [], 'completed_window_topics': [],
              'nominal_replay_performed': False, 'window_schedule_complete_unsaturated': False,
              'index_completeness_proved': False, 'historical_routing_proved': False,
              'authenticated_chain_mapping': False, 'scientific_admissions': 0, 'detector_scores': 0}
    def seen():
        return {'log_ids': set(), 'tx_positions': {}, 'tx_contexts': {}, 'timestamps': {}, 'block_hashes': {}}
    seen_control, seen_window = seen(), seen()
    facets, selectors = set(checkpoints['discovered_nonzero_facets']), set(checkpoints['discovered_selectors'])
    try:
        for query in queries:
            if capture.records:
                time.sleep(plan['caps']['inter_request_pause_seconds'])
            rows = rows_from_envelope(capture.get(query), plan['caps']['max_response_logs'])
            normalized = [normalize_log(x, query, plan, codec, signatures,
                          seen_control if query['role'] == 'control' else seen_window, headers) for x in rows]
            if query['role'] == 'control':
                matches = [x for x in normalized if x['transaction_hash'] == receipt['transactionHash'].lower()
                           and x['log_index'] == int(known_logs[query['topic0']]['logIndex'], 16)]
                need(len(matches) == 1, 'Expected constructor log not uniquely returned')
                verify_control(matches[0], known_logs[query['topic0']], codec)
                result['controls'].append({'topic': signatures[query['topic0']], 'returned_rows': len(rows),
                    'known_log_matched': True, 'block_hash_available': matches[0]['block_hash'] is not None,
                    'removed_status_available': matches[0]['removed'] is not None})
            else:
                for row in normalized:
                    event = row['decoded']
                    if event['event'] == 'DiamondCut':
                        facets.update(cut['facet'] for cut in event['cuts'] if cut['facet'] != codec.ZERO)
                        selectors.update(s for cut in event['cuts'] for s in cut['selectors'])
                    need(len(facets) <= plan['caps']['max_facets'] and len(selectors) <= plan['caps']['max_selectors'],
                         'Discovery union cap exceeded')
                    row.pop('normalized_log')
                    result['events'].append(row)
                result['completed_window_topics'].append(signatures[query['topic0']])
            transport.save(args.output / 'progress.json', result)
        result['window_schedule_complete_unsaturated'] = True
        result.update(history.fold(result['events'], states['start'], states['end'], plan, helper, codec))
        result['disposition'] = ('EVENT_REPLAY_SEMANTICS_UNRESOLVED' if result['nominal_replay_error'] else
            'INDEXER_EVENT_CHECKPOINT_CONSISTENCY_ROUTING_UNRESOLVED' if all(result['end_checkpoint_comparison'].values())
            else 'INDEXER_EVENT_CHECKPOINT_MISMATCH_UNRESOLVED')
    except Exception as exc:
        result.update(disposition='UNAVAILABLE_OR_MALFORMED_OR_SATURATED_UNDER_FROZEN_PLAN', detail=type(exc).__name__ + ': ' + str(exc))
    finally:
        result.update(completed_utc=transport.stamp(), elapsed_seconds=time.monotonic() - capture.started,
            http_gets=len(capture.records), retained_response_bytes=capture.bytes,
            event_type_counts=dict(Counter(x['decoded']['event'] for x in result['events'])),
            window_records_missing_block_hash=sum(x['block_hash'] is None for x in result['events']),
            window_records_missing_removed_status=sum(x['removed'] is None for x in result['events']),
            discovered_nonzero_facets=sorted(facets), discovered_selectors=sorted(selectors),
            nonzero_initializer_event_count=sum(x['decoded'].get('initializer_effects_unclosed', False) for x in result['events']))
        transport.save(args.output / 'summary.json', result)
    print(json.dumps({k: v for k, v in result.items() if k not in {'events', 'nominal_replay_end', 'discovered_selectors'}}, indent=2))


if __name__ == '__main__':
    main()
