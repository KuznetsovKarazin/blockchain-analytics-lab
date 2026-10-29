#!/usr/bin/env python3
"""Offline event-level audit of the three frozen Phase30 streams.

Independent causal history calculation. This does not re-extract token flows
from raw logs: V6.1 retained derived observations and raw-log hashes only.
Reference roles are joined after all label-blind decisions are complete.
"""
from collections import defaultdict
from datetime import datetime, timezone
from fractions import Fraction
from pathlib import Path
import csv
import gzip
import hashlib
import json

HERE = Path(__file__).resolve().parent
PAPER = HERE.parents[1]
DAY = 86400 * 10**9
CASES = ('cohort28_07', 'cohort28_11', 'cohort28_14')
MODES = ('daily_reset', 'lookback_7d', 'cumulative_in_window')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, obj):
    path.write_text(json.dumps(obj, sort_keys=True, indent=2) + '\n')


def iso(t):
    return datetime.fromtimestamp(t // 10**9, timezone.utc).isoformat()


def run():
    roles = json.loads((HERE / 'role_adjudication.json').read_text())
    outside_path = HERE/'outside_reference_bundles'/'manifest.json'
    outside = {}
    if outside_path.exists():
        bundle_manifest = json.loads(outside_path.read_text())
        for item in bundle_manifest['rows']:
            raw_logs = []
            metadata = None
            for receipt in item['receipts']:
                path = outside_path.parent/receipt['file']
                assert sha(path) == receipt['sha256']
                payload = json.loads(path.read_text())
                if path.name == 'metadata.json':
                    metadata = payload
                else:
                    raw_logs.extend(payload['items'])
            assert metadata['hash'].lower() == item['tx'] and metadata['status'] == 'ok'
            assert len(raw_logs) == item['all_emitter_logs']
            assert len({x['index'] for x in raw_logs}) == len(raw_logs)
            indices = sorted(x['index'] for x in raw_logs)
            assert all(b == a+1 for a, b in zip(indices, indices[1:]))
            frame = json.loads((PAPER/'phase28'/'CANDIDATE_FRAME.json').read_text())
            core = next(x['core_address'] for x in frame['cases'] if x['id'] == item['case']).lower()
            assert sum((x['address']['hash'] if isinstance(x['address'],dict) else x['address']).lower() == core
                       for x in raw_logs) == item['core_emitter_logs'] == 0
            outside[item['tx']] = {k: v for k, v in item.items() if k != 'receipts'}
    all_events, summaries, all_refs, checks, provenance = [], [], [], [], []
    for case in CASES:
        base = PAPER / 'phase30'
        source = base / 'indexed' / case / 'indexer_observations.jsonl.gz'
        with gzip.open(source, 'rt') as handle:
            records = [json.loads(line) for line in handle]
        manifest = json.loads((base / 'indexed' / case / 'acquisition_manifest.json').read_text())
        assert manifest['processed'] == manifest['input_transactions'] == len(records)
        assert manifest['status'] == 'COMPLETE_INDEXED_SOURCE_MATCHED'
        canonical = json.dumps(records, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        assert hashlib.sha256(canonical).hexdigest() == manifest['indexed_rows_sha256']
        frozen = json.loads((base / 'results' / case / 'label_blind_replay.json').read_text())
        past = defaultdict(list)
        rank_last = {mode: None for mode in MODES}
        rank_sent = {mode: 0 for mode in MODES}
        rank_notifications = {mode: [] for mode in MODES}
        count_last, count_sent, count_notifications, last_day = None, 0, [], None
        window, events = [], []
        for record in records:
            tx = record['transaction']
            t, txid = tx['event_time_ns'], tx['transaction_hash']
            day = t // DAY
            view = record['views']['fixed_core']
            if day != last_day:
                rank_last = {mode: None for mode in MODES}
                rank_sent = {mode: 0 for mode in MODES}
                count_last, count_sent, window, last_day = None, 0, [], day
            window = [(pt, n) for pt, n in window if pt > t - 60 * 10**9]
            window.append((t, view['archived_core_log_count']))
            count = sum(n for _, n in window)
            count_raw = count >= 10
            count_group = count_raw and (count_last is None or t - count_last >= 300 * 10**9)
            if count_group:
                count_last = t
            count_emit = count_group and count_sent < 5
            if count_emit:
                count_sent += 1
                count_notifications.append(txid)
            positive = {x['token_address']: int(x['external_out_raw']) for x in view['token_flows']
                        if int(x['external_out_raw']) > 0}
            assert len(positive) == sum(int(x['external_out_raw']) > 0 for x in view['token_flows'])
            modes = {}
            for mode in MODES:
                tokens = []
                for token, amount in sorted(positive.items()):
                    history = past[token]
                    if mode == 'daily_reset':
                        history = [(pt, n, h) for pt, n, h in history if pt // DAY == day]
                    elif mode == 'lookback_7d':
                        history = [(pt, n, h) for pt, n, h in history if pt >= t - 7 * DAY]
                    history = history[-128:]
                    n = len(history)
                    numerator = 1 + sum(v >= amount for _, v, _ in history)
                    rank = Fraction(numerator, n + 1)
                    tokens.append({'token': token, 'positive_gross_outflow_raw': str(amount),
                                   'strictly_prior_positive_count': n,
                                   'rank_numerator': numerator, 'rank_denominator': n + 1,
                                   'empirical_rank_descriptive': str(rank),
                                   'ready': n >= 19, 'trigger_1_20': n >= 19 and rank <= Fraction(1, 20),
                                   'prior_transaction_hashes': [h for _, _, h in history]})
                raw = any(x['trigger_1_20'] for x in tokens)
                candidate = raw and (rank_last[mode] is None or t - rank_last[mode] >= 300 * 10**9)
                if candidate:
                    rank_last[mode] = t
                emit = candidate and rank_sent[mode] < 5
                if emit:
                    rank_sent[mode] += 1
                    rank_notifications[mode].append(txid)
                modes[mode] = {'tokens': tokens, 'ready': any(x['ready'] for x in tokens),
                               'raw_trigger': raw, 'group_candidate': candidate,
                               'notification_greedy_B5': emit}
            events.append({'case': case, 'tx': txid, 'timestamp_utc': iso(t), **tx,
                           'core_logs': view['archived_core_log_count'],
                           'all_emitter_logs': record['all_emitter_log_count'],
                           'successful_execution_evidence': 'V6.1 indexed acquisition status=ok gate',
                           'positive_outflow_token_count': len(positive), 'rank': modes,
                           'count': {'core_logs_60s_including_current': count, 'raw_trigger': count_raw,
                                     'group_candidate': count_group, 'notification_greedy_B5': count_emit}})
            for token, amount in positive.items():
                past[token].append((t, amount, txid))
        for mode in MODES:
            expected = next(x for x in frozen['case_score_rows'] if
                            x['method'] == 'outflow_rank_1_20' and x['init'] == mode and
                            x['policy'] == 'greedy' and x['B'] == 5)
            assert rank_notifications[mode] == expected['notified_transactions']
            assert sum(x['rank'][mode]['ready'] for x in events) == expected['eligible_tx']
            checks.append({'case': case, 'method': 'outflow_rank_1_20', 'mode': mode, 'status': 'PASS'})
        expected = next(x for x in frozen['case_score_rows'] if x['method'] == 'core_count_60s_10'
                        and x['policy'] == 'greedy' and x['B'] == 5)
        assert count_notifications == expected['notified_transactions']
        checks.append({'case': case, 'method': 'core_count_60s_10', 'mode': 'daily_reset', 'status': 'PASS'})
        event_map = {e['tx']: e for e in events}
        for ref in roles['references']:
            if ref['case'] != case:
                continue
            event = event_map.get(ref['tx'])
            all_refs.append({**ref, 'in_frozen_selected_stream': event is not None,
                             'event_evidence': event,
                             'outside_stream_indexed_raw_bundle_evidence': outside.get(ref['tx']),
                             'interpretation': 'Role-stratified reference observation; no incident-recall denominator.'})
        summaries.append({'case': case, 'selected_transactions': len(events),
                          'positive_outflow_transactions': sum(e['positive_outflow_token_count'] > 0 for e in events),
                          'positive_outflow_tokens': len(past),
                          'positive_outflow_history_counts': {k: len(v) for k, v in sorted(past.items())},
                          'rank_eligible_transactions': {m: sum(e['rank'][m]['ready'] for e in events) for m in MODES},
                          'rank_notifications_greedy_B5': {m: len(rank_notifications[m]) for m in MODES},
                          'count_notifications_greedy_B5': len(count_notifications),
                          'complete_fixed_core_stream_in_stored_window': True,
                          'complete_incident_inventory': False,
                          'receipt_root_authenticated': False})
        all_events.extend(events)
        provenance.extend({'path': str(p.relative_to(PAPER)), 'sha256': sha(p)} for p in
                          [source, base/'indexed'/case/'acquisition_manifest.json',
                           base/'data'/case/'source_identity_manifest.json',
                           base/'data'/case/'selected_tx_identities.jsonl.gz',
                           base/'results'/case/'label_blind_replay.json'])
    write_json(HERE/'event_observations.json', all_events)
    write_json(HERE/'role_observations.json', all_refs)
    write_json(HERE/'summary.json', {'schema': 'phase31_three_cases_observation_audit_v1', 'cases': summaries,
               'greedy_B5_cells_reproduced': len(checks), 'checks': checks, 'inputs': provenance,
               'offstream_raw_reference_bundles_verified': len(outside),
               'raw_feature_extraction_repeated': False,
               'raw_feature_extraction_limitation': 'V6.1 stores feature aggregates and hashes, not raw indexed topics/data.',
               'status': 'PASS_OFFLINE_DERIVED_OBSERVATIONS_WITH_SOURCE_LIMITATIONS'})
    print(json.dumps(summaries, indent=2))


if __name__ == '__main__':
    run()
