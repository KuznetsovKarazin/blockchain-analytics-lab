"""Freeze and run a descriptive attack-day join around the unchanged log replay.

External labels never enter the replay worker or change its count/group/budget
parameters. Six reported executions remain one previously catalogued L2 incident.
This script does not establish receipt success, unlabelled negatives or recall.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

PAPER = Path(__file__).resolve().parent
ROOT = PAPER.parents[1]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_new(path, value):
    with Path(path).open('x') as handle:
        json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write('\n')


def rows(path):
    with Path(path).open() as handle:
        return [json.loads(line) for line in handle]


def position(row):
    return row['block_number'], row['transaction_index'], row['log_index']


def aggregate(decisions):
    counts = Counter(events=len(decisions))
    for field in ('raw_trigger', 'group_candidate', 'notification_emitted'):
        counts[field] = sum(row[field] is True for row in decisions)
    for reason in ('grouped', 'budget', 'below_threshold', 'duplicate', 'late'):
        counts['reason_' + reason] = sum(row['suppression_reason'] == reason for row in decisions)
    if counts['raw_trigger'] != counts['reason_grouped'] + counts['group_candidate']:
        raise RuntimeError('raw/group accounting does not reconcile')
    if counts['group_candidate'] != counts['notification_emitted'] + counts['reason_budget']:
        raise RuntimeError('candidate/budget accounting does not reconcile')
    return dict(counts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--headers', type=Path, required=True)
    parser.add_argument('--labels', type=Path, default=PAPER / 'incidents/labels/euler_20230313_labels.json')
    parser.add_argument('--config', type=Path, default=PAPER / 'event_log_attack_day_config.json')
    parser.add_argument('--run-id')
    args = parser.parse_args()
    for name in ('input', 'headers', 'labels', 'config'):
        setattr(args, name, getattr(args, name).resolve())
    run_id = args.run_id or datetime.now(timezone.utc).strftime('event_logs_attack_%Y%m%dT%H%M%S_%fZ')
    if Path(run_id).name != run_id:
        raise ValueError('run-id must be one path component')
    run = PAPER / 'runs' / run_id
    if run.exists():
        raise FileExistsError(run)
    original_config = PAPER / 'event_log_pilot_config.json'
    original = json.loads(original_config.read_text())
    config = json.loads(args.config.read_text())
    differences = {key for key in original.keys() | config.keys() if original.get(key) != config.get(key)}
    if not differences <= {'source_day', 'rule_purpose', 'claim_scope'} or config['source_day'] != '2023-03-13':
        raise ValueError('only source_day and declared descriptions may differ from the original config')
    if config['core'] != original['core'] or config['core'] != {
        'address': '0x27182842e098f60e3d576794a5bffb0777e025d3', 'chain_id': 1,
        'window_seconds': 60, 'threshold_count': 10, 'cooldown_seconds': 300, 'daily_budget': 5}:
        raise ValueError('frozen core parameters changed')
    if config['playback_speed_factors'] != [1, 1000000] or config['repetitions'] != 3:
        raise ValueError('expected six original engineering cells')
    acquisition_path = PAPER / 'runs' / args.input.parent.name / 'acquisition_manifest.json'
    acquisition = json.loads(acquisition_path.read_text())
    if acquisition['status'] != 'complete' or not all(acquisition['checks'].values()):
        raise ValueError('acquisition is not complete and checked')
    if acquisition['scope']['day_utc'] != config['source_day']:
        raise ValueError('config day does not match acquisition day')
    for path in (args.input, args.headers):
        expected = [item for item in acquisition['files'] if Path(item['path']).name == path.name]
        if len(expected) != 1 or sha(path) != expected[0]['sha256']:
            raise ValueError('input/header hash does not match acquisition manifest')
    labels = json.loads(args.labels.read_text())
    selected = labels['exploit_transactions']
    hashes = {row['tx_hash'] for row in selected}
    if len(hashes) != 6 or not all(row['positive_incident_label'] is True for row in selected):
        raise ValueError('expected the frozen six externally reported executions')
    if labels['candidate_id'] != 'candidate_euler_20230313' or not labels['prior_exposure_level'].startswith('L2'):
        raise ValueError('candidate/exposure mismatch')
    events, headers = rows(args.input), rows(args.headers)
    header_map = {row['block_number']: row for row in headers}
    if len(header_map) != len(headers):
        raise ValueError('duplicate header numbers')
    if any(position(a) >= position(b) for a, b in zip(events, events[1:])):
        raise ValueError('source logs are not in strict canonical order')
    by_tx = defaultdict(list)
    for row in events:
        header = header_map[row['block_number']]
        if row['block_hash'] != header['block_hash'] or row['event_time_ns'] != header['event_time_ns']:
            raise ValueError('source/header mismatch')
        by_tx[row['transaction_hash']].append(row)
    joins = []
    for label in selected:
        tx = by_tx.get(label['tx_hash'], [])
        if not tx:
            raise ValueError('frozen reported execution missing from acquired source population')
        coordinate = {(row['block_number'], row['block_hash'], row['transaction_index'], row['event_time_ns']) for row in tx}
        if len(coordinate) != 1:
            raise ValueError('inconsistent transaction coordinates')
        first = tx[0]
        for key in ('block_number', 'block_hash', 'transaction_index'):
            if label.get(key) is not None and label[key] != first[key]:
                raise ValueError('acquired coordinates conflict with frozen metadata')
        joins.append({key: first[key] for key in ('transaction_hash', 'block_number', 'block_hash', 'transaction_index', 'event_time_ns')} | {
            'block_timestamp_utc': datetime.fromtimestamp(first['event_time_ns'] // 1000000000, timezone.utc).isoformat(),
            'core_log_count': len(tx), 'first_log_index': first['log_index'], 'last_log_index': tx[-1]['log_index'],
            'receipt_acquired': False, 'receipt_status': None,
            'label_role': label['role'], 'join_evidence': 'actual selected source logs plus acquired matching header hash/time'})
    joins.sort(key=lambda row: (row['block_number'], row['transaction_index']))
    first_tx = joins[0]['block_number'], joins[0]['transaction_index']
    watched = (args.input, args.headers, args.labels, args.config, original_config, Path(__file__), PAPER / 'event_log_replay.py', acquisition_path)
    frozen_hashes = {str(path.relative_to(ROOT)): sha(path) for path in watched}
    stamp = datetime.now(timezone.utc).isoformat()
    artifact_dir = PAPER / 'incidents/labels'
    join_path = artifact_dir / (run_id + '_raw_join.json')
    freeze_path = artifact_dir / (run_id + '_evaluation_freeze.json')
    write_new(join_path, {'schema': 'reported_execution_raw_log_join_v1', 'created_utc': stamp,
        'run_id': run_id, 'candidate_id': labels['candidate_id'], 'prior_exposure_level': labels['prior_exposure_level'],
        'source_file_hashes': frozen_hashes, 'label_manifest_preserved': True,
        'source_logs': len(events), 'source_transactions': len(by_tx),
        'reported_executions': joins, 'reported_execution_core_logs': sum(row['core_log_count'] for row in joins),
        'first_reported_execution_transaction_position': first_tx,
        'receipt_status': 'unknown; no full RPC receipts acquired',
        'independent_incident_count': None, 'reported_incident_count': 1,
        'scope': 'Membership and exact ordering only; does not establish complete attack set, semantic labels, deployed ABI or unseen-case eligibility.'})
    specification = {
        'schema': 'event_log_attack_day_descriptive_freeze_v1', 'frozen_before_worker_execution_utc': stamp,
        'run_id': run_id, 'source_file_hashes': frozen_hashes, 'raw_join_sha256': sha(join_path),
        'config_changes_from_ordinary_day': sorted(differences), 'frozen_core': config['core'],
        'cells': [{'speed_factor': speed, 'repetition': rep} for speed in config['playback_speed_factors'] for rep in range(1, 4)],
        'primary_measure': 'Count notification_emitted=true rows whose source transaction_hash belongs to the frozen six externally reported executions.',
        'supporting_measures': {
            'reported_execution_counts': 'For rows belonging to each of six hashes and their union: event count, raw_trigger=true, group_candidate=true, notification_emitted=true, and suppression_reason grouped/budget/below_threshold/duplicate/late.',
            'pre_first_execution_budget': 'Count emitted notifications on rows with (block_number,transaction_index) strictly less than the first reported execution, grouped by playback budget_day_utc; report against fixed daily_budget=5.',
            'whole_day_counts': 'Same accounting over every selected source log; no negative label is assigned to other transactions.'},
        'ordering': 'Exact chain order (block_number,transaction_index,log_index), not source-report list order.',
        'run_policy': 'Execute unchanged event_log_replay.py and unchanged core parameters once per declared cell; labels are joined only after decisions are closed and hashed.',
        'interpretation_limits': ['Six reported executions are one L2-exposed incident.', 'No unlabelled false-positive or independent recall claim.',
            'No threshold tuning, label-fed worker, hindsight-selected emitter or population restricted to attack hashes.',
            'Historical observation/label-availability and receipt status remain unknown.',
            'Core Withdraw is not a monetary outflow measure; no ABI or loss calculation.',
            'Playback UTC budget and local queue timings are not historical response times.'],
    }
    write_new(freeze_path, specification)
    command = [sys.executable, str(PAPER / 'event_log_replay.py'), '--input', str(args.input),
               '--config', str(args.config), '--run-id', run_id]
    subprocess.run(command, cwd=ROOT, check=True)
    manifest = json.loads((run / 'manifest.json').read_text())
    if manifest['status'] != 'complete':
        raise RuntimeError('replay did not complete')
    if any(sha(ROOT / path) != expected for path, expected in frozen_hashes.items()):
        raise RuntimeError('frozen input, label, config or code changed during execution')
    outputs = []
    for name in manifest['cells']:
        cell = run / name
        summary = json.loads((cell / 'summary.json').read_text())
        path = cell / 'decisions.jsonl.gz'
        if sha(path) != summary['log_sha256']['decisions.jsonl.gz']:
            raise ValueError('persisted decision hash mismatch')
        with gzip.open(path, 'rt') as handle:
            decisions = [json.loads(line) for line in handle]
        if len(decisions) != len(events) or any(position(a) != position(b) or a['transaction_hash'] != b['transaction_hash'] for a, b in zip(events, decisions)):
            raise RuntimeError('decision/source row identities differ')
        if any(row['label_used'] is not False for row in decisions):
            raise RuntimeError('worker unexpectedly used labels')
        chosen = [row for row in decisions if row['transaction_hash'] in hashes]
        prior = [row for row in decisions if (row['block_number'], row['transaction_index']) < first_tx]
        pre_by_day = Counter(row['budget_day_utc'] for row in prior if row['notification_emitted'])
        emitted = [{key: row[key] for key in ('alert_id', 'transaction_hash', 'block_number', 'transaction_index', 'log_index', 'event_time_ns', 'budget_day_utc')} for row in chosen if row['notification_emitted']]
        outputs.append({'cell': name, 'speed_factor': summary['speed_factor'], 'repetition': summary['repetition'],
            'decisions_sha256': sha(path), 'timing_sha256': sha(cell / 'timing.jsonl.gz'),
            'semantic_decisions_sha256': summary['semantic_decisions_sha256'],
            'whole_day': aggregate(decisions), 'reported_execution_union': aggregate(chosen),
            'by_reported_execution': [{'transaction_hash': row['transaction_hash'], **aggregate([d for d in chosen if d['transaction_hash'] == row['transaction_hash']])} for row in joins],
            'pre_first_reported_execution': {'all_source_logs': len(prior), 'emitted_notifications': sum(pre_by_day.values()),
                'emitted_by_playback_budget_day': dict(pre_by_day), 'daily_budget': config['core']['daily_budget']},
            'emitted_notifications_with_reported_execution_source': emitted})
    metrics = [{key: value for key, value in cell.items() if key not in ('cell', 'speed_factor', 'repetition', 'decisions_sha256', 'timing_sha256')} for cell in outputs]
    if not all(value == metrics[0] for value in metrics):
        raise RuntimeError('descriptive join differs across speed/repetition cells')
    for path in (Path(__file__), args.labels, freeze_path, join_path):
        shutil.copy2(path, run / 'source_snapshot' / path.name)
    result = {'schema': 'event_log_attack_day_descriptive_result_v1', 'run_id': run_id,
        'created_utc': datetime.now(timezone.utc).isoformat(), 'status': 'pass',
        'evaluation_freeze_sha256': sha(freeze_path), 'raw_join_sha256': sha(join_path),
        'label_manifest_sha256_before_and_after': sha(args.labels), 'frozen_sources_unchanged': True,
        'descriptive_counts_invariant_across_six_cells': True, 'receipt_status': 'unknown',
        'reported_incident_count': 1, 'prior_exposure_level': labels['prior_exposure_level'],
        'claim_scope': 'Descriptive source-transaction membership of unchanged engineering-rule notifications, not attack recall, false positives, prevention or independent evaluation.',
        'cells': outputs}
    write_new(run / 'descriptive_label_evaluation.json', result)
    write_new(run / 'descriptive_evaluation_artifacts.json', {'schema': 'descriptive_evaluation_artifacts_v1',
        'files': [{'path': str(path.relative_to(ROOT)), 'bytes': path.stat().st_size, 'sha256': sha(path)}
                  for path in [freeze_path, join_path, run / 'descriptive_label_evaluation.json', *sorted((run / 'source_snapshot').iterdir())]],
        'compressed_logs': [{'cell': cell['cell'], 'decisions_sha256': cell['decisions_sha256'], 'timing_sha256': cell['timing_sha256']} for cell in outputs]})
    print(json.dumps({'run_id': run_id, 'status': 'pass', 'whole_day': outputs[0]['whole_day'],
        'reported_execution_union': outputs[0]['reported_execution_union'], 'pre_first_reported_execution': outputs[0]['pre_first_reported_execution']}))


if __name__ == '__main__':
    main()
