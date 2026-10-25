"""Freeze a descriptive label join, then evaluate only closed budget-study logs.

This program never invokes a replay, supplies labels to policies or edits labels.
It verifies the frozen study and aligns decisions to the exact selected source
rows. One externally reported L2 incident remains one incident across nine cells.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import shutil

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'papers/monitoring_jss').is_dir())
PAPER = ROOT / 'papers/monitoring_jss'
NS = 1_000_000_000
EXPECTED_LABEL_SHA = '3518e1c753a3f0ba31b6977ab5b4f3811c5a3846569e1e930922af9084115046'
SOURCE_FIELDS = ('chain_id', 'address', 'block_number', 'block_hash',
                 'transaction_hash', 'transaction_index', 'log_index', 'event_time_ns')
REASONS = ('grouped', 'quota', 'token', 'budget', 'below_threshold', 'duplicate', 'late')


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def write_new(path, value):
    with Path(path).open('x') as f:
        json.dump(value, f, indent=2, sort_keys=True, allow_nan=False)
        f.write('\n')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verified(path, expected):
    require(sha(path) == expected, f'SHA-256 mismatch: {path}')


def utc_ns(text):
    value = datetime.fromisoformat(text.replace('Z', '+00:00'))
    require(value.utcoffset().total_seconds() == 0 and not value.microsecond, 'UTC whole seconds required')
    delta = value - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * NS


def source_position(row):
    return tuple(row[k] for k in ('block_number', 'transaction_index', 'log_index'))


def coordinate(row, notification=False):
    result = {k: row[k] for k in SOURCE_FIELDS}
    result['block_timestamp_utc'] = datetime.fromtimestamp(row['event_time_ns'] // NS, timezone.utc).isoformat()
    if notification:
        result.update({k: row[k] for k in ('alert_id', 'notification_time_ns', 'budget_day_utc')})
        result['notification_time_domain'] = 'historical_event_time_ns_logical_simulation'
        result['observed_delivery_time'] = None
    return result


def validate_labels(config, path):
    verified(path, EXPECTED_LABEL_SHA)
    require(config['label_manifest_sha256'] == EXPECTED_LABEL_SHA, 'changed expected label digest')
    labels = read(path)
    require(labels['candidate_id'] == config['candidate_id'] and labels['chain_id'] == 1, 'label candidate/chain mismatch')
    require(labels['prior_exposure_level'].startswith('L2'), 'L2 exposure must remain disclosed')
    positives = [x for x in labels['exploit_transactions']
                 if x['role'] == config['positive_role'] and x['positive_incident_label'] is True]
    require(len(positives) == 1 and [x['tx_hash'] for x in positives] == config['positive_hashes'], 'positive set differs from frozen single execution')
    require(positives[0]['block_number'] == config['positive_block_number'], 'frozen positive block differs')
    require(positives[0]['block_timestamp_utc'] == config['positive_block_timestamp_utc'], 'frozen positive time differs')
    require(not ({x['tx_hash'] for x in labels['context_transactions_not_positive_labels']} & set(config['positive_hashes'])), 'context is positive')
    return labels


def freeze(config_path, destination):
    config_path, destination = Path(config_path).resolve(), Path(destination).resolve()
    config = read(config_path)
    labels = PAPER / config['label_manifest']
    validate_labels(config, labels)
    design = PAPER / config['design_freeze_path']
    verified(design, config['design_freeze_sha256'])
    verified(PAPER / 'budget_policy_study_config.json', config['study_config_sha256'])
    destination.mkdir(parents=True, exist_ok=False)
    files = {}
    for name, path in [('evaluate_budget_policy_labels.py', Path(__file__)),
                       ('config.json', config_path), ('label_manifest.json', labels),
                       ('study_design_freeze.json', design),
                       ('qa_contract.json', PAPER / 'qa/budget_policy_label_join_contract.json'),
                       ('test_budget_policy_label_join.py', PAPER / 'tests/test_budget_policy_label_join.py')]:
        target = destination / name
        shutil.copyfile(path, target)
        require(sha(path) == sha(target), 'snapshot copy changed')
        files[name] = {'sha256': sha(target), 'bytes': target.stat().st_size, 'source': str(path.resolve())}
    manifest = {'schema_version': 'budget_policy_label_join_freeze_v1',
                'frozen_at_utc': datetime.now(timezone.utc).isoformat(),
                'files': files, 'actual_study_join_executed': False,
                'claim_scope': config['claim_scope'],
                'provenance_only_no_policy_outcomes_read': True}
    path = destination / 'join_freeze.json'
    write_new(path, manifest)
    return {'join_freeze': str(path), 'sha256': sha(path), 'status': 'frozen_not_executed'}


def frozen_join(path, expected):
    path = Path(path).resolve()
    verified(path, expected)
    record = read(path)
    require(record['schema_version'] == 'budget_policy_label_join_freeze_v1', 'wrong join freeze schema')
    for name, item in record['files'].items():
        verified(path.parent / name, item['sha256'])
        verified(item['source'], item['sha256'])
    require(sha(__file__) == record['files']['evaluate_budget_policy_labels.py']['sha256'], 'join implementation differs from freeze')
    config = read(path.parent / 'config.json')
    labels = validate_labels(config, path.parent / 'label_manifest.json')
    return record, config, labels


def source_rows(items):
    previous = None
    for item in items:
        path = Path(item['path'])
        if not path.is_absolute():
            path = ROOT / path
        verified(path, item['sha256'])
        count = 0
        with path.open() as f:
            for line in f:
                row = json.loads(line)
                key = source_position(row)
                require(previous is None or key > previous, 'source order is not strictly canonical')
                previous = key
                day = datetime.fromtimestamp(row['event_time_ns'] // NS, timezone.utc).date().isoformat()
                require(day == item['day_utc'], 'source outside declared day')
                count += 1
                yield row
        require(count == item['rows'], 'source row count changed')
        verified(path, item['sha256'])


def decision_rows(path, expected_sha, expected_rows):
    verified(path, expected_sha)
    count = 0
    with gzip.open(path, 'rt') as f:
        for line in f:
            row = json.loads(line)
            count += 1
            yield row
    require(count == expected_rows, 'decision gzip row count mismatch')
    verified(path, expected_sha)


def descriptive_cell(decisions, sources, config, policy, budget):
    """No policy recomputation; exact source identity and explicit count algebra."""
    positives = set(config['positive_hashes'])
    counts = Counter({key: 0 for key in config['counts']})
    preceding = Counter()
    first, first_notification, last_preceding = None, None, None
    selected_coordinates, selected_fingerprint = set(), hashlib.sha256()
    total, positive_ns = 0, utc_ns(config['positive_block_timestamp_utc'])
    day_counts = Counter()
    for row, source in itertools.zip_longest(decisions, sources):
        require(row is not None and source is not None, 'decision/source lengths differ')
        require(all(row[k] == source[k] for k in SOURCE_FIELDS), 'decision/source identity or coordinates differ')
        require(row['chain_id'] == config['chain_id'] and row['address'] == config['address'], 'unexpected population')
        require(row['policy'] == policy and row['daily_budget'] == budget, 'cell policy/budget differs')
        require(row['label_used'] is False, 'policy used labels')
        require(row['clock_domain'] == 'historical_event_time_ns_logical_simulation', 'unexpected clock domain')
        require(type(row['notification_emitted']) is bool and type(row['group_candidate']) is bool, 'invalid decision booleans')
        require(row['raw_trigger'] is None or type(row['raw_trigger']) is bool, 'invalid raw trigger')
        require(row['suppression_reason'] is None or row['suppression_reason'] in REASONS, 'unknown suppression reason')
        require(row['budget_day_utc'] == datetime.fromtimestamp(row['event_time_ns'] // NS, timezone.utc).date().isoformat(), 'budget day differs from preserved source UTC day')
        total += 1
        if row['notification_emitted']:
            require(row['alert_id'] is not None and row['notification_time_ns'] == row['event_time_ns'], 'notification timestamp/identity invalid')
            require(row['group_candidate'] is True and row['suppression_reason'] is None, 'emission accounting invalid')
            day_counts[row['budget_day_utc']] += 1
            require(day_counts[row['budget_day_utc']] <= budget, 'hard cap exceeded in decision log')
            if row['block_number'] < config['positive_block_number']:
                require(row['event_time_ns'] < positive_ns, 'prefix block/time ordering conflicts')
                preceding[row['budget_day_utc']] += 1
                last_preceding = coordinate(row, True)
        if row['transaction_hash'] not in positives:
            continue
        require(row['block_number'] == config['positive_block_number'] and row['event_time_ns'] == positive_ns, 'positive coordinates conflict with frozen label metadata')
        selected_coordinates.add((row['block_number'], row['block_hash'], row['transaction_index'], row['event_time_ns']))
        selected_fingerprint.update(json.dumps([row[k] for k in SOURCE_FIELDS], separators=(',', ':')).encode() + b'\n')
        if first is None:
            first = coordinate(row)
        if row['notification_emitted'] and first_notification is None:
            first_notification = coordinate(row, True)
        counts['selected_exploit_logs'] += 1
        counts['raw_triggers'] += row['raw_trigger'] is True
        counts['group_candidates'] += row['group_candidate'] is True
        counts['emitted'] += row['notification_emitted'] is True
        reason = row['suppression_reason']
        rename = {'quota': 'quota_rejected', 'token': 'token_rejected', 'budget': 'hard_budget_rejected'}
        if reason is not None:
            counts[rename.get(reason, reason)] += 1
    require(len(selected_coordinates) <= 1, 'single reported transaction has conflicting coordinates')
    require(counts['raw_triggers'] == counts['grouped'] + counts['group_candidates'], 'raw/group accounting failed')
    require(counts['group_candidates'] == counts['quota_rejected'] + counts['token_rejected'] + counts['hard_budget_rejected'] + counts['emitted'], 'candidate accounting failed')
    require(counts['selected_exploit_logs'] == counts['raw_triggers'] + counts['below_threshold'] + counts['duplicate'] + counts['late'], 'selected-row accounting failed')
    used = preceding[config['positive_source_day_utc']]
    return {'policy': policy, 'daily_budget': budget, 'decision_rows_verified': total,
            'positive_execution_counts': dict(counts),
            'positive_source_identity_sha256': selected_fingerprint.hexdigest(),
            'positive_membership_observed': first is not None,
            'first_positive_source_log': first,
            'first_positive_notification_admitted': first_notification,
            'preceding_notifications': {'cutoff': 'strictly smaller source block_number',
                'cutoff_block_number': config['positive_block_number'],
                'cutoff_source_event_time_ns': positive_ns,
                'whole_window_before_block': sum(preceding.values()),
                'by_utc_day': dict(sorted(preceding.items())),
                'positive_day_utc': config['positive_source_day_utc'],
                'positive_day_cap_used_before_block': used,
                'positive_day_cap_remaining_before_block': budget - used,
                'last_preceding_notification_admitted': last_preceding,
                'same_block_prior_transactions_included': False,
                'observed_response_latency': None}}


def evaluate(study, freeze_path, freeze_sha, destination):
    study, destination = Path(study).resolve(), Path(destination).resolve()
    require(not destination.exists(), 'evaluation output already exists')
    freeze_record, config, labels = frozen_join(freeze_path, freeze_sha)
    manifest = read(study / 'run_manifest.json')
    require(manifest['status'] == 'complete', 'study is not complete')
    require(manifest.get('frozen_sources_config_inputs_unchanged') is True, 'study frozen-input check did not pass')
    require(manifest['written_artifact_verification']['status'] == 'pass', 'study written artifact verification failed')
    require(datetime.fromisoformat(freeze_record['frozen_at_utc']) <= datetime.fromisoformat(manifest['started_at_utc']), 'join was not frozen before policy execution')
    require(manifest['config_sha256'] == config['study_config_sha256'], 'study design/config differs')
    verified(study / 'config.json', config['study_config_sha256'])
    watched = {str(study / p): h for p, h in manifest['frozen_file_sha256'].items()}
    watched.update(manifest['tracked_source_sha256'])
    watched.update({str(study / p): h for p, h in manifest['result_artifact_sha256'].items()})
    watched[str(study / 'run_manifest.json')] = sha(study / 'run_manifest.json')
    for path, expected in watched.items():
        verified(path, expected)
    provenance = manifest['provenance']['label_manifest']
    require(provenance['sha256'] == EXPECTED_LABEL_SHA, 'study captured different labels')
    validate_labels(config, study / provenance['copy'])
    summary, study_config = read(study / 'study_summary.json'), read(study / 'config.json')
    require(summary['status'] == 'complete' and summary['labels_used'] is False, 'closed unlabelled study required')
    require(summary['raw_feature_streams_identical'] is True, 'raw feature equality check missing')
    expected_ids = {f"{e['id']}__{p}__B{b}" for e in study_config['emitters'] for p in config['policies'] for b in config['budgets']}
    cells = summary['cells']
    require(len(cells) == 18 and {c['cell_id'] for c in cells} == expected_ids, 'full eighteen-cell study grid missing or repeated')
    inputs = read(study / 'resolved_inputs.json')[config['population_id']]
    input_manifest = read(study / 'input_manifest.json')
    require(input_manifest['status'] == 'complete', 'acquisition manifest incomplete')
    require(len(inputs) == 30, 'expected thirty source days')
    day = next(d for d in input_manifest['days'] if d['day_utc'] == config['positive_source_day_utc'])
    item = next(r for r in inputs if r['day_utc'] == config['positive_source_day_utc'])
    header_path = Path(item['shared_headers_path'])
    if not header_path.is_absolute():
        header_path = ROOT / header_path
    verified(header_path, day['headers_output']['sha256'])
    with header_path.open() as f:
        matching_headers = [r for line in f if (r := json.loads(line))['block_number'] == config['positive_block_number']]
    require(len(matching_headers) == 1 and matching_headers[0]['event_time_ns'] == utc_ns(config['positive_block_timestamp_utc']), 'positive block header missing or time conflicts')
    header = matching_headers[0]
    outputs, gzip_checks = [], []
    for cell in cells:
        cell_dir = study / 'cells' / cell['cell_id']
        require(read(cell_dir / 'summary.json') == cell, 'cell/study summaries differ')
        dec = cell['decision_log']
        path = study / dec['path']
        require(path.resolve() == (cell_dir / 'decisions.jsonl.gz').resolve(), 'decision path outside declared cell')
        require(dec['sha256'] == cell['artifacts']['decisions.jsonl.gz'], 'decision digest fields disagree')
        rows = decision_rows(path, dec['sha256'], dec['rows'])
        if cell['population_id'] == config['population_id']:
            result = descriptive_cell(rows, source_rows(inputs), config, cell['policy'], cell['daily_budget'])
            if result['first_positive_source_log'] is not None:
                require(result['first_positive_source_log']['block_hash'] == header['block_hash'], 'positive source/header hash mismatch')
            result.update(cell_id=cell['cell_id'], decisions_sha256=dec['sha256'])
            outputs.append(result)
        else:
            for _ in rows:
                pass
        gzip_checks.append({'cell_id': cell['cell_id'], 'sha256': dec['sha256'], 'rows_read_through_eof': dec['rows'], 'crc_read_to_eof': True})
    require(len(outputs) == config['expected_cells'], 'nine Beanstalk cells required')
    require(len({(r['positive_source_identity_sha256'], r['positive_execution_counts']['selected_exploit_logs']) for r in outputs}) == 1, 'positive source membership differs across cells')
    for path, expected in watched.items():
        verified(path, expected)
    frozen_join(freeze_path, freeze_sha)
    verified(header_path, day['headers_output']['sha256'])
    destination.mkdir(parents=True, exist_ok=False)
    for name in [*freeze_record['files'], 'join_freeze.json']:
        shutil.copyfile(Path(freeze_path).resolve().parent / name, destination / name)
    result = {'schema_version': 'budget_policy_descriptive_label_join_v1', 'status': 'pass',
              'created_at_utc': datetime.now(timezone.utc).isoformat(),
              'study_run': str(study), 'study_run_manifest_sha256': watched[str(study / 'run_manifest.json')],
              'join_freeze_sha256': freeze_sha, 'label_manifest_sha256': EXPECTED_LABEL_SHA,
              'candidate_id': labels['candidate_id'], 'prior_exposure_level': labels['prior_exposure_level'],
              'reported_incident_count': 1, 'independent_recall_estimate': None,
              'claim_scope': config['claim_scope'], 'receipt_status': None,
              'historical_observed_time': None, 'historical_label_available_time': None,
              'positive_execution_hashes': config['positive_hashes'],
              'context_not_positive_or_negative': [x['tx_hash'] for x in labels['context_transactions_not_positive_labels']],
              'positive_block_header': header, 'all_study_decision_gzip_checks': gzip_checks,
              'frozen_inputs_verified_before_and_after': True, 'cells': outputs}
    write_new(destination / 'descriptive_label_evaluation.json', result)
    write_new(destination / 'artifact_manifest.json', {'schema_version': 'budget_policy_label_join_artifacts_v1',
        'files': [{'path': p.name, 'sha256': sha(p), 'bytes': p.stat().st_size} for p in sorted(destination.iterdir()) if p.is_file()]})
    return {'status': 'pass', 'output': str(destination), 'cells': len(outputs), 'reported_incidents': 1}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    f = sub.add_parser('freeze')
    f.add_argument('--config', type=Path, default=PAPER / 'budget_policy_label_join_config.json')
    f.add_argument('--output', type=Path, required=True)
    e = sub.add_parser('evaluate')
    e.add_argument('--study-run', type=Path, required=True)
    e.add_argument('--join-freeze', type=Path, required=True)
    e.add_argument('--join-freeze-sha256', required=True)
    e.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = freeze(args.config, args.output) if args.command == 'freeze' else evaluate(args.study_run, args.join_freeze, args.join_freeze_sha256, args.output)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
