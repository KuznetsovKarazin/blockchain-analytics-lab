"""Synthetic join/accounting integrity only; no acquisition or real decisions."""
import copy
import gzip
import importlib.util
import json
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[1] / 'evaluate_budget_policy_labels.py'
spec = importlib.util.spec_from_file_location('label_join', PATH)
join = importlib.util.module_from_spec(spec)
spec.loader.exec_module(join)


def fixture_rows():
    config = join.read(PATH.with_name('budget_policy_label_join_config.json'))
    t = join.utc_ns(config['positive_block_timestamp_utc'])
    positive = config['positive_hashes'][0]
    rows = []
    for number, tx, index, reason, raw, candidate, emitted in [
        (14602789, '0x'+'1'*64, 0, None, True, True, True),
        (14602790, '0x'+'2'*64, 0, None, True, True, True),
        (14602790, positive, 1, 'below_threshold', False, False, False),
        (14602790, positive, 2, 'quota', True, True, False),
        (14602790, positive, 3, None, True, True, True),
        (14602790, positive, 4, 'grouped', True, False, False),
    ]:
        event_t = t - 12*join.NS if number < 14602790 else t
        rows.append(dict(chain_id=1, address=config['address'], block_number=number,
            block_hash='0x'+f'{number:064x}', transaction_hash=tx,
            transaction_index=0 if tx != positive else 1, log_index=index,
            event_time_ns=event_t, policy='paced_cumulative', daily_budget=5,
            label_used=False, clock_domain='historical_event_time_ns_logical_simulation',
            notification_emitted=emitted, raw_trigger=raw, group_candidate=candidate,
            suppression_reason=reason, alert_id=f'alert:{number}:{index}' if emitted else None,
            notification_time_ns=event_t if emitted else None, budget_day_utc='2022-04-17'))
    sources = [{k: r[k] for k in join.SOURCE_FIELDS} for r in rows]
    return config, rows, sources


def test_single_positive_role_counts_and_strict_before_block_prefix():
    config, rows, sources = fixture_rows()
    out = join.descriptive_cell(rows, sources, config, 'paced_cumulative', 5)
    counts = out['positive_execution_counts']
    assert counts['selected_exploit_logs'] == 4
    assert counts['raw_triggers'] == 3 and counts['grouped'] == 1
    assert counts['group_candidates'] == 2 and counts['quota_rejected'] == 1
    assert counts['emitted'] == 1 and counts['below_threshold'] == 1
    assert out['first_positive_source_log']['log_index'] == 1
    assert out['first_positive_notification_admitted']['log_index'] == 3
    assert out['preceding_notifications']['positive_day_cap_used_before_block'] == 1
    assert out['preceding_notifications']['positive_day_cap_remaining_before_block'] == 4
    # The other notification in the same block is explicitly outside this prefix.
    assert out['preceding_notifications']['whole_window_before_block'] == 1


@pytest.mark.parametrize('mutation', ['identity', 'short_source', 'label_used', 'count_algebra', 'positive_time'])
def test_invalid_membership_or_accounting_fails(mutation):
    config, rows, sources = fixture_rows()
    if mutation == 'identity':
        sources[3]['transaction_hash'] = '0x'+'a'*64
    elif mutation == 'short_source':
        sources.pop()
    elif mutation == 'label_used':
        rows[0]['label_used'] = True
    elif mutation == 'count_algebra':
        rows[3]['group_candidate'] = False
    else:
        rows[3]['event_time_ns'] += 1
        sources[3]['event_time_ns'] += 1
    with pytest.raises(ValueError):
        join.descriptive_cell(rows, sources, config, 'paced_cumulative', 5)


def test_absent_positive_membership_is_explicit_not_invented_detection():
    config, rows, sources = fixture_rows()
    out = join.descriptive_cell(rows[:2], sources[:2], config, 'paced_cumulative', 5)
    assert out['positive_membership_observed'] is False
    assert out['positive_execution_counts']['selected_exploit_logs'] == 0
    assert out['first_positive_source_log'] is None
    assert out['first_positive_notification_admitted'] is None


def test_decision_gzip_requires_hash_count_and_crc(tmp_path):
    path = tmp_path / 'decisions.jsonl.gz'
    with gzip.open(path, 'wt') as f:
        f.write(json.dumps({'x': 1})+'\n')
    assert list(join.decision_rows(path, join.sha(path), 1)) == [{'x': 1}]
    with pytest.raises(ValueError):
        list(join.decision_rows(path, '0'*64, 1))
    with pytest.raises(ValueError):
        list(join.decision_rows(path, join.sha(path), 2))
    content = bytearray(path.read_bytes()); content[-8] ^= 1; path.write_bytes(content)
    with pytest.raises((gzip.BadGzipFile, EOFError)):
        list(join.decision_rows(path, join.sha(path), 1))
