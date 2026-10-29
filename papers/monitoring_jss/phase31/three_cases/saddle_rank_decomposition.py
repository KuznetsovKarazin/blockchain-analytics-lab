#!/usr/bin/env python3
"""Offline decomposition of the later Saddle extraction's cumulative sUSD rank."""
import argparse
import hashlib
import json
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGET = '0xe7e0474793aad11875c131ebd7582c8b73499dd3c5a473b59e6762d4e373d7b8'
TOKEN = '0x57ab1ec28d129707052df4df418d58a2d46d5f51'
MODE = 'cumulative_in_window'
OUTPUT = HERE / 'saddle_rank_decomposition.json'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def token_record(event):
    matches = [row for row in event['rank'][MODE]['tokens'] if row['token'] == TOKEN]
    assert len(matches) == 1
    return matches[0]


def chain_order(event):
    return event['block_number'], event['transaction_index']


def decompose():
    event_path = HERE / 'event_observations.json'
    role_path = HERE / 'role_adjudication.json'
    events = json.loads(event_path.read_text())
    by_hash = {row['transaction_hash']: row for row in events}
    assert len(by_hash) == len(events)
    current = by_hash[TARGET]
    current_token = token_record(current)
    amount = int(current_token['positive_gross_outflow_raw'])
    prior_hashes = current_token['prior_transaction_hashes']
    assert len(prior_hashes) == len(set(prior_hashes)) == 20
    comparisons = []
    for tx in prior_hashes:
        event = by_hash[tx]
        assert event['case'] == current['case'] == 'cohort28_07'
        assert chain_order(event) < chain_order(current)
        prior_amount = int(token_record(event)['positive_gross_outflow_raw'])
        assert prior_amount > 0
        comparisons.append({
            'transaction_hash': tx,
            'timestamp_utc': event['timestamp_utc'],
            'positive_gross_outflow_raw': str(prior_amount),
            'comparison_to_current': '>=' if prior_amount >= amount else '<',
        })
    ge_count = sum(row['comparison_to_current'] == '>=' for row in comparisons)
    numerator, denominator = 1 + ge_count, len(comparisons) + 1
    assert ge_count == 2 and (numerator, denominator) == (3, 21)
    assert numerator == current_token['rank_numerator']
    assert denominator == current_token['rank_denominator']
    assert current_token['strictly_prior_positive_count'] == len(comparisons)
    assert current_token['ready'] and not current_token['trigger_1_20']

    # Role labels are joined only after the numerical comparisons are complete.
    roles = json.loads(role_path.read_text())
    role_map = {row['tx']: row for row in roles['references']}
    for row in comparisons:
        role = role_map.get(row['transaction_hash'])
        row['role'] = role['role'] if role else 'unadjudicated_in_this_ledger'
        row['role_status'] = role['role_status'] if role else None
        row['source_ids'] = role['source_ids'] if role else []
    greater_or_equal = [row for row in comparisons if row['comparison_to_current'] == '>=']
    return {
        'schema': 'phase31_saddle_cumulative_susd_rank_decomposition_v1',
        'status': 'PASS',
        'input_sha256': {p.name: digest(p) for p in (event_path, role_path)},
        'script_sha256': digest(Path(__file__)),
        'case': current['case'],
        'history_mode': MODE,
        'token_address': TOKEN,
        'current': {
            'transaction_hash': TARGET,
            'timestamp_utc': current['timestamp_utc'],
            'positive_gross_outflow_raw': str(amount),
            'role': role_map[TARGET]['role'],
            'role_status': role_map[TARGET]['role_status'],
            'source_ids': role_map[TARGET]['source_ids'],
        },
        'strictly_prior_positive_count': len(comparisons),
        'prior_greater_or_equal_count': ge_count,
        'other_prior_values_strictly_smaller_count': len(comparisons) - ge_count,
        'prior_greater_or_equal': greater_or_equal,
        'all_prior_comparisons': comparisons,
        'rank_numerator': numerator,
        'rank_denominator': denominator,
        'rank_unsimplified': f'{numerator}/{denominator}',
        'rank_simplified': str(Fraction(numerator, denominator)),
        'history_minimum': 19,
        'stage_B_history_ready': True,
        'stage_C_rank_threshold': '1/20',
        'stage_C_trigger': False,
        'limits': [
            'Raw integers are gross emitted core-boundary token outflows, not net loss or profit.',
            'This decomposition uses stored event observations; it does not independently re-extract source logs.',
            'The subsequent-extraction role is an explicit chain-sequence and actor-attribution inference.',
            'The whitehat rescue remains in label-blind history but is not a harmful-extraction reference.',
            'This is one fixed-core observed history, not a complete incident inventory or a general detection claim.',
        ],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Verify saved output without rewriting it.')
    args = parser.parse_args()
    expected = json.dumps(decompose(), indent=2, sort_keys=True) + '\n'
    if args.check:
        assert OUTPUT.read_text() == expected, 'Stored decomposition differs from current inputs/script.'
    else:
        OUTPUT.write_text(expected)
    print('PASS: 20 prior values; 2 >= current, 18 < current; rank 3/21 = 1/7.')
