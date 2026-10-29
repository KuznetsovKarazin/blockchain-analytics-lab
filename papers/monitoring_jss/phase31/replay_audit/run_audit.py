#!/usr/bin/env python3
"""Offline V6.1 audit; writes only phase31 outputs and temporary replay files.

Run from repository root:
 python papers/monitoring_jss/phase31/replay_audit/run_audit.py

The original source/indexer verifiers and independently implemented 441-cell
checker are rerun. A separate quadratic count reconstruction supplies the
boundary/dispatch review evidence; attack references are joined only after
all label-blind sequence and policy comparisons finish. No external requests.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
from fractions import Fraction
import importlib.util
import json
from pathlib import Path
import tempfile

NS = 10**9
DAY = 86400 * NS
CASES = {
    'cohort28_02': ('phase29', 'Umbrella'),
    'cohort28_07': ('phase30', 'Saddle'),
    'cohort28_09': ('phase29', 'Inverse'),
    'cohort28_10': ('phase29', 'Schnoodle'),
    'cohort28_11': ('phase30', 'XCarnival'),
    'cohort28_13': ('phase29', 'Omni'),
    'cohort28_14': ('phase30', 'Audius'),
}

def need(ok, msg):
    if not ok:
        raise AssertionError(msg)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def utc(ns):
    return datetime.fromtimestamp(ns // NS, timezone.utc).isoformat()

def count_by_full_scan(records, strict_boundary=False):
    """Quadratic oracle: explicitly sum every preceding same-day observation.

    Distinct from the frozen deque implementation. Window is (t-60s, t],
    current transaction included, ordered earlier transactions at t included.
    """
    answer, last = [], {}
    for i, record in enumerate(records):
        tx = record['transaction']; t = tx['event_time_ns']; day = t // DAY
        total = sum(previous['views']['fixed_core']['archived_core_log_count']
                    for previous in records[:i+1]
                    if previous['transaction']['event_time_ns'] // DAY == day
                    and previous['transaction']['event_time_ns'] > t - 60 * NS)
        raw = total >= 10
        gap = t - last[day] if day in last else None
        candidate = raw and (gap is None or (gap > 300*NS if strict_boundary else gap >= 300*NS))
        if candidate:
            last[day] = t
        answer.append({'tx': tx['transaction_hash'], 'time': t, 'day': utc(t)[:10],
                       'count_60s': total, 'raw': raw, 'candidate': candidate,
                       'gap_from_previous_candidate_ns': gap})
    return answer

def policy_trace(seq, budget, policy):
    counts, output = {}, []
    current_day = None; last_t = None; credit = Fraction(1)
    for row in seq:
        day = row['day']; t = row['time']
        if day != current_day:
            current_day = day; last_t = (t//DAY)*DAY; credit = Fraction(1)
        if policy == 'token_bucket':
            credit = min(Fraction(1), credit + Fraction((t-last_t)*budget, DAY))
        before = counts.get(day, 0)
        quota = min(budget, 1 + budget*(t % DAY)//DAY) if policy == 'paced_cumulative' else budget
        credit_before = credit
        if not row['candidate']:
            reason = 'not_candidate'
        elif before >= budget:
            reason = 'hard_daily_cap'
        elif policy == 'paced_cumulative' and before >= quota:
            reason = 'paced_quota'
        elif policy == 'token_bucket' and credit < 1:
            reason = 'token_shortage'
        else:
            reason = 'emitted'
        emitted = reason == 'emitted'
        counts[day] = before + int(emitted)
        if emitted and policy == 'token_bucket':
            credit -= 1
        output.append({**row, 'time_utc': utc(t), 'daily_used_before': before,
                       'daily_used_after': counts[day], 'notification_emitted': emitted,
                       'suppression_reason': reason, 'paced_quota': quota,
                       'token_credit_before': str(credit_before) if policy=='token_bucket' else None,
                       'token_credit_after': str(credit) if policy=='token_bucket' else None})
        last_t = t
    return output

def minimal_records(times, values):
    return [{'transaction': {'event_time_ns': t, 'transaction_hash': f'0x{i:064x}', 'block_hash': f'0x{i+1:064x}', 'block_number': i+1, 'transaction_index': 0, 'chain_id': 1},
             'views': {'fixed_core': {'archived_core_log_count': value, 'token_flows': []}}}
            for i, (t, value) in enumerate(zip(times, values))]

def boundary_checks(independent):
    from phase22_science_replay import count_method
    def frozen_count(records):
        return count_method([{'transaction': r['transaction'],
                              'archived_core_log_count': r['views']['fixed_core']['archived_core_log_count'],
                              'token_flows': []} for r in records])
    tests = []
    for gap, expected in [(300*NS-1, False), (300*NS, True), (300*NS+1, True)]:
        records = minimal_records([1000*NS, 1000*NS+gap], [10, 10])
        reference = count_by_full_scan(records)
        actual = independent.stand_alone_method(records, 'core_count_60s_10', 'daily_reset')
        need([r['candidate'] for r in actual] == [True, expected], '300s boundary implementation')
        need([r['candidate'] for r in reference] == [True, expected], '300s boundary oracle')
        need([r['group_candidate'] for r in frozen_count(records)] == [True, expected], '300s production boundary')
        tests.append({'gap_ns': gap, 'expected_second_candidate': expected, 'status': 'PASS'})
    records = minimal_records([1000*NS, 1299*NS, 1300*NS, 1599*NS, 1600*NS], [10]*5)
    expected = [True, False, True, False, True]
    seq = count_by_full_scan(records)
    need([r['candidate'] for r in seq] == expected, 'candidate anchor shifts on grouped raw trigger')
    emitted, suppressed = independent.independent_policy(seq, 'greedy', 1)
    need(emitted == [seq[0]['tx']] and suppressed == 2, 'dispatch changes grouping anchor')
    tests.append({'case': 'group anchor is prior group candidate, including budget-blocked candidates',
                  'candidate_flags': expected, 'B1_notifications': 1, 'B1_budget_suppressed': 2, 'status': 'PASS'})
    for gap, expected in [(60*NS-1, True), (60*NS, False), (60*NS+1, False)]:
        records = minimal_records([1000*NS, 1000*NS+gap], [9, 1])
        seq = count_by_full_scan(records)
        actual = independent.stand_alone_method(records, 'core_count_60s_10', 'daily_reset')
        need(seq[1]['raw'] == actual[1]['raw'] == frozen_count(records)[1]['raw_trigger'] == expected, '60s lower boundary')
        tests.append({'case': 'count window lower bound', 'gap_ns': gap,
                      'expected_second_raw_trigger': expected, 'status': 'PASS'})
    return tests

def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--paper', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--out', type=Path, default=Path(__file__).resolve().parent / 'results')
    args = parser.parse_args(); paper = args.paper.resolve(); out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = load_module('source_verify', paper/'phase29/verify_source_streams.py')
    indexed = load_module('indexed_verify', paper/'phase29/verify_indexed.py')
    independent = load_module('independent', paper/'phase30/independent_policy_audit.py')
    replay_modules = {phase: load_module(phase+'_replay', paper/phase/'fixed_replay.py') for phase in ('phase29', 'phase30')}
    inputs = set(paper/'phase28'/x for x in ('CANDIDATE_FRAME.json',))
    inputs.update(paper/'phase28/results'/f'batch_{i}.json' for i in range(8))
    inputs.update(paper/'phase29'/x for x in ('verify_source_streams.py', 'verify_indexed.py', 'REFERENCE_ROLE_LEDGER.json'))
    inputs.update(paper/phase/x for phase in ('phase29','phase30') for x in ('fixed_replay.py','independent_policy_audit.py'))
    inputs.update(paper/x for x in ('phase18/initialization_full_replay.py','phase22/phase22_science_replay.py','semantic_flow_replay.py'))
    for case, (phase, _) in CASES.items():
        for directory in ('data', 'indexed', 'results'):
            inputs.update((paper/phase/directory/case).glob('*'))
    before = {str(path.relative_to(paper)): sha(path) for path in sorted(inputs) if path.is_file()}
    audits = []; sequences = {}; frozen = {}; observation_records = {}; policy_traces = {}
    with tempfile.TemporaryDirectory(prefix='article2-v61-replay-') as tmp:
        for case, (phase, name) in CASES.items():
            src = source.verify(case, paper/phase/'data'/case, paper)
            idx = indexed.verify(case, paper/phase/'data'/case, paper/phase/'indexed'/case)
            algo = independent.compare_one(case, paper)
            new = Path(tmp)/case
            replay_modules[phase].replay(case, paper/phase/'indexed'/case, new, None)
            # Frozen JSON objects match exactly (CSV differs only in CRLF normalization).
            for filename in ('label_blind_replay.json',):
                need(json.loads((new/filename).read_bytes()) == json.loads((paper/phase/'results'/case/filename).read_bytes()),
                     f'{case}: rerun differs from frozen {filename}')
            records = independent.open_inputs(paper/phase/'indexed'/case)
            seq = count_by_full_scan(records)
            check_seq = independent.stand_alone_method(records, 'core_count_60s_10', 'daily_reset')
            need(all(all(left[k] == right[k] for k in ('tx','time','day','raw','candidate'))
                     for left, right in zip(seq, check_seq)), f'{case}: count oracle mismatch')
            sequences[case] = seq; observation_records[case] = records
            frozen[case] = json.loads((paper/phase/'results'/case/'label_blind_replay.json').read_bytes())
            policy_traces[case] = {}
            for policy in ('greedy', 'paced_cumulative', 'token_bucket'):
                for budget in (1,5,20):
                    trace = policy_trace(seq, budget, policy)
                    cell = next(c for c in frozen[case]['case_score_rows'] if c['method']=='core_count_60s_10'
                                and c['policy']==policy and c['B']==budget)
                    need([r['tx'] for r in trace if r['notification_emitted']] == cell['notified_transactions'],
                         f'{case} {policy}/{budget}: fraction-arithmetic policy oracle mismatch')
                    policy_traces[case][f'{policy}_B{budget}'] = trace
            audits.append({'case': case, 'name': name, 'source_verifier': src,
                           'indexer_verifier': idx, 'independent_algorithm': algo,
                           'frozen_replay_and_join_json_equal': True, 'independent_count_oracle': 'PASS'})
    # Labels are first read by this audit after label-blind calculations are sealed.
    ledger = json.loads((paper/'phase29/REFERENCE_ROLE_LEDGER.json').read_bytes())
    case_refs = {r['case_id']: r for r in ledger['case_records']}
    # Reproduce the legacy joins separately after all label-blind comparisons.
    with tempfile.TemporaryDirectory(prefix='article2-v61-label-last-') as tmp:
        for case, (phase, _) in CASES.items():
            new = Path(tmp)/case
            replay_modules[phase].replay(case, paper/phase/'indexed'/case, new, paper/'phase29/REFERENCE_ROLE_LEDGER.json')
            need(json.loads((new/'reference_join.json').read_bytes()) ==
                 json.loads((paper/phase/'results'/case/'reference_join.json').read_bytes()),
                 f'{case}: legacy reference join differs')
    uniform = []
    for case, (phase, name) in CASES.items():
        ref = case_refs[case]
        candidates = sorted({r['tx'] for r in ref['indexed_references']
                             if r.get('status') == 'ok' and r.get('within_original_fork_window') is True})
        selected = {r['tx'] for r in sequences[case]}
        present = [tx for tx in candidates if tx in selected]
        method_hits = {}
        for method in ('core_count_60s_10', 'outflow_rank_1_20'):
            for mode in (('daily_reset',) if method.startswith('core') else ('daily_reset','lookback_7d','cumulative_in_window')):
                cell = next(c for c in frozen[case]['case_score_rows'] if c['method']==method and c['init']==mode and c['policy']=='greedy' and c['B']==5)
                method_hits[method+'/'+mode] = {'notifications': cell['notifications'],
                        'exact_candidate_hash_matches': sorted(set(present) & set(cell['notified_transactions']))}
        uniform.append({'case': case, 'name': name, 'ledger_role_status': ref['source_status'],
                        'candidate_hash_count': len(candidates), 'selected_candidate_count': len(present),
                        'selected_candidate_hashes': present, 'unselected_candidate_hashes': sorted(set(candidates)-selected),
                        'methods_primary_greedy_B5': method_hits,
                        'criterion': 'frozen indexed reference: status=ok and within original window; denominator is selected subset',
                        'role_qualification_performed': False, 'incident_performance_admitted': False})
    sch_case = 'cohort28_10'; sch_ref = case_refs[sch_case]['independently_supported_reference_hash']
    sch_seq = sequences[sch_case]
    sch_trace = policy_traces[sch_case]
    sch_out = {}
    for key, trace in sch_trace.items():
        day = next(x['day'] for x in trace if x['tx']==sch_ref)
        target = next(x for x in trace if x['tx']==sch_ref)
        sch_out[key] = {'selected_tx': len(trace), 'raw_triggers': sum(r['raw'] for r in trace),
                       'group_candidates': sum(r['candidate'] for r in trace),
                       'notifications': sum(r['notification_emitted'] for r in trace),
                       'budget_suppressed': sum(r['suppression_reason'] in ('hard_daily_cap','paced_quota','token_shortage') for r in trace),
                       'reference_tx': sch_ref, 'reference_trace': target,
                       'same_day_raw_trigger_trace': [r for r in trace if r['day']==day and r['raw']]}
    need(sch_out['greedy_B5']['notifications'] == 27 and len(sch_seq) == 134, 'Schnoodle headline')
    need(sch_out['greedy_B1']['reference_trace']['suppression_reason']=='hard_daily_cap', 'Schnoodle B1 failure not dispatch')
    need(sch_out['greedy_B5']['reference_trace']['notification_emitted'], 'Schnoodle B5 no hit')
    need(sch_out['token_bucket_B5']['reference_trace']['suppression_reason']=='token_shortage', 'Schnoodle token bucket B5 cause')
    sch_out['notification_fraction_of_selected_tx_B5'] = 27/134
    sch_out['notification_fraction_is_not_false_positive_rate'] = True
    inv_records = observation_records['cohort28_09']
    inv_seq = sequences['cohort28_09']; inv_strict = count_by_full_scan(inv_records, strict_boundary=True)
    diff = [{'tx': a['tx'], 'time_utc': utc(a['time']), 'gap_ns': a['gap_from_previous_candidate_ns'],
             'candidate_with_ge_300': a['candidate'], 'candidate_with_gt_300': b['candidate']}
            for a,b in zip(inv_seq,inv_strict) if a['candidate'] != b['candidate']]
    need(len(diff)==1 and diff[0]['gap_ns']==300*NS, 'Inverse historical boundary mismatch')
    boundaries = {'synthetic_edge_checks': boundary_checks(independent),
                  'Inverse_historical_boundary': {'with_ge_300_group_candidates': sum(r['candidate'] for r in inv_seq),
                    'with_gt_300_group_candidates': sum(r['candidate'] for r in inv_strict), 'changed_transactions': diff},
                  'frozen_rule_retained': 'candidate gap >= 300 seconds; grouped raw triggers do not move anchor'}
    after = {str(path.relative_to(paper)): sha(path) for path in sorted(inputs) if path.is_file()}
    need(before == after, 'Frozen input changed during audit')
    summary = {'schema': 'article2_phase31_v61_offline_replay_audit_v1', 'status': 'PASS',
               'baseline_commit': '651daa926bb3803ad76227389a4fb35c1027da63',
               'cases': audits, 'total_cases': 7, 'total_selected_transactions': sum(len(v) for v in sequences.values()),
               'independent_policy_cells_matched': sum(a['independent_algorithm']['cells_matched'] for a in audits),
               'source_and_indexer_pairs_passed': 7, 'count_policy_cells_checked_by_fraction_arithmetic_oracle': 63, 'label_blind_replay_and_legacy_join_objects_reproduced': 14,
               'frozen_files_unchanged': True, 'frozen_input_files_hashed': len(before),
               'network_requests': 0,
               'limits': ['No receipt-root authentication.',
                          'Original AWS topics/data were not reconstructed by this offline audit.',
                          'Published normalized observations and archived manifests were checked; digest checks do not independently establish historical truth.',
                          '441 cells are repeated settings over seven nonrandom streams, not independent incident trials.',
                          'Uniform reference table is a provisional hash join; pending semantic roles remain pending.']}
    write(out/'REPLAY_AUDIT.json', summary)
    write(out/'SCHNOODLE_DISPATCH_TRACE.json', sch_out)
    write(out/'GROUPING_BOUNDARY_AUDIT.json', boundaries)
    write(out/'UNIFORM_PROVISIONAL_REFERENCE_JOIN.json', {'baseline_ledger_sha256': sha(paper/'phase29/REFERENCE_ROLE_LEDGER.json'), 'cases': uniform})
    write(out/'INPUT_SHA256.json', before)
    print(json.dumps({k:summary[k] for k in ('status','total_cases','total_selected_transactions','independent_policy_cells_matched','frozen_files_unchanged')}, sort_keys=True))

if __name__ == '__main__':
    main()
