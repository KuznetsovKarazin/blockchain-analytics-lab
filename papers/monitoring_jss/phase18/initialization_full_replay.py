#!/usr/bin/env python3
"""Phase18: independent complete policy replay for Phase17 initialization modes.

Read-only 30-day, two-component cohort. Verifies every original daily-reset
method and admission decision (two semantic ranks, three budget policies,
three caps), then joins exactly the already admitted reference transactions.
Counterfactual modes keep the original daily grouping and budget resets; only
positive token amount histories are changed, to isolate initialization.
No detector tuning, raw-chain acquisition, ground-truth inference or labels
used in the scoring stage. Requires Python >=3.10, standard library only.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from fractions import Fraction
import gzip
import hashlib
import json
from pathlib import Path
import zipfile

SHA256_EVIDENCE = '56f19a262c36f5438d11d19cbb8434ea3dcb731b1cbdae34f479f667ec9997e2'
CASES = ('lifi_20220320', 'revest_20220327')
MODES = ('daily_reset', 'lookback_7d', 'cumulative_in_window')
METHODS = ('outflow_rank_1_20', 'outflow_rank_1_10')
POLICIES = ('greedy', 'paced_cumulative', 'token_bucket')
BUDGETS = (1, 5, 20)
DAY_NS = 86400 * 10**9
GROUP_NS = 300 * 10**9
HISTORY_LIMIT = 128
MIN_HISTORY = 19


def sha256_path(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for b in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def jsonlines(z, path):
    b = z.read(path)
    if path.endswith('.gz'):
        b = gzip.decompress(b)
    return [json.loads(line) for line in b.splitlines() if line.strip()]


def day_of(ns):
    return datetime.fromtimestamp(ns // 10**9, tz=timezone.utc).date().isoformat()


def build_method_decisions(observations, mode, threshold):
    """Recompute token rank, grouping and eligibility without attack labels."""
    assert mode in MODES
    assert threshold in (20, 10)
    hist = defaultdict(list)
    last_day = None
    last_candidate_ns = None
    rows = []
    for obs in observations:
        tx = obs['transaction']
        t = tx['event_time_ns']
        day = day_of(t)
        if day != last_day:
            if mode == 'daily_reset':
                hist.clear()
            last_candidate_ns = None
            last_day = day
        scores = []
        for flow in obs['token_flows']:
            amount = int(flow['external_out_raw'])
            if amount <= 0:
                continue
            token = flow['token_address']
            prev = hist[token]
            if mode == 'lookback_7d':
                prev = [record for record in prev if record[0] >= t - 7 * DAY_NS]
                hist[token] = prev
            count = len(prev)
            numerator = 1 + sum(past_amount >= amount for _, past_amount in prev)
            denominator = count + 1
            eligible = count >= MIN_HISTORY
            trigger = eligible and numerator * threshold <= denominator
            scores.append({'token': token, 'amount_raw': str(amount),
                           'n': count, 'numerator': numerator,
                           'denominator': denominator,
                           'eligible': eligible, 'trigger': trigger})
        raw = any(s['trigger'] for s in scores)
        grouped = raw and last_candidate_ns is not None and t - last_candidate_ns < GROUP_NS
        candidate = raw and not grouped
        if candidate:
            last_candidate_ns = t
        rows.append({'day': day, 'tx': tx['transaction_hash'], 'time_ns': t,
                     'method': f'outflow_rank_1_{threshold}', 'scores': scores,
                     'positive_count': len(scores),
                     'eligible_count': sum(s['eligible'] for s in scores),
                     'raw_trigger': raw, 'group_candidate': candidate,
                     'grouping_reason': ('candidate' if candidate else 'grouped' if grouped else
                                         'no_positive_external_outflow' if not scores else
                                         'cold_start_only' if not any(s['eligible'] for s in scores) else
                                         'rank_not_exceeded')})
        for s in scores:
            token = s['token']
            hist[token] = (hist[token] + [(t, int(s['amount_raw']))])[-HISTORY_LIMIT:]
    return rows


def apply_policy(rows, policy, B):
    """Independent transcription of frozen semantic_flow_replay AdmissionState."""
    last_day = None
    clock = 0
    credits = DAY_NS
    sent = 0
    output = []
    for r in rows:
        t = r['time_ns']
        day = r['day']
        if day != last_day:
            start = (t // DAY_NS) * DAY_NS
            last_day = day
            clock = start
            credits = DAY_NS
            sent = 0
        if policy == 'token_bucket':
            credits = min(DAY_NS, credits + (t - clock) * B)
        quota = min(B, 1 + (B * (t - (t // DAY_NS) * DAY_NS)) // DAY_NS) if policy == 'paced_cumulative' and B else B
        emitted = False
        if not r['group_candidate']:
            reason = 'not_candidate'
        elif sent >= B:
            reason = 'hard_daily_cap'
        elif policy == 'paced_cumulative' and sent >= quota:
            reason = 'paced_quota'
        elif policy == 'token_bucket' and credits < DAY_NS:
            reason = 'token_shortage'
        else:
            emitted, reason = True, 'emitted'
            if policy == 'token_bucket':
                credits -= DAY_NS
        if emitted:
            sent += 1
        clock = t
        output.append({'day': day, 'tx': r['tx'], 'notification_emitted': emitted,
                       'suppression_reason': reason, 'notifications_on_day': sent,
                       'daily_quota': quota, 'token_credit_units': credits if policy == 'token_bucket' else None})
    return output


def compare_frozen(z, case, method, method_rows, policies):
    """Require exact equality of frozen daily method and budget decisions."""
    methods_by_date = defaultdict(list)
    for r in method_rows:
        methods_by_date[r['day']].append(r)
    for day, mine in methods_by_date.items():
        old = jsonlines(z, f'runtime/replays/{case}/{day}/{method}__methods.jsonl.gz')
        assert len(old) == len(mine), (case, method, day, len(old), len(mine))
        for o, m in zip(old, mine):
            assert o['transaction']['transaction_hash'] == m['tx']
            assert o['raw_trigger'] == m['raw_trigger']
            assert o['group_candidate'] == m['group_candidate']
            assert o['grouping_reason'] == m['grouping_reason']
            assert o['positive_token_count'] == m['positive_count']
            assert o['eligible_token_count'] == m['eligible_count']
            old_scores = o['token_scores']
            assert len(old_scores) == len(m['scores'])
            for os, ms in zip(old_scores, m['scores']):
                assert (os['token_address'], os['external_out_raw'], os['history_count'],
                        os['tail_rank']['numerator'], os['tail_rank']['denominator'], os['trigger']) == (
                        ms['token'], ms['amount_raw'], ms['n'], ms['numerator'], ms['denominator'], ms['trigger'])
    checked = len(method_rows)
    cell_rows = 0
    for (policy, B), model_rows in policies.items():
        grouped = defaultdict(list)
        for row in model_rows:
            grouped[row['day']].append(row)
        for day, mine in grouped.items():
            frozen = jsonlines(z, f'runtime/replays/{case}/{day}/{method}__{policy}__{B}__decisions.jsonl.gz')
            assert len(frozen) == len(mine)
            for original, recomputed in zip(frozen, mine):
                assert original['transaction']['transaction_hash'] == recomputed['tx']
                for k in ('notification_emitted', 'suppression_reason', 'notifications_on_day',
                          'daily_quota', 'token_credit_units'):
                    assert original[k] == recomputed[k], (case, method, policy, B, day, k,original[k],recomputed[k])
                cell_rows += 1
    return checked, cell_rows


def summarize(case, mode, method, method_rows, admissions):
    base = {'case': case, 'initialization': mode, 'method': method,
            'selected_tx': len(method_rows),
            'positive_outflow_tx': sum(bool(r['scores']) for r in method_rows),
            'eligible_tx': sum(r['eligible_count'] > 0 for r in method_rows),
            'raw_triggers': sum(r['raw_trigger'] for r in method_rows),
            'group_candidates': sum(r['group_candidate'] for r in method_rows)}
    result = []
    for (policy, B), adm in admissions.items():
        result.append({**base, 'policy': policy, 'daily_budget': B,
                       'notifications': sum(r['notification_emitted'] for r in adm),
                       'group_suppressed': sum(r['raw_trigger'] and not r['group_candidate'] for r in method_rows),
                       'budget_suppressed': sum(r['suppression_reason'] in ('hard_daily_cap', 'paced_quota','token_shortage') for r in adm),
                       'emitted_tx': [r['tx'] for r in adm if r['notification_emitted']],
                       'emitted_dates': [r['day'] for r in adm if r['notification_emitted']]})
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence-zip', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    h = sha256_path(args.evidence_zip)
    if h != SHA256_EVIDENCE:
        raise SystemExit('Evidence SHA-256 mismatch: ' + h)
    args.out.mkdir(parents=True, exist_ok=True)
    detail = {}
    completed = []
    verified_methods = verified_decisions = 0
    with zipfile.ZipFile(args.evidence_zip) as z:
        for case in CASES:
            prefix = 'runtime/attempt2/observations/' + case + '/'
            names = sorted(n for n in z.namelist() if n.startswith(prefix) and n.endswith('.jsonl'))
            assert len(names) == 30
            observations = [ob for name in names for ob in jsonlines(z, name)]
            assert len(set(r['transaction']['transaction_hash'] for r in observations)) == len(observations)
            for mode in MODES:
                for method in METHODS:
                    method_rows = build_method_decisions(observations, mode, int(method.rsplit('_', 1)[-1]))
                    admissions = {(p, B): apply_policy(method_rows, p, B) for p in POLICIES for B in BUDGETS}
                    if mode == 'daily_reset':
                        n1, n2 = compare_frozen(z, case, method, method_rows, admissions)
                        verified_methods += n1
                        verified_decisions += n2
                    completed.extend(summarize(case, mode, method, method_rows, admissions))
                    detail[(case,mode,method)] = {'methods': method_rows, 'admissions': admissions}
        # Sealed reference identities are introduced AFTER all label-free outcomes and QA.
        references = json.loads(z.read('runtime/scientific_results/reference_mechanisms.json'))['references']
        for row in completed:
            case, mode, method = (row[k] for k in ('case', 'initialization', 'method'))
            allrefs = [r['transaction']['transaction_hash'] for r in references if r['case_id'] == case]
            notified = set(row['emitted_tx'])
            row['known_execution_count'] = len(allrefs)
            row['known_execution_hits'] = sum(tx in notified for tx in allrefs)
            row['known_execution_notified_tx'] = sorted(tx for tx in allrefs if tx in notified)
            row['unknown_notifications'] = row['notifications'] - row['known_execution_hits']
            # These are unknown in reference inventory, not proven negative.
        compact = [{k:v for k,v in r.items() if k not in ('emitted_tx','emitted_dates','known_execution_notified_tx')} for r in completed]
        import csv
        with (args.out / 'full_replay_cells.csv').open('w',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=list(compact[0]))
            writer.writeheader();writer.writerows(compact)
        with (args.out/'full_replay_summary.json').open('w') as f:
            json.dump({'status':'COMPLETE', 'phase16_reference_sha256':h,
                       'verified_original_method_rows':verified_methods,
                       'verified_original_decision_rows':verified_decisions,
                       'cases': list(CASES),'modes': list(MODES),
                       'thresholds':list(METHODS),'policies':list(POLICIES),'budgets':list(BUDGETS),
                       'cell_summaries':completed},f,indent=2)
        with (args.out/'recomputed_transaction_decisions.jsonl').open('w') as f:
            for (case,mode,method),d in detail.items():
                for m in d['methods']:
                    f.write(json.dumps({'case':case,'mode':mode,'method':method,**m},sort_keys=True)+'\n')
        print('PASS methods',verified_methods,'decisions',verified_decisions,'cells',len(completed))
        for r in completed:
            if r['policy']=='greedy' and r['daily_budget']==5:
                print(r['case'],r['initialization'],r['method'],r['eligible_tx'],r['raw_triggers'],r['group_candidates'],r['notifications'],r['known_execution_hits'],'/',r['known_execution_count'])

if __name__=='__main__':
    main()