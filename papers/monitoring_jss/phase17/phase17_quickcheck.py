#!/usr/bin/env python3
"""Independent read-only A/B/C diagnostics of published Phase16 evidence.

No network, no detector execution, no changes to frozen inputs. Labels joined
only after all score histories are computed. Requires Python >=3.10.
"""
import argparse
import collections
import datetime as dt
import gzip
import hashlib
import json
import zipfile
from fractions import Fraction

EXPECTED = '56f19a262c36f5438d11d19cbb8434ea3dcb731b1cbdae34f479f667ec9997e2'
CASES = ('lifi_20220320', 'revest_20220327')
MODES = ('daily', 'rolling_7d', 'continuous')

def parse_lines(data):
    return [json.loads(s) for s in data.splitlines() if s.strip()]

def analyze(items, mode):
    history = collections.defaultdict(list)
    scored = {}
    current_day = None
    eligible = raw20 = raw10 = 0
    for obs in items:
        tx = obs['transaction']
        stamp = tx['event_time_ns']
        day = dt.datetime.fromtimestamp(stamp // 10**9, dt.timezone.utc).date().isoformat()
        if mode == 'daily' and day != current_day:
            history.clear()
        current_day = day
        positive = [(x['token_address'], int(x['external_out_raw']))
                    for x in obs['token_flows'] if int(x['external_out_raw']) > 0]
        scores = []
        for token, value in positive:
            past = history[token]
            if mode == 'rolling_7d':
                past = [p for p in past if p[0] >= stamp - 7 * 86400 * 10**9]
                history[token] = past
            n = len(past)
            ratio = Fraction(1 + sum(v >= value for _, v in past), n + 1)
            scores.append({'token': token, 'n': n,
                           'rank': f'{ratio.numerator}/{ratio.denominator}',
                           'eligible': n >= 19,
                           'r20': n >= 19 and ratio <= Fraction(1, 20),
                           'r10': n >= 19 and ratio <= Fraction(1, 10)})
        e = any(x['eligible'] for x in scores)
        p20 = any(x['r20'] for x in scores)
        p10 = any(x['r10'] for x in scores)
        eligible += e
        raw20 += p20
        raw10 += p10
        scored[tx['transaction_hash']] = {'day': day, 'eligible': e,
            'r20': p20, 'r10': p10, 'tokens': scores,
            'erc20': obs['counts']['erc20_shaped'],
            'monitored_erc20': obs['counts']['monitored_erc20_shaped'],
            'core_logs': obs['archived_core_log_count'],
            'all_logs': obs['counts']['logs']}
        for token, value in positive:
            history[token] = (history[token] + [(stamp, value)])[-128:]
    return {'n': len(items), 'eligible': eligible,
            'raw20': raw20, 'raw10': raw10}, scored

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('sealed_evidence_zip')
    opts = ap.parse_args()
    with open(opts.sealed_evidence_zip, 'rb') as f:
        actual = hashlib.sha256(f.read()).hexdigest()
    if actual != EXPECTED:
        raise SystemExit('Evidence ZIP hash mismatch: ' + actual)
    with zipfile.ZipFile(opts.sealed_evidence_zip) as z:
        scans = {}
        outputs = {}
        for case in CASES:
            files = sorted(x for x in z.namelist() if
                x.startswith('runtime/attempt2/observations/' + case + '/')
                and x.endswith('.jsonl'))
            if len(files) != 30:
                raise SystemExit('Missing daily observation file: ' + case)
            items = [r for name in files for r in parse_lines(z.read(name))]
            for mode in MODES:
                summary, rows = analyze(items, mode)
                scans[case, mode] = rows
                outputs[case, mode] = summary
            # Independently require identity of the ORIGINAL frozen daily replay.
            original = {}
            for name in z.namelist():
                if name.startswith('runtime/replays/' + case + '/') and name.endswith('/outflow_rank_1_20__methods.jsonl.gz'):
                    original.update((r['transaction']['transaction_hash'], r)
                       for r in parse_lines(gzip.decompress(z.read(name))))
            assert len(original) == len(items)
            for txid, frozen in original.items():
                computed = scans[case, 'daily'][txid]
                assert frozen['raw_trigger'] == computed['r20']
                assert frozen['eligible_token_count'] == sum(t['eligible'] for t in computed['tokens'])
                assert [(t['token_address'], t['history_count'], t['eligible'])
                        for t in frozen['token_scores']] == [
                        (t['token'], t['n'], t['eligible']) for t in computed['tokens']]
        # Reference membership is used only after label-blind scans and checks.
        refs = json.loads(z.read('runtime/scientific_results/reference_mechanisms.json'))['references']
        matches = []
        for ref in refs:
            case = ref['case_id']
            txid = ref['transaction']['transaction_hash']
            matches.append({'case': case, 'reference_tx': txid,
                **{mode: scans[case, mode][txid] for mode in MODES}})
        print(json.dumps({'population': {case: {
            mode: outputs[case, mode] for mode in MODES} for case in CASES},
            'references': matches}, indent=2))

if __name__ == '__main__':
    main()
