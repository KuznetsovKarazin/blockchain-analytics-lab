#!/usr/bin/env python3
"""Offline arithmetic audit of the unmodified Phase28 source census."""
import csv
import hashlib
import json
from collections import defaultdict
from datetime import date, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAPER = HERE.parents[1]
INPUT = PAPER / 'phase28/results/CENSUS_DAILY.csv'
FRAME = PAPER / 'phase28/CANDIDATE_FRAME.json'

def summary(rows):
    tx = [int(row['tx']) for row in rows]
    n_nonempty = sum(x > 0 for x in tx)
    n_nonempty_lt20 = sum(0 < x < 20 for x in tx)
    return {
        'emitter_days': len(tx), 'selected_transactions': sum(tx),
        'zero_transaction_days': sum(x == 0 for x in tx),
        'nonempty_days': n_nonempty,
        'days_below20_including_zeros': sum(x < 20 for x in tx),
        'nonempty_days_below20': n_nonempty_lt20,
        'nonempty_days_below20_fraction': n_nonempty_lt20 / n_nonempty if n_nonempty else None,
        'days_at_least20': sum(x >= 20 for x in tx),
    }

def main():
    rows = list(csv.DictReader(INPUT.open()))
    frame = json.loads(FRAME.read_text())
    groups = defaultdict(list)
    for row in rows:
        assert int(row['tx']) >= 0
        assert int(row['core_events']) >= int(row['tx'])
        groups[row['id']].append(row)
    assert set(groups) == {case['id'] for case in frame['cases']}
    cases=[]
    for case in frame['cases']:
        rr=groups[case['id']]
        days=sorted(date.fromisoformat(row['day']) for row in rr)
        assert len(days)==30 and len(set(days))==30
        assert days[-1]-days[0]==timedelta(days=29)
        cases.append({'id':case['id'],'family':case['family'],
                      'window_first':str(days[0]),'window_last':str(days[-1]),**summary(rr)})
    result={'schema':'phase31_census_denominator_audit_v1',
            'inputs_sha256':{str(p.relative_to(PAPER)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [INPUT,FRAME]},
            'interpretation':'Conditional nonempty-day descriptor, not deployment-adjusted and not same-token rank readiness; no population estimate.',
            'summary':summary(rows),'cases':cases}
    assert result['summary']['emitter_days']==480
    assert result['summary']['selected_transactions']==44780
    assert result['summary']['zero_transaction_days']==302
    assert result['summary']['nonempty_days']==178
    assert result['summary']['days_below20_including_zeros']==410
    assert result['summary']['nonempty_days_below20']==108
    (HERE/'CENSUS_DENOMINATORS.json').write_text(json.dumps(result,indent=2)+'\n')
    with (HERE/'CENSUS_DENOMINATORS.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(cases[0]),lineterminator='\n');w.writeheader();w.writerows(cases)
    print(json.dumps(result['summary'],indent=2))

if __name__=='__main__': main()
