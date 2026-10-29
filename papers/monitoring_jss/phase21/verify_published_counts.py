#!/usr/bin/env python3
"""Independent consistency checker for Phase21 derived selected-TX counts.

This verifies published aggregate integrity against frozen Phase20 source-level
counts. It does not independently re-read original AWS Parquet row groups.
"""
import csv
import statistics
from collections import defaultdict
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'phase20'/'daily_core_log_counts.csv'
DERIVED=ROOT/'phase21'/'selected_tx_daily_counts.csv'
MAP={'proxy':'bacon_proxy_core_logs','fETH':'rari_feth_core_logs',
     'fUSDC':'rari_fusdc_core_logs','comptroller':'rari_comptroller_core_logs'}

def main():
    with BASE.open(newline='') as f: original={(r['case_id'],r['utc_day']):r for r in csv.DictReader(f)}
    with DERIVED.open(newline='') as f: rows=list(csv.DictReader(f))
    assert len(original)==60 and len(rows)==120,(len(original),len(rows))
    seen=set()
    groups=defaultdict(list)
    for row in rows:
        case,day,component=row['case_id'],row['utc_day'],row['core']
        key=(case,day,component)
        assert key not in seen,key
        seen.add(key)
        assert (case,day) in original,key
        assert component in MAP and row['verified_against_phase20']=='true'
        assert (case.startswith('bacon') and component=='proxy') or (case.startswith('rari') and component!='proxy')
        logs=int(row['logs']); tx=int(row['selected_transactions']); union=int(row['union_transactions'])
        assert logs==int(original[case,day][MAP[component]]),key
        assert 0<=tx<=logs and tx<=union,key
        groups[(case,day)].append((component,tx,union))
    assert len(groups)==60
    for k,vals in groups.items():
        assert len(vals)==(1 if k[0].startswith('bacon') else 3),k
        unions={v[2] for v in vals}
        assert len(unions)==1,k
        u=next(iter(unions))
        assert max(v[1] for v in vals)<=u<=sum(v[1] for v in vals),k
    for component in MAP:
        arr=sorted(int(r['selected_transactions']) for r in rows if r['core']==component)
        assert len(arr)==30
        print(component,{'total':sum(arr),'median':statistics.median(arr),
                         'days_lt20':sum(t<20 for t in arr),'max':max(arr)})
    print('PASS: 60 dates, 120 component-date rows, original core-log counts and union bounds')
if __name__=='__main__':main()
