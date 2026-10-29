#!/usr/bin/env python3
"""Check new independent mathematics on the existing frozen seven-stream grid."""
import hashlib,json
from pathlib import Path
from verify_nomad import method_trace,dispatch,readjsonl
HERE=Path(__file__).resolve().parent
PAPER=HERE.parents[1]

def main():
    checks=[]
    for phase,ids in [('phase29',['cohort28_02','cohort28_09','cohort28_10','cohort28_13']),('phase30',['cohort28_07','cohort28_11','cohort28_14'])]:
        for case in ids:
            records=readjsonl(PAPER/phase/'indexed'/case/'indexer_observations.jsonl.gz')
            path=PAPER/phase/'results'/case/'label_blind_replay.json'
            result=json.loads(path.read_text())
            target={(r['method'],r['init'],r['policy'],r['B']):r for r in result['case_score_rows']}
            n=0
            for method in ['outflow_rank_1_20','outflow_rank_1_10','core_count_60s_10']:
                for mode in ['daily_reset'] if method.startswith('core_count') else ['daily_reset','lookback_7d','cumulative_in_window']:
                    trace=method_trace(records,method,mode)
                    for policy in ['greedy','paced_cumulative','token_bucket']:
                        for budget in [1,5,20]:
                            got,sup=dispatch(trace,policy,budget);expected=target[(method,mode,policy,budget)]
                            actual={'notified_transactions':got,'notifications':len(got),'suppression_due_to_budget':sup,'raw_triggers':sum(x['raw'] for x in trace),'group_candidates':sum(x['candidate'] for x in trace),'eligible_tx':sum(x['eligible'] for x in trace) if method.startswith('outflow') else None}
                            assert all(expected[k]==v for k,v in actual.items()),(case,method,mode,policy,budget)
                            n+=1
            checks.append({'case':case,'cells':n,'selected_tx':len(records),'published_result_sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    out={'status':'PASS','scope':'Validate the new standalone mathematical implementation against frozen seven-stream results before using it on new Nomad data; no new experiment or new source-completeness claim.','script_sha256':hashlib.sha256((HERE/'verify_nomad.py').read_bytes()).hexdigest(),'total_cells':sum(x['cells'] for x in checks),'checks':checks}
    (HERE/'IMPLEMENTATION_BASELINE_CHECK.json').write_text(json.dumps(out,indent=2)+'\n')
    print('PASS:',out['total_cells'],'frozen mathematical cells')

if __name__=='__main__':main()
