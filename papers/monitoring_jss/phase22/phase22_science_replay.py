#!/usr/bin/env python3
"""Phase22 C: deterministic, label-last replay of fixed monitoring rules.

Consumes 30-day Blockscout-derived observations with AWS-pinned selected TX
identity and log-count checks. Reuses original Phase18 rank+budget methods and
frozen Phase8 count monitor; no network, label-dependent changes or tuning.
The Rari three components are *separate* views, not pooled cores.
"""
from __future__ import annotations
import argparse,csv,datetime as dt,gzip,hashlib,json,sys,collections,importlib.util
from pathlib import Path

CASES={
  'bacon_20220305':{'reference':'0x7d2296bcb936aa5e2397ddf8ccba59f54a178c3901666b49291d880369dbcf31','roles':['proxy'],'expected_tx':256},
  'rari_pool127_20220430':{'reference':'0xab486012f21be741c9e674ffda227e30518e8a1e37a5f1d58d0b0d41f6e76530','roles':['fETH','fUSDC','comptroller'],'expected_tx':411}}
MODES=('daily_reset','lookback_7d','cumulative_in_window')
METHODS=('outflow_rank_1_20','outflow_rank_1_10','core_count_60s_10')
POLICIES=('greedy','paced_cumulative','token_bucket')
CAPS=(1,5,20)
DAY_NS=86400*10**9

def require(ok,msg):
    if not ok:raise ValueError(msg)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def dstr(t):return dt.datetime.fromtimestamp(t//10**9,tz=dt.timezone.utc).date().isoformat()

def load_indexed(path,case):
    base=path.parent
    manifest=json.loads((base/'acquisition_manifest.json').read_text())
    require(manifest['schema']=='phase22_indexed_all_emitter_selected_bundles_v1' and manifest['case']==case,'manifest case/schema')
    require(manifest['status']=='COMPLETE_30_DAYS' and manifest['processed']==manifest['requested']==CASES[case]['expected_tx'],
            'indexer input not complete for 30-day population')
    records=[json.loads(z) for z in gzip.open(path,'rt',encoding='utf8') if z.strip()]
    require(manifest['selected_rows_sha256']==sha(canonical(records)),'indexed observation manifest hash mismatch')
    require(len(records)==manifest['processed'],'indexed count mismatch')
    prev=None
    for row in records:
        tx=row['transaction'];order=(tx['block_number'],tx['transaction_index'])
        require(prev is None or order>prev,'non-monotonic selected transaction order')
        prev=order
        require(row['source_tier']=='pinned_AWS_selected_identity_and_indexed_Blockscout_all_emitter_logs_v1',
                'source tier falsely elevated')
        require(row['day_utc']==dstr(tx['event_time_ns']),'timestamp/day mismatch')
        require(row['dataset_execution_status_source']=='Blockscout_v2_success_status','execution not independently checked')
        require(row['all_emitter_log_count']>=sum(row['core_log_counts'].values())>0,'invalid core/bundle counts')
    require(len(set(row['transaction']['transaction_hash'] for row in records))==len(records),'duplicate selected hash')
    require(len(set(row['day_utc'] for row in records))<=30,'day coverage invalid')
    return manifest,records

def count_method(observations):
    from semantic_flow_replay import CountMonitor
    decisions=[];last_day=None;monitor=None
    for obs in observations:
        tx=obs['transaction'];day=dstr(tx['event_time_ns'])
        if day!=last_day:
            start=tx['event_time_ns']//DAY_NS*DAY_NS
            monitor=CountMonitor(start_ns=start,end_ns=start+DAY_NS,window_ns=60*10**9,
                                 threshold_count=10,grouping_ns=300*10**9)
            last_day=day
        out=monitor.observe(tx,obs['archived_core_log_count'])
        decisions.append({'day':day,'tx':tx['transaction_hash'],'time_ns':tx['event_time_ns'],
              'method':'core_count_60s_10','scores':[], 'positive_count':None,'eligible_count':None,
              'raw_trigger':out['raw_trigger'],'group_candidate':out['group_candidate'],
              'grouping_reason':out['grouping_reason']})
    return decisions

def summarize(case,role,mode,method,rows,policy_rows):
    ans=[]
    for (policy,B),admitted in policy_rows.items():
        emitted=[x['tx'] for x in admitted if x['notification_emitted']]
        row={'case':case,'core_view':role,'initialization':mode,'method':method,
         'policy':policy,'daily_budget':B,'selected_tx':len(rows),
         'positive_core_outflow_tx':sum(x['positive_count']>0 for x in rows) if method.startswith('outflow') else None,
         'eligible_tx':sum(x['eligible_count']>0 for x in rows) if method.startswith('outflow') else None,
         'raw_triggers':sum(x['raw_trigger'] for x in rows),
         'group_candidates':sum(x['group_candidate'] for x in rows),
         'notifications':len(emitted),'group_suppressed':sum(x['raw_trigger'] and not x['group_candidate'] for x in rows),
         'budget_suppressed':sum(x['suppression_reason'] in ('hard_daily_cap','paced_quota','token_shortage') for x in admitted),
         'emitted_tx':emitted}
        byday=collections.Counter(x['day'] for x in admitted if x['notification_emitted'])
        require(all(n<=B for n in byday.values()),'daily hard cap violated')
        ans.append(row)
    return ans

def compute_mode_diagnostics(obs):
    days=collections.defaultdict(collections.Counter)
    for row in obs:
        day=dstr(row['transaction']['event_time_ns'])
        for flow in row['token_flows']:
            if int(flow['external_out_raw'])>0:
                days[day][flow['token_address']]+=1
    n_token_days=sum(len(x) for x in days.values())
    counts=[n for d in days.values() for n in d.values()]
    return {'positive_token_days':n_token_days,'token_days_reaching_twenty_positive_tx':sum(n>=20 for n in counts),
        'max_positive_transactions_per_token_day':max(counts,default=0),
        'positive_token_day_counts':[{'day':day,'token':token,'positive_selected_tx':cnt}
          for day,d in sorted(days.items()) for token,cnt in sorted(d.items())]}

def main():
    p=argparse.ArgumentParser();p.add_argument('--bacon',type=Path,required=True)
    p.add_argument('--rari',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    args=p.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    paper=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(paper))
    sys.path.insert(0,str(paper/'phase18'))
    from initialization_full_replay import build_method_decisions,apply_policy
    # Scientific results are frozen before labels/references are read.
    allrows=[];per_reference=[];populations={};provenance={};flow_diagnostics={}
    paths={'bacon_20220305':args.bacon,'rari_pool127_20220430':args.rari}
    for case,path in paths.items():
        manifest,records=load_indexed(path,case)
        provenance[case]={'indexed_sha256':sha(path.read_bytes()),'acquisition_manifest_sha256':sha((path.parent/'acquisition_manifest.json').read_bytes()),
            'S3_selected_identity_sha256':manifest['s3_selected_identity_file_sha256'],
            'source_tier':'AWS_S3_pinned_selected_tx_identities_plus_complete_Blockscout_indexed_logs_and_transaction_status'}
        populations[case]={'selected_union_tx':len(records),'core_views':{}}
        for role in CASES[case]['roles']:
            observations=[]
            for row in records:
                if role not in row['views']:continue
                observations.append({'transaction':row['transaction'],
                     'archived_core_log_count':row['views'][role]['archived_core_log_count'],
                     'token_flows':row['views'][role]['token_flows']})
            require(observations,'no selected records for nominal core '+role)
            populations[case]['core_views'][role]={'selected_tx':len(observations)}
            flow_diagnostics[f'{case}/{role}']=compute_mode_diagnostics(observations)
            for mode in MODES:
                for method in METHODS:
                    if method.startswith('outflow'):
                        decisions=build_method_decisions(observations,mode,int(method.rsplit('_',1)[-1]))
                    else:
                        # Count method never uses the token-history initialisation.
                        if mode!='daily_reset':continue
                        decisions=count_method(observations)
                    admits={(policy,B):apply_policy(decisions,policy,B) for policy in POLICIES for B in CAPS}
                    allrows.extend(summarize(case,role,mode,method,decisions,admits))
                    per_reference.append({'case':case,'core_view':role,'initialization':mode,'method':method,
                         'method_trace':[{k:z[k] for k in ('tx','day','time_ns','positive_count','eligible_count','raw_trigger','group_candidate','grouping_reason')}
                                         for z in decisions],
                         'admissions':{f'{p}/{B}':[x for x in arr] for (p,B),arr in admits.items()}})
    # Only after all label-free scores and notification streams are complete,
    # intersect the previously documented source-independent reference identities.
    known={case:CASES[case]['reference'] for case in CASES}
    for row in allrows:
        reference=known[row['case']]
        row['known_subset_references']=1 if any(r['case']==row['case'] and r['core_view']==row['core_view'] and
            any(x['tx']==reference for x in r['method_trace']) for r in per_reference) else 0
        row['known_subset_exact_tx_hits']=int(reference in row['emitted_tx'])
        row['other_notifications_status']='UNKNOWN_NOT_FALSE_POSITIVES'
        row['unknown_notifications']=row['notifications']-row['known_subset_exact_tx_hits']
    cols=[k for k in allrows[0] if k not in ('emitted_tx',)]
    with (args.out/'full_replay_cells.csv').open('w',newline='',encoding='utf8') as f:
        wr=csv.DictWriter(f,fieldnames=cols);wr.writeheader();wr.writerows({k:r[k] for k in cols} for r in allrows)
    root={'schema':'phase22_mixed_source_matched_policy_replay_v1','status':'COMPLETE',
       'distinct_external_case_families':2,'source_tier':'S3_selected_identities_verified_by_original_parquet; indexer topics/data/status',
       'not_all_topic_data_original_S3':True,'pre_exposed_context':'Bacon_Rari_candidates_selected_after_prior_LiFi_Revest_results',
       'case_reference_completeness':'KNOWN_SUBSET_ONLY','calibrated_FPR_estimated':False,
       'methods':list(METHODS),'modes':list(MODES),'policies':list(POLICIES),'caps':list(CAPS),
       'cell_count':len(allrows),'provenance':provenance,'populations':populations,
       'reference_rows_used_only_in_post_join':True,'cells':allrows,'flow_diagnostics':flow_diagnostics}
    (args.out/'full_replay.json').write_text(json.dumps(root,indent=2)+'\n')
    with gzip.open(args.out/'per_transaction_replay.jsonl.gz','wt',encoding='utf8') as f:
        for r in per_reference:f.write(json.dumps(r,sort_keys=True,separators=(',',':'))+'\n')
    print('COMPLETE',len(allrows),'cells',sum(x['known_subset_exact_tx_hits'] for x in allrows),'matched cell-hits',flush=True)
    for case in CASES:
        for role in CASES[case]['roles']:
            for method in ('outflow_rank_1_20','core_count_60s_10'):
                for x in allrows:
                    if ((x['case'],x['core_view'],x['initialization'],x['method'],x['policy'],x['daily_budget']) ==
                        (case,role,'daily_reset',method,'greedy',5)):
                        print(case,role,method,'eligible',x['eligible_tx'],'notifications',x['notifications'],
                              'hit',x['known_subset_exact_tx_hits'])

if __name__=='__main__':main()