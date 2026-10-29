#!/usr/bin/env python3
"""Rebuild reviewer-requested cross-case tables from published, hash-verified evidence.

No network, no detector training, no case re-adjudication; preserves Phase16/18/22.
Only exact known-subset reference joins are used; unknown alerts are not negative.
"""
import argparse,csv,datetime as dt,gzip,hashlib,json,zipfile,collections,sys
from pathlib import Path
from fractions import Fraction

CASE_FILES={'bacon_20220305':'Article2_Phase22_IndexedFull_12894646607.zip',
 'rari_pool127_20220430':'Article2_Phase22_IndexedFull_12894666788.zip'}
REFS={'bacon_20220305':'0x7d2296bcb936aa5e2397ddf8ccba59f54a178c3901666b49291d880369dbcf31',
 'rari_pool127_20220430':'0xab486012f21be741c9e674ffda227e30518e8a1e37a5f1d58d0b0d41f6e76530'}
MODES=('daily_reset','lookback_7d','cumulative_in_window')
DAY=86400*10**9

def require(x,msg):
 if not x:raise ValueError(msg)
def rawhash(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def day(t):return dt.datetime.fromtimestamp(t//10**9,tz=dt.timezone.utc).date().isoformat()
def iso(t):return dt.datetime.fromtimestamp(t/10**9,tz=dt.timezone.utc).isoformat().replace('+00:00','Z')
def writecsv(path, rows,keys):
 with open(path,'w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,keys);w.writeheader();w.writerows(rows)

def load_indexed(base,case):
 with zipfile.ZipFile(base/CASE_FILES[case]) as z:
  manifest=json.loads(z.read('acquisition_manifest.json'))
  items=[json.loads(x) for x in gzip.decompress(z.read('indexer_observations.jsonl.gz')).splitlines() if x.strip()]
 require(manifest['status']=='COMPLETE_30_DAYS' and manifest['processed']==manifest['requested']==len(items),'indexer incomplete')
 require(manifest['selected_rows_sha256']==hashlib.sha256(canonical(items)).hexdigest(),'indexer digest mismatch')
 return items,manifest

def score_readiness(observations, min_history, mode):
 memory=collections.defaultdict(list);last_day=None;n=0
 for row in observations:
  t=row['transaction']['event_time_ns'];d=day(t)
  if mode=='daily_reset' and d!=last_day:memory.clear()
  last_day=d
  eligible=False;updates=[]
  for flow in row['token_flows']:
   amount=int(flow['external_out_raw'])
   if amount<=0:continue
   tok=flow['token_address'];prev=memory[tok]
   if mode=='lookback_7d':
    prev=[(time,value) for time,value in prev if time>=t-7*DAY]
    memory[tok]=prev
   eligible |= len(prev)>=min_history
   updates.append((tok,amount))
  n+=eligible
  for tok,amount in updates:memory[tok]=(memory[tok]+[(t,amount)])[-128:]
 return n

def main():
 p=argparse.ArgumentParser();p.add_argument('--base',type=Path,default=Path('/mnt/data'));p.add_argument('--out',type=Path,required=True)
 a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
 # Independent, full decision-level replication must be green.
 sys.path.insert(0,str(Path(__file__).resolve().parent))
 from verify_phase22_science_independent import verify
 verified=verify(a.base);require(verified['status']=='PASS' and verified['cells_recomputed']==252,'independent Phase22 FAIL')
 with zipfile.ZipFile(a.base/'Article2_Phase22_CompleteReplay.zip') as z:
  report=json.loads(z.read('full_replay.json'))
 require(len(report['cells'])==252 and report['source_tier'].startswith('S3_selected_identities_verified'),'Phase22 incomplete')
 selected=[]; readiness=[]; attack=[]; ledger=[]
 for case in CASE_FILES:
  data,manifest=load_indexed(a.base,case);reference=REFS[case]
  ref=next(x for x in data if x['transaction']['transaction_hash']==reference)
  tx=ref['transaction'];moment=(tx['block_number'],tx['transaction_index']);d=day(tx['event_time_ns'])
  for view in ('proxy',) if case.startswith('bacon') else ('fETH','fUSDC','comptroller'):
   viewdata=[r for r in data if view in r['views']]
   onday=[r for r in viewdata if r['day_utc']==d]
   before=[r for r in onday if (r['transaction']['block_number'],r['transaction']['transaction_index'])<moment]
   after=[r for r in onday if (r['transaction']['block_number'],r['transaction']['transaction_index'])>moment]
   require(len(before)+len(after)+1==len(onday) and view in ref['views'],'reference view/date missing')
   pre_positive=collections.Counter()
   for row in before:
    for fl in row['views'][view]['token_flows']:
     if int(fl['external_out_raw'])>0:pre_positive[fl['token_address']]+=1
   attack.append({'case':case,'view':view,'utc_attack':iso(tx['event_time_ns']),'all_day_selected_tx':len(onday),
    'strictly_before':len(before),'reference_tx':1,'strictly_after':len(after),
    'max_same_token_positive_history_before':max(pre_positive.values(),default=0),
    'necessary_19_prior_selected_tx':int(len(before)>=19),
    'necessary_19_prior_positive_same_token':int(max(pre_positive.values(),default=0)>=19),
    'indexer_reference_status':'verified_successful_in_indexer'})
   ob=[{'transaction':x['transaction'],'token_flows':x['views'][view]['token_flows']} for x in viewdata]
   for mode in MODES:
    for h in (1,5,10,19,39):
     k=score_readiness(ob,h,mode)
     readiness.append({'case':case,'view':view,'mode':mode,'min_prior_positive':h,
      'selected_tx':len(ob),'eligible_tx':k,'eligible_fraction':round(k/len(ob),6)})
   primary=[r for r in report['cells'] if r['case']==case and r['core_view']==view and r['policy']=='greedy' and r['daily_budget']==5 and r['method'] in ('outflow_rank_1_20','core_count_60s_10')]
   for row in primary:
    selected.append({k:row.get(k) for k in ['case','core_view','initialization','method','selected_tx','positive_core_outflow_tx','eligible_tx','raw_triggers','group_candidates','notifications','unknown_notifications','known_subset_exact_tx_hits']})
    # Rank and timestamp of emitted reference or unadjudicated notifications via independent (not detector) recomputation.
    if row['method'].startswith('outflow_rank_'):
     from verify_phase22_science_independent import build_methods
     traces=build_methods(data,view,row['initialization'],20)
     indexed={r['tx']:r for r in traces}
     for alerted in row['emitted_tx']:
      x=indexed[alerted];triggering=[{'token':t,'prior_n':n,'rank':ratio} for t,n,ratio,tr in x['scores'] if tr]
      ledger.append({'case':case,'view':view,'mode':row['initialization'],'method':row['method'],
        'policy':'greedy','B':5,'tx':alerted,'utc':iso(x['time']),
        'reference_status':'VERIFIED_KNOWN_EXECUTION' if alerted==reference else 'UNADJUDICATED',
        'ranked_tokens':json.dumps(triggering,separators=(',',':'))})
 # Legacy Li.Fi/Revest ledger and primary comparisons from accepted Phase18 reproducible output.
 p18=a.base/'article2_work/phase18/results/full_replay_summary.json'
 old=json.loads(p18.read_text());require(old['status']=='COMPLETE' and old['verified_original_decision_rows']==8532,'Phase18 unverified')
 rows18=[json.loads(s) for s in (a.base/'article2_work/phase18/results/recomputed_transaction_decisions.jsonl').read_text().splitlines() if s.strip()]
 ix18={(r['case'],r['mode'],r['method'],r['tx']):r for r in rows18}
 for c in old['cell_summaries']:
  if c['policy']!='greedy' or c['daily_budget']!=5 or c['method']!='outflow_rank_1_20':continue
  selected.append({'case':c['case'],'core_view':'fixed-core','initialization':c['initialization'],'method':c['method'],
    'selected_tx':c['selected_tx'],'positive_core_outflow_tx':c['positive_outflow_tx'],
    'eligible_tx':c['eligible_tx'],'raw_triggers':c['raw_triggers'],'group_candidates':c['group_candidates'],
    'notifications':c['notifications'],'unknown_notifications':c['unknown_notifications'],
    'known_subset_exact_tx_hits':c['known_execution_hits']})
  for txid in c['emitted_tx']:
   x=ix18[(c['case'],c['initialization'],c['method'],txid)]
   ranks=[{'token':t['token'],'prior_n':t['n'],'rank':f"{t['numerator']}/{t['denominator']}"} for t in x['scores'] if t['trigger']]
   ledger.append({'case':c['case'],'view':'fixed-core','mode':c['initialization'],'method':c['method'],
     'policy':'greedy','B':5,'tx':txid,'utc':iso(x['time_ns']),
     'reference_status':'VERIFIED_KNOWN_EXECUTION' if txid in c.get('known_execution_notified_tx',[]) else 'UNADJUDICATED',
     'ranked_tokens':json.dumps(ranks,separators=(',',':'))})
 # Add the two independently validated Phase16/18 populations to the same
 # label-free readiness sensitivity table; verify the m=19 values against Phase18.
 legacy_path=a.base/'article2_work/sealed_evidence.zip'
 require(rawhash(legacy_path)=='56f19a262c36f5438d11d19cbb8434ea3dcb731b1cbdae34f479f667ec9997e2',
         'Phase16 sealed evidence changed')
 with zipfile.ZipFile(legacy_path) as z:
  for case in ('lifi_20220320','revest_20220327'):
   paths=sorted(p for p in z.namelist() if p.startswith(f'runtime/attempt2/observations/{case}/') and p.endswith('.jsonl'))
   require(len(paths)==30,'Phase16 daily observation partitions missing')
   observations=[json.loads(line) for path in paths for line in z.read(path).decode().splitlines() if line.strip()]
   for mode in MODES:
    expected=next(c['eligible_tx'] for c in old['cell_summaries'] if c['case']==case and c['initialization']==mode
           and c['method']=='outflow_rank_1_20' and c['policy']=='greedy' and c['daily_budget']==5)
    for h in (1,5,10,19,39):
     n=score_readiness(observations,h,mode)
     if h==19:require(n==expected,'Phase16 recomputation differs from Phase18 rank eligibility')
     readiness.append({'case':case,'view':'fixed-core','mode':mode,'min_prior_positive':h,
      'selected_tx':len(observations),'eligible_tx':n,'eligible_fraction':round(n/len(observations),6)})
 # Stable ordering: always permit 0 records, never invent empty days.
 selected.sort(key=lambda x:(x['case'],x['core_view'],x['initialization'],x['method']))
 readiness.sort(key=lambda x:(x['case'],x['view'],x['mode'],x['min_prior_positive']))
 ledger.sort(key=lambda x:(x['case'],x['mode'],x['utc'],x['view']))
 writecsv(a.out/'attack_day_before_after.csv',attack,list(attack[0]))
 writecsv(a.out/'primary_outcomes.csv',selected,list(selected[0]))
 writecsv(a.out/'readiness_sensitivity.csv',readiness,list(readiness[0]))
 writecsv(a.out/'alert_ledger.csv',ledger,list(ledger[0]))
 audit={'status':'PASS','as_of':'2026-10-29','independent_phase22':verified['status'],
  'phase22_recomputed_cells':verified['cells_recomputed'],
  'phase22_zip_sha256':rawhash(a.base/'Article2_Phase22_CompleteReplay.zip'),
  'indexed_zip_sha256':{case:rawhash(a.base/name) for case,name in CASE_FILES.items()},
  'phase18_source_sha256':rawhash(p18),
  'new_external_families':2,'new_verified_known_reference_tx':2,
  'historical_external_families':2,'historical_known_reference_tx':3,
  'retrospective_interventions':True,'all_primary_reference_inventories':'KNOWN_SUBSET_ONLY',
  'source_tier':'selected S3 identity plus indexer topics/data and success; not receipt-root authenticated',
  'table_rows':{'attack_day':len(attack),'primary_outcomes':len(selected),
   'readiness_sensitivity':len(readiness),'alert_ledger':len(ledger)},
  'outputs_sha256':{f.name:rawhash(f) for f in a.out.glob('*.csv')}}
 (a.out/'audit_manifest.json').write_text(json.dumps(audit,indent=2)+'\n')
 print('PASS',audit['table_rows'])
 for x in attack:print('ATTACK',x['case'],x['view'],x['strictly_before'],x['max_same_token_positive_history_before'])

if __name__=='__main__':main()
