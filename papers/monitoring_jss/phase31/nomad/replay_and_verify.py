#!/usr/bin/env python3
"""Offline label-blind fixed-method replay plus separate implementation check.

Reads only accepted source manifest/bundles/observations. No attack-reference
file or network source is imported. Outputs scientific results only on COMPLETE.
"""
import argparse,collections,csv,datetime,gzip,hashlib,json,re,sys
from pathlib import Path
PAPER=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(PAPER))
for p in ['phase18','phase22','phase29']:sys.path.insert(0,str(PAPER/p))
from initialization_full_replay import build_method_decisions,apply_policy
from phase22_science_replay import count_method,compute_mode_diagnostics
from independent_policy_audit import stand_alone_method,independent_policy
TRANSFER='0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
ZERO='0x'+'0'*40
MODES=('daily_reset','lookback_7d','cumulative_in_window')
METHODS=('outflow_rank_1_20','outflow_rank_1_10','core_count_60s_10')
def ck(x,s):
 if not x:raise AssertionError(s)
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(x):return hashlib.sha256(x).hexdigest()
def loadgz(p):
 with gzip.open(p,'rt') as f:return [json.loads(s) for s in f if s.strip()]
def save(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+'\n')
def independent_outflows(events,core):
 # Independent shape decoder and gross positive outflow aggregation only.
 # Does not import retained observe/decode_transfer_shape.
 out=collections.defaultdict(int)
 for e in events:
  t=e['topics'];d=e['data']
  if not(len(t)==3 and t[0]==TRANSFER and re.fullmatch('0x[0-9a-f]{64}',d)):continue
  if not(all(re.fullmatch('0x[0-9a-f]{64}',x) for x in t[1:]) and all(x[2:26]=='0'*24 for x in t[1:])):continue
  sender='0x'+t[1][-40:];recipient='0x'+t[2][-40:]
  if sender==core and recipient not in (core,ZERO):out[e['address']]+=int(d,16)
 return {k:v for k,v in out.items() if v>0}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--data',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);a=ap.parse_args()
 m=json.loads((a.data/'acquisition_manifest.json').read_bytes());ck(m['status']=='COMPLETE','refuse incomplete source');ck(not m['reference_labels_used'] and not m['detector_scores_computed'],'source not label blind')
 fb=(PAPER/'phase28/CANDIDATE_FRAME.json').read_bytes();bb=(PAPER/'phase28/results/batch_7.json').read_bytes()
 ck(m['frame_sha256']==sha(fb) and m['census_batch_sha256']==sha(bb),'frozen provenance mismatch')
 frozen=next(x for x in json.loads(bb)['case_results'] if x['id']==m['case'])
 coreentry=next(x for x in json.loads(fb)['cases'] if x['id']==m['case'])
 ck(m['core']==frozen['core_address']==coreentry['core_address'],'frozen core mismatch')
 ck([d['day'] for d in m['days']]==[d['day'] for d in frozen['days']] and len(m['days'])==30,'frozen30-day window mismatch')
 for d,o in zip(m['days'],frozen['days']):
  ck(o['status']=='COMPLETE_ORIGINAL_PROJECTED_SOURCE' and d['selected']==o['distinct_core_selected_tx'],'frozen daily population mismatch')
  ck((d['status']=='REUSED_COMPLETE_ZERO_SELECTED_CENSUS')==(d['selected']==0),'zero day evidence mismatch')
 raw=loadgz(a.data/'raw_selected_bundles.jsonl.gz');records=loadgz(a.data/'observations.jsonl.gz')
 ck(sha(canon(raw))==m['raw_bundles_sha256'] and sha(canon(records))==m['observations_sha256'],'input hash mismatch');ck(len(raw)==len(records)==930,'population count')
 txkeys=[];txhashes=[];corecounts=collections.Counter()
 for b,r in zip(raw,records):
  ck(b['transaction']==r['transaction'] and b['receipt_status']==r['receipt_status']==1,'source status mismatch');identity=b['transaction'];events=b['events'];core=m['core']
  txkeys.append((identity['block_number'],identity['transaction_index']));txhashes.append(identity['transaction_hash'])
  utcday=datetime.datetime.fromtimestamp(identity['event_time_ns']//10**9,datetime.timezone.utc).date().isoformat()
  ck(utcday==b['day_utc']==r['day_utc'],'event time outside day')
  corecounts[utcday]+=sum(e['address']==core for e in events)
  ck(len(events)==r['all_emitter_log_count'],'event bundle count mismatch')
  ck(all(all(e[k]==identity[k] for k in ('block_number','block_hash','transaction_hash','transaction_index','event_time_ns')) for e in events),'mixed event identity')
  ck(all(y['log_index']==x['log_index']+1 for x,y in zip(events,events[1:])),'event gaps')
  ck(sha(canon(events))==r['all_emitter_logs_sha256'],'raw payload digest')
  ck(sum(e['address']==core for e in events)==r['views']['fixed_core']['archived_core_log_count'],'core event count')
  expected={f['token_address']:int(f['external_out_raw']) for f in r['views']['fixed_core']['token_flows'] if int(f['external_out_raw'])>0}
  ck(independent_outflows(events,core)==expected,'independent positive gross outflow differs')
 ck(txkeys==sorted(set(txkeys)) and len(set(txhashes))==930,'noncausal or duplicate transactions')
 for d in frozen['days']:ck(corecounts[d['day']]==d['core_emitted_events'],'frozen daily core count mismatch')
 counts=collections.Counter(r['day_utc'] for r in records)
 for d in m['days']:ck(counts[d['day']]==d['selected'],'daily coverage mismatch')
 observations=[{'transaction':r['transaction'],'archived_core_log_count':r['views']['fixed_core']['archived_core_log_count'],'token_flows':r['views']['fixed_core']['token_flows']} for r in records]
 cells=[];traces=[];matched=0
 for method in METHODS:
  for mode in (('daily_reset',) if method.startswith('core_count') else MODES):
   decisions=count_method(observations) if method.startswith('core_count') else build_method_decisions(observations,mode,int(method.rsplit('_',1)[-1]))
   independent=stand_alone_method(records,method,mode)
   ck(len(decisions)==len(independent)==930,'trace length')
   for x,y in zip(decisions,independent):
    ck(x['tx']==y['tx'] and x['raw_trigger']==y['raw'] and x['group_candidate']==y['candidate'],'method trace mismatch')
    if method.startswith('outflow'):ck((x['eligible_count']>0)==y['eligible'],'independent eligibility mismatch')
   traces.extend({'method':method,'mode':mode,**x} for x in decisions)
   for policy in ('greedy','paced_cumulative','token_bucket'):
    for budget in (1,5,20):
     ad=apply_policy(decisions,policy,budget);notified=[x['tx'] for x in ad if x['notification_emitted']]
     suppressed=sum(x['suppression_reason'] in ('hard_daily_cap','paced_quota','token_shortage') for x in ad)
     ni,si=independent_policy(independent,policy,budget);ck(ni==notified and si==suppressed,'independent dispatch mismatch')
     row={'case':m['case'],'method':method,'init':mode,'policy':policy,'B':budget,'selected_tx':930,'eligible_tx':sum(x['eligible_count']>0 for x in decisions) if method.startswith('outflow') else None,'raw_triggers':sum(x['raw_trigger'] for x in decisions),'group_candidates':sum(x['group_candidate'] for x in decisions),'notifications':len(notified),'suppression_due_to_budget':suppressed,'notified_transactions':notified}
     cells.append(row);matched+=1
 a.out.mkdir(parents=True,exist_ok=False)
 result={'schema':'article2_phase31_nomad_label_blind_replay_v1','status':'COMPLETE','case':m['case'],'source_tier':m['source_tier'],'source_manifest_sha256':sha((a.data/'acquisition_manifest.json').read_bytes()),'reference_labels_used':False,'reference_join_performed':False,'case_score_rows':cells,'case_token_feasibility':compute_mode_diagnostics(observations)}
 save(a.out/'label_blind_replay.json',result);save(a.out/'method_traces.json',traces)
 with (a.out/'method_policy_cells.csv').open('w',newline='') as f:
  keys=[k for k in cells[0] if k!='notified_transactions'];w=csv.DictWriter(f,fieldnames=keys);w.writeheader();w.writerows({k:r[k] for k in keys} for r in cells)
 audit={'status':'PASS','case':m['case'],'selected_transactions_verified':930,'full_log_bundles_verified':930,'independent_positive_outflow_matches':930,'independent_policy_cells_matched':matched,'method_trace_rows_compared':len(traces),'receipt_root_verified':False,'source_tier':m['source_tier'],'labels_used':False,'replay_sha256':sha((a.out/'label_blind_replay.json').read_bytes())}
 save(a.out/'independent_verification.json',audit);print(json.dumps(audit))
 for row in cells:
  if row['policy']=='greedy' and row['B']==5:print({k:v for k,v in row.items() if k!='notified_transactions'})
if __name__=='__main__':main()
