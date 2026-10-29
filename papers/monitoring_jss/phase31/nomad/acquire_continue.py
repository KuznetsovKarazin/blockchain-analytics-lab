#!/usr/bin/env python3
"""Bounded continuation of verified COMPLETE days from a capped source attempt.

This is a separate attempt, never relabels the earlier run complete. It reuses
only full source-validated day bundles, not partial Parquet bodies.
"""
import argparse,collections,datetime as dt,gzip,hashlib,json,shutil,sys,urllib.request,urllib.parse,xml.etree.ElementTree as ET
from pathlib import Path
PAPER=Path(__file__).resolve().parents[2]
for p in ['phase16/collector','phase29','phase27','phase15/adapter']:sys.path.insert(0,str(PAPER/p))
import range_collector as rc
from selected_original_tx import match_positions,ts_ns
from verify_aws_log_payloads import normalize
from retained_observation_core import observe
CASE='cohort28_15'
LC=['address','block_number','transaction_index','transaction_hash','block_hash','block_timestamp','log_index','topics','data']
TC=['hash','transaction_index','block_hash','block_number','block_timestamp','receipt_status']
def ck(x,s):
 if not x:raise ValueError(s)
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(x):return hashlib.sha256(x).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
def gzsave(p,rows):
 with p.open('wb') as f:
  with gzip.GzipFile(fileobj=f,filename='',mode='wb',mtime=0) as g:
   for r in rows:g.write(canon(r)+b'\n')
def txsource(day):
 prefix=f'v1.0/eth/transactions/date={day}/'
 url=rc.ENDPOINT+'?'+urllib.parse.urlencode({'list-type':'2','prefix':prefix,'max-keys':'100'})
 with urllib.request.urlopen(url,timeout=25) as r:
  ck(r.status==200,'listing status');raw=r.read(300001)
 ck(len(raw)<=300000,'listing bound');root=ET.fromstring(raw)
 def field(n,k):return next((c.text for c in n if c.tag.rsplit('}',1)[-1]==k),None)
 ck(field(root,'IsTruncated')=='false','truncated transaction listing')
 a=[x for x in root if x.tag.rsplit('}',1)[-1]=='Contents'];ck(len(a)==1,'transaction daily partition count')
 return {'table':'transactions','day_utc':day,'key':field(a[0],'Key'),'size_bytes':int(field(a[0],'Size')),'etag_opaque':field(a[0],'ETag')}, {'url':url,'body':raw.decode(),'sha256':sha(raw)}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--out',required=True,type=Path);ap.add_argument('--previous',required=True,type=Path);a=ap.parse_args();a.out.mkdir(parents=True,exist_ok=False)
 import pyarrow as pa,pyarrow.compute as pc,pyarrow.parquet as pq
 fb=(PAPER/'phase28/CANDIDATE_FRAME.json').read_bytes();bb=(PAPER/'phase28/results/batch_7.json').read_bytes()
 frame=json.loads(fb);batch=json.loads(bb);c=next(x for x in batch['case_results'] if x['id']==CASE);core=next(x['core_address'] for x in frame['cases'] if x['id']==CASE)
 ck(batch['frame_sha256']==sha(fb),'frame identity');ck(c['summary']['total_distinct_selected_tx']==930,'frozen selected count');ck(c['core_address']==core,'frozen core')
 previous_raw=(a.previous/'acquisition_manifest.json').read_bytes();previous=json.loads(previous_raw)
 ck(previous['status']=='INCOMPLETE' and previous['frame_sha256']==sha(fb) and previous['census_batch_sha256']==sha(bb),'ineligible prior attempt')
 ck(not previous['reference_labels_used'] and not previous['detector_scores_computed'],'previous attempt scored or labelled')
 prior_range=json.loads((a.previous/'range_capture/session.json').read_bytes())
 wall_failure=previous['failure']['reason'].startswith('wall cap') or previous['failure']['reason']=='wall/request cap'
 timed_out_at_cap=previous['failure']['type'] in ('TimeoutError','URLError') and prior_range['wall_seconds_elapsed']>=1799
 ck(wall_failure or timed_out_at_cap,'only documented wall-cap failure permits continuation')
 prior_listings=json.loads((a.previous/'transaction_source_listings.json').read_bytes())
 listing_bytes=sum(len(x['body'].encode()) for x in prior_listings)
 limits_raw=(Path(__file__).parent/'CONTINUATION_LIMITS.json').read_bytes();continuation_limits=json.loads(limits_raw)
 ck(continuation_limits['previous_attempt_manifest_sha256']==sha(previous_raw),'continuation amendment names wrong prior attempt')
 ck(continuation_limits['cumulative_response_bytes']<=5000000000 and not continuation_limits['reference_labels_used'] and not continuation_limits['detector_scores_computed'],'invalid pre-score continuation ceiling')
 caps={'requests':1600-previous['range_requests']-len(prior_listings)-12,'total_response_bytes':continuation_limits['cumulative_response_bytes']-previous['range_bytes']-listing_bytes-100000,'wall_seconds':min(1800,max(1,int(3600-prior_range['wall_seconds_elapsed']))),'request_timeout_seconds':45,'max_range_bytes':32000000,'max_footer_bytes':1500000,'max_rows':10000000,'max_row_groups':100,'max_top_level_columns':100,'max_leaf_columns':120,'max_source_bytes':850000000,'retries':0,'concurrency':1}
 plan={'schema_version':'article2_phase16_range_source_plan_v1','endpoint':rc.ENDPOINT,'caps':caps,'required_columns':{'logs':LC,'transactions':TC}}
 save(a.out/'source_plan.json',plan)
 sess=rc.RangeSession(plan,a.out/'range_capture')
 def readgz(path):
  with gzip.open(path,'rt') as z:return [json.loads(line) for line in z if line.strip()]
 rawbundles=readgz(a.previous/'raw_selected_bundles.jsonl.gz');observations=readgz(a.previous/'observations.jsonl.gz')
 ck(sha(canon(rawbundles))==previous['raw_bundles_sha256'] and sha(canon(observations))==previous['observations_sha256'],'prior complete-day byte identity changed')
 ck(len(rawbundles)==len(observations)==previous['selected_transactions'],'prior population differs')
 days=list(previous['days']);listings=list(prior_listings);failure=None
 inherited={d['day'] for d in days};ck(len(inherited)==len(days),'duplicate prior days')
 ck(sum(d['selected'] for d in days)==len(observations),'prior daily sum differs')
 save(a.out/'inherited_attempt_manifest.json',previous);save(a.out/'inherited_range_session.json',prior_range)
 save(a.out/'inherited_source_plan.json',json.loads((a.previous/'source_plan.json').read_bytes()))
 save(a.out/'inherited_range_requests.json',json.loads((a.previous/'range_capture/requests.json').read_bytes()))
 try:
  for d in c['days']:
   day=d['day'];ck(d['status']=='COMPLETE_ORIGINAL_PROJECTED_SOURCE','original census incomplete')
   if day in inherited:continue
   if not d['distinct_core_selected_tx']:
    days.append({'day':day,'status':'REUSED_COMPLETE_ZERO_SELECTED_CENSUS','selected':0,'source_key':d['source_key'],'source_etag':d['source_etag']});continue
   src={'table':'logs','day_utc':day,'key':d['source_key'],'size_bytes':d['source_size'],'etag_opaque':d['source_etag']}
   before=sess.bytes;reader=rc.SourceReader(src,sess,a.out/'sparse',pa,pq).open();positions=set();ncore=0;nr=0
   for rg,tab in reader.iter_row_groups(['address','block_number','transaction_index']):
    nr+=len(tab);matched=tab.filter(pc.equal(pc.utf8_lower(tab.column('address')),core));ncore+=len(matched)
    positions.update((int(r['block_number']),int(r['transaction_index'])) for r in matched.select(['block_number','transaction_index']).to_pylist())
   ck(nr==d['original_log_rows'],'original row count');ck(ncore==d['core_emitted_events'],'original core count');ck(len(positions)==d['distinct_core_selected_tx'],'original selected count')
   bundles=collections.defaultdict(list)
   for rg in range(reader.metadata.num_row_groups):
    keys=reader.read_row_group(rg,['block_number','transaction_index']);mask=match_positions(keys,positions,pa,pc)
    if pc.any(mask).as_py():
     for r in reader.read_row_group(rg,LC).filter(mask).to_pylist():bundles[(int(r['block_number']),int(r['transaction_index']))].append(normalize(r))
   ck(set(bundles)==positions,'missing bundle')
   log_ranges=[{k:r[k] for k in ['start','length','response_sha256']} for r in reader.ranges];shutil.rmtree(reader.directory)
   txsrc,listing=txsource(day);listings.append(listing);tr=rc.SourceReader(txsrc,sess,a.out/'sparse',pa,pq).open();txs={};nt=0
   for rg,tab in tr.iter_row_groups(['block_number','transaction_index']):
    nt+=len(tab);mask=match_positions(tab,positions,pa,pc)
    if pc.any(mask).as_py():
     for row in tr.read_row_group(rg,TC).filter(mask).to_pylist():
      key=(int(row['block_number']),int(row['transaction_index']));ck(key not in txs,'duplicate transaction');txs[key]=row
   ck(nt==tr.metadata.num_rows,'transaction coverage');ck(set(txs)==positions,'selected status missing')
   for key in sorted(positions):
    events=sorted(bundles[key],key=lambda r:r['log_index']);tx=txs[key];e=events[0];ck(tx['receipt_status']==1,'selected execution failed')
    idx=[r['log_index'] for r in events];ck(all(y==x+1 for x,y in zip(idx,idx[1:])),'gapped full bundle')
    identity={k:e[k] for k in ['block_number','block_hash','transaction_hash','transaction_index','event_time_ns']};identity['chain_id']=1
    ck(tx['hash'].lower()==identity['transaction_hash'] and tx['block_hash'].lower()==identity['block_hash'] and ts_ns(tx['block_timestamp'])==identity['event_time_ns'],'transaction log identity mismatch')
    ck(all(all(r[k]==identity[k] for k in ['block_number','block_hash','transaction_hash','transaction_index','event_time_ns']) for r in events),'mixed bundle identity')
    n=sum(r['address']==core for r in events);ck(n>0,'selected core absent')
    ob=observe(identity,events,[core],n,sha(canon(src)),sha(fb),dataset_execution_status=1)
    record={'case':CASE,'day_utc':day,'transaction':identity,'source_tier':'original_AWS_Parquet_selected_full_logs_and_transaction_receipt_status','dataset_execution_status_source':'original_AWS_transactions_receipt_status','receipt_status':1,'all_emitter_log_count':len(events),'all_emitter_logs_sha256':sha(canon(events)),'core_log_counts':{'fixed_core':n},'views':{'fixed_core':{'token_flows':ob['token_flows'],'counts':ob['counts'],'archived_core_log_count':n,'observation_sha256':sha(canon(ob))}}}
    observations.append(record);rawbundles.append({'transaction':identity,'receipt_status':1,'day_utc':day,'core_emitter':core,'events':events})
   days.append({'day':day,'status':'COMPLETE_ORIGINAL_LOG_PAYLOAD_AND_TX_STATUS','selected':len(positions),'all_emitter_logs':sum(len(x) for x in bundles.values()),'logs_source':src,'transactions_source':txsrc,'logs_ranges':log_ranges,'transaction_ranges':[{k:r[k] for k in ['start','length','response_sha256']} for r in tr.ranges],'bytes':sess.bytes-before})
   shutil.rmtree(tr.directory)
   gzsave(a.out/'raw_selected_bundles.jsonl.gz',rawbundles);gzsave(a.out/'observations.jsonl.gz',observations);save(a.out/'day_checkpoint.json',days)
   print('SOURCE_OK',day,'selected',len(positions),'total',len(observations),'bytes',sess.bytes,flush=True)
  ck(len(observations)==930 and len(days)==30,'source census total differs');sess.close('COMPLETE')
 except Exception as ex:
  failure={'type':type(ex).__name__,'reason':str(ex)}
  try:sess.close('INCOMPLETE')
  except Exception:pass
 gzsave(a.out/'raw_selected_bundles.jsonl.gz',rawbundles);gzsave(a.out/'observations.jsonl.gz',observations);save(a.out/'transaction_source_listings.json',listings)
 report={'schema':'article2_phase31_original_payload_acquisition_v1','case':CASE,'core':core,'status':'COMPLETE' if failure is None else 'INCOMPLETE','failure':failure,'frame_sha256':sha(fb),'census_batch_sha256':sha(bb),'protocol_sha256':sha((Path(__file__).parent/'PROTOCOL.md').read_bytes()),'source_tier':'original_AWS_Parquet_selected_full_logs_and_transaction_receipt_status','receipt_root_verified':False,'reference_labels_used':False,'detector_scores_computed':False,'selected_transactions':len(observations),'expected_transactions':930,'raw_bundles_sha256':sha(canon(rawbundles)),'observations_sha256':sha(canon(observations)),'days':days,'range_requests':previous['range_requests']+len(sess.requests),'range_bytes':previous['range_bytes']+sess.bytes,'new_range_requests':len(sess.requests),'new_range_bytes':sess.bytes,'previous_attempt_manifest_sha256':sha(previous_raw),'inherited_complete_days':sorted(inherited),'source_active_wall_seconds':prior_range['wall_seconds_elapsed']+json.loads((a.out/'range_capture/session.json').read_bytes())['wall_seconds_elapsed'],'protocol_amendment_sha256':sha((Path(__file__).parent/'CONTINUATION_PROTOCOL.md').read_bytes()),'continuation_limits_sha256':sha(limits_raw),'cumulative_response_byte_cap':continuation_limits['cumulative_response_bytes']}
 save(a.out/'acquisition_manifest.json',report);print('FINAL',report['status'],failure,'tx',len(observations),flush=True)
 if failure:raise SystemExit(1)
if __name__=='__main__':main()
