#!/usr/bin/env python3
"""Frozen original-Parquet census; shared source dates, no attack labels or scores."""
from __future__ import annotations
import argparse,gzip,hashlib,json,shutil,statistics,sys,urllib.parse,urllib.request
import xml.etree.ElementTree as ET
from datetime import date,timedelta,datetime,timezone
from pathlib import Path
BASE=Path(__file__).resolve().parent
PAPER=BASE.parents[1]
COLUMNS=['address','block_number','transaction_index']
def need(x,m):
 if not x:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def save(p,x):
 p.parent.mkdir(parents=True,exist_ok=True);tmp=p.with_name(p.name+'.pending');tmp.write_text(json.dumps(x,indent=2,sort_keys=True)+'\n');tmp.replace(p)
def dates(w):
 a=date.fromisoformat(w['window_first']);b=date.fromisoformat(w['window_last_inclusive']);need((b-a).days==29,'not30days');return [(a+timedelta(days=i)).isoformat() for i in range(30)]
def listing(rc,day,out):
 prefix=f'v1.0/eth/logs/date={day}/';url=rc.ENDPOINT+'?'+urllib.parse.urlencode({'list-type':'2','prefix':prefix,'max-keys':'100'})
 req=urllib.request.Request(url,headers={'User-Agent':'article2-phase32-catalogue-census/1.0'})
 started=datetime.now(timezone.utc).isoformat()
 with urllib.request.urlopen(req,timeout=18) as r:
  need(r.status==200,'listing HTTP');body=r.read(300001);need(len(body)<=300000,'listing size')
 root=ET.fromstring(body)
 def field(node,name):return next((c.text for c in node if c.tag.rsplit('}',1)[-1]==name),None)
 need(field(root,'IsTruncated')=='false','truncated listing')
 objects=[x for x in root if x.tag.rsplit('}',1)[-1]=='Contents'];need(len(objects)==1,'require1original daily part')
 key=field(objects[0],'Key');size=int(field(objects[0],'Size'));etag=field(objects[0],'ETag')
 need(key.startswith(prefix) and key.endswith('.snappy.parquet') and 10000<size<800000000 and etag,'source binding')
 path=out/'listings'/f'{day}.xml';path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body)
 receipt={'url':url,'http_status':200,'started_utc':started,'bytes':len(body),'sha256':sha(body),'path':str(path.relative_to(out))}
 source={'table':'logs','day_utc':day,'key':key,'size_bytes':size,'etag_opaque':etag}
 return source,receipt

def main():
 p=argparse.ArgumentParser();p.add_argument('--batch',type=int,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 fb=(BASE/'CANDIDATE_FRAME.json').read_bytes();wb=(BASE/'FORK_WINDOWS.json').read_bytes();f=json.loads(fb);w=json.loads(wb)
 need(f['schema']=='article2_phase32_catalogue_completion_frame_v1' and len(f['cases'])==7,'frame')
 need(w['frame_sha256']==sha(fb) and w['complete']==7,'window binding');need(0<=a.batch<len(f['batches']),'batch')
 ids=f['batches'][a.batch];cases=[x for x in f['cases'] if x['id'] in ids];need([x['id'] for x in cases]==ids,'batchorder')
 wins={x['id']:x for x in w['results']};case_dates={c['id']:dates(wins[c['id']]) for c in cases};days=sorted(set(d for v in case_dates.values() for d in v))
 sys.path.insert(0,str(PAPER/'phase16/collector'));import range_collector as rc
 import pyarrow as pa,pyarrow.parquet as pq,pyarrow.compute as pc
 need(pa.__version__=='19.0.1','decoder version differs')
 a.output.mkdir(parents=True,exist_ok=False)
 plan={'schema_version':'article2_phase16_range_source_plan_v1','endpoint':rc.ENDPOINT,'caps':{'requests':1000,'total_response_bytes':1400000000,'wall_seconds':1000,'request_timeout_seconds':35,'max_range_bytes':18000000,'max_footer_bytes':1000000,'max_rows':7000000,'max_row_groups':64,'max_top_level_columns':60,'max_leaf_columns':80,'max_source_bytes':800000000,'retries':0,'concurrency':1},'required_columns':{'logs':COLUMNS}}
 result={'schema':'article2_phase32_source_census_batch_v1','batch':a.batch,'frame_sha256':sha(fb),'windows_sha256':sha(wb),'protocol_sha256':sha((BASE/'PROTOCOL.md').read_bytes()),'collector_sha256':sha(Path(__file__).read_bytes()),'original_range_reader_sha256':sha((PAPER/'phase16/collector/range_collector.py').read_bytes()),'status':'INCOMPLETE','source_tier':'original_S3_address_block_tx_index_projected_all_rowgroups','source_traffic_label_blind':True,'attack_reference_join':False,'scores_computed':False,'no_missing_day_imputation':True,'source_days':[],'case_results':[{'id':c['id'],'family':c['family'],'core_address':c['core_address'],'poC_fork_block':c['poC_fork_block'],'window_first':wins[c['id']]['window_first'],'window_last_inclusive':wins[c['id']]['window_last_inclusive'],'days':[],'status':'INCOMPLETE'} for c in cases]}
 by_id={c['id']:c for c in result['case_results']};session=rc.RangeSession(plan,a.output/'range_session')
 try:
  for day in days:
   active=[c for c in cases if day in case_dates[c['id']]];cores=sorted({c['core_address'] for c in active});source,receipt=listing(rc,day,a.output)
   n0=len(session.requests);b0=session.bytes
   reader=rc.SourceReader(source,session,a.output/'sparse',pa,pq).open();seen={x:set() for x in cores};events={x:0 for x in cores};rows=0
   for group,tab in reader.iter_row_groups(COLUMNS):
    rows+=len(tab);addrs=pc.utf8_lower(tab.column('address'))
    for core in cores:
     matched=tab.filter(pc.equal(addrs,core)).select(['block_number','transaction_index']);events[core]+=matched.num_rows
     for row in matched.to_pylist():
      b,i=row['block_number'],row['transaction_index'];need(type(b)is int and type(i)is int and b>=0 and i>=0,'invalidcoordinates');seen[core].add((b,i))
   need(rows==reader.metadata.num_rows,'incomplete rows')
   proof=reader.manifest();proofpath=a.output/'source_manifests'/f'{day}.json';save(proofpath,proof)
   source_day={'day':day,'source':source,'listing_receipt':receipt,'original_log_rows':rows,'row_groups':reader.metadata.num_row_groups,'source_manifest_path':str(proofpath.relative_to(a.output)),'source_manifest_sha256':sha(proofpath.read_bytes()),'http_ranges':len(session.requests)-n0,'response_bytes':session.bytes-b0,'active_cases':[c['id'] for c in active]}
   result['source_days'].append(source_day)
   for core in cores:
    need(len(seen[core])<=events[core],'selected exceedslogs');coords=sorted(seen[core]);raw=(json.dumps(coords,separators=(',',':'))+'\n').encode();path=a.output/'selected_coordinates'/core/f'{day}.json.gz';path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(gzip.compress(raw,mtime=0))
    row={'day':day,'status':'COMPLETE_ORIGINAL_PROJECTED_SOURCE','core_emitted_events':events[core],'distinct_core_selected_tx':len(coords),'selected_coordinates_path':str(path.relative_to(a.output)),'selected_coordinates_sha256':sha(path.read_bytes()),'selected_coordinates_plain_sha256':sha(raw),'source_capture_day':day}
    for c in active:
     if c['core_address']==core:by_id[c['id']]['days'].append(dict(row))
   print('COMPLETE',a.batch,day,[(x,len(seen[x]),events[x]) for x in cores],flush=True)
   save(a.output/'source_census.json',result)
   shutil.rmtree(reader.directory)
  for c in result['case_results']:
   need([x['day'] for x in c['days']]==case_dates[c['id']],'missingdates');nums=[x['distinct_core_selected_tx'] for x in c['days']]
   c['summary']={'days':30,'total_distinct_selected_tx':sum(nums),'total_core_emitted_events':sum(x['core_emitted_events'] for x in c['days']),'days_lt20':sum(n<20 for n in nums),'days_ge20':sum(n>=20 for n in nums),'days_zero':sum(n==0 for n in nums),'days_positive_lt20':sum(0<n<20 for n in nums),'median_tx_per_day':statistics.median(nums),'max_tx_per_day':max(nums)}
   c['status']='COMPLETE_SOURCE_CENSUS_NOT_DETECTOR_ADMITTED'
  result['status']='COMPLETE_SOURCE_CENSUS';result['complete_cases']=len(cases)
 except Exception as e:
  result['error']=type(e).__name__+': '+str(e);print('FAILED',result['error'],flush=True)
 finally:
  session.close('COMPLETE' if result['status']=='COMPLETE_SOURCE_CENSUS' else 'INCOMPLETE')
  result['range_requests']=len(session.requests);result['range_response_bytes']=session.bytes;result['listing_response_bytes']=sum(x['listing_receipt']['bytes'] for x in result['source_days']);result['range_session_sha256']=sha((a.output/'range_session/session.json').read_bytes());result['range_receipts_sha256']=sha((a.output/'range_session/requests.json').read_bytes());save(a.output/'source_census.json',result)
  print('FINAL',a.batch,result['status'],len(session.requests),session.bytes,flush=True)
 if result['status']!='COMPLETE_SOURCE_CENSUS':raise SystemExit(2)
if __name__=='__main__':main()
