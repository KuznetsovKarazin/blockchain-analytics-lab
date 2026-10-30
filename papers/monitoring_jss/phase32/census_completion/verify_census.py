#!/usr/bin/env python3
"""Independent offline coordinate recount, source-provenance and catalogue audit.

No imports from the acquisition or original census implementations. Original
Parquet bytes are not distributed; source-byte-to-selection re-extraction is
explicitly outside this offline verifier's scope.
"""
from __future__ import annotations
import argparse,csv,gzip,hashlib,json,re,statistics
from collections import Counter
from datetime import date,datetime,timedelta,timezone
from pathlib import Path
import xml.etree.ElementTree as ET
BASE=Path(__file__).resolve().parent
PAPER=BASE.parents[1]
ENDPOINT='https://aws-public-blockchain.s3.us-east-2.amazonaws.com/'
COLS=['address','block_number','transaction_index']
def need(x,m):
 if not x:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):return json.loads(p.read_text())
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def save(p,x):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
def interval(w):
 start=date.fromisoformat(w['window_first']);end=date.fromisoformat(w['window_last_inclusive']);need((end-start).days==29,'30date window');return [(start+timedelta(days=i)).isoformat() for i in range(30)]
def safe(root,name):
 p=Path(name);need(not p.is_absolute() and '..' not in p.parts,'unsafe evidence path');return root/p

def verify_frame():
 freeze=read(BASE/'ACQUISITION_FREEZE.json')
 for n,h in freeze['files_sha256'].items():need(sha((BASE/n).read_bytes())==h,'frozen input changed '+n)
 f=read(BASE/'CANDIDATE_FRAME.json');w=read(BASE/'FORK_WINDOWS.json');m=read(BASE/'metadata/METADATA_AUDIT.json');mapping=read(BASE/'metadata/SOURCE_MAPPING.json')
 need(w['frame_sha256']==sha((BASE/'CANDIDATE_FRAME.json').read_bytes()),'windowframebinding')
 old=read(PAPER/'phase28/CANDIDATE_FRAME.json');old_windows=read(PAPER/'phase28/FORK_WINDOWS.json')
 need(f['old_frame_sha256']==sha((PAPER/'phase28/CANDIDATE_FRAME.json').read_bytes()),'originalframechanged')
 inventory=read(PAPER/'phase31/cohort_audit/SOURCE_INVENTORY.json')['poc_source_files']
 old_catalogue=read(PAPER/'phase31/cohort_audit/CATALOGUE_DISPOSITION.json')
 coverage=read(BASE/'CATALOGUE_COVERAGE.json')
 expected={x['source_path']:x for x in inventory};need(len(expected)==67 and sum(x['fork_rpc_alias']=='mainnet' for x in expected.values())==28,'67/28catalogue')
 ledger={x['source_path']:x for x in coverage['rows']};need(set(ledger)==set(expected),'fullcataloguecoverage')
 for n,x in ledger.items():need(all(x[k]==expected[n][k] for k in ['source_sha256','git_blob_sha1','fork_rpc_alias']),'sourceidentity '+n)
 counts=Counter(x['disposition'] for x in ledger.values());need(counts=={'OTHER_CHAIN_EXCLUDED':39,'PRIMARY_STUDY_SOURCE':4,'ORIGINAL_EXTENSION_NOMINATION':16,'NEW_EXTENSION_NOMINATION':8},'dispositions')
 for x in ledger.values():need((x['disposition']=='OTHER_CHAIN_EXCLUDED')==(x['fork_rpc_alias']!='mainnet'),'chainexclusion')
 oldfiles={x['source_path']:x['id'] for x in old['cases']};newfiles={v['source_path']:c['id'] for c in f['cases'] for v in c['source_files']}
 need(len(oldfiles)==16 and len(newfiles)==8 and not set(oldfiles)&set(newfiles),'extensionfilepartition')
 for n,cid in oldfiles.items():need(ledger[n]['case_id']==cid and ledger[n]['disposition']=='ORIGINAL_EXTENSION_NOMINATION','oldnomination')
 for n,cid in newfiles.items():need(ledger[n]['case_id']==cid and ledger[n]['disposition']=='NEW_EXTENSION_NOMINATION','newnomination')
 need(len(f['cases'])==7 and len({(x['core_address'],x['poC_fork_block']) for x in f['cases']})==7,'sevenuniqueviews')
 need(len({x['core_address'] for x in f['cases']})==6,'sixnewcores')
 need([x for b in f['batches'] for x in b]==[x['id'] for x in f['cases']] and list(map(len,f['batches']))==[2,2,2,1],'batchpartition')
 mapped={x['source_path']:x for x in mapping['rows']};blocks={x['fork_block']:x for x in m['fork_blocks']};wins={x['id']:x for x in w['results']}
 for c in f['cases']:
  for source in c['source_files']:
   x=mapped[source['source_path']];need(x['core_address']==c['core_address'] and x['fork_block']==c['poC_fork_block'] and x['source_sha256']==source['source_sha256'],'componentnomination')
  b=blocks[c['poC_fork_block']];need(wins[c['id']]['core_address']==c['core_address'] and all(wins[c['id']][k]==b[k] for k in ['fork_block','block_hash','fork_block_utc','window_first','window_last_inclusive']),'windowmetadata')
  stamp=datetime.fromisoformat(b['fork_block_utc']);need(stamp.utcoffset()==timedelta() and stamp.date().isoformat()==b['window_last_inclusive'],'UTCforkdate');interval(b)
 newkeys={(c['core_address'],d) for c in f['cases'] for d in interval(wins[c['id']])};need(len(newkeys)==183,'183uniquenewemitterdays')
 allcores={x['core_address'] for x in old['cases']+f['cases']};need(len(allcores)==22,'22totalcores')
 return f,w,old,old_windows,coverage,m

def verify_batch(folder,batch,f,w):
 x=read(folder/'source_census.json');need(x['schema']=='article2_phase32_source_census_batch_v1' and x['status']=='COMPLETE_SOURCE_CENSUS','incompletebatch')
 need(x['batch']==batch and x['complete_cases']==len(f['batches'][batch]),'batchidentity')
 for key,name in [('frame_sha256','CANDIDATE_FRAME.json'),('windows_sha256','FORK_WINDOWS.json'),('protocol_sha256','PROTOCOL.md'),('collector_sha256','source_census.py')]:need(x[key]==sha((BASE/name).read_bytes()),'acquisitioninput '+key)
 need(x['original_range_reader_sha256']==sha((PAPER/'phase16/collector/range_collector.py').read_bytes()),'rangereaderpin')
 need(x['source_traffic_label_blind'] and not x['attack_reference_join'] and not x['scores_computed'] and x['no_missing_day_imputation'],'scientificscopeflags')
 s=read(folder/'range_session/session.json');plan=read(folder/'range_session/plan.json');requests=read(folder/'range_session/requests.json');caps=plan['caps']
 need(s['status']=='COMPLETE' and s['request_count']==len(requests)==x['range_requests'],'completecapture')
 need(s['plan_canonical_sha256']==sha(canonical(plan)) and plan['endpoint']==ENDPOINT,'planbinding')
 need(plan['required_columns']=={'logs':COLS},'projection')
 need((caps['requests'],caps['total_response_bytes'],caps['wall_seconds'],caps['retries'],caps['concurrency'])==(1000,1400000000,1000,0,1),'resourcecaps')
 need(len(requests)<=1000 and s['wall_seconds_elapsed']<1000 and s['retries']==0 and not s['cache_or_full_object_reuses'],'resources')
 need(x['range_session_sha256']==sha((folder/'range_session/session.json').read_bytes()) and x['range_receipts_sha256']==sha((folder/'range_session/requests.json').read_bytes()),'capturehash')
 total=sum(r['response_bytes'] for r in requests);need(total==s['retained_response_bytes']==x['range_response_bytes'] and total<=1400000000,'responsebytes')
 receipt={r['ordinal']:r for r in requests};need(sorted(receipt)==list(range(1,len(requests)+1)),'receiptsequence')
 for r in requests:
  source=r['source'];start=r['start'];length=r['length'];size=source['size_bytes'];need(r['transport_ok'] and r['http_status']==206 and r['response_bytes']==length and 0<=start<start+length<=size,'rangetransport')
  need(r['response_url']==source['url']==ENDPOINT+source['key'] and r['etag']==source['etag_opaque'],'rangeidentity')
  need(r['request_headers']['If-Match']==r['etag'] and r['request_headers']['Range']==f'bytes={start}-{start+length-1}' and r['content_range']==f'bytes {start}-{start+length-1}/{size}' and int(r['content_length'])==length and r['content_encoding'] in [None,'identity'],'rangeheaders')
  need(re.fullmatch('[0-9a-f]{64}',r['response_sha256']) and not r['invalid_header_body_read'],'rangehashsyntax')
 need(datetime.fromisoformat(s['started_utc'])>datetime.fromisoformat(f['frozen_utc']),'acquisitionprecededfreeze')
 cases={c['id']:c for c in f['cases']};wins={c['id']:c for c in w['results']};selected=f['batches'][batch]
 expected_days=sorted({d for cid in selected for d in interval(wins[cid])});need([d['day'] for d in x['source_days']]==expected_days,'completeuniquesourcedays')
 source_by_day={d['day']:d for d in x['source_days']};used=set();listingbytes=0
 for day,source_day in source_by_day.items():
  source=source_day['source'];need(source['day_utc']==day and source['table']=='logs' and source['key'].startswith(f'v1.0/eth/logs/date={day}/'),'sourcedate')
  active=[cid for cid in selected if day in interval(wins[cid])];need(source_day['active_cases']==active,'activecaseassignment')
  l=source_day['listing_receipt'];lb=safe(folder,l['path']).read_bytes();need(sha(lb)==l['sha256'] and len(lb)==l['bytes']<=300000 and l['http_status']==200,'listingreceipt');listingbytes+=len(lb)
  xml=ET.fromstring(lb)
  def field(n,k):return next((c.text for c in n if c.tag.rsplit('}',1)[-1]==k),None)
  need(field(xml,'IsTruncated')=='false','truncatedlisting');contents=[n for n in xml if n.tag.rsplit('}',1)[-1]=='Contents'];need(len(contents)==1,'sourceinventory')
  need(field(contents[0],'Key')==source['key'] and int(field(contents[0],'Size'))==source['size_bytes'] and field(contents[0],'ETag')==source['etag_opaque'],'listingobjectidentity')
  pp=safe(folder,source_day['source_manifest_path']);need(sha(pp.read_bytes())==source_day['source_manifest_sha256'],'proofhash');proof=read(pp)
  normalized={**source,'url':ENDPOINT+source['key']};need(proof['source']==normalized and proof['source_id']==sha(canonical(normalized)),'proofsource')
  nr=proof['row_group_count'];rows=proof['row_group_rows'];need(nr==len(rows)==source_day['row_groups'] and sum(rows)==proof['row_count_metadata']==source_day['original_log_rows'],'rowcoverage')
  reads=proof['read_projections'];need(len(reads)==nr and [z['row_group'] for z in reads]==list(range(nr)) and all(z['columns']==COLS and z['rows']==rows[z['row_group']] for z in reads),'allrowgroupsprojected')
  chunks=proof['column_chunks'];need(len(chunks)==3*nr and {(z['row_group'],z['column']) for z in chunks}=={(g,c) for g in range(nr) for c in COLS} and all(z['acquired'] for z in chunks),'allcolumnsacquired')
  ranges=proof['successful_original_ranges'];need(source_day['http_ranges']==len(ranges) and source_day['response_bytes']==sum(z['response_bytes'] for z in ranges),'dayresources')
  spans=[]
  for z in ranges:
   ordinal=z['ordinal'];need(ordinal not in used and receipt[ordinal]==z and z['source']==normalized,'proofreceiptmembership');used.add(ordinal);spans.append((z['start'],z['start']+z['length']))
  spans.sort();need(all(spans[i][1]<=spans[i+1][0] for i in range(len(spans)-1)),'overlappingranges')
  need(sum(b-a for a,b in spans)==proof['available_original_bytes'],'availablebytecount')
  for ch in chunks:
   cursor=ch['start'];end=ch['end_exclusive'];need(end-cursor==ch['compressed_bytes']>0,'chunkbound')
   for a,b in spans:
    if a<=cursor<b:cursor=b
   need(cursor>=end,'unbackedcolumnchunk')
  need(not proof['holes_are_original_bytes'] and not proof['statistics_values_exported_or_used'] and not proof['receipt_roots_verified'],'sourceclaimscope')
 need(used==set(receipt) and listingbytes==x['listing_response_bytes'],'unattributedsourcecost')
 need([c['id'] for c in x['case_results']]==selected,'resultcaseorder');daily=[];case_rows=[]
 for c in x['case_results']:
  target=cases[c['id']];win=wins[c['id']];need(c['status']=='COMPLETE_SOURCE_CENSUS_NOT_DETECTOR_ADMITTED' and c['core_address']==target['core_address'] and c['poC_fork_block']==target['poC_fork_block'],'casebinding')
  need(c['window_first']==win['window_first'] and c['window_last_inclusive']==win['window_last_inclusive'] and [r['day'] for r in c['days']]==interval(win),'casewindow')
  for r in c['days']:
   need(r['status']=='COMPLETE_ORIGINAL_PROJECTED_SOURCE' and r['source_capture_day']==r['day'] and c['id'] in source_by_day[r['day']]['active_cases'],'dailyacceptance')
   pp=safe(folder,r['selected_coordinates_path']);compressed=pp.read_bytes();need(sha(compressed)==r['selected_coordinates_sha256'],'coordinatescompressedhash');raw=gzip.decompress(compressed);need(sha(raw)==r['selected_coordinates_plain_sha256'],'coordinatesplainhash');coords=json.loads(raw)
   need(all(type(z)is list and len(z)==2 and all(type(v)is int and v>=0 for v in z) for z in coords),'coordinateformat')
   tuples=[tuple(z) for z in coords];need(tuples==sorted(set(tuples)) and len(tuples)==r['distinct_core_selected_tx']<=r['core_emitted_events']<=source_by_day[r['day']]['original_log_rows'],'coordinatecount')
   need(f"/{c['core_address']}/" in '/'+r['selected_coordinates_path'] and pp.name==r['day']+'.json.gz','coordinatefilebinding')
   daily.append({'id':c['id'],'family':c['family'],'core_address':c['core_address'],'day':r['day'],'tx':len(tuples),'core_events':r['core_emitted_events'],'cohort':'completion','source_key':source_by_day[r['day']]['source']['key']})
  nums=[r['distinct_core_selected_tx'] for r in c['days']];expected={'days':30,'total_distinct_selected_tx':sum(nums),'total_core_emitted_events':sum(r['core_emitted_events'] for r in c['days']),'days_lt20':sum(n<20 for n in nums),'days_ge20':sum(n>=20 for n in nums),'days_zero':sum(n==0 for n in nums),'days_positive_lt20':sum(0<n<20 for n in nums),'median_tx_per_day':statistics.median(nums),'max_tx_per_day':max(nums)};need(c['summary']==expected,'casemath')
  case_rows.append({'id':c['id'],'family':c['family'],'core_address':c['core_address'],'fork_block':c['poC_fork_block'],'first':c['window_first'],'last':c['window_last_inclusive'],**expected})
 return daily,case_rows,{'batch':batch,'source_days':len(expected_days),'range_requests':len(requests),'range_response_bytes':total,'listing_response_bytes':listingbytes,'selected_coordinate_files':len({r['selected_coordinates_path'] for c in x['case_results'] for r in c['days']}),'source_census_sha256':sha((folder/'source_census.json').read_bytes())}

def summary(rows):
 counts=[r['tx'] for r in rows];nonempty=sum(n>0 for n in counts);low=sum(0<n<20 for n in counts)
 return {'emitter_days':len(rows),'zero_days':sum(n==0 for n in counts),'nonempty_days':nonempty,'nonempty_below20_days':low,'nonempty_below20_fraction':low/nonempty if nonempty else None,'below20_days':sum(n<20 for n in counts),'ge20_days':sum(n>=20 for n in counts),'selected_transaction_observations':sum(counts),'core_emitted_events':sum(r['core_events'] for r in rows)}
def csv_write(p,rows):
 with p.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator='\n');w.writeheader();w.writerows(rows)
def main():
 p=argparse.ArgumentParser();p.add_argument('--results',type=Path,default=BASE/'results');p.add_argument('--out',type=Path,default=BASE/'audit');a=p.parse_args();f,w,old,ow,coverage,meta=verify_frame()
 daily=[];case_rows=[];batches=[]
 for b in range(4):
  d,c,r=verify_batch(a.results/f'batch_{b}',b,f,w);daily+=d;case_rows+=c;batches.append(r)
 need(len(daily)==210 and len(case_rows)==7,'allnewcases')
 old_by_id={x['id']:x for x in old['cases']};oldwins={x['id']:x for x in ow['results']};old_daily=[]
 for r in csv.DictReader((PAPER/'phase28/results/CENSUS_DAILY.csv').open()):
  c=old_by_id[r['id']];need(r['day'] in interval(oldwins[r['id']]),'oldwindow');tx=int(r['tx']);events=int(r['core_events']);need(0<=tx<=events,'oldcounts')
  old_daily.append({'id':r['id'],'family':c['family'],'core_address':c['core_address'],'day':r['day'],'tx':tx,'core_events':events,'cohort':'original16','source_key':r['original_source']})
 need(len(old_daily)==480 and Counter(x['id'] for x in old_daily)=={k:30 for k in old_by_id},'oldcomplete480')
 oldsum=summary(old_daily);need((oldsum['selected_transaction_observations'],oldsum['zero_days'],oldsum['nonempty_days'],oldsum['nonempty_below20_days'])==(44780,302,178,108),'oldbaseline')
 allrows=old_daily+daily;unique={};overlaps=[]
 for r in allrows:
  key=(r['core_address'],r['day'])
  if key in unique:
   prev=unique[key];need(all(r[k]==prev[k] for k in ['tx','core_events','source_key']),'overlappingwindowcountsdisagree');overlaps.append({'core_address':key[0],'day':key[1],'first_view':prev['id'],'second_view':r['id']})
  else:unique[key]=r
 unique_rows=[unique[k] for k in sorted(unique)];need(len(allrows)==690 and len(unique_rows)==663 and len(overlaps)==27,'deduplication')
 creation_old=read(PAPER/'phase31/cohort_audit/deployment/DEPLOYMENT_AUDIT.json');need(creation_old['complete'] and creation_old['accepted']==16,'oldcreationmetadata')
 creations={r['core_address']:r['creation_utc_day'] for r in creation_old['cases']};creations.update({r['core_address']:r['creation_utc_day'] for r in meta['contract_creations']});need(len(creations)==22,'22creations')
 pre=[r for r in unique_rows if r['day']<creations[r['core_address']]];partial=[r for r in unique_rows if r['day']==creations[r['core_address']]];after=[r for r in unique_rows if r['day']>creations[r['core_address']]]
 need(all(r['tx']==0 for r in pre),'predeploymentemissionconflict');need(len(pre)==214 and len(partial)==10 and len(after)==439,'deploymentdenominators')
 newunique=[r for r in unique_rows if r['cohort']=='completion'];need(len(newunique)==183,'newuniquedays')
 report={'schema':'phase32_catalogue_completion_independent_audit_v1','status':'PASS','network_requests':0,'catalogue_coverage':{k:coverage[k] for k in ['catalogue_files','ethereum_files','extension_source_files','extension_unique_windows','extension_unique_core_addresses','counts']},'new_cases':case_rows,'batches':batches,'original16':oldsum,'new7_window_weighted':summary(daily),'new6_unique_emitter_days':summary(newunique),'extended23_window_weighted':summary(allrows),'extended22_unique_emitter_days':summary(unique_rows),'duplicate_circle_days':overlaps,'deployment_sensitivity':{'strictly_predeployment':summary(pre),'partial_creation_dates':summary(partial),'including_partial_creation_dates':summary(partial+after),'fully_after_creation_date':summary(after)},'inputs_sha256':{'CANDIDATE_FRAME.json':sha((BASE/'CANDIDATE_FRAME.json').read_bytes()),'FORK_WINDOWS.json':sha((BASE/'FORK_WINDOWS.json').read_bytes()),'CATALOGUE_COVERAGE.json':sha((BASE/'CATALOGUE_COVERAGE.json').read_bytes()),'metadata/METADATA_AUDIT.json':sha((BASE/'metadata/METADATA_AUDIT.json').read_bytes()),'old_daily_csv':sha((PAPER/'phase28/results/CENSUS_DAILY.csv').read_bytes()),'verifier':sha(Path(__file__).read_bytes())},'limits':['Complete source-file coverage within one pinned seven-directory catalogue is not population coverage of Ethereum incidents.','Operational component nominations remain investigator-informed; fork-date windows are not attack-time histories.','Offline checks independently recount retained selected coordinates and reconcile source/listing/range/coverage evidence; original Parquet byte-to-selection re-extraction requires online acquisition.','Source range hashes are not receipt-root authentication; no attack labels or detector scores were evaluated.']}
 a.out.mkdir(parents=True,exist_ok=True);save(a.out/'CENSUS_AUDIT.json',report);csv_write(a.out/'NEW_CASES.csv',case_rows);csv_write(a.out/'COMBINED_WINDOW_DAILY.csv',allrows);csv_write(a.out/'COMBINED_UNIQUE_EMITTER_DAILY.csv',unique_rows)
 print(json.dumps({'status':'PASS','primary_unique_emitter_days':report['extended22_unique_emitter_days'],'new_case_counts':[(c['id'],c['total_distinct_selected_tx']) for c in case_rows]},sort_keys=True))
if __name__=='__main__':main()
