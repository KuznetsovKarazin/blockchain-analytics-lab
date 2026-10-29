#!/usr/bin/env python3
"""Retain full Blockscout response bytes and selected log payloads, label-free.

Resumes from verified per-transaction bundles and a hash-chained HTTP ledger.
No detector or attack-reference module is imported. --verify-only is offline.
"""
from __future__ import annotations
import argparse, collections, datetime, gzip, hashlib, json, re, sys, time
import urllib.error, urllib.parse, urllib.request
from pathlib import Path
from types import SimpleNamespace
PAPER=Path(__file__).resolve().parents[2]
for p in ('phase22','phase29','phase15/adapter'):sys.path.insert(0,str(PAPER/p))
import phase22_indexed_bundles as old
from indexed_selected_bundles import source_bounded_logs
CASES=('cohort28_07','cohort28_11','cohort28_14')
HEADERS={'User-Agent':'article2-indexed-creation-audit/1.0','Accept':'application/json'}
TRANSFER='0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
ZERO='0x'+'0'*40

def need(ok,msg):
 if not ok:raise AssertionError(msg)
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def sha(x):return hashlib.sha256(x).hexdigest()
def save(path,x):
 tmp=path.with_suffix(path.suffix+'.tmp');tmp.write_bytes(canon(x)+b'\n');tmp.replace(path)
def gzwrite(path,raw):
 path.parent.mkdir(parents=True,exist_ok=True);tmp=path.with_suffix(path.suffix+'.tmp')
 with tmp.open('wb') as f:
  with gzip.GzipFile(fileobj=f,filename='',mode='wb',mtime=0) as g:g.write(raw)
 tmp.replace(path)
def gzread(path):
 with gzip.open(path,'rb') as f:return f.read()
def lines(path):return [json.loads(x) for x in gzread(path).splitlines() if x.strip()]
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()

def independent_features(rows,core):
 counts=dict(logs=len(rows),erc20_shaped=0,erc721_shaped=0,opaque=0,monitored_erc20_shaped=0,zero_value_transfers=0);flows={}
 for r in rows:
  t=r['topics'];d=r['data']
  need(len(t)<=4 and all(re.fullmatch(r'0x[0-9a-f]{64}',x) for x in t),'bad topics')
  need(re.fullmatch(r'0x(?:[0-9a-f]{2})*',d),'bad data')
  if not t or t[0]!=TRANSFER:counts['opaque']+=1;continue
  need(len(t) in (3,4) and all(x[2:26]=='0'*24 for x in t[1:3]),'unsupported Transfer shape')
  if len(t)==4:need(d=='0x','bad ERC721 shape');counts['erc721_shaped']+=1;continue
  need(len(d)==66,'bad ERC20 shape');counts['erc20_shaped']+=1
  value=int(d,16);sender='0x'+t[1][-40:];recipient='0x'+t[2][-40:]
  counts['zero_value_transfers']+=int(value==0)
  if sender!=core and recipient!=core:continue
  counts['monitored_erc20_shaped']+=1;token=r['address']
  if token not in flows:
   flows[token]={'chain_id':1,'token_address':token,'transfer_log_count':0}
   flows[token].update({kind+suffix:0 for kind in ('external_in','external_out','internal','mint_from_zero','burn_to_zero') for suffix in ('_raw','_count')})
  f=flows[token]
  category=('internal' if sender==recipient==core else 'mint_from_zero' if sender==ZERO else
            'burn_to_zero' if recipient==ZERO else 'external_in' if recipient==core else 'external_out')
  f[category+'_raw']+=value;f[category+'_count']+=1;f['transfer_log_count']+=1
 for f in flows.values():
  f['net_external_in_raw']=f['external_in_raw']-f['external_out_raw']
  f['net_event_in_raw']=f['net_external_in_raw']+f['mint_from_zero_raw']-f['burn_to_zero_raw']
  for key in f:
   if key.endswith('_raw'):f[key]=str(f[key])
 return counts,[flows[x] for x in sorted(flows)]

def load_inputs():
 all_cases={};pins={}
 framepath=PAPER/'phase28/CANDIDATE_FRAME.json';frame=json.loads(framepath.read_bytes());pins[str(framepath.relative_to(PAPER))]=sha(framepath.read_bytes())
 for case in CASES:
  srcdir=PAPER/'phase30/data'/case;idxdir=PAPER/'phase30/indexed'/case
  man=json.loads((srcdir/'source_identity_manifest.json').read_bytes());im=json.loads((idxdir/'acquisition_manifest.json').read_bytes())
  ids=lines(srcdir/'selected_tx_identities.jsonl.gz');features=lines(idxdir/'indexer_observations.jsonl.gz')
  need(man['status']=='COMPLETE_SOURCE_ONLY' and im['status']=='COMPLETE_INDEXED_SOURCE_MATCHED','incomplete baseline')
  need(sha(canon(ids))==man['ids_sha256'] and sha(canon(features))==im['indexed_rows_sha256'],'baseline digest')
  need(len(ids)==len(features)==man['transaction_count']==im['processed'],'baseline count')
  core=next(x['core_address'] for x in frame['cases'] if x['id']==case)
  need(core==man['core_emitter'],'baseline core');need(man['frame_sha256']==sha(framepath.read_bytes()),'baseline frame')
  all_cases[case]={'ids':ids,'features':dict((r['transaction']['transaction_hash'],r) for r in features),'core':core}
  for path in (srcdir/'source_identity_manifest.json',srcdir/'selected_tx_identities.jsonl.gz',idxdir/'acquisition_manifest.json',idxdir/'indexer_observations.jsonl.gz'):
   pins[str(path.relative_to(PAPER))]=sha(path.read_bytes())
 need(sum(len(v['ids']) for v in all_cases.values())==125,'expected125')
 return all_cases,pins

class Capture:
 def __init__(self,out,max_requests,max_bytes,wall_seconds,offline=False):
  self.out=out;self.out.mkdir(parents=True,exist_ok=True);self.ledger=out/'http_receipts.jsonl';self.receipts=[]
  self.start=time.monotonic();self.max_requests=max_requests;self.max_bytes=max_bytes;self.wall_seconds=wall_seconds;self.bytes=0;self.offline=offline
  previous='0'*64
  if self.ledger.exists():
   for line in self.ledger.read_bytes().splitlines():
    r=json.loads(line);digest=r.pop('chain_sha256');need(r['previous_sha256']==previous and sha(canon(r))==digest,'receipt chain conflict');r['chain_sha256']=digest
    need(r['sequence']==len(self.receipts)+1,'receipt sequence');raw=gzread(out/r['response_file'])
    need(sha(raw)==r['response_sha256'] and len(raw)==r['response_bytes'],'receipt raw body conflict')
    self.receipts.append(r);self.bytes+=len(raw);previous=digest
 def fetch(self,url,_log=None,_limits=None):
  need(not self.offline,'network request during offline verify')
  for attempt in range(3):
   need(len(self.receipts)<self.max_requests and self.bytes<self.max_bytes and time.monotonic()-self.start<self.wall_seconds,'acquisition bound exhausted')
   status=None;error=None;raw=b''
   try:
    with urllib.request.urlopen(urllib.request.Request(url,headers=HEADERS),timeout=25) as response:
     status=response.status;raw=response.read(2200001)
   except urllib.error.HTTPError as exc:status=exc.code;error=type(exc).__name__;raw=exc.read(2200001)
   except (urllib.error.URLError,TimeoutError) as exc:error=type(exc).__name__
   sequence=len(self.receipts)+1;relative=f'responses/{sequence:06d}.json.gz'
   gzwrite(self.out/relative,raw);self.bytes+=len(raw)
   r={'sequence':sequence,'url':url,'attempt':attempt+1,'retrieved_at_utc':utc(),'status':status,'error':error,
      'response_file':relative,'response_bytes':len(raw),'response_sha256':sha(raw),
      'previous_sha256':self.receipts[-1]['chain_sha256'] if self.receipts else '0'*64}
   r['chain_sha256']=sha(canon(r))
   with self.ledger.open('ab') as f:f.write(canon(r)+b'\n');f.flush()
   self.receipts.append(r)
   need(len(raw)<=2200000 and self.bytes<=self.max_bytes,'body byte bound')
   if status==200:return json.loads(raw)
   if status not in (None,429,500,502,503,504):raise RuntimeError(f'HTTP {status} {url}')
   if attempt<2:time.sleep(2**attempt)
  raise RuntimeError(f'transient request failed after three attempts: {url}')
 def body(self,sequence):
  r=self.receipts[sequence-1];need(r['status']==200,'bundle uses failed response')
  return json.loads(gzread(self.out/r['response_file']))

def expected(src,case):return {**src,'case':case,'all_emitter_log_count':src['all_emitter_logs'],'core_log_counts':{'fixed_core':src['core_emitter_logs']}}

def check_bundle(bundle,src,case,core,frozen,capture):
 need(bundle['case']==case and bundle['expected']==expected(src,case),'bundle source identity')
 meta_sequence=bundle['metadata_receipt'];meta=capture.body(meta_sequence);meta_receipt=capture.receipts[meta_sequence-1]
 need(meta_receipt['url']==old.BASE+src['transaction_hash'],'metadata endpoint')
 need(meta==bundle['transaction_metadata'],'metadata differs from retained HTTP body')
 need(meta['hash'].lower()==src['transaction_hash'] and meta['status']=='ok','success/tx mismatch')
 need(meta['block_number']==src['block_number'] and meta['position']==src['transaction_index'] and old.parse_time(meta['timestamp'])==src['event_time_ns'],'metadata/source mismatch')
 log_items=[];cursor=None
 for sequence in bundle['log_page_receipts']:
  r=capture.receipts[sequence-1];url=old.BASE+src['transaction_hash']+'/logs'
  if cursor:url+='?'+urllib.parse.urlencode(cursor)
  need(r['url']==url,'retained pagination URL mismatch');payload=capture.body(sequence)
  need(isinstance(payload.get('items'),list) and payload['items'],'empty log page');log_items.extend(payload['items']);cursor=payload.get('next_page_params')
 need(cursor is None,'incomplete retained pagination')
 normalized=old.normalized_indexed_rows(log_items,expected(src,case));need(normalized==bundle['normalized_events'],'raw HTTP normalization differs')
 need(sha(canon(normalized))==frozen['all_emitter_logs_sha256']==bundle['normalized_events_sha256'],'historical full payload digest mismatch')
 feature=old.feature_record(normalized,expected(src,case),{'fixed_core':core});frozen_without_pages={k:v for k,v in frozen.items() if k!='indexed_pages'}
 need(feature==frozen_without_pages,'re-extracted frozen feature field differs')
 counts,flows=independent_features(normalized,core)
 need(counts==feature['views']['fixed_core']['counts'] and flows==feature['views']['fixed_core']['token_flows'],'independent counts/flows differ')
 return {'case':case,'tx':src['transaction_hash'],'all_emitter_logs':len(normalized),'normalized_events_sha256':sha(canon(normalized)),
         'historical_payload_digest_match':True,'all_frozen_feature_fields_match':True,'independent_event_counts_and_flows_match':True,'receipt_status':'ok'}

def run():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=Path(__file__).resolve().parent/'data');p.add_argument('--verify-only',action='store_true');p.add_argument('--case',choices=CASES);p.add_argument('--max-requests',type=int,default=1200);p.add_argument('--max-bytes',type=int,default=100000000);p.add_argument('--wall-seconds',type=int,default=1800);args=p.parse_args()
 args.out.mkdir(parents=True,exist_ok=True);cases,pins=load_inputs();cases={k:v for k,v in cases.items() if args.case is None or k==args.case};expected_total=sum(len(x['ids']) for x in cases.values());capture=Capture(args.out,args.max_requests,args.max_bytes,args.wall_seconds,args.verify_only)
 matched=[];failure=None
 def manifest():
  state={'schema':'article2_phase31_phase30_raw_payload_recovery_v1','status':'COMPLETE' if len(matched)==expected_total and failure is None else 'INCOMPLETE',
         'expected_transactions':expected_total,'case_scope':list(cases),'verified_transactions':len(matched),'all_emitter_logs':sum(x['all_emitter_logs'] for x in matched),
         'case_transaction_counts':dict(collections.Counter(x['case'] for x in matched)),'failure':failure,
         'source_tier':'AWS_selected_identities_and_counts_plus_retained_Blockscout_full_response_bytes_logs_and_status',
         'receipt_root_authenticated':False,'original_AWS_topics_data_reacquired':False,'attack_references_read':False,'detector_scoring_performed':False,
         'baseline_input_sha256':pins,'response_count':len(capture.receipts),'response_bytes':capture.bytes,
         'response_chain_head':capture.receipts[-1]['chain_sha256'] if capture.receipts else '0'*64,
         'transaction_verification':matched}
  save(args.out/('offline_verification.json' if args.verify_only else 'acquisition_manifest.json'),state)
  return state
 try:
  for case,item in cases.items():
   for src in item['ids']:
    need(not (args.out/'STOP').exists(),'cooperative pause requested; resumable data retained')
    txid=src['transaction_hash'];path=args.out/'bundles'/case/(txid+'.json.gz')
    if path.exists():bundle=json.loads(gzread(path))
    else:
     need(not args.verify_only,f'missing retained bundle {case}/{txid}')
     meta=capture.fetch(old.BASE+txid);metadata_sequence=len(capture.receipts)
     need(meta['hash'].lower()==txid and meta['status']=='ok','not successful selected tx')
     first_log_sequence=len(capture.receipts)+1
     shim=SimpleNamespace(BASE=old.BASE,fetch_json=capture.fetch)
     raw,pages=source_bounded_logs(txid,src['all_emitter_logs'],[],{},shim)
     log_sequences=[r['sequence'] for r in capture.receipts[first_log_sequence-1:] if r['status']==200]
     normalized=old.normalized_indexed_rows(raw,expected(src,case))
     bundle={'case':case,'expected':expected(src,case),'transaction_metadata':meta,'metadata_receipt':metadata_sequence,
             'log_page_receipts':log_sequences,'normalized_events':normalized,'normalized_events_sha256':sha(canon(normalized))}
     # Verify before accepting a durable per-transaction bundle.
     check_bundle(bundle,src,case,item['core'],item['features'][txid],capture);gzwrite(path,canon(bundle)+b'\n')
     time.sleep(.16)
    matched.append(check_bundle(bundle,src,case,item['core'],item['features'][txid],capture))
    if len(matched)%10==0:print('VERIFIED',len(matched),'/',expected_total,'requests',len(capture.receipts),'bytes',capture.bytes,flush=True)
    if not args.verify_only:manifest()
 except Exception as exc:
  failure={'type':type(exc).__name__,'message':str(exc),'completed':len(matched)}
 state=manifest();print('FINAL',state['status'],len(matched),failure,flush=True)
 if state['status']!='COMPLETE':raise SystemExit(1)
if __name__=='__main__':run()
