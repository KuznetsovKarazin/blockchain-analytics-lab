#!/usr/bin/env python3
"""Phase22 B: independently indexed all-emitter logs for S3-pinned selected tx.

Match exact transaction identities, successful transaction status, emitted core
log counts and full bundle lengths to original AWS Parquet projected evidence.
The log event topics and data are fetched from Blockscout, not original AWS,
and that source-tier difference is retained explicitly. No attack labels, model
training, rank threshold tuning or detector evaluation occurs in this step.
"""
from __future__ import annotations
import argparse, datetime as dt, gzip, hashlib, json, time, urllib.error, urllib.parse, urllib.request, sys
from pathlib import Path

BASE='https://eth.blockscout.com/api/v2/transactions/'
def require(ok,msg):
    if not ok:raise ValueError(msg)
def sha(x):return hashlib.sha256(x).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()

def parse_time(v):
    value=dt.datetime.fromisoformat(v.replace('Z','+00:00'))
    if value.tzinfo is None:value=value.replace(tzinfo=dt.timezone.utc)
    return int((value.astimezone(dt.timezone.utc)-dt.datetime(1970,1,1,tzinfo=dt.timezone.utc)).total_seconds()*1_000_000_000)

def fetch_json(url,rate_log,limits):
    # Explicit bounded retries only for transient failures. Keep request history.
    for attempt in range(5):
        if len(rate_log)>=limits['max_requests'] or time.monotonic()-limits['start']>limits['wall_seconds']:
            raise RuntimeError('Request or wall-time cap')
        begun=time.monotonic();status=None;byte_count=0
        try:
            request=urllib.request.Request(url,headers={'User-Agent':'article2-external-case-validation/2026-10-29','Accept':'application/json'})
            with urllib.request.urlopen(request,timeout=25) as res:
                status=res.status
                data=res.read(2_200_001)
            byte_count=len(data)
            require(len(data)<=2_200_000,'oversized indexed log response')
            limits['bytes']+=len(data)
            require(limits['bytes']<=limits['max_bytes'],'indexer cumulative byte cap')
            value=json.loads(data)
            rate_log.append({'source':'blockscout_v2','operation':url.split('/api/v2/')[-1].split('?')[0],
               'attempt':attempt+1,'code':status,'bytes':byte_count,'sha256':sha(data),'seconds':round(time.monotonic()-begun,3)})
            return value
        except (urllib.error.HTTPError,urllib.error.URLError,TimeoutError) as ex:
            status=getattr(ex,'code',None)
            rate_log.append({'source':'blockscout_v2','operation':url.split('/api/v2/')[-1].split('?')[0],
               'attempt':attempt+1,'code':status,'error':type(ex).__name__,'seconds':round(time.monotonic()-begun,3)})
            if status not in (429,500,502,503,504,None) or attempt>=4:raise
            time.sleep(min(15,2**attempt))
    raise RuntimeError('retries exhausted')

def logs_of_tx(txid,rate_log,limits):
    collected=[];cursor=None;pages=0
    while True:
        pages+=1;require(pages<=12,'excessive paginated logs')
        url=BASE+txid+'/logs'
        if cursor:
            require(type(cursor) is dict and 0<len(cursor)<=5,'bad pagination cursor')
            url+='?'+urllib.parse.urlencode(cursor)
        payload=fetch_json(url,rate_log,limits)
        require(type(payload) is dict and type(payload.get('items')) is list,'Blockscout schema changed')
        items=payload['items'];require(len(items)<=50,'unexpected page size')
        collected.extend(items)
        next_page=payload.get('next_page_params')
        if next_page is None:break
        require(next_page!=cursor and items,'pagination stalled')
        cursor=next_page
    return collected,pages

def normalized_indexed_rows(items,expected):
    source_cols=[]
    for src in items:
        addr=src['address']['hash'] if isinstance(src['address'],dict) else src['address']
        topics=[t.lower() for t in src.get('topics',[]) if t is not None]
        row={'address':addr.lower(),'topics':topics,'data':src['data'].lower(),
          'transaction_index':expected['transaction_index'],'log_index':src['index'],
          'transaction_hash':src['transaction_hash'].lower(),'block_number':src['block_number'],
          'block_hash':src['block_hash'].lower(),'event_time_ns':parse_time(src['block_timestamp'])}
        require(row['transaction_hash']==expected['transaction_hash'] and row['block_number']==expected['block_number']
                and row['block_hash']==expected['block_hash'] and row['event_time_ns']==expected['event_time_ns'],
                'Blockscout event not identical to S3 selected tx identity')
        source_cols.append(row)
    source_cols.sort(key=lambda x:x['log_index'])
    idx=[x['log_index'] for x in source_cols]
    require(len(set(idx))==len(idx) and all(b==a+1 for a,b in zip(idx,idx[1:])), 'indexed event log indices not contiguous')
    require(len(source_cols)==expected['all_emitter_log_count'] and
            idx[0]==expected['first_log_index'] and idx[-1]==expected['last_log_index'],
            'indexed all-emitter bundle differs from AWS identity/count bound')
    for role,core in expected['core_log_counts'].items():
        # roles values here are counts; addresses will be supplied separately.
        pass
    return source_cols

def feature_record(rows,expected,cores):
    # Reuse byte-frozen pure extraction, but mark the *actual* indexed source tier.
    from retained_observation_core import observe
    identity={key:expected[key] for key in ('block_number','block_hash','transaction_hash','transaction_index','event_time_ns')}
    identity['chain_id']=1
    record={'case':expected['case'],'day_utc':expected['day_utc'],'transaction':identity,
            'source_tier':'pinned_AWS_selected_identity_and_indexed_Blockscout_all_emitter_logs_v1',
            'dataset_execution_status_source':'Blockscout_v2_success_status',
            'all_emitter_log_count':len(rows),'all_emitter_logs_sha256':sha(canonical(rows)),
            'core_log_counts':expected['core_log_counts'],'views':{}}
    for role,addr in cores.items():
        n=sum(row['address']==addr.lower() for row in rows)
        require(n==expected['core_log_counts'][role],f'core emitter count conflict: {role}')
        if n:
            obs=observe(identity,rows,[addr.lower()],n,'0'*64,'1'*64,dataset_execution_status=1)
            # Actual observed data are Blockscout; do not inherit the AWS native tier!
            obs['evidence']['tier']='pinned_AWS_selected_identity_and_indexed_Blockscout_full_logs'
            obs['evidence']['source_kind']='blockscout_v2_full_logs_original_AWS_identity_control'
            obs['evidence']['source_audit_manifest_sha256']=sha(canonical(expected))
            obs['evidence']['selection_manifest_sha256']=sha(canonical({'core':addr,'view':role}))
            record['views'][role]={'token_flows':obs['token_flows'],'counts':obs['counts'],
                       'archived_core_log_count':n,'observation_sha256':sha(canonical(obs))}
    return record

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--case',required=True,choices=('bacon_20220305','rari_pool127_20220430'))
    p.add_argument('--identities',required=True,type=Path);p.add_argument('--out',required=True,type=Path)
    p.add_argument('--max-tx',type=int,default=10000);args=p.parse_args()
    import sys
    paper=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(paper/'phase15/adapter'))
    ids_raw=args.identities.read_bytes();ids=json.loads(ids_raw)
    require(isinstance(ids,list) and ids and all(x['day_utc'] for x in ids),'invalid phase22 S3 selection')
    if args.case=='bacon_20220305':cores={'proxy':'0xb8919522331c59f5c16bdfaa6a121a6e03a91f62'}
    else:cores={'fETH':'0x26267e41ceca7c8e0f143554af707336f27fa051',
      'fUSDC':'0xebe0d1cb6a0b8569929e062d67bfbC07608f0a47',
      'comptroller':'0x3f2d1bc6d02522dbcdb216b2e75edddafe04b16f'}
    args.out.mkdir(parents=True,exist_ok=False)
    info={'schema':'phase22_indexed_all_emitter_selected_bundles_v1','case':args.case,
      's3_selected_identity_file_sha256':sha(ids_raw),'source':'Blockscout_public_v2_indexer',
      'source_attestation':'all-event count, log indices, core emitter count, canonical tx hash/block/timestamp matched to pinned AWS original',
      'not_original_AWS_topic_data':True,'attack_labels_used':False,'detector_scores_computed':False,
      'requested':len(ids),'status':'INCOMPLETE','processed':0,'failures':[]}
    log=[];limits={'max_requests':4000,'start':time.monotonic(),'wall_seconds':2700,'max_bytes':500_000_000,'bytes':0}
    out_rows=[]
    try:
      for i,expected in enumerate(ids[:args.max_tx]):
        expected=dict(expected,case=args.case)
        txid=expected['transaction_hash']
        tx=fetch_json(BASE+txid,log,limits)
        require(tx['hash'].lower()==txid and tx['status']=='ok','not a successful execution according to indexed metadata')
        require(tx['position']==expected['transaction_index'] and tx['block_number']==expected['block_number'],
                'indexed tx position/block differs from S3')
        require(parse_time(tx['timestamp'])==expected['event_time_ns'],'indexed transaction time differs from S3')
        events,pages=logs_of_tx(txid,log,limits)
        rows=normalized_indexed_rows(events,expected)
        record=feature_record(rows,expected,cores)
        record['indexer_api_pages']=pages
        out_rows.append(record)
        if (i+1)%10==0:
            print('INDEXED',args.case,i+1,'/',min(args.max_tx,len(ids)),'requests',len(log),'bytes',limits['bytes'],flush=True)
        time.sleep(.08)
      info['processed']=len(out_rows)
      info['status']='COMPLETE_30_DAYS' if len(out_rows)==len(ids) else 'COMPLETE_DIAGNOSTIC_SUBSET'
    except Exception as exc:
      info['failures'].append({'index':len(out_rows),'error':type(exc).__name__+': '+str(exc)[:300]})
      print('HALT',info['failures'][-1],flush=True)
    info.update({'requests':len(log),'response_bytes':limits['bytes'],'selected_rows_sha256':sha(canonical(out_rows))})
    with gzip.open(args.out/'indexer_observations.jsonl.gz','wt',encoding='utf8') as f:
       for row in out_rows:f.write(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n')
    (args.out/'acquisition_manifest.json').write_text(json.dumps(info,indent=2,sort_keys=True)+'\n')
    (args.out/'indexer_response_receipts.json').write_text(json.dumps(log,indent=2)+'\n')
    if info['failures']:raise SystemExit(1)

if __name__=='__main__':main()