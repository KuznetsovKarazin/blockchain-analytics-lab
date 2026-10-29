#!/usr/bin/env python3
"""Phase22 A: original-S3 transaction identity recovery from pinned Phase21 set.

Only reads Parquet projections, not token amounts or exploit labels. Every selected
(block,transaction_index) is matched against the full daily original log table.
No detector runs or altered scientific settings.
"""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, shutil, sys, urllib.parse, urllib.request, xml.etree.ElementTree as ET
from collections import defaultdict, Counter
from pathlib import Path

FIELDS=['block_number','transaction_index','transaction_hash','block_hash','block_timestamp','address','log_index']

def req(condition,msg):
    if not condition:raise ValueError(msg)
def digest(data):return hashlib.sha256(data).hexdigest()
def canonical(obj):return json.dumps(obj,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def xmlfield(node,name):return next((x.text for x in node if x.tag.rsplit('}',1)[-1]==name),None)
def stamp(v):
    if isinstance(v,str):v=dt.datetime.fromisoformat(v.replace('Z','+00:00'))
    req(isinstance(v,dt.datetime),'timestamp not a datetime')
    if v.tzinfo is None:v=v.replace(tzinfo=dt.timezone.utc)
    t=v.astimezone(dt.timezone.utc)
    return int((t-dt.datetime(1970,1,1,tzinfo=dt.timezone.utc)).total_seconds()*1_000_000_000)

def matchmask(tab,positions,pa,pc):
    x=pc.add(pc.multiply(tab.column('block_number'),pa.scalar(65536,pa.int64())),tab.column('transaction_index'))
    return pc.is_in(x,value_set=pa.array([b*65536+i for b,i in positions],type=pa.int64()))

def main():
    p=argparse.ArgumentParser();p.add_argument('--case',required=True,choices=['bacon_20220305','rari_pool127_20220430'])
    p.add_argument('--selection',required=True,type=Path);p.add_argument('--out',required=True,type=Path)
    p.add_argument('--max-days',type=int,default=30);p.add_argument('--limit-bytes',type=int,default=3500000000)
    args=p.parse_args()
    import pyarrow as pa,pyarrow.compute as pc,pyarrow.parquet as pq
    paper=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(paper/'phase16/collector'))
    import range_collector as rc
    raw=args.selection.read_bytes();selection=json.loads(raw)
    req(selection['status']=='COMPLETE_LABEL_FREE_PROJECTION' and selection['case']==args.case,'Phase21 selection mismatch')
    req(selection['attack_labels_used'] is False and selection['admissions']==0,'label contamination')
    phase20=json.loads((paper/'phase20/source_evidence/core_traffic.json').read_bytes())
    req(phase20['status']=='COMPLETE_ADDRESS_ONLY_60_DAYS','Phase20 audit not accepted')
    days=selection['per_day'][:args.max_days];req(0<len(days)<=30,'invalid window length')
    args.out.mkdir(parents=True,exist_ok=False)
    plan={'schema_version':'article2_phase16_range_source_plan_v1','endpoint':rc.ENDPOINT,
      'caps':{'requests':2500,'total_response_bytes':args.limit_bytes,'wall_seconds':2400,
        'request_timeout_seconds':50,'max_range_bytes':32000000,'max_footer_bytes':1500000,
        'max_rows':100000000,'max_row_groups':1024,'max_top_level_columns':128,'max_leaf_columns':256,
        'max_source_bytes':2147483648,'retries':0,'concurrency':1},'required_columns':{'logs':FIELDS}}
    sess=rc.RangeSession(plan,args.out/'range_receipts')
    report={'schema':'phase22_s3_selected_transaction_identities_v1','case':args.case,
      'phase21_selection_sha256':digest(raw),'scoring_performed':False,'attack_labels_used':False,
      'all_emitter_token_data_downloaded':False,'daily':[],'status':'INCOMPLETE','failure':None}
    records=[]
    try:
      for d in days:
        day=d['day'];phase20_day=next(x for x in phase20['days'] if x['case']==args.case and x['day']==day)
        req(phase20_day['status']=='FULL_ORIGINAL_ADDRESS_COLUMN_AUDIT','incomplete Phase20 day')
        source={'table':'logs','day_utc':day,'key':phase20_day['source_key'],
          'size_bytes':phase20_day['source_declared_bytes'],'etag_opaque':phase20_day['source_etag']}
        src_positions={tuple(x) for x in d['candidate_union_tx_keys']}
        req(len(src_positions)==d['candidate_union_selected_tx_count'],'selection duplicate')
        reader=rc.SourceReader(source,sess,args.out/'sparse',pa,pq).open()
        groups=defaultdict(list)
        total_rows=0;hit_rowgroups=0
        # Every rowgroup is scanned using exact original block/tx index column bytes.
        for rg,tab in reader.iter_row_groups(['block_number','transaction_index']):
            total_rows+=len(tab)
            mask=matchmask(tab,src_positions,pa,pc)
            n=int(pc.sum(pc.cast(mask,pa.int64())).as_py() or 0)
            if not n:continue
            hit_rowgroups+=1
            selected=reader.read_row_group(rg,FIELDS).filter(mask).to_pylist()
            for row in selected:
                pos=(int(row['block_number']),int(row['transaction_index']))
                req(pos in src_positions,'selected source key inconsistent')
                groups[pos].append(row)
        req(total_rows==reader.metadata.num_rows==phase20_day['source_log_rows'],'rowgroup/source row mismatch')
        req(set(groups)==src_positions,'incomplete selected transaction identities')
        counts={name:0 for name in selection['contract_roles']}
        local=[]
        for pos,logs in sorted(groups.items()):
            logs=sorted(logs,key=lambda x:x['log_index'])
            ix=[int(x['log_index']) for x in logs]
            req(len(set(ix))==len(ix) and all(b==a+1 for a,b in zip(ix,ix[1:])),f'noncontiguous log bundle {pos}')
            hashes={x['transaction_hash'].lower() for x in logs};blocks={x['block_hash'].lower() for x in logs}
            times={stamp(x['block_timestamp']) for x in logs}
            req(len(hashes)==len(blocks)==len(times)==1,'inconsistent log identities')
            emitted={k:sum(x['address'].lower()==addr.lower() for x in logs) for k,addr in selection['contract_roles'].items()}
            req(sum(emitted.values())>=1,'no core log for selected identity')
            for k in counts:counts[k]+=emitted[k]
            record={'day_utc':day,'block_number':pos[0],'transaction_index':pos[1],
              'transaction_hash':next(iter(hashes)),'block_hash':next(iter(blocks)),'event_time_ns':next(iter(times)),
              'all_emitter_log_count':len(logs),'first_log_index':ix[0],'last_log_index':ix[-1],
              'core_log_counts':emitted}
            local.append(record)
        req(counts==d['source_log_counts']==phase20_day['core_log_counts'],'original core count mismatch')
        records.extend(local)
        report['daily'].append({'day':day,'source_key':source['key'],'source_etag':source['etag_opaque'],
          'expected_source_rows':total_rows,'core_log_counts':counts,'selected_tx_count':len(local),
          'all_emitter_logs':sum(x['all_emitter_log_count'] for x in local),'rowgroups_with_selected':hit_rowgroups,
          'source_ranges':[{'start':x['start'],'length':x['length'],'sha256':x['response_sha256']} for x in reader.ranges]})
        shutil.rmtree(reader.directory)
        print('ACCEPTED',args.case,day,'TX',len(local),'all-emitter logs',report['daily'][-1]['all_emitter_logs'],'GET bytes',sess.bytes,flush=True)
      sess.close('COMPLETE')
      report['status']='COMPLETE_30_DAYS' if len(days)==30 else 'COMPLETE_SUBSET_DIAGNOSTIC'
    except Exception as e:
      report['failure']={'type':type(e).__name__,'reason':str(e),'day_index':len(report['daily'])}
      print('HALTED',report['failure'],flush=True)
      try:sess.close('INCOMPLETE')
      except Exception:pass
    report['range_request_count']=len(sess.requests);report['range_body_bytes']=sess.bytes
    report['record_count']=len(records);report['record_sha256']=digest(canonical(records))
    (args.out/'selected_tx_identities.json').write_text(json.dumps(records,sort_keys=True,indent=2)+'\n')
    (args.out/'source_audit.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    req(report['failure'] is None,'source capture incomplete')

if __name__=='__main__':main()