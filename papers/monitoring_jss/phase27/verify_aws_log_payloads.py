#!/usr/bin/env python3
"""Verify AWS original log topics/data of *every* Bacon/Rari emitted notification.

Selected tx hashes come solely from already frozen primary 19-row alert ledger.
Compares original AWS Parquet event contents with SHA-256 of already published
Blockscout-normalized bundles. Uses complete original source row-group reads,
If-Match ETags, exact byte ranges, and records only per-tx SHA/provenance.
No statuses, attack labels, trace semantics or receipt-root claims.
"""
import argparse,csv,datetime as dt,gzip,hashlib,json,sys,zipfile
from collections import defaultdict
from pathlib import Path

def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def digest(x):return hashlib.sha256(canonical(x)).hexdigest()
def require(test,reason):
    if not test:raise ValueError(reason)

def load_archive(path):
    with zipfile.ZipFile(path) as z:
        rows=[json.loads(x) for x in gzip.decompress(z.read('indexer_observations.jsonl.gz')).splitlines() if x]
    return {r['transaction']['transaction_hash']:r for r in rows}

def keyval(v):
    if isinstance(v,str):return v.lower()
    if isinstance(v,(bytes,bytearray)):return '0x'+v.hex()
    raise ValueError('unexpected hex type')

def time_ns(t):
    if isinstance(t,dt.datetime):
        if t.tzinfo is None:t=t.replace(tzinfo=dt.timezone.utc)
        require(t.utcoffset()==dt.timedelta(0),'non-UTC source timestamp')
        return int(t.timestamp()*1000000000)
    raise ValueError('unsupported timestamp type '+type(t).__name__)

def normalize(r):
    topics=r['topics']
    if not isinstance(topics,list):raise ValueError('non-list topics')
    return {'address':keyval(r['address']),
        'topics':[keyval(v) for v in topics if v is not None],
        'data':keyval(r['data']),
        'transaction_index':int(r['transaction_index']),
        'log_index':int(r['log_index']),
        'transaction_hash':keyval(r['transaction_hash']),
        'block_number':int(r['block_number']),
        'block_hash':keyval(r['block_hash']),
        'event_time_ns':time_ns(r['block_timestamp'])}

def main():
    p=argparse.ArgumentParser()
    for f in ('ledger','phase20','bacon_archive','rari_archive','out'):p.add_argument('--'+f.replace('_','-'),type=Path,required=True)
    args=p.parse_args()
    import pyarrow as pa,pyarrow.compute as pc,pyarrow.parquet as pq
    root=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(root/'phase16/collector'))
    import range_collector as rc
    captured={**load_archive(args.bacon_archive),**load_archive(args.rari_archive)}
    ledger=list(csv.DictReader(args.ledger.open(newline='')))
    require(len(ledger)==19,'19 original primary notifications expected')
    selected={}
    for row in ledger:
        case=row['case'];tx=row['tx'].lower()
        if case not in ('bacon_20220305','rari_pool127_20220430'):continue
        require(tx in captured, 'alert transaction missing from frozen normalized observations')
        ob=captured[tx]
        if tx in selected:require(selected[tx]['transaction']==ob['transaction'],'duplicate tx conflict')
        selected[tx]=ob
    assert len(selected)>=9 and len(selected)<=11,(len(selected),list(selected))
    require('0x7d2296bcb936aa5e2397ddf8ccba59f54a178c3901666b49291d880369dbcf31' in selected,'Bacon original ref missing')
    require('0xab486012f21be741c9e674ffda227e30518e8a1e37a5f1d58d0b0d41f6e76530' in selected,'Rari original ref missing')
    baseline=json.loads(args.phase20.read_text())
    require(baseline['status']=='COMPLETE_ADDRESS_ONLY_60_DAYS','source identity not accepted')
    dates=defaultdict(set)
    for tx,r in selected.items():
        dates[(r['case'],r['day_utc'])].add(tx)
    caps={'requests':250,'total_response_bytes':2500000000,'wall_seconds':690,'request_timeout_seconds':45,
       'max_range_bytes':60000000,'max_footer_bytes':1000000,'max_rows':7000000,
       'max_row_groups':64,'max_top_level_columns':60,'max_leaf_columns':80,
       'max_source_bytes':800000000,'retries':0,'concurrency':1}
    cols=['address','topics','data','transaction_index','log_index','transaction_hash','block_number','block_hash','block_timestamp']
    plan={'schema_version':'article2_phase16_range_source_plan_v1','endpoint':rc.ENDPOINT,
          'caps':caps,'required_columns':{'logs':cols}}
    args.out.mkdir(parents=True,exist_ok=False)
    sess=rc.RangeSession(plan,args.out/'range_capture')
    matches=[];sources=[];success=False
    try:
        for (case,day),target in sorted(dates.items()):
            origin=next(x for x in baseline['days'] if x['case']==case and x['day']==day)
            src={'table':'logs','day_utc':day,'key':origin['source_key'],
                 'size_bytes':origin['source_declared_bytes'],'etag_opaque':origin['source_etag']}
            reader=rc.SourceReader(src,sess,args.out/'sparse',pa,pq).open()
            groups=[]
            present=set()
            for index,table in reader.iter_row_groups(['transaction_hash']):
                vals=pc.utf8_lower(table.column('transaction_hash'))
                inter=target.intersection(vals.to_pylist())
                if inter:groups.append(index);present|=inter
            require(present==target,'not all original source transactions found '+case+' '+day)
            rows=defaultdict(list)
            for index,table in reader.iter_row_groups(cols,groups):
                mask=pc.is_in(pc.utf8_lower(table.column('transaction_hash')),value_set=pa.array(sorted(target)))
                matched=table.filter(mask).to_pylist()
                for item in matched:
                    v=normalize(item);rows[v['transaction_hash']].append(v)
            for tx in sorted(target):
                values=sorted(rows[tx],key=lambda v:v['log_index'])
                exp=selected[tx]
                # Original event-time from S3 must agree with indexer event-time
                require(all(r['event_time_ns']==exp['transaction']['event_time_ns'] for r in values),'event time mismatch')
                require(all(r['block_hash']==exp['transaction']['block_hash'] for r in values),'block hash mismatch')
                require(len(values)==exp['all_emitter_log_count'],'log count differs')
                d=digest(values)
                require(d==exp['all_emitter_logs_sha256'],'AWS topics/data differ from Blockscout normalized bundle: '+tx)
                matches.append({'case':case,'day':day,'tx':tx,'log_count':len(values),
                    'aws_all_emitter_logs_sha256':d,'indexer_original_sha256':exp['all_emitter_logs_sha256'],
                    'status':'MATCHED_ALL_ORIGINAL_S3_LOG_CONTENT'})
            sources.append({'case':case,'day':day,'source_key':src['key'],'etag':src['etag_opaque'],
                            'total_source_rows':reader.metadata.num_rows,'matching_row_groups':groups,
                            'range_sha256':[r['response_sha256'] for r in reader.ranges]})
            print(case,day,'tx',len(target),'rowgroups',groups,'range_bytes_so_far',sess.bytes,flush=True)
        success=True
        sess.close('COMPLETE')
    finally:
        if not success:
            try:sess.close('INCOMPLETE')
            except Exception:pass
        report={'schema':'article2_source_topic_data_independent_spotcheck_v1',
            'status':'PASS' if success else 'INCOMPLETE',
            'reference_inventory':'Phase23 frozen primary rank-1/20 greedy B5 ledger',
            'scope':'all primary semantic notifications in the newly indexed Bacon/Rari case families; no source status or receipt root authentication',
            'selected_transactions':len(selected),'original_log_matches':len(matches),
            'matches':matches,'source_days':sources,
            'range_requests':len(sess.requests),'range_response_bytes':sess.bytes,
            'source_phase20_sha256':hashlib.sha256(args.phase20.read_bytes()).hexdigest(),
            'no_additional_labels':True,'no_detector_execution':True}
        (args.out/'summary.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        print('FINAL',report['status'],'matches',len(matches),'requests',len(sess.requests),'bytes',sess.bytes,flush=True)
    if not success:sys.exit(1)
if __name__=='__main__':main()