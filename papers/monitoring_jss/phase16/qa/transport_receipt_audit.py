#!/usr/bin/env python3
"""Independent offline audit of captured original ranges and retained ZIP sources.

No production imports, network, Parquet decode, selection, labels, or scores.
This audit authenticates retained byte provenance only; a separate auditor must
derive required column extents from the authenticated footer before decoding.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import zipfile

ENDPOINT='https://aws-public-blockchain.s3.us-east-2.amazonaws.com/'
FIELDS=('table','day_utc','key','size_bytes','etag_opaque','url')

def need(ok, message):
    if not ok: raise ValueError(message)

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()

def digest(value): return hashlib.sha256(canonical(value)).hexdigest()

def stream_sha(handle,length=None):
    h=hashlib.sha256();count=0
    while length is None or count<length:
        b=handle.read(1048576 if length is None else min(1048576,length-count))
        if not b: break
        count+=len(b);h.update(b)
    need(length is None or count==length,'truncated original bytes')
    return h.hexdigest(),count

def file_sha(path,start=0,length=None):
    with Path(path).open('rb') as f:
        f.seek(start);return stream_sha(f,length)[0]

def load(path,expected=None):
    path=Path(path)
    if expected is not None: need(file_sha(path)==expected,'bound file changed: '+str(path))
    return json.loads(path.read_bytes())

def binding(bind,repo):
    need(set(bind)=={'path','sha256'},'binding fields differ')
    p=Path(bind['path']);need(not p.is_absolute() and '..' not in p.parts,'unsafe binding path')
    return load(repo/p,bind['sha256'])

def source_identity(source):
    out={k:source[k] for k in FIELDS}
    need(out['table'] in ('blocks','logs','transactions'),'source table')
    day=out['day_utc'];need(type(day)is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}',day),'source day')
    need(re.fullmatch(r'v1\.0/eth/'+out['table']+'/date='+day+r'/[A-Za-z0-9_.-]+\.parquet',out['key']),'source key')
    need(out['url']==ENDPOINT+out['key'],'source URL')
    need(type(out['size_bytes'])is int and out['size_bytes']>=12,'source size')
    need(type(out['etag_opaque'])is str and out['etag_opaque'],'source ETag')
    return out

def union(spans):
    result=[]
    for a,b in sorted(spans):
        need(type(a)is int and type(b)is int and 0<=a<b,'invalid available interval')
        if result and a<=result[-1][1]: result[-1][1]=max(result[-1][1],b)
        else: result.append([a,b])
    return result

def covered(spans,start,end):
    return any(a<=start and end<=b for a,b in union(spans))

def utc(value):
    d=datetime.fromisoformat(value);need(d.tzinfo is not None,'timestamp lacks timezone');return d

def validate_record(record,source,path,caps,ordinal,started):
    """Check exact original receipt and its retained bytes, independently."""
    need(record['ordinal']==ordinal and type(record['ordinal'])is int,'request ordinal differs')
    need(record['source']==source,'request source differs from frozen inventory')
    a,n=record['start'],record['length']
    need(type(a)is int and type(n)is int and 0<=a and 0<n<=caps['max_range_bytes'] and a+n<=source['size_bytes'],'request bounds')
    need(record['transport_ok'] is True and 'failure' not in record,'failed or pending request')
    need(record['method']=='GET' and record['http_status']==206 and record['response_url']==source['url'],'HTTP method/status/redirect')
    need(record['etag']==source['etag_opaque'],'response ETag differs')
    need(record['content_range']==f"bytes {a}-{a+n-1}/{source['size_bytes']}",'Content-Range differs')
    length=record['content_length'];need(type(length)is str and length.isdigit() and int(length)==n,'Content-Length differs')
    need(record['content_encoding'] in (None,'identity'),'encoded response')
    headers=record['request_headers']
    need(headers['Range']==f'bytes={a}-{a+n-1}' and headers['If-Match']==source['etag_opaque'] and headers['Accept-Encoding']=='identity','request header binding')
    need(record['response_bytes']==n and type(record['response_bytes'])is int,'response byte count')
    need(record['stored_file_name']==path.name and record['stored_offset']==a,'stored byte location differs')
    need(record['invalid_header_body_read'] is False,'invalid header body consumption')
    begin,end=utc(record['started_utc']),utc(record['completed_utc'])
    need(started<=begin<=end and (end-started).total_seconds()<=caps['wall_seconds'],'request outside original wall deadline')
    need(file_sha(path,a,n)==record['response_sha256'],'retained original range hash differs')
    return [a,a+n]

def footer_evidence(path,source,available,caps):
    size=source['size_bytes']
    need(covered(available,0,4) and covered(available,size-8,size),'original magic/trailer not acquired')
    with path.open('rb') as f:
        need(f.read(4)==b'PAR1','original leading magic')
        f.seek(size-8);trailer=f.read(8)
    length=int.from_bytes(trailer[:4],'little');start=size-8-length
    need(trailer[4:]==b'PAR1' and 0<length<=caps['max_footer_bytes'] and start>=4,'original footer bounds')
    need(covered(available,start,size),'original footer contains sparse holes')
    return {'leading_magic_sha256':file_sha(path,0,4),'footer_start':start,'footer_length':length,
            'footer_and_trailer_sha256':file_sha(path,start,size-start)}

def audit_reuse(source,path,expect,archive_path,old_day,archive_cache):
    """Verify archive hash, original raw member, and original acquisition receipt."""
    need(expect['source_key']==source['key'] and expect['source_url']==source['url'] and expect['size_bytes']==source['size_bytes'] and expect['etag_opaque']==source['etag_opaque'],'reuse expectation identity differs')
    expected_sha=expect['expected_whole_object_sha256'];day=source['day_utc']
    need(old_day['day_utc']==day and old_day['archive']['sha256']==expect['expected_archive_sha256'],'original archive binding differs')
    receipt=old_day['source_objects'][source['table']]
    need(receipt['hash_scope']=='whole source object' and receipt['sha256']==expected_sha and receipt['bytes']==source['size_bytes'],'original whole-object receipt hash/size differs')
    need(receipt['source']['url']==source['url'] and receipt['source']['etag']==source['etag_opaque'] and receipt['source']['size']==source['size_bytes'],'original acquisition source identity differs')
    utc(receipt['acquired_utc'])
    if day not in archive_cache:
        need(archive_path.stat().st_size==old_day['archive']['bytes'] and file_sha(archive_path)==expect['expected_archive_sha256'],'retained ZIP bytes differ')
        with zipfile.ZipFile(archive_path) as z:
            names=z.namelist();need(len(names)==len(set(names)),'duplicate ZIP members')
            original_raw=z.read('day_manifest.json');original=json.loads(original_raw)
            need(original['day_utc']==day and original['source_objects']==old_day['source_objects'],'ZIP original acquisition receipt differs')
        archive_cache[day]={'archive_sha256':expect['expected_archive_sha256'],'original_day_receipt_sha256':hashlib.sha256(original_raw).hexdigest()}
    name=expect['expected_original_member_name'];need(name==('headers.parquet' if source['table']=='blocks' else 'logs.parquet'),'noncanonical source member')
    with zipfile.ZipFile(archive_path) as z:
        info=z.getinfo(name);need(info.file_size==source['size_bytes'],'raw ZIP member size differs')
        with z.open(info) as f: actual,count=stream_sha(f)
    need(actual==expected_sha and count==source['size_bytes'] and file_sha(path)==expected_sha,'raw ZIP member or extracted bytes differ')
    return {**archive_cache[day],'original_member_name':name,'original_member_sha256':actual,
            'original_acquisition_receipt_sha256':digest(receipt),'whole_source_sha256':expected_sha}

def audit(args):
    repo=args.repo.resolve();root=args.collection.resolve()
    plan=load(args.plan,args.expected_plan_sha256)
    need(canonical(load(root/'frozen_plan.json'))==canonical(plan),'runtime frozen plan differs')
    collector=repo/'papers/monitoring_jss/phase16/collector/range_collector.py'
    pipeline=repo/'papers/monitoring_jss/phase16/pipeline/streaming_pipeline.py'
    need(file_sha(collector)==plan['collector_sha256'] and file_sha(pipeline)==plan['pipeline_sha256'],'execution code differs from frozen plan')
    result=load(root/'collection_result.json',args.expected_result_sha256)
    need(result['status']=='COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT' and result['plan_sha256']==args.expected_plan_sha256,'collection is not complete/frozen')
    for k in ('transfer_decoding_performed','detector_scoring_performed','labels_used'):need(result[k] is False,'premature semantic work')
    manifests=load(root/'transport_sources.json',args.expected_transport_sources_sha256)['sources']
    inventory=binding(plan['source_union'],repo);sources=[source_identity(x) for x in inventory['objects']]
    bykey={s['key']:s for s in sources};need(len(bykey)==len(sources),'duplicate inventory source')
    paths=load(root/'runtime_source_paths.json');need(set(paths)==set(bykey),'runtime source population differs')
    mm={m['source']['key']:m for m in manifests};need(len(mm)==len(manifests) and set(mm)==set(bykey),'manifest source population differs')
    need(result['transport_sources']==len(sources),'result source count differs')
    cplan=plan['collector'];caps=cplan['caps'];transport=root/'transport'
    need(load(transport/'plan.json')==cplan,'capture plan differs')
    session=load(transport/'session.json');records=load(transport/'requests.json')
    need(session['status']=='COMPLETE' and session['plan_canonical_sha256']==digest(cplan),'capture not complete/bound')
    need(session['attempt_id']==digest({'plan':digest(cplan),'started_utc':session['started_utc']}),'capture attempt binding differs')
    need(caps['retries']==session['retries']==0 and caps['concurrency']==1,'retry/concurrency differs')
    need(len(records)==session['request_count']<=caps['requests'],'request accounting/cap differs')
    need(0<=session['wall_seconds_elapsed']<=caps['wall_seconds'],'capture wall cap differs')
    started=utc(session['started_utc']);prior=started;grouped=defaultdict(list);spans=defaultdict(list)
    for i,r in enumerate(records,1):
        key=r['source']['key'];need(key in bykey,'unexpected requested source')
        p=Path(paths[key]);need(p.is_absolute() and p.is_file() and p.stat().st_size==bykey[key]['size_bytes'],'retained source path/size')
        span=validate_record(r,bykey[key],p,caps,i,started)
        need(utc(r['started_utc'])>=prior,'parallel or out-of-order requests');prior=utc(r['completed_utc'])
        grouped[key].append(r);spans[key].append(span)
    total=sum(r['response_bytes'] for r in records)
    need(total==session['retained_response_bytes']<=caps['total_response_bytes'],'retained byte accounting/cap differs')
    expectation=load(args.reuse_expectations,args.expected_reuse_expectations_sha256) if args.reuse_expectations else {'objects':[]}
    expected={x['source_key']:x for x in expectation['objects']}
    archives=load(args.archives) if args.archives else {};old=load(args.original_manifest,args.expected_original_manifest_sha256) if args.original_manifest else {'days':[]}
    old_days={x['day_utc']:x for x in old['days']};archive_cache={};verified=[];reuses=[]
    for key,source in bykey.items():
        path=Path(paths[key]).resolve();need(path.is_file() and path.stat().st_size==source['size_bytes']<=caps['max_source_bytes'],'source file size/cap')
        manifest=mm[key];need(manifest['source']==source and manifest['source_id']==digest(source),'manifest source identity differs')
        whole=manifest['whole_source_sha256_verified'];need(type(whole)is bool,'whole source flag type')
        source_receipts=grouped[key];origin=None
        if whole:
            need(not source_receipts and key in expected,'whole reuse has new ranges or missing original expectation')
            need(args.expected_reuse_expectations_sha256 and args.expected_original_manifest_sha256,'reuse origin is not explicitly hash-bound')
            frozen=plan.get('whole_object_reuse_expectations',{}).get(key)
            need(frozen is not None and frozen['sha256']==expected[key]['expected_whole_object_sha256'] and all(frozen[k]==source[k] for k in ('size_bytes','etag_opaque')),'whole reuse missing/different in frozen plan')
            acquired=binding(frozen['acquisition_receipt'],repo)
            need(acquired['source_key']==key and acquired['sha256']==frozen['sha256'] and all(acquired[k]==source[k] for k in ('size_bytes','etag_opaque')),'frozen acquisition receipt differs')
            need(all(acquired[k]==expected[key][k] for k in ('expected_archive_sha256','expected_original_member_name')),'frozen acquisition archive/member differs')
            day=source['day_utc'];need(day in archives and day in old_days,'reuse original archive/receipt absent')
            origin=audit_reuse(source,path,expected[key],Path(archives[day]),old_days[day],archive_cache)
            need(manifest['whole_source_sha256']==origin['whole_source_sha256'],'producer whole hash differs')
            available=[[0,source['size_bytes']]];reuses.append(key)
        else:
            need(manifest['whole_source_sha256'] is None and source_receipts,'range source lacks successful original receipts')
            need(path==(root/'cache'/digest(source)/'source.parquet').resolve(),'range source outside expected cache')
            cache=load(path.parent/'ranges.json')
            need(cache['source']==source and cache['attempt_id']==session['attempt_id'],'range cache source/attempt differs')
            need(cache['ranges']==source_receipts,'range cache differs from complete charged requests')
            available=union(spans[key]);need(sum(b-a for a,b in spans[key])==sum(b-a for a,b in available),'overlapping responses')
        need(manifest['successful_original_ranges']==source_receipts and manifest['available_ranges']==available and manifest['available_original_bytes']==sum(b-a for a,b in available),'manifest range evidence differs')
        need(manifest['holes_are_original_bytes'] is False and manifest['statistics_values_exported_or_used'] is False,'invalid manifest evidence claim')
        footer=footer_evidence(path,source,available,caps)
        verified.append({'source_key':key,'source':source,'source_id':digest(source),'path':str(path),
                         'available_ranges':available,'whole_source_sha256_verified':whole,
                         'whole_source_sha256':None if origin is None else origin['whole_source_sha256'],
                         'successful_range_count':len(source_receipts),'range_receipts_canonical_sha256':digest(source_receipts),
                         'original_footer_evidence':footer,'whole_object_origin':origin})
    claimed={x['source_id'] for x in session['cache_or_full_object_reuses'] if x['kind']=='verified_whole_object'}
    need(claimed=={digest(bykey[k]) for k in reuses},'whole reuse accounting differs')
    out={'schema_version':'article2_phase16_independent_transport_audit_v1','status':'PASS_TRANSPORT_ORIGINAL_BYTES',
         'recorded_utc':datetime.now(timezone.utc).isoformat(),'plan_sha256':args.expected_plan_sha256,
         'collection_result_sha256':args.expected_result_sha256,'transport_sources_sha256':args.expected_transport_sources_sha256,
         'collector_sha256':plan['collector_sha256'],'pipeline_sha256':plan['pipeline_sha256'],
         'auditor_sha256':file_sha(__file__),'requests_sha256':file_sha(transport/'requests.json'),
         'session_sha256':file_sha(transport/'session.json'),'runtime_source_paths_sha256':file_sha(root/'runtime_source_paths.json'),
         'reuse_expectations_sha256':args.expected_reuse_expectations_sha256,'original_manifest_sha256':args.expected_original_manifest_sha256,
         'request_count':len(records),'retained_response_bytes':total,'source_count':len(verified),
         'whole_object_reuse_count':len(reuses),'verified_sources':verified,'network_requests':0,
         'parquet_rows_decoded':0,'selection_or_scientific_acceptance':False,'receipt_root_verified':False,
         'limitations':['Byte provenance from retained acquisition records; not an Ethereum receipt-root proof.',
                        'Source footer column extents, table coverage, selection, bundles, and decisions require separate independent audit.']}
    need(not args.output.exists(),'audit output already exists');args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');return out

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('repo','collection','plan','output'):p.add_argument('--'+k,type=Path,required=True)
    for k in ('expected-plan-sha256','expected-result-sha256','expected-transport-sources-sha256'):p.add_argument('--'+k,required=True)
    for k in ('reuse-expectations','archives','original-manifest'):p.add_argument('--'+k,type=Path)
    for k in ('expected-reuse-expectations-sha256','expected-original-manifest-sha256'):p.add_argument('--'+k)
    args=p.parse_args();v=audit(args);print(json.dumps({k:v[k] for k in ('status','source_count','request_count','retained_response_bytes','whole_object_reuse_count')}))

if __name__=='__main__':main()
