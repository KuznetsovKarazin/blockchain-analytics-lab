#!/usr/bin/env python3
"""Independent compact-byte audit for one explicitly accepted ENOSPC recovery.

The original pending checkpoint stays pending. External closure attestations,
known retained bytes, unknown pending bytes and conservative budget charges are
kept distinct. No network, Parquet decode, scoring, or capture mutation occurs.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from datetime import datetime,timedelta,timezone
import hashlib
import json
from pathlib import Path
import re

ENDPOINT='https://aws-public-blockchain.s3.us-east-2.amazonaws.com/'
SOURCE_FIELDS=('table','day_utc','key','size_bytes','etag_opaque','url')
REQUEST_LIMIT=5000
BYTE_LIMIT=16*1024**3
DEADLINE_SECONDS=14400
PENDING_ORDINAL=730
PENDING_LENGTH=275821
KNOWN_PREFIX_COUNT=729
CASES=('lifi_20220320','revest_20220327')
FORENSIC_NAMES={'metadata_inventory','allocation_review','path_relocation',
                'external_resource_failure_attestation','accepted_range_review'}

def need(ok,message):
    if not ok:raise ValueError(message)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()

def integer(value,name,minimum=0):
    need(type(value)is int and value>=minimum,'invalid integer: '+name);return value

def hexsha(value):
    need(type(value)is str and re.fullmatch('[0-9a-f]{64}',value),'invalid SHA256');return value

def file_sha(path,start=0,length=None):
    h=hashlib.sha256();got=0
    with Path(path).open('rb') as f:
        f.seek(start)
        while length is None or got<length:
            part=f.read(1048576 if length is None else min(1048576,length-got))
            if not part:break
            h.update(part);got+=len(part)
    need(length is None or got==length,'truncated retained bytes');return h.hexdigest()

def read(path,expected=None):
    if expected is not None:need(file_sha(path)==hexsha(expected),'bound file changed: '+str(path))
    def pairs(items):
        result={}
        for k,v in items:
            need(k not in result,'duplicate JSON key');result[k]=v
        return result
    return json.loads(Path(path).read_bytes(),object_pairs_hook=pairs,
                      parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite JSON')))

def bound(binding,base):
    need(type(binding)is dict and set(binding)=={'path','sha256'},'binding shape')
    path=Path(binding['path']);path=path if path.is_absolute() else Path(base)/path
    need(path.is_file() and file_sha(path)==hexsha(binding['sha256']),'bound file changed: '+str(path));return path.resolve()

def inside(root,relative):
    p=Path(relative);need(type(relative)is str and relative and not p.is_absolute() and '..' not in p.parts,'unsafe relative path')
    path=(Path(root)/p).resolve();need(path.is_relative_to(Path(root).resolve()),'relative path escapes root');return path

def utc(value):
    need(type(value)is str,'explicit UTC time required');d=datetime.fromisoformat(value.replace('Z','+00:00'))
    need(d.utcoffset()==timedelta(0),'explicit UTC time required');return d

def identity(value):
    s={k:value[k] for k in SOURCE_FIELDS};table,day=s['table'],s['day_utc']
    need(table in ('blocks','logs','transactions'),'source table')
    need(type(day)is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}',day),'source date')
    need(re.fullmatch(r'v1\.0/eth/'+table+'/date='+day+r'/[A-Za-z0-9_.-]+\.parquet',s['key']),'source key')
    need(s['url']==ENDPOINT+s['key'],'source URL');integer(s['size_bytes'],'source size',12)
    need(type(s['etag_opaque'])is str and s['etag_opaque'],'opaque source ETag missing');return s

def overlap(a,b):return max(a[0],b[0])<min(a[1],b[1])

def request_identity(record,ordinal,sources,caps):
    integer(record['ordinal'],'ordinal',1);need(record['ordinal']==ordinal,'global request ordinal differs')
    s=identity(record['source']);need(sources.get(s['key'])==s==record['source'],'request source differs')
    start=integer(record['start'],'range start');length=integer(record['length'],'range length',1)
    need(start+length<=s['size_bytes']<=caps['max_source_bytes'] and length<=caps['max_range_bytes'],'range/source cap')
    h=record['request_headers'];need(record['method']=='GET' and h['Range']==f'bytes={start}-{start+length-1}'
        and h['If-Match']==s['etag_opaque'] and h['Accept-Encoding']=='identity','request header/source binding')
    return s,[start,start+length]

def successful_receipt(record,source,start_limit,end_limit):
    need(record['transport_ok'] is True and type(record['response_bytes'])is int
         and record['response_bytes']==record['length'] and 'failure' not in record,'receipt is not fully successful')
    hexsha(record['response_sha256']);a,n=record['start'],record['length'];length=record['content_length']
    need(record['http_status']==206 and record['response_url']==source['url'] and record['etag']==source['etag_opaque'],'HTTP status/identity differs')
    need(record['content_range']==f'bytes {a}-{a+n-1}/{source["size_bytes"]}'
         and type(length)is str and length.isdigit() and int(length)==n
         and record['content_encoding'] in (None,'identity') and record['invalid_header_body_read'] is False,'HTTP range/length/encoding differs')
    begin,end=utc(record['started_utc']),utc(record['completed_utc'])
    need(start_limit<=begin<=end<=end_limit,'successful GET outside declared time interval');return begin,end

def validate_cost_ledgers(parent_requests,new_requests,parent_session,session,sources,caps,accepted_utc,manual):
    """The original final zero is an unresolved placeholder, never measured zero."""
    need(caps['requests']==REQUEST_LIMIT and caps['total_response_bytes']==BYTE_LIMIT and caps['wall_seconds']==7200,'original caps differ')
    need(parent_session['schema_version']=='article2_phase16_range_capture_v1'
         and parent_session['status']=='OPEN_REQUEST_PENDING','original checkpoint was rewritten or not the declared pending attempt')
    need(len(parent_requests)==parent_session['request_count']==PENDING_ORDINAL,'original request population differs')
    need(parent_session['attempt_id']==session['parent_attempt_id'],'parent attempt identity differs')
    start=utc(parent_session['started_utc']);deadline=start+timedelta(seconds=DEADLINE_SECONDS);accepted=utc(accepted_utc)
    need(session['original_started_utc']==parent_session['started_utc'] and utc(session['absolute_deadline_utc'])==deadline,'absolute deadline reset')
    need(start<=accepted<=utc(session['started_utc'])<deadline,'recovery started before acceptance or after deadline')
    pending=parent_requests[-1]
    need(pending['ordinal']==PENDING_ORDINAL and pending['length']==PENDING_LENGTH
         and pending['transport_ok'] is False and pending['response_bytes']==0,'declared unresolved pending request differs')
    need(not {'completed_utc','response_sha256','failure','http_status','response_url','etag','content_range','content_length','content_encoding'}.intersection(pending),'pending placeholder was promoted into a finalized response')
    need(type(manual)is dict and set(manual)=={'parent_request_ordinal','source_key','start','length'},'exact pending reacquisition authorization missing')
    integer(manual['parent_request_ordinal'],'manual ordinal',1);integer(manual['start'],'manual start');integer(manual['length'],'manual length',1)
    need(manual=={'parent_request_ordinal':pending['ordinal'],'source_key':pending['source']['key'],'start':pending['start'],'length':pending['length']},'manual pending range differs')
    requested=defaultdict(list);origins=[];prior_end=start;known_parent=0
    for ordinal,r in enumerate(parent_requests,1):
        source,span=request_identity(r,ordinal,sources,caps)
        need(not any(overlap(span,x) for x in requested[source['key']]),'original attempted ranges overlap')
        requested[source['key']].append(span)
        if ordinal<PENDING_ORDINAL:
            begin,end=successful_receipt(r,source,start,start+timedelta(seconds=7200))
            need(begin>=prior_end,'original GETs reordered');prior_end=end;known_parent+=r['response_bytes']
            origins.append({'origin_attempt_id':parent_session['attempt_id'],'origin_ordinal':ordinal,'receipt':r})
        else:need(prior_end<=utc(r['started_utc'])<=utc(parent_session['updated_utc']) and utc(r['started_utc'])<start+timedelta(seconds=7200),'pending original request chronology')
    need(len(origins)==KNOWN_PREFIX_COUNT and known_parent==parent_session['retained_response_bytes'],'original successful prefix accounting differs')
    inherited_charged=known_parent+pending['length'];need(inherited_charged<=BYTE_LIMIT,'original pending reservation exceeds cap')
    new_known=0;new_charged=0;new_failed=[];manual_count=0;previous=utc(session['started_utc']);new_spans=defaultdict(list)
    for i,r in enumerate(new_requests,PENDING_ORDINAL+1):
        source,span=request_identity(r,i,sources,caps);key=source['key']
        need(not new_failed,'request issued after failed recovery request')
        need(inherited_charged+new_charged+r['length']<=BYTE_LIMIT,'full request reservation exceeds cumulative byte cap')
        need(not any(overlap(span,x) for x in new_spans[key]),'automatic/overlapping recovery retry')
        new_spans[key].append(span)
        manual_range=key==pending['source']['key'] and span==[pending['start'],pending['start']+pending['length']]
        if manual_range:
            need(i==PENDING_ORDINAL+1 and manual_count==0 and r['resource_recovery_request_kind']=='explicit_pending_reacquisition'
                 and r['reacquisition_of']=={'attempt_id':parent_session['attempt_id'],'ordinal':PENDING_ORDINAL},'pending retry is not the one explicitly authorized first new GET')
            manual_count+=1
        else:
            need(r['resource_recovery_request_kind']=='previously_unrequested_range' and r.get('reacquisition_of') is None,'ordinary GET has false origin')
        for old in requested[key]:need(not overlap(span,old) or manual_range and old==[pending['start'],pending['start']+pending['length']],'new GET overlaps original accepted/requested range')
        need(r['origin_attempt_id']==session['attempt_id'],'new response origin differs')
        integer(r['response_bytes'],'new recorded bytes');need(r['response_bytes']<=r['length'],'new response exceeds declared length')
        begin,end=utc(r['started_utc']),utc(r['completed_utc']);need(previous<=begin<=end and accepted<=begin<deadline,'new request chronology');previous=end
        if r['transport_ok'] is True:
            successful_receipt(r,source,accepted,deadline)
            need(r['body_storage_kind']=='immutable_blob' and r['physical_blob_offset']==0 and r.get('received_bytes_known')==r['response_bytes']
                 and 'storage_failure' not in r,'new response storage misrepresented')
            origins.append({'origin_attempt_id':session['attempt_id'],'origin_ordinal':i,'receipt':r})
        else:new_failed.append(r)
        new_known+=r['response_bytes'];new_charged+=r['length']
    count=len(parent_requests)+len(new_requests);need(count<=REQUEST_LIMIT,'cumulative GET cap')
    need(session['inherited_request_count']==len(parent_requests) and session['new_request_count']==len(new_requests)
         and session['cumulative_request_count']==count,'request accounting differs')
    need(session['inherited_response_bytes']==known_parent and session['new_response_bytes']==new_known
         and session['cumulative_response_bytes']==known_parent+new_known,'known retained byte accounting differs')
    reserved_new=sum(x['length']-x['response_bytes'] for x in new_failed)
    need(session['reserved_parent_pending_response_bytes']==pending['length']
         and session['reserved_new_failed_or_pending_response_bytes']==reserved_new
         and session['inherited_charged_response_bytes']==inherited_charged
         and session['new_charged_response_bytes']==new_charged==new_known+reserved_new
         and session['cumulative_charged_response_bytes']==inherited_charged+new_charged<=BYTE_LIMIT,'conservative pending/new reservation differs')
    need(session['parent_pending_response_bytes'] is None and session['actual_cumulative_response_bytes_complete'] is False
         and session['response_byte_count_scope']=='RECORDED_RETAINED_ONLY_PARENT_PENDING_UNKNOWN','unknown original bytes were misrepresented as measured zero/complete cost')
    need(session['automatic_retries']==0 and session['manual_reacquisition_count']==manual_count
         and session['cumulative_retry_count']==manual_count,'manual/automatic retry accounting differs')
    need(session['status']!='COMPLETE' or manual_count==1 and not new_failed,'incomplete/failed recovery promoted to complete')
    if session['status']=='COMPLETE':
        closed=utc(session['updated_utc']);elapsed=session['cumulative_wall_seconds_elapsed']
        need(previous<=closed<=deadline and type(elapsed) in (int,float) and 0<=elapsed<=DEADLINE_SECONDS
             and abs((closed-start).total_seconds()-elapsed)<=2,'final preparation exceeded absolute deadline or clocks differ')
    return {'accepted_origins':origins,'known_parent_response_bytes':known_parent,'known_new_response_bytes':new_known,
        'known_cumulative_response_bytes':known_parent+new_known,'parent_pending_response_bytes':None,
        'actual_cumulative_response_bytes_complete':False,'reserved_parent_pending_response_bytes':pending['length'],
        'reserved_new_failed_or_pending_response_bytes':reserved_new,'inherited_charged_response_bytes':inherited_charged,
        'new_charged_response_bytes':new_charged,'cumulative_charged_response_bytes':inherited_charged+new_charged,
        'cumulative_request_count':count,'manual_reacquisition_count':manual_count,'new_failed_requests':len(new_failed),
        'wire_bytes_measured':False,'original_checkpoint_status':'OPEN_REQUEST_PENDING','original_terminal_cause':'EXTERNALLY_ATTESTED_ENOSPC'}

def strict_blob_read(blobs,start,length):
    need(type(start)is int and type(length)is int and start>=0 and length>=0,'invalid strict read')
    cursor=start;end=start+length;parts=[]
    for b in blobs:
        lo,hi=b['start'],b['start']+b['length']
        if hi<=cursor:continue
        if lo>=end:break
        need(lo<=cursor,'attempt to read unacquired hole')
        take=min(end,hi)-cursor
        with Path(b['path']).open('rb') as f:f.seek(cursor-lo);raw=f.read(take)
        need(len(raw)==take,'blob truncated during strict read');parts.append(raw);cursor+=take
        if cursor==end:break
    need(cursor==end,'attempt to read unacquired hole');return b''.join(parts)

def verify_compact_descriptor(path,source,wrappers,runtime_root,attempt_id,parent_attempt_id,max_footer_bytes):
    path=Path(path).resolve();runtime_root=Path(runtime_root).resolve();d=read(path);sid=digest(source)
    need(path==(runtime_root/'storage'/sid/'source_storage.json').resolve(),'descriptor outside fixed source storage')
    need(d['schema_version']=='article2_phase16_compact_source_v1' and d['storage_kind']=='compact_descriptor'
         and d['source']==source and d['source_id']==sid and d['logical_size_bytes']==source['size_bytes']
         and d['attempt_id']==attempt_id and d['parent_attempt_id']==parent_attempt_id,'descriptor source/origin differs')
    by_origin={(x['origin_attempt_id'],x['origin_ordinal']):x for x in wrappers}
    need(len(by_origin)==len(wrappers)==len(d['segments']),'descriptor/evidence segment count differs')
    blobs=[];seen=set();previous=0
    for segment in d['segments']:
        start=integer(segment['start'],'segment start');length=integer(segment['length'],'segment length',1)
        need(previous<=start and start+length<=source['size_bytes'],'segments overlap, reorder or exceed source');previous=start+length
        key=(segment['origin_attempt_id'],segment['origin_ordinal']);need(key in by_origin and key not in seen,'segment origin absent/repeated');seen.add(key)
        wrapper=by_origin[key];r=wrapper['receipt'];need(r['source']==source and r['transport_ok'] is True
            and r['start']==start and r['length']==r['response_bytes']==length
            and segment['receipt_sha256']==digest(r),'segment does not bind complete original accepted receipt')
        blob=inside(path.parent,segment['blob_path']);need(blob.is_relative_to(runtime_root),'blob outside pinned runtime')
        expected=hexsha(segment['blob_sha256']);need(blob.name==f'{key[0]}-{key[1]:06d}-{expected}.bin','blob is not content-addressed to exact origin')
        binding=wrapper['blob'];need(inside(runtime_root,binding['path'])==blob and binding['size_bytes']==length
             and binding['sha256']==expected==r['response_sha256'],'wrapper/blob binding differs')
        st=blob.stat();need(blob.is_file() and st.st_size==length and not st.st_mode&0o222,'blob is not exact-length/read-only')
        need(file_sha(blob)==expected,'immutable original blob bytes changed')
        if key[0]==attempt_id:
            need(r['blob']==binding and r['physical_blob_offset']==0 and r['body_storage_kind']=='immutable_blob','new receipt physical blob differs')
        blobs.append({'start':start,'length':length,'path':str(blob),'sha256':expected,
                      'origin_attempt_id':key[0],'origin_ordinal':key[1],'receipt_sha256':digest(r)})
    need(seen==set(by_origin),'accepted evidence missing from descriptor')
    size=source['size_bytes'];leading=strict_blob_read(blobs,0,4);trailer=strict_blob_read(blobs,size-8,8)
    footer_len=int.from_bytes(trailer[:4],'little');footer_start=size-8-footer_len
    need(leading==b'PAR1' and trailer[4:]==b'PAR1' and 0<footer_len<=max_footer_bytes and footer_start>=4,'original Parquet magic/footer bounds differ')
    footer=strict_blob_read(blobs,footer_start,footer_len+8)
    return {'source_key':source['key'],'source':source,'source_id':sid,'storage_kind':'compact_descriptor',
        'descriptor_path':str(path),'descriptor_sha256':file_sha(path),'available_ranges':[[b['start'],b['start']+b['length']] for b in blobs],
        'verified_blobs':blobs,'whole_source_sha256_verified':False,'whole_source_sha256':None,
        'range_receipts_canonical_sha256':digest([x['receipt'] for x in wrappers]),
        'original_footer_evidence':{'leading_magic_sha256':hashlib.sha256(leading).hexdigest(),'footer_start':footer_start,
                                  'footer_length':footer_len,'footer_and_trailer_sha256':hashlib.sha256(footer).hexdigest()}}

RUNTIME_ROOT=Path('/tmp/article2_phase16_runtime_159bf77d8682')
REQUIRED_PARENT={'frozen_plan.json','runtime_acceptances.json','transport/plan.json','transport/session.json',
    'transport/requests.json','runtime_source_paths.json','transport/requests.json.pending','failure.json','collection_result.json'}
LIMITS={'absolute_deadline_seconds_from_a1_start':14400,'cumulative_get_limit':5000,
    'cumulative_response_byte_limit':17179869184,'automatic_retries':0,'maximum_explicit_manual_reacquisitions':1,
    'pending_get_byte_charge':'FULL_DECLARED_RANGE_LENGTH','source_storage':'IMMUTABLE_RANGE_BLOBS_STRICT_ARROW_VIEW',
    'pending_parent_range_accepted':False}
CODE_NAMES={'protocol.py','compact_collector.py','pipeline.py','independent_transport_audit.py',
    'independent_compact_reader.py','audit_sources.py'}

def check_fields(value,expected,message):
    for key,item in expected.items():need(key in value and canonical(value[key])==canonical(item),message+': '+key)

def metadata_inventory(root):
    result={str(p.relative_to(root)):file_sha(p) for p in sorted(root.rglob('*'))
            if p.is_file() and (p.name.endswith('.json') or p.name.endswith('.json.pending'))}
    for name in REQUIRED_PARENT:result.setdefault(name,None)
    return result

def validate_forensic_evidence(documents,bindings,parent,session,requests,binding_parent):
    """Authenticate external closure without inventing a producer failure record."""
    pending=requests[-1];known=sum(r['response_bytes'] for r in requests[:-1])
    att=documents['external_resource_failure_attestation']
    check_fields(att,{'schema_version':'article2_phase16_external_resource_failure_attestation_v1',
        'status':'ROOT_OBSERVED_TERMINATED_ENOSPC_ORIGINAL_CHECKPOINT_UNCHANGED',
        'conservative_parent_response_byte_charge':known+pending['length'],
        'producer_failure_json_exists':False,'producer_collection_result_exists':False,
        'committed_metadata_rewritten':False,'canonical_source_bytes_changed_by_root':False,
        'source_payload_decoded_by_original_collection':True,'new_detector_scores_computed':0,
        'new_reference_requests':0,'wall_continuation_eligible':False},'external ENOSPC attestation differs')
    terminal=att['terminal_observation'];obs=att['process_observation'];checkpoint=att['original_checkpoint']
    need(terminal['exit_code']==1 and terminal['reported_primary_exception']=='OSError: [Errno 28] No space left on device'
         and terminal['tool_output_chunk_id'] and terminal['source_of_attestation'],'terminal failure not externally attested ENOSPC')
    lower,upper=utc(obs['last_observed_running_utc']),utc(obs['first_observed_ended_utc'])
    need(utc(session['updated_utc'])<=lower<=upper<=utc(att['attested_utc'])
         and obs['exact_failure_time_known'] is False,'external termination bracket differs')
    bound(obs['runtime_observer_log'],binding_parent)
    check_fields(checkpoint,{'status':session['status'],'attempt_id':session['attempt_id'],'started_utc':session['started_utc'],
        'last_updated_utc':session['updated_utc'],'wall_seconds_elapsed':session['wall_seconds_elapsed'],
        'request_count':len(requests),'successful_request_count':len(requests)-1,
        'committed_successful_response_bytes':known},'external checkpoint differs')
    need(checkpoint['failed_terminal_request']=={'ordinal':pending['ordinal'],'source_key':pending['source']['key'],
        'start':pending['start'],'length':pending['length'],'persisted_response_bytes_placeholder':0,
        'actual_terminal_received_bytes':None,'actual_terminal_written_bytes':None,
        'response_completion_and_identity_headers_persisted':False,'accepted_for_source_use':False,
        'conservative_charge_bytes':pending['length']},'pending unknown was converted into response evidence')
    support={b['sha256'] for b in att['supporting_evidence']}
    need({bindings[k]['sha256'] for k in FORENSIC_NAMES-{'external_resource_failure_attestation'}}<=support,'forensic cross-bindings absent')
    for b in att['supporting_evidence']:bound(b,binding_parent)
    inventory=documents['metadata_inventory'];summary=inventory['summary']
    need(inventory['schema_version']=='article2_phase16_readonly_a1_metadata_forensics_v1','metadata inventory schema')
    check_fields(summary,{'all_files_stable_during_read':True,'committed_request_records':len(requests),
        'committed_successful_requests':len(requests)-1,'committed_response_bytes_sum':known,
        'committed_incomplete_ordinals':[pending['ordinal']],'cache_successful_range_records':len(requests)-1,
        'cache_accepted_response_bytes_sum':known,'session_counts_match_committed_requests':True,
        'complete_attempt_costs_established':False,'failure_json_exists':False,'collection_result_json_exists':False,
        'cache_receipt_mismatch_ordinals':[],'cache_non_successful_ordinals':[],
        'duplicate_cache_ordinals':[],'successful_committed_requests_missing_cache':[]},'metadata forensic evidence differs')
    check_fields(session,summary['session'],'forensic session snapshot differs')
    for entry in inventory['files']:
        p=inside(parent,entry['path']);need(p.is_file() and p.stat().st_size==entry['size_bytes'] and file_sha(p)==entry['sha256'],'original metadata snapshot differs')
    allocation=documents['allocation_review']
    check_fields(allocation,{'schema_version':'phase16_enospc_allocation_review_v1',
        'status':'FORENSIC_METADATA_ONLY_NO_SCIENTIFIC_ADMISSION','capture_mutations_by_this_reviewer':False,
        'source_payload_read_by_this_report':False},'allocation review differs')
    need(allocation['metadata_inventory']['sha256']==bindings['metadata_inventory']['sha256'],'allocation inventory binding differs')
    relocation=documents['path_relocation']
    check_fields(relocation,{'schema_version':'article2_phase16_forensic_path_relocation_v1',
        'capture_file_contents_modified':False},'relocation evidence differs')
    old=Path(relocation['old_logical_root'])
    need(Path(relocation['current_physical_root']).resolve()==parent and old.is_symlink() and old.resolve()==parent,'relocation physical/logical root differs')
    preserved={x['path']:x['sha256'] for x in inventory['files'] if x['checkpoint_kind']=='COMMITTED_FILENAME'}
    need(relocation['metadata_sha256_before_and_after']==preserved,'relocation hashes omit/change original committed metadata')
    check_fields(documents['accepted_range_review'],{'status':'CANONICAL_ACCEPTED_RANGES_HASH_VERIFIED_AUXILIARY_COPIES_REMOVED',
        'verified_successful_requests':len(requests)-1,'verified_response_bytes':known,
        'canonical_capture_files_changed':False,'pending_request_not_promoted':True},'prior accepted range review differs')
    return known,pending,lower,upper

def validate_chain(amendment_path,expected_sha256,repo):
    path=Path(amendment_path).resolve();amendment=read(path,expected_sha256)
    check_fields(amendment,{'schema_version':'article2_phase16_storage_recovery_acceptance_v1',
        'status':'ACCEPTED_BEFORE_RECOVERY_IMPORT_AND_REQUESTS_ONLY','accepted_before_recovery_requests':True,
        'accepted_before_recovery_source_import':True,'source_payload_previously_exposed':True},'prospective recovery acceptance differs')
    need('accepted_before_affected_payload' not in amendment,'false before-original-payload assertion')
    plan_path=bound(amendment['recovery_plan'],path.parent);plan=read(plan_path)
    original_path=bound(plan['original_plan_binding'],plan_path.parent);original=read(original_path)
    extra={'original_plan_binding','storage_recovery_transport','storage_recovery_execution_bindings'}
    baseline={k:v for k,v in plan.items() if k not in extra};baseline['schema_version']=original['schema_version']
    need(plan['schema_version']=='article2_phase16_storage_recovery_source_plan_v1'
         and canonical(baseline)==canonical(original),'original scientific/source plan changed')
    need(canonical(plan['storage_recovery_transport'])==canonical(LIMITS),'operational recovery limits changed')
    caps=original['collector']['caps'];check_fields(caps,{'wall_seconds':7200,'requests':5000,'total_response_bytes':BYTE_LIMIT,
        'request_timeout_seconds':60,'retries':0,'concurrency':1},'original transport limits differ')
    code=[]
    for b in plan['storage_recovery_execution_bindings']:
        need(not Path(b['path']).is_absolute() and '..' not in Path(b['path']).parts,'code binding not repository relative')
        code.append(bound(b,repo))
    required={Path(__file__).resolve().parent/name for name in CODE_NAMES}
    need(len(code)==6 and set(code)==required,'exact six recovery code bindings missing/extra/duplicate')
    seal_path=bound(amendment['first_attempt_seal'],path.parent);seal=read(seal_path)
    check_fields(seal,{'schema_version':'article2_phase16_external_resource_closure_seal_v1',
        'status':'EXTERNALLY_CLOSED_ENOSPC_CHECKPOINT_PRESERVED','closure_class':'EXTERNAL_ENOSPC_TERMINATION',
        'producer_status':'OPEN_REQUEST_PENDING','original_plan_sha256':plan['original_plan_binding']['sha256'],
        'original_attempt_compliant_completion':False},'external closure differs')
    parent=Path(seal['parent_root']).resolve();output=Path(amendment['recovery_output_root'])
    need(parent==RUNTIME_ROOT/'attempt1' and output.is_absolute() and output.resolve()==RUNTIME_ROOT/'attempt2','pinned A1/A2 runtime differs')
    evidence=seal['parent_evidence_bindings'];need(evidence==metadata_inventory(parent)==amendment['parent_evidence_bindings'],'sealed original metadata changed')
    need(evidence['failure.json'] is None and evidence['collection_result.json'] is None
         and evidence['transport/requests.json.pending']==hashlib.sha256(b'').hexdigest(),'original producer closure was manufactured/changed')
    need(canonical(read(parent/'frozen_plan.json'))==canonical(original)
         and canonical(read(parent/'transport/plan.json'))==canonical(original['collector']),'original runtime plan lineage differs')
    session=read(parent/'transport/session.json');requests=read(parent/'transport/requests.json')
    need(session['schema_version']=='article2_phase16_range_capture_v1' and session['status']=='OPEN_REQUEST_PENDING'
         and session['retries']==0 and session['request_count']==len(requests)==PENDING_ORDINAL,'original checkpoint identity differs')
    need(session['attempt_id']==digest({'plan':digest(original['collector']),'started_utc':session['started_utc']})
         and session['plan_canonical_sha256']==digest(original['collector']),'original attempt identity differs')
    need(abs((utc(session['updated_utc'])-utc(session['started_utc'])).total_seconds()-session['wall_seconds_elapsed'])<=2,'original UTC/monotonic discrepancy')
    bindings=seal['forensic_bindings'];need(type(bindings)is dict and set(bindings)==FORENSIC_NAMES and amendment['forensic_bindings']==bindings,'forensic bindings differ')
    need(all(Path(b['path']).is_absolute() for b in bindings.values()),'forensic binding requires absolute path')
    documents={k:read(bound(b,path.parent)) for k,b in bindings.items()}
    known,pending,lower,upper=validate_forensic_evidence(documents,bindings,parent,session,requests,path.parent)
    check_fields(seal,{'attempt_id':session['attempt_id'],'started_utc':session['started_utc'],
        'original_request_count':PENDING_ORDINAL,'original_successful_request_count':KNOWN_PREFIX_COUNT,
        'known_parent_response_bytes':known,'pending_received_bytes':None,
        'reserved_parent_pending_response_bytes':pending['length'],'inherited_charged_response_bytes':known+pending['length'],
        'actual_parent_response_bytes_complete':False},'sealed original costs differ')
    need(utc(seal['process_end_lower_bound_utc'])==lower and utc(seal['process_end_upper_bound_utc'])==upper
         and utc(documents['external_resource_failure_attestation']['attested_utc'])<=utc(seal['sealed_utc']),'external seal chronology differs')
    completed=[];partial=[]
    for directory in sorted((parent/'days').iterdir()):
        need(directory.is_dir() and re.fullmatch(r'\d{4}-\d{2}-\d{2}',directory.name),'unexpected prior day folder')
        core=directory/'core_selection.json';prepared=directory/'prepared.json'
        def local(p):return {'path':str(p.relative_to(parent)),'sha256':file_sha(p)}
        if prepared.exists():
            need(core.is_file(),'prepared prior day missing core seal');completed.append({'day_utc':directory.name,'prepared':local(prepared),'core_selection':local(core)})
        elif core.exists():partial.append({'day_utc':directory.name,'core_selection':local(core)})
    need(completed==seal['completed_days'] and partial==seal['partial_core_selection_seals'] and len(partial)<=1,'prior exposure inventory changed')
    exposure_path=bound(amendment['exposure_report'],path.parent);exposure=read(exposure_path)
    check_fields(exposure,{'schema_version':'article2_phase16_source_only_exposure_report_v1','status':'ROOT_REVIEWED_SOURCE_ONLY_EXPOSURE',
        'first_attempt_seal_sha256':amendment['first_attempt_seal']['sha256'],'source_payload_exposed':True,
        'detector_scoring_started':False,'new_reference_acquisition_started':False,'performance_or_reference_results_examined':False,
        'completed_days':[x['day_utc'] for x in completed],'partial_core_selection_days':[x['day_utc'] for x in partial]},'source-only exposure review differs')
    need(exposure['reviewer'].strip() and exposure['exposure_description'].strip(),'exposure reviewer/description absent')
    accepted=utc(amendment['accepted_utc']);start=utc(session['started_utc'])
    need(upper<=utc(seal['sealed_utc'])<=utc(exposure['reviewed_utc'])<=accepted<start+timedelta(seconds=DEADLINE_SECONDS),'prospective acceptance chronology differs')
    originals=amendment['original_measurement_acceptances']
    need(set(originals)==set(CASES) and canonical(read(parent/'runtime_acceptances.json'))==canonical(originals),'original measurement acceptances changed')
    configs={}
    for b in original['case_configs']:
        config=read(bound(b,repo));need(config['case_id'] not in configs,'duplicate case');configs[config['case_id']]=b
    need(set(configs)==set(CASES),'original case population differs')
    for case,b in originals.items():
        ap=bound(b,path.parent);ac=read(ap)
        check_fields(ac,{'schema_version':'fixed_address_measurement_acceptance_v1','status':'ACCEPTED_FOR_DECLARED_FIXED_ADDRESS_MEASUREMENT',
            'accepted_before_affected_payload':True,'all_frame_dispositions_completed':True,'config_sha256':configs[case]['sha256']},'original measurement acceptance differs')
        need(utc(ac['accepted_utc'])<=start,'original measurement accepted after exposure')
        gp=bound(ac['gate_bindings']['source_plan'],ap.parent);gate=read(gp)
        need(gate['schema_version']=='article2_phase16_bound_source_execution_gate_v1' and gate['status']=='ROOT_ACCEPTED_AS_PART_OF_DECLARED_MEASUREMENT'
             and gate['source_plan']['sha256']==plan['original_plan_binding']['sha256'],'original source execution gate differs')
        bound(gate['source_plan'],gp.parent)
        for b in gate['execution_source_bindings']:bound(b,repo)
    return {'amendment':amendment,'amendment_path':path,'plan':plan,'plan_path':plan_path,
        'original_plan':original,'original_plan_path':original_path,'seal':seal,'seal_path':seal_path,
        'parent':parent,'parent_session':session,'parent_requests':requests,'parent_bindings':evidence}

def prepare_whole_provenance(plan,repo,receipt_path,receipt_sha256):
    """Bind prior ZIP verification; do not rematerialize or reread ZIP files."""
    expectations=read(bound(plan['reuse_expectations_binding'],repo))
    need(expectations['schema_version']=='phase16_retained_original_source_reuse_expectations_v1','whole reuse expectations schema')
    prior={Path(b['path']).name:(read(bound(b,repo)),b['sha256']) for b in expectations['bindings']}
    manifest,msha=prior['manifest.json'];review,rsha=prior['phase4_acquisition_independent_review.json']
    need(review['status']=='PASS' and review['manifest_sha256']==msha and not review['failures'],'pre-exposure independent acquisition review differs')
    recovery=read(receipt_path,receipt_sha256)
    check_fields(recovery,{'schema_version':'phase16_recovered_original_objects_v1',
        'status':'VERIFIED_ORIGINAL_OBJECTS_READY_FOR_COLLECTOR_REUSE',
        'reuse_expectations_sha256':plan['reuse_expectations_binding']['sha256'],
        'new_dataset_http_requests':0,'parquet_rows_decoded':0,'detector_scores':0},'prior original-object recovery receipt differs')
    need(recovery['source_inventory_sha256']==plan['source_union']['sha256'],'recovery source inventory differs')
    need(set(recovery['accepted_case_bindings'])=={'lifi','revest'} and all(x['source_plan_sha256']==plan['original_plan_binding']['sha256'] for x in recovery['accepted_case_bindings'].values()),'recovery original measurement plan differs')
    expected={r['source_key']:r for r in expectations['objects']};objects={r['source_key']:r for r in recovery['objects']}
    archives={r['day_utc']:r for r in recovery['completed_archives']};expected_archives={r['day_utc']:r for r in expectations['archives']}
    need(len(expected)==len(expectations['objects'])==len(objects)==len(recovery['objects'])==18 and set(expected)==set(objects),'recovered original object population differs')
    need(len(archives)==len(recovery['completed_archives'])==len(expected_archives)==9 and set(archives)==set(expected_archives),'prior verified archive population differs')
    for day,a in archives.items():need(a['sha256']==expected_archives[day]['sha256'] and a['bytes']==expected_archives[day]['bytes'],'prior verified ZIP identity differs')
    need(sum(r['size_bytes'] for r in objects.values())==recovery['whole_source_bytes_verified']==expectations['original_source_object_bytes_total'],'recovery byte total differs')
    for key,e in expected.items():
        row=objects[key];need(row['sha256']==e['expected_whole_object_sha256'] and row['size_bytes']==e['size_bytes'] and row['etag_opaque']==e['etag_opaque'],'prior recovered member differs')
    need(set(plan['whole_object_reuse_expectations'])==set(expected),'frozen whole object population differs')
    return {'expected':expected,'objects':objects,'days':{r['day_utc']:r for r in manifest['days']},
        'review_days':{r['day']:r for r in review['days']},'original_manifest_sha256':msha,
        'prior_independent_acquisition_review_sha256':rsha,'recovery_receipt_sha256':receipt_sha256,
        'recovery_receipt_path':str(Path(receipt_path).resolve()),'fresh_zip_reads':0}

def verify_whole_object(source,path,plan,repo,provenance,max_footer_bytes):
    key=source['key'];e=provenance['expected'][key];frozen=plan['whole_object_reuse_expectations'][key]
    need(e['source_key']==key and e['source_url']==source['url'] and e['size_bytes']==source['size_bytes']
         and e['etag_opaque']==source['etag_opaque'],'whole-object expected source identity differs')
    expected=hexsha(e['expected_whole_object_sha256']);need(frozen['sha256']==expected and frozen['size_bytes']==source['size_bytes'] and frozen['etag_opaque']==source['etag_opaque'],'frozen whole identity differs')
    acquired=read(bound(frozen['acquisition_receipt'],repo))
    check_fields(acquired,{'source_key':key,'sha256':expected,'size_bytes':source['size_bytes'],'etag_opaque':source['etag_opaque'],
        'expected_archive_sha256':e['expected_archive_sha256'],'expected_original_member_name':e['expected_original_member_name']},'frozen original acquisition binding differs')
    day=provenance['days'][source['day_utc']];audit=provenance['review_days'][source['day_utc']];receipt=day['source_objects'][source['table']]
    need(receipt['hash_scope']=='whole source object' and receipt['sha256']==expected and receipt['bytes']==source['size_bytes']
         and receipt['source']['url']==source['url'] and receipt['source']['etag']==source['etag_opaque']
         and receipt['source']['size']==source['size_bytes'],'original acquisition receipt identity differs')
    member='headers.parquet' if source['table']=='blocks' else 'logs.parquet'
    need(source['table'] in ('blocks','logs') and e['expected_original_member_name']==member,'noncanonical whole member')
    need(day['archive']['sha256']==audit['archive']['sha256']==e['expected_archive_sha256']
         and audit['status']=='PASS' and audit['all_archive_members_crc_sha_bytes_verified'] is True
         and audit['canonical_whole_source_hashes'][member]=={'bytes':source['size_bytes'],'sha256':expected},'prior independent ZIP/member evidence differs')
    path=Path(path).resolve();need(path.is_file() and path.stat().st_size==source['size_bytes'] and file_sha(path)==expected,'current canonical whole-source bytes differ')
    size=source['size_bytes']
    with path.open('rb') as f:
        leading=f.read(4);f.seek(size-8);trailer=f.read(8)
        n=int.from_bytes(trailer[:4],'little');start=size-8-n
        need(leading==b'PAR1' and trailer[4:]==b'PAR1' and 0<n<=max_footer_bytes and start>=4,'whole-source Parquet framing differs')
        f.seek(start);footer=f.read(n+8)
    return {'source_key':key,'source':source,'source_id':digest(source),'storage_kind':'verified_whole_object',
        'path':str(path),'sha256':expected,'available_ranges':[[0,size]],'whole_source_sha256_verified':True,
        'whole_source_sha256':expected,'verified_blobs':[],'range_receipts_canonical_sha256':digest([]),
        'original_footer_evidence':{'leading_magic_sha256':hashlib.sha256(leading).hexdigest(),'footer_start':start,
            'footer_length':n,'footer_and_trailer_sha256':hashlib.sha256(footer).hexdigest()},
        'whole_object_origin':{'original_acquisition_receipt_sha256':digest(receipt),'original_member_name':member,
            'original_member_sha256':expected,'prior_verified_archive_sha256':e['expected_archive_sha256'],
            'original_manifest_sha256':provenance['original_manifest_sha256'],
            'prior_independent_acquisition_review_sha256':provenance['prior_independent_acquisition_review_sha256'],
            'recovery_receipt_sha256':provenance['recovery_receipt_sha256'],'current_whole_bytes_verified':True,'fresh_zip_reads':0}}

def merge(spans):
    out=[]
    for a,b in sorted(spans):
        if out and a<=out[-1][1]:out[-1][1]=max(b,out[-1][1])
        else:out.append([a,b])
    return out

def write_new(path,value):
    path=Path(path);need(not path.exists(),'audit output already exists');path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x') as f:json.dump(value,f,sort_keys=True,indent=2,allow_nan=False);f.write('\n')

def audit(args):
    repo=args.repo.resolve();root=args.collection.resolve();ctx=validate_chain(args.amendment,args.expected_amendment_sha256,repo)
    amendment=ctx['amendment'];plan=ctx['plan'];original=ctx['original_plan'];plan_sha=amendment['recovery_plan']['sha256']
    need(root==Path(amendment['recovery_output_root']).resolve(),'collection differs from single accepted recovery destination')
    need(not args.output.resolve().is_relative_to(ctx['parent']) and not args.ledger_output.resolve().is_relative_to(ctx['parent']),'audit must not mutate A1')
    need(not args.output.exists() and not args.ledger_output.exists(),'fresh audit/ledger outputs required')
    need(file_sha(root/'frozen_plan.json')==plan_sha and file_sha(root/'storage_recovery_amendment.json')==args.expected_amendment_sha256,'runtime accepted plan/amendment changed')
    result=read(root/'collection_result.json',args.expected_result_sha256)
    check_fields(result,{'schema_version':'phase16_storage_recovery_collection_result_v1','status':'COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT',
        'plan_sha256':plan_sha,'original_plan_binding':plan['original_plan_binding'],'original_source_plan_sha256':plan['original_plan_binding']['sha256'],
        'storage_recovery_amendment_sha256':args.expected_amendment_sha256,'storage_recovery_number':1,'source_payload_previously_exposed':True,
        'transfer_decoding_performed':False,'detector_scoring_performed':False,'labels_used':False,'transport_sources':113,'study_days':37},'collection result differs')
    need(not (root/'failure.json').exists(),'completed collection has failure artifact')
    manifests=read(root/'transport_sources.json',args.expected_transport_sources_sha256)['sources']
    locations=read(root/'runtime_source_storage.json',result['runtime_source_storage_sha256'])
    need(result['transport_sources_sha256']==args.expected_transport_sources_sha256,'result transport manifest digest differs')
    inventory=read(bound(plan['source_union'],repo));need(plan['source_union']==plan['inventory_binding'],'source inventory binding differs')
    sources={identity(s)['key']:identity(s) for s in inventory['objects']}
    need(len(sources)==len(inventory['objects'])==113 and set(locations)==set(sources),'frozen/runtime source population differs')
    by_manifest={m['source']['key']:m for m in manifests};need(len(by_manifest)==len(manifests)==113 and set(by_manifest)==set(sources),'manifest source population differs')
    transport=root/'transport';session=read(transport/'session.json');new_requests=read(transport/'requests.json')
    need(file_sha(transport/'inherited_requests.json')==ctx['parent_bindings']['transport/requests.json'],'full inherited ledger changed or filtered')
    need(read(transport/'plan.json')==original['collector'] and read(transport/'parent_bindings.json')==ctx['parent_bindings']
         and read(transport/'forensic_bindings.json')==amendment['forensic_bindings'],'collector original/forensic binding differs')
    check_fields(session,{'schema_version':'article2_phase16_storage_recovery_capture_v1','status':'COMPLETE',
        'parent_persisted_status':'OPEN_REQUEST_PENDING','parent_closure':'EXTERNALLY_ATTESTED_ENOSPC_EXIT_WITH_UNRESOLVED_FINAL_RESPONSE',
        'recovery_plan_sha256':plan_sha,'original_accepted_plan_sha256':plan['original_plan_binding']['sha256'],
        'original_collector_plan_canonical_sha256':digest(original['collector']),
        'parent_bindings_canonical_sha256':digest(ctx['parent_bindings']),
        'forensic_bindings_canonical_sha256':digest(amendment['forensic_bindings']),
        'parent_positive_bodies_verified':True,'parent_pending_range_imported':False,'runtime_root':str(root),
        'storage_kind':'IMMUTABLE_RANGE_BLOBS_STRICT_ARROW_VIEW','manual_reacquisition':amendment['manual_reacquisition']},'session binding/state differs')
    need(session['attempt_id']==digest({'parent_attempt_id':ctx['parent_session']['attempt_id'],
        'parent_session_sha256':ctx['parent_bindings']['transport/session.json'],'recovery_plan_sha256':plan_sha,'started_utc':session['started_utc']}),'new attempt identity differs')
    caps=original['collector']['caps'];need(session['effective_caps']=={**caps,'wall_seconds':DEADLINE_SECONDS},'effective caps differ')
    costs=validate_cost_ledgers(ctx['parent_requests'],new_requests,ctx['parent_session'],session,sources,caps,
        amendment['accepted_utc'],amendment['manual_reacquisition'])
    accepted=read(transport/'accepted_range_evidence.json')
    need(accepted['schema_version']=='article2_phase16_compact_accepted_ranges_v1','accepted evidence schema')
    wrappers=accepted['ranges'];need([{k:v for k,v in x.items() if k!='blob'} for x in wrappers]==costs['accepted_origins'],'accepted evidence omits/reorders/changes receipts or promotes pending bytes')
    grouped=defaultdict(list)
    for wrapper in wrappers:grouped[wrapper['receipt']['source']['key']].append(wrapper)
    attempted={r['source']['key'] for r in ctx['parent_requests']+new_requests}
    provenance=prepare_whole_provenance(plan,repo,args.recovery_receipt,args.expected_recovery_receipt_sha256)
    verified=[];reuses=[]
    for key,source in sources.items():
        need(source['size_bytes']<=caps['max_source_bytes'],'whole/range source size cap')
        location=locations[key];need(set(location)=={'storage_kind','path'},'typed source location fields differ')
        path=Path(location['path']);need(path.is_absolute(),'runtime source location is not absolute')
        m=by_manifest[key];rows=grouped[key];receipts=[x['receipt'] for x in rows]
        need(m['schema_version']=='article2_phase16_compact_projected_source_manifest_v1' and m['source']==source
             and m['source_id']==digest(source) and m['storage_kind']==location['storage_kind'],'source manifest identity/storage differs')
        if location['storage_kind']=='compact_descriptor':
            checked=verify_compact_descriptor(path,source,rows,root,session['attempt_id'],session['parent_attempt_id'],caps['max_footer_bytes'])
            need(m['whole_source_sha256_verified'] is False and m['whole_source_sha256'] is None
                 and m['descriptor_sha256']==checked['descriptor_sha256'],'sparse compact object misrepresented as whole source')
        else:
            need(location['storage_kind']=='verified_whole_object' and not rows and key not in attempted,'whole source replaces attempted range evidence')
            checked=verify_whole_object(source,path,plan,repo,provenance,caps['max_footer_bytes']);reuses.append(key)
            need(m['whole_source_sha256_verified'] is True and m['whole_source_sha256']==checked['sha256'],'whole-source manifest digest differs')
        available=merge(checked['available_ranges'])
        need(m['successful_original_ranges']==receipts and m['evidence_origins']==rows
             and m['available_ranges']==available and m['available_original_bytes']==sum(b-a for a,b in available),'manifest accepted range evidence differs')
        need(m['inherited_ranges']==[x for x in rows if x['origin_attempt_id']==session['parent_attempt_id']]
             and m['new_ranges']==[x['receipt'] for x in rows if x['origin_attempt_id']==session['attempt_id']],'manifest original/new lineage differs')
        need(m['holes_are_original_bytes'] is False and m['statistics_values_exported_or_used'] is False
             and m['receipt_roots_verified'] is False and m['independent_chain_completeness_verified'] is False,'producer claims unsupported source integrity')
        verified.append(checked)
    need(set(reuses)==set(provenance['expected']) and len(reuses)==18,'whole reuse count/population differs')
    claimed={x['source_id'] for x in session['cache_or_full_object_reuses'] if x['kind']=='verified_whole_object'}
    need(claimed=={digest(sources[k]) for k in reuses},'whole reuse session accounting differs')
    need(ctx['parent_bindings']==metadata_inventory(ctx['parent']),'A1 metadata changed during byte audit')
    need(file_sha(ctx['amendment_path'])==args.expected_amendment_sha256 and file_sha(ctx['plan_path'])==plan_sha,'acceptance changed during audit')
    clean_costs={k:v for k,v in costs.items() if k!='accepted_origins'}
    ledger={'schema_version':'article2_phase16_storage_recovery_multiattempt_ledger_v1',
        'status':'VERIFIED_RECORDED_COSTS_WITH_FULL_UNRESOLVED_PENDING_RESERVATION','storage_recovery_amendment_sha256':args.expected_amendment_sha256,
        'original_source_plan_sha256':plan['original_plan_binding']['sha256'],'plan_sha256':plan_sha,
        'first_attempt_seal_sha256':amendment['first_attempt_seal']['sha256'],'forensic_bindings':amendment['forensic_bindings'],
        'inherited_requests_sha256':file_sha(transport/'inherited_requests.json'),'new_requests_sha256':file_sha(transport/'requests.json'),
        'original_session_sha256':ctx['parent_bindings']['transport/session.json'],'new_session_sha256':file_sha(transport/'session.json'),
        'inherited_requests':ctx['parent_requests'],'new_requests':new_requests,'limits':LIMITS,**clean_costs}
    write_new(args.ledger_output,ledger)
    report={'schema_version':'article2_phase16_independent_storage_recovery_transport_audit_v1',
        'status':'PASS_STORAGE_RECOVERY_TRANSPORT_ORIGINAL_BYTES','recorded_utc':datetime.now(timezone.utc).isoformat(),
        'auditor_sha256':file_sha(__file__),'plan_sha256':plan_sha,'original_source_plan_sha256':plan['original_plan_binding']['sha256'],
        'storage_recovery_amendment_path':str(ctx['amendment_path']),'storage_recovery_amendment_sha256':args.expected_amendment_sha256,
        'first_attempt_seal_path':str(ctx['seal_path']),'first_attempt_seal_sha256':amendment['first_attempt_seal']['sha256'],
        'parent_root':str(ctx['parent']),'collection_result_sha256':args.expected_result_sha256,
        'transport_sources_sha256':args.expected_transport_sources_sha256,'runtime_source_storage_sha256':result['runtime_source_storage_sha256'],
        'requests_sha256':file_sha(transport/'requests.json'),'inherited_requests_sha256':file_sha(transport/'inherited_requests.json'),
        'session_sha256':file_sha(transport/'session.json'),'accepted_range_evidence_sha256':file_sha(transport/'accepted_range_evidence.json'),
        'multiattempt_ledger_path':str(args.ledger_output.resolve()),'multiattempt_ledger_sha256':file_sha(args.ledger_output),
        'source_count':len(verified),'whole_object_reuse_count':len(reuses),'verified_sources':verified,
        'recovery_receipt_sha256':args.expected_recovery_receipt_sha256,'fresh_zip_reads':0,'network_requests':0,
        'parquet_rows_decoded':0,'selection_or_scientific_acceptance':False,'receipt_root_verified':False,**clean_costs,
        'limitations':['Original ENOSPC terminal response bytes remain unknown; full requested length is reserved, not reported as measured wire traffic.',
            'Imported bytes match original accepted response digests and bound forensic lineage; original pending bytes are never imported.',
            'Prior bound ZIP/member verification is reused; current canonical whole-source bytes are freshly hashed without rereading ZIP files.',
            'Required column extents, all table projections, daily selection, bundles and decisions require separate independent audit.']}
    write_new(args.output,report);return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('repo','collection','amendment','recovery-receipt','output','ledger-output'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('expected-amendment-sha256','expected-result-sha256','expected-transport-sources-sha256','expected-recovery-receipt-sha256'):p.add_argument('--'+name,required=True)
    args=p.parse_args();report=audit(args)
    print(json.dumps({k:report[k] for k in ('status','source_count','whole_object_reuse_count','cumulative_request_count','cumulative_charged_response_bytes')}))

if __name__=='__main__':main()
