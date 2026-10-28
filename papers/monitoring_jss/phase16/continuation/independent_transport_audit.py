#!/usr/bin/env python3
"""Candidate independent audit of one explicitly accepted transport continuation.

No network or Parquet decoding. Original A1 receipts, including failed bytes,
remain distinct from new A2 receipts and from successful evidence. This module
does not itself authorize continuation or alter the original capture.
"""
from __future__ import annotations
from collections import defaultdict
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re

ENDPOINT='https://aws-public-blockchain.s3.us-east-2.amazonaws.com/'
TOTAL_REQUEST_CAP=5000
TOTAL_BYTE_CAP=16*1024**3
ABSOLUTE_WALL_SECONDS=14400
WALL_FAILURES={'ValueError: wall cap during range',
               'ValueError: wall cap after range read',
               'ValueError: wall cap after response close'}
TIMEOUT_PAIRS={('TimeoutError','timed out'),('TimeoutError','The read operation timed out'),
               ('URLError','<urlopen error timed out>'),('URLError','<urlopen error The read operation timed out>')}
TIMEOUT_FAILURES={name+': '+message for name,message in TIMEOUT_PAIRS}
RESPONSE_FIELDS={'http_status','response_url','etag','content_range','content_length','content_encoding'}
IDENTITY_FIELDS=('table','day_utc','key','size_bytes','etag_opaque','url')
CASES=('lifi_20220320','revest_20220327')
REQUIRED_PARENT={'frozen_plan.json','runtime_acceptances.json','transport/plan.json',
                 'transport/session.json','transport/requests.json','runtime_source_paths.json',
                 'failure.json','collection_result.json'}

def need(ok,message):
    if not ok:raise ValueError(message)

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()

def digest(value):return hashlib.sha256(canonical(value)).hexdigest()

def integer(value,name,minimum=0):
    need(type(value)is int and value>=minimum,'invalid integer: '+name);return value

def sha(value):
    need(type(value)is str and re.fullmatch('[0-9a-f]{64}',value),'invalid SHA256');return value

def file_sha(path,start=0,length=None):
    h=hashlib.sha256();got=0
    with Path(path).open('rb') as f:
        f.seek(start)
        while length is None or got<length:
            b=f.read(1048576 if length is None else min(1048576,length-got))
            if not b:break
            got+=len(b);h.update(b)
    need(length is None or got==length,'retained original bytes truncated');return h.hexdigest()

def read(path,expected=None):
    if expected is not None:need(file_sha(path)==sha(expected),'bound artifact changed: '+str(path))
    def pairs(items):
        out={}
        for key,value in items:
            need(key not in out,'duplicate JSON key');out[key]=value
        return out
    return json.loads(Path(path).read_bytes(),object_pairs_hook=pairs,
                      parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite JSON')))

def bound(value,base):
    need(type(value)is dict and set(value)=={'path','sha256'},'binding fields differ')
    p=Path(value['path']);p=p if p.is_absolute() else Path(base)/p
    need(p.is_file() and file_sha(p)==sha(value['sha256']),'bound artifact changed: '+str(p));return p.resolve()

def parent_path(parent,name):
    p=Path(name);need(type(name)is str and name and not p.is_absolute() and '..' not in p.parts,'unsafe parent evidence path')
    out=(Path(parent)/p).resolve();need(out.is_relative_to(Path(parent).resolve()),'parent evidence path escapes');return out

def utc(value):
    need(type(value)is str,'UTC timestamp required')
    out=datetime.fromisoformat(value.replace('Z','+00:00'))
    need(out.utcoffset()==timedelta(0),'explicit UTC timestamp required');return out

def identity(source):
    out={k:source[k] for k in IDENTITY_FIELDS};table=out['table'];day=out['day_utc']
    need(table in ('blocks','logs','transactions'),'unknown source table')
    need(type(day)is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}',day),'source date')
    need(re.fullmatch(r'v1\.0/eth/'+table+'/date='+day+r'/[A-Za-z0-9_.-]+\.parquet',out['key']),'source key')
    need(out['url']==ENDPOINT+out['key'],'source URL')
    integer(out['size_bytes'],'source bytes',12)
    need(type(out['etag_opaque'])is str and out['etag_opaque'],'source ETag missing');return out

def overlap(a,b):return max(a[0],b[0])<min(a[1],b[1])

def deadline_associated_timeout(record,session):
    """Exact operational association only; the actual timeout argument is unknown."""
    if record.get('failure') not in TIMEOUT_FAILURES or record.get('transport_ok') is not False:return False
    start=utc(session['started_utc']);deadline=start+timedelta(seconds=7200)
    begin,end=utc(record['started_utc']),utc(record['completed_utc']);closed=utc(session['updated_utc'])
    elapsed=session['wall_seconds_elapsed']
    if not (start+timedelta(seconds=7140)<=begin<deadline<=end<=closed and elapsed>=7200
            and abs((closed-start).total_seconds()-elapsed)<=2):return False
    present=RESPONSE_FIELDS.intersection(record)
    if not present:return record['response_bytes']==0
    if present!=RESPONSE_FIELDS:return False
    source=record['source'];a,n=record['start'],record['length'];length=record['content_length']
    return (record['http_status']==206 and record['response_url']==source['url']
            and record['etag']==source['etag_opaque']
            and record['content_range']==f'bytes {a}-{a+n-1}/{source["size_bytes"]}'
            and type(length)is str and length.isdigit() and int(length)==n
            and record['content_encoding'] in (None,'identity'))

def validate_chain(amendment_path,expected_sha256,repo):
    """Independently bind prospective acceptance, immutable exposure, and code."""
    path=Path(amendment_path).resolve();amendment=read(path,expected_sha256)
    need(amendment['schema_version']=='article2_phase16_source_continuation_acceptance_v1'
         and amendment['status']=='ACCEPTED_BEFORE_CONTINUATION_ONLY','continuation not prospectively accepted')
    need('accepted_before_affected_payload' not in amendment
         and amendment['accepted_before_continuation_requests'] is True
         and amendment['source_payload_previously_exposed'] is True,'original exposure was hidden or backdated')
    plan_path=bound(amendment['continuation_plan'],path.parent);plan=read(plan_path)
    original_path=bound(plan['original_plan_binding'],plan_path.parent);original=read(original_path)
    extra={'original_plan_binding','continuation_transport','continuation_execution_bindings'}
    baseline={k:v for k,v in plan.items() if k not in extra};baseline['schema_version']=original['schema_version']
    need(plan['schema_version']=='article2_phase16_continuation_source_plan_v1'
         and canonical(baseline)==canonical(original),'original scientific/source plan was changed')
    limits={'absolute_deadline_seconds_from_a1_start':14400,'cumulative_get_limit':5000,
            'cumulative_response_byte_limit':17179869184,'automatic_retries':0,'maximum_explicit_manual_reacquisitions':1,
            'failed_get_byte_charge':'FULL_DECLARED_RANGE_LENGTH'}
    need(canonical(plan['continuation_transport'])==canonical(limits),'continuation limits differ')
    caps=original['collector']['caps'];need(caps['wall_seconds']==7200 and caps['requests']==5000
        and caps['total_response_bytes']==17179869184 and caps['retries']==0 and caps['concurrency']==1,'original caps differ')
    execution=plan['continuation_execution_bindings'];code_paths=[bound(x,repo) for x in execution]
    required={Path(__file__).resolve(),Path(__file__).with_name('protocol.py').resolve(),
              Path(__file__).with_name('collector.py').resolve(),Path(__file__).with_name('continue_pipeline.py').resolve(),
              Path(__file__).with_name('audit_sources.py').resolve()}
    need(len(code_paths)==len(set(code_paths)) and required<=set(code_paths),'prospective executable/auditor binding absent or repeated')
    seal_path=bound(amendment['first_attempt_seal'],path.parent);seal=read(seal_path)
    need(seal['schema_version']=='article2_phase16_first_attempt_closure_seal_v1'
         and seal['status']=='CLOSED_ORIGINAL_ATTEMPT_PRESERVED'
         and seal['original_attempt_compliant_completion'] is False
         and seal['original_plan_sha256']==plan['original_plan_binding']['sha256'],'original closure seal differs')
    parent=Path(seal['parent_root']).resolve();evidence=seal['parent_evidence_bindings']
    output_root=Path(amendment['continuation_output_root'])
    need(output_root.is_absolute() and not output_root.resolve().is_relative_to(parent),'continuation destination absent or inside original capture')
    need(type(evidence)is dict and REQUIRED_PARENT<=set(evidence) and amendment['parent_evidence_bindings']==evidence,'original evidence map differs/incomplete')
    names={str(p.relative_to(parent)) for p in parent.rglob('*.json') if p.is_file()}
    need(names=={n for n,s in evidence.items() if s is not None},'immutable original JSON inventory changed')
    for name,expected in evidence.items():
        p=parent_path(parent,name)
        if expected is None:need(not p.exists(),'formerly absent original artifact appeared')
        else:need(p.is_file() and file_sha(p)==sha(expected),'original metadata changed: '+name)
    need(canonical(read(parent/'frozen_plan.json'))==canonical(original)
         and canonical(read(parent/'transport/plan.json'))==canonical(original['collector']),'original plan lineage differs')
    session=read(parent/'transport/session.json');requests=read(parent/'transport/requests.json')
    need(session['schema_version']=='article2_phase16_range_capture_v1','a continuation cannot itself be continued')
    need(seal['producer_status']==session['status'] and seal['original_wall_contract_status']=='FAILED','original producer/wall distinction hidden')
    need(session['attempt_id']==seal['attempt_id']==digest({'plan':digest(original['collector']),'started_utc':session['started_utc']}),'original attempt identity differs')
    need(session['started_utc']==seal['started_utc'] and session['updated_utc']==seal['closed_utc'],'original start/closure differs')
    start,closed=utc(session['started_utc']),utc(session['updated_utc'])
    need(type(session['wall_seconds_elapsed']) in (int,float) and session['wall_seconds_elapsed']>=7200
         and abs((closed-start).total_seconds()-session['wall_seconds_elapsed'])<=2,'natural original wall closure not established')
    need((seal['original_request_count'],seal['original_response_bytes'],seal['original_wall_seconds_elapsed'])
         ==(len(requests),sum(x['response_bytes'] for x in requests),session['wall_seconds_elapsed']),'sealed original costs differ')
    failure=read(parent/'failure.json') if evidence['failure.json'] is not None else None
    collection=read(parent/'collection_result.json') if evidence['collection_result.json'] is not None else None
    unsuccessful=[x for x in requests if x.get('transport_ok') is not True]
    reserved=sum(integer(x['length']-x['response_bytes'],'unretained original failed range bytes') for x in unsuccessful)
    need(seal['reserved_parent_failed_response_bytes']==reserved
         and seal['inherited_charged_response_bytes']==sum(x['response_bytes'] for x in requests)+reserved,'original conservative byte reservation differs')
    complete=session['status']=='COMPLETE'
    if complete:
        need(seal['closure_class']=='COMPLETE_OVER_ORIGINAL_WALL_LIMIT' and session['wall_seconds_elapsed']>7200
             and failure is None and collection is not None and not unsuccessful
             and collection['status']=='COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT'
             and collection['plan_sha256']==plan['original_plan_binding']['sha256'],'producer COMPLETE does not establish eligible over-wall closure')
        need(seal['timeout_causality_unresolved'] is False,'complete branch cannot assert timeout uncertainty')
    else:
        need(session['status']=='FAILED' and failure is not None and collection is None,'original is not natural FAILED closure')
        need(failure['status']=='FAILED_NOT_ACCEPTED','original failure status differs')
        if unsuccessful:
            need(len(unsuccessful)==1 and unsuccessful[0] is requests[-1],'only final failed GET may be eligible')
            last=unsuccessful[0];timeout=deadline_associated_timeout(last,session)
            if timeout:
                need((failure['error_type'],failure['error']) in TIMEOUT_PAIRS
                     and last['failure']==failure['error_type']+': '+failure['error']
                     and seal['closure_class']=='DEADLINE_ASSOCIATED_TIMEOUT_CAUSALITY_UNRESOLVED'
                     and seal['timeout_causality_unresolved'] is True
                     and amendment['manual_reacquisition'] is not None,'deadline timeout association/uncertainty/manual authorization differs')
            else:
                need(failure['error_type']=='ValueError' and last.get('failure') in WALL_FAILURES
                     and last['failure']=='ValueError: '+failure['error'] and seal['closure_class']=='WALL_LIMIT_FAILED'
                     and seal['timeout_causality_unresolved'] is False,'last failure was neither exact wall expiry nor narrowly associated timeout')
        else:need(failure['error_type']=='ValueError' and failure['error']=='wall/request cap'
                  and len(requests)<5000 and seal['closure_class']=='WALL_LIMIT_FAILED'
                  and seal['timeout_causality_unresolved'] is False,'pre-request failure was not exclusively wall expiry')
    for report in (failure,collection):
        if report is not None:need(report['transfer_decoding_performed'] is False and report['detector_scoring_performed'] is False,'original attempt not source-only')
    dates=[]
    for day in seal['completed_days']:
        dates.append(day['day_utc'])
        for field,name in (('prepared','prepared.json'),('core_selection','core_selection.json')):
            b=day[field];need(b['path']==f'days/{day["day_utc"]}/{name}' and evidence[b['path']]==b['sha256'],'completed exposure artifact not sealed')
    beginning=datetime.fromisoformat(original['study_start'])
    need(dates==[(beginning+timedelta(days=i)).date().isoformat() for i in range(len(dates))],'completed exposure is not an exact study prefix')
    partial=seal['partial_core_selection_seals'];need(len(partial)<=1,'multiple incomplete core-selection days')
    for day in partial:
        b=day['core_selection'];need(b['path']==f'days/{day["day_utc"]}/core_selection.json'
             and evidence[b['path']]==b['sha256'] and day['day_utc']==(beginning+timedelta(days=len(dates))).date().isoformat(),'partial core-selection exposure differs')
    exposure_path=bound(amendment['exposure_report'],path.parent);exposure=read(exposure_path)
    need(exposure['schema_version']=='article2_phase16_source_only_exposure_report_v1'
         and exposure['status']=='ROOT_REVIEWED_SOURCE_ONLY_EXPOSURE'
         and exposure['first_attempt_seal_sha256']==amendment['first_attempt_seal']['sha256'],'exposure review not bound')
    need(exposure['source_payload_exposed'] is True and exposure['detector_scoring_started'] is False
         and exposure['new_reference_acquisition_started'] is False
         and exposure['performance_or_reference_results_examined'] is False,'performance/reference exposure makes continuation ineligible')
    need(exposure['completed_days']==dates and exposure['partial_core_selection_days']==[x['day_utc'] for x in partial],'exposed day membership omitted')
    need(type(exposure['reviewer'])is str and exposure['reviewer'].strip()
         and type(exposure['exposure_description'])is str and exposure['exposure_description'].strip(),'exposure reviewer/description absent')
    accepted=utc(amendment['accepted_utc'])
    need(closed<=utc(seal['sealed_utc'])<=utc(exposure['reviewed_utc'])<=accepted<start+timedelta(seconds=14400),'prospective closure/exposure/acceptance chronology differs')
    eligibility=amendment.get('complete_overwall_source_validity_review')
    if complete:
        need(eligibility is not None,'COMPLETE-over-wall requires independent original source validity proof')
        ep=bound(eligibility,path.parent);er=read(ep)
        need(er['schema_version']=='article2_phase16_complete_overwall_eligibility_review_v1'
             and er['status']=='PASS_SOURCE_VALIDITY_ONLY_ORIGINAL_WALL_CONTRACT_FAILED'
             and er['first_attempt_seal_sha256']==amendment['first_attempt_seal']['sha256']
             and er['original_plan_sha256']==plan['original_plan_binding']['sha256']
             and er['original_collection_result_sha256']==evidence['collection_result.json']
             and er['producer_status']=='COMPLETE' and er['original_wall_contract_status']=='FAILED','over-wall eligibility scope/status differs')
        for field in ('all_http_gets_within_original_deadline','all_source_parts_and_projection_integrity_valid','selection_and_prepared_bundles_valid'):need(er[field] is True,'over-wall source validity incomplete')
        need(er['source_identity_schema_validation_errors'] is False and er['source_objects']==113 and er['study_days']==37
             and type(er['reviewer'])is str and er['reviewer'].strip() and bool(er['evidence_bindings']),'over-wall independent validity evidence missing')
        need(utc(seal['sealed_utc'])<=utc(er['reviewed_utc'])<=accepted,'source eligibility review not prospective')
        for b in er['evidence_bindings']:bound(b,ep.parent)
    else:need(eligibility is None,'ordinary FAILED branch has unexpected complete eligibility claim')
    originals=amendment['original_measurement_acceptances']
    need(set(originals)==set(CASES) and canonical(read(parent/'runtime_acceptances.json'))==canonical(originals),'original two measurement acceptances changed')
    configs={}
    for b in original['case_configs']:
        cp=bound(b,repo);config=read(cp);need(config['case_id'] not in configs,'duplicate case config');configs[config['case_id']]=(b,config)
    need(set(configs)==set(CASES),'original case set differs')
    for case,b in originals.items():
        ap=bound(b,path.parent);ac=read(ap)
        need(ac['schema_version']=='fixed_address_measurement_acceptance_v1'
             and ac['status']=='ACCEPTED_FOR_DECLARED_FIXED_ADDRESS_MEASUREMENT'
             and ac['accepted_before_affected_payload'] is True and ac['all_frame_dispositions_completed'] is True
             and ac['config_sha256']==configs[case][0]['sha256'] and utc(ac['accepted_utc'])<=start,'original measurement acceptance differs')
        gate_path=bound(ac['gate_bindings']['source_plan'],ap.parent);gate=read(gate_path)
        need(gate['schema_version']=='article2_phase16_bound_source_execution_gate_v1'
             and gate['status']=='ROOT_ACCEPTED_AS_PART_OF_DECLARED_MEASUREMENT'
             and gate['source_plan']['sha256']==plan['original_plan_binding']['sha256'],'original source-plan authorization differs')
        bound(gate['source_plan'],gate_path.parent)
        for b in gate['execution_source_bindings']:bound(b,repo)
    return {'amendment':amendment,'amendment_path':path,'plan':plan,'plan_path':plan_path,
            'original_plan':original,'original_plan_path':original_path,'seal':seal,'exposure':exposure,
            'parent':parent,'parent_session':session,'parent_requests':requests,
            'parent_bindings':evidence,'manual_reacquisition':amendment['manual_reacquisition']}

def validate_record(record,ordinal,sources,caps):
    integer(record['ordinal'],'request ordinal',1);need(record['ordinal']==ordinal,'global request ordinal differs')
    source=identity(record['source']);key=source['key']
    need(key in sources and record['source']==sources[key]==source,'request source differs from frozen inventory')
    start=integer(record['start'],'request start');length=integer(record['length'],'request length',1)
    got=integer(record['response_bytes'],'received bytes')
    need(start+length<=source['size_bytes']<=caps['max_source_bytes'] and length<=caps['max_range_bytes'] and got<=length,'request/source bounds')
    need(record['method']=='GET' and record['stored_offset']==start and record['stored_file_name']=='source.parquet','request method/storage differs')
    headers=record['request_headers']
    need(headers['Range']==f'bytes={start}-{start+length-1}' and headers['If-Match']==source['etag_opaque'] and headers['Accept-Encoding']=='identity','request headers differ')
    need(type(record['transport_ok'])is bool and record['invalid_header_body_read'] is False,'transport acceptance flags')
    sha(record['response_sha256'])
    if got==0:need(record['response_sha256']==hashlib.sha256(b'').hexdigest(),'zero-byte receipt hash differs')
    begin,end=utc(record['started_utc']),utc(record['completed_utc']);need(begin<=end,'request chronology')
    if record['transport_ok']:
        need(got==length and 'failure' not in record,'successful receipt has partial/failure')
    # A wall-failed GET had already passed all header predicates before reading.
    if record['transport_ok'] or record.get('failure') in WALL_FAILURES or (record.get('failure') in TIMEOUT_FAILURES and RESPONSE_FIELDS.intersection(record)):
        need(record['http_status']==206 and record['response_url']==source['url'] and record['etag']==source['etag_opaque'],'HTTP status/identity differs')
        need(record['content_range']==f'bytes {start}-{start+length-1}/{source["size_bytes"]}','Content-Range differs')
        n=record['content_length'];need(type(n)is str and n.isdigit() and int(n)==length,'Content-Length differs')
        need(record['content_encoding'] in (None,'identity'),'encoded response')
    return source,[start,start+length],begin,end

def validate_ledgers(parent_requests,new_requests,parent_session,new_session,sources,original_caps,
                     accepted_utc,manual_reacquisition=None):
    """Independently validate all cumulative costs and the single retry exception.

    Return successful records with explicit origin; never rewrite either ledger.
    The caller must verify every recorded byte at its original source offset.
    """
    need(type(parent_requests)is list and type(new_requests)is list,'request ledgers must be lists')
    need(original_caps['requests']==TOTAL_REQUEST_CAP and original_caps['total_response_bytes']==TOTAL_BYTE_CAP,'original cumulative caps differ')
    need(parent_session['status'] in ('FAILED','COMPLETE'),'parent attempt must be naturally closed')
    complete_over_wall=parent_session['status']=='COMPLETE'
    need(parent_session['wall_seconds_elapsed']>original_caps['wall_seconds'] if complete_over_wall
         else parent_session['wall_seconds_elapsed']>=original_caps['wall_seconds'],'parent did not reach original wall deadline')
    need(parent_session['request_count']==len(parent_requests),'parent request accounting differs')
    need(parent_session['retained_response_bytes']==sum(integer(x['response_bytes'],'parent response bytes') for x in parent_requests),'parent byte accounting differs')
    start=utc(parent_session['started_utc']);deadline=start+timedelta(seconds=ABSOLUTE_WALL_SECONDS)
    accepted=utc(accepted_utc);need(start<=accepted<deadline,'prospective acceptance outside absolute deadline')
    need(new_session['parent_attempt_id']==parent_session['attempt_id'],'continuation parent attempt differs')
    need(new_session['original_started_utc']==parent_session['started_utc'],'original start was reset')
    need(utc(new_session['absolute_deadline_utc'])==deadline,'absolute deadline was reset or extended')
    need(accepted<=utc(new_session['started_utc'])<deadline,'new session predates acceptance or exceeds deadline')
    need(new_session['attempt_id']!=parent_session['attempt_id'],'continuation attempt must be distinct')
    parent_failed=[x for x in parent_requests if not x['transport_ok']]
    need(not complete_over_wall or not parent_failed,'producer COMPLETE cannot contain failed requests')
    need(len(parent_failed)<=1 and (not parent_failed or parent_failed[0] is parent_requests[-1]),'only final parent request may have failed')
    timeout=bool(parent_failed and deadline_associated_timeout(parent_failed[0],parent_session))
    if parent_failed:need(parent_failed[0].get('failure') in WALL_FAILURES or timeout,'parent failed for an ineligible reason')
    need(not timeout or manual_reacquisition is not None,'deadline-associated timeout requires explicit manual reacquisition')
    if manual_reacquisition is not None:
        need(set(manual_reacquisition)=={'parent_request_ordinal','source_key','start','length'} and len(parent_failed)==1,'manual reacquisition lacks exact final wall-failed request')
        integer(manual_reacquisition['parent_request_ordinal'],'manual parent ordinal',1)
        integer(manual_reacquisition['start'],'manual range start');integer(manual_reacquisition['length'],'manual range length',1)
        f=parent_failed[0]
        need(manual_reacquisition=={'parent_request_ordinal':f['ordinal'],'source_key':f['source']['key'],'start':f['start'],'length':f['length']},'manual reacquisition target differs')
    parent_bytes=sum(x['response_bytes'] for x in parent_requests)
    reserved_parent=sum(integer(x['length']-x['response_bytes'],'parent failed reservation') for x in parent_failed)
    inherited_charged=parent_bytes+reserved_parent;new_charged=0
    need(inherited_charged<=TOTAL_BYTE_CAP,'original full failed-range reservation exceeds cumulative byte cap')
    accepted_records=[];available=defaultdict(list);parent_requested=defaultdict(list);all_new=defaultdict(list)
    previous=start;manual_count=0;new_failed=[]
    for origin,records,offset in (('parent',parent_requests,0),('new',new_requests,len(parent_requests))):
        for n,record in enumerate(records,offset+1):
            source,span,begin,end=validate_record(record,n,sources,original_caps);key=source['key']
            need(begin>=previous,'parallel or reordered requests');previous=end
            if origin=='parent':
                need(begin>=start,'parent request predates start')
                if record['transport_ok']:need((end-start).total_seconds()<=original_caps['wall_seconds'],'accepted parent response exceeded original deadline')
                need(not any(overlap(span,x) for x in parent_requested[key]),'overlapping parent requests')
                parent_requested[key].append(span)
            else:
                need(record['origin_attempt_id']==new_session['attempt_id'],'new request attempt origin differs')
                need(inherited_charged+new_charged+record['length']<=TOTAL_BYTE_CAP,'new request reservation exceeds cumulative byte cap')
                new_charged+=record['length']
                need(begin>=accepted and begin>=utc(new_session['started_utc']),'request predates prospective acceptance/start')
                if record['transport_ok']:need(end<=deadline,'accepted continuation response exceeded absolute deadline')
                need(not new_failed,'request issued after failed continuation request')
                need(not any(overlap(span,x) for x in all_new[key]),'automatic or overlapping continuation retry')
                all_new[key].append(span)
                manual=False
                if parent_failed and key==parent_failed[0]['source']['key'] and overlap(span,[parent_failed[0]['start'],parent_failed[0]['start']+parent_failed[0]['length']]):
                    f=parent_failed[0]
                    need(manual_reacquisition is not None and span==[f['start'],f['start']+f['length']],'unaccepted original bytes reacquired without exact manual exception')
                    manual_count+=1;need(manual_count<=1,'manual reacquisition repeated')
                    need(record['continuation_request_kind']=='explicit_manual_reacquisition'
                         and record['reacquisition_of']=={'attempt_id':parent_session['attempt_id'],'ordinal':f['ordinal']},'manual receipt origin marker differs')
                    manual=True
                if not manual:
                    need(record['continuation_request_kind']=='previously_unrequested_range'
                         and record.get('reacquisition_of') is None,'new ordinary request misrepresents origin')
                if not record['transport_ok']:new_failed.append(record)
            if record['transport_ok']:
                need(not any(overlap(span,x) for x in available[key]),'successful ranges overlap previous accepted evidence')
                available[key].append(span)
                accepted_records.append({'origin_attempt_id':parent_session['attempt_id'] if origin=='parent' else new_session['attempt_id'],
                                         'origin_ordinal':record['ordinal'],'receipt':record})
    request_total=len(parent_requests)+len(new_requests)
    new_bytes=sum(x['response_bytes'] for x in new_requests)
    reserved_new=sum(integer(x['length']-x['response_bytes'],'new failed reservation') for x in new_failed)
    need(request_total<=TOTAL_REQUEST_CAP and parent_bytes+new_bytes<=TOTAL_BYTE_CAP,'cumulative request/byte cap exceeded')
    need(new_session['inherited_request_count']==len(parent_requests) and new_session['new_request_count']==len(new_requests)
         and new_session['cumulative_request_count']==request_total,'continuation request accounting differs')
    need(new_session['inherited_response_bytes']==parent_bytes and new_session['new_response_bytes']==new_bytes
         and new_session['cumulative_response_bytes']==parent_bytes+new_bytes,'continuation byte accounting differs')
    need(new_session['manual_reacquisition_count']==manual_count,'manual reacquisition accounting differs')
    need(new_session['reserved_parent_failed_response_bytes']==reserved_parent
         and new_session['reserved_new_failed_or_pending_response_bytes']==reserved_new
         and new_session['inherited_charged_response_bytes']==inherited_charged
         and new_session['new_charged_response_bytes']==new_bytes+reserved_new==new_charged
         and new_session['cumulative_charged_response_bytes']==inherited_charged+new_charged<=TOTAL_BYTE_CAP,'conservative failed-range charge differs')
    need(new_session['status']!='COMPLETE' or not new_failed,'failed continuation was promoted to complete')
    return {'accepted_range_evidence':accepted_records,'available_ranges':dict(available),
            'inherited_request_count':len(parent_requests),'new_request_count':len(new_requests),
            'cumulative_request_count':request_total,'inherited_response_bytes':parent_bytes,
            'new_response_bytes':new_bytes,'cumulative_response_bytes':parent_bytes+new_bytes,
            'unaccepted_response_bytes':sum(x['response_bytes'] for x in parent_requests+new_requests if not x['transport_ok']),
            'reserved_parent_failed_response_bytes':reserved_parent,
            'reserved_new_failed_or_pending_response_bytes':reserved_new,
            'inherited_charged_response_bytes':inherited_charged,'new_charged_response_bytes':new_charged,
            'cumulative_charged_response_bytes':inherited_charged+new_charged,'wire_bytes_measured':False,
            'manual_reacquisition_count':manual_count,'new_failed_request_count':len(new_failed),
            'absolute_deadline_utc':deadline.isoformat(),
            'timeout_causality_unresolved':timeout,
            'original_attempt_disposition':('producer COMPLETE; original wall contract FAILED' if complete_over_wall
                else 'producer FAILED; deadline-associated transport timeout; exact causal contribution unknown; original wall contract FAILED' if timeout
                else 'producer FAILED at natural wall closure; original wall contract FAILED')}


def byte_helpers():
    """Reuse only the exact previously reviewed independent byte primitives."""
    path=Path(__file__).resolve().parents[1]/'qa/transport_receipt_audit.py'
    expected='9358885bffdf96d12fdfc7a9a578ccb5d770ae713af02c773b0494ae2dc38699'
    need(file_sha(path)==expected,'independent byte helper dependency changed')
    spec=importlib.util.spec_from_file_location('phase16_original_independent_byte_helpers',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module,expected


def audit(args):
    repo=Path(args.repo).resolve();root=Path(args.collection).resolve()
    context=validate_chain(args.amendment,args.expected_amendment_sha256,repo)
    amendment,plan,original=context['amendment'],context['plan'],context['original_plan']
    need(root==Path(amendment['continuation_output_root']).resolve(),'collection differs from single prospectively accepted output root')
    plan_sha=amendment['continuation_plan']['sha256'];parent=context['parent']
    need(canonical(read(root/'frozen_plan.json'))==canonical(plan),'continuation runtime plan differs')
    need(file_sha(root/'continuation_amendment.json')==args.expected_amendment_sha256,'runtime amendment differs')
    result=read(root/'collection_result.json',args.expected_result_sha256)
    need(result['schema_version']=='phase16_continuation_collection_result_v1'
         and result['status']=='COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT'
         and result['plan_sha256']==plan_sha and result['original_plan_binding']==plan['original_plan_binding']
         and result['continuation_amendment_sha256']==args.expected_amendment_sha256
         and result['continuation_number']==1 and result['source_payload_previously_exposed'] is True,'collection continuation scope/lineage differs')
    for k in ('transfer_decoding_performed','detector_scoring_performed','labels_used'):need(result[k] is False,'premature detector/label work')
    code_parent=Path(__file__).parent
    need(result['continuation_pipeline_sha256']==file_sha(code_parent/'continue_pipeline.py')
         and result['continuation_collector_sha256']==file_sha(code_parent/'collector.py')
         and result['prepared_with_original_pipeline_sha256']==original['pipeline_sha256'],'collection code differs')
    inventory=read(bound(plan['source_union'],repo));sources={x['key']:identity(x) for x in inventory['objects']}
    need(len(sources)==len(inventory['objects'])==113,'frozen transport population differs')
    transport=root/'transport';session=read(transport/'session.json');new=read(transport/'requests.json')
    need(session['schema_version']=='article2_phase16_continuation_capture_v1' and session['status']=='COMPLETE','continuation transport not complete')
    need(session['continuation_plan_sha256']==plan_sha and session['original_collector_plan_canonical_sha256']==digest(original['collector']),'session plan lineage differs')
    need(read(transport/'parent_bindings.json')==context['parent_bindings']
         and session['parent_bindings_canonical_sha256']==digest(context['parent_bindings']),'session parent seal differs')
    need(canonical(read(transport/'plan.json'))==canonical(original['collector']),'original collector plan changed')
    need(file_sha(transport/'inherited_requests.json')==context['parent_bindings']['transport/requests.json'],'original request ledger bytes changed')
    inherited=read(transport/'inherited_requests.json');need(inherited==context['parent_requests'],'inherited ledger differs from original')
    need(session['attempt_id']==digest({'parent_attempt_id':context['parent_session']['attempt_id'],
        'parent_session_sha256':context['parent_bindings']['transport/session.json'],
        'continuation_plan_sha256':plan_sha,'started_utc':session['started_utc']}),'continuation attempt identity differs')
    caps=original['collector']['caps'];need(session['effective_caps']=={**caps,'wall_seconds':14400}
        and session['automatic_retries']==0 and session['original_attempt_retry_count']==0
        and session['parent_positive_bodies_verified'] is True,'effective caps or inherited verification differs')
    need(session['manual_reacquisition']==context['manual_reacquisition'],'manual exception differs from acceptance')
    need(session['inherited_cache_or_full_object_reuses']==context['parent_session']['cache_or_full_object_reuses'],'original object reuse records changed')
    accounting=validate_ledgers(inherited,new,context['parent_session'],session,sources,caps,
                               amendment['accepted_utc'],context['manual_reacquisition'])
    need(accounting['new_failed_request_count']==0,'failed new response cannot establish complete evidence')
    need(session['manual_reacquisition_count']==(1 if context['manual_reacquisition'] is not None else 0)
         and session['cumulative_retry_count']==session['manual_reacquisition_count'],'declared manual reacquisition incomplete or retry count hidden')
    start=utc(context['parent_session']['started_utc']);closed=utc(session['updated_utc'])
    need(0<=session['cumulative_wall_seconds_elapsed']<=14400
         and closed<=start+timedelta(seconds=14400)
         and abs((closed-start).total_seconds()-session['cumulative_wall_seconds_elapsed'])<=2,'total continuation closure exceeded absolute deadline')
    evidence=read(transport/'accepted_range_evidence.json')
    need(evidence['schema_version']=='article2_phase16_continuation_accepted_ranges_v1'
         and evidence['ranges']==accounting['accepted_range_evidence'],'accepted evidence view differs from full charged ledgers')
    paths=read(root/'runtime_source_paths.json');need(set(paths)==set(sources),'continuation source path population differs')
    manifests=read(root/'transport_sources.json',args.expected_transport_sources_sha256)['sources']
    mm={x['source']['key']:x for x in manifests};need(len(mm)==len(manifests)==len(sources) and set(mm)==set(sources),'source manifest population differs')
    need(result['transport_sources']==len(sources),'collection source count differs')
    old_paths=read(parent/'runtime_source_paths.json') if context['parent_bindings']['runtime_source_paths.json'] is not None else {}
    grouped=defaultdict(list)
    for origin in evidence['ranges']:grouped[origin['receipt']['source']['key']].append(origin)
    # Every original positive body is independently rehashed at immutable A1,
    # including the failed prefix which is never copied into accepted evidence.
    for record in inherited:
        source=record['source'];key=source['key'];old=Path(old_paths.get(key,parent/'cache'/digest(source)/'source.parquet')).resolve()
        need(old.is_file() and old.stat().st_size==source['size_bytes'],'original source body absent or resized')
        need(file_sha(old,record['start'],record['response_bytes'])==record['response_sha256'],'immutable original accepted/failed body changed')
        current=Path(paths[key]).resolve()
        need(not old.samefile(current),'continuation ranged cache aliases immutable original file')
        if record['transport_ok']:
            need(file_sha(current,record['start'],record['length'])==record['response_sha256'],'inherited accepted range copy differs')
        elif record['response_bytes'] and context['manual_reacquisition'] is not None:
            need(file_sha(current,record['start'],record['response_bytes'])==record['response_sha256'],'manual reacquisition contradicts original failed prefix')
    for record in new:
        path=Path(paths[record['source']['key']]).resolve()
        need(file_sha(path,record['start'],record['response_bytes'])==record['response_sha256'],'new retained original range changed')
    helpers,helper_sha=byte_helpers()
    retained=read(bound(plan['reuse_expectations_binding'],repo));expected={x['source_key']:x for x in retained['objects']}
    archives=read(args.archives) if args.archives else {}
    old_manifest=read(args.original_manifest,args.expected_original_manifest_sha256) if args.original_manifest else {'days':[]}
    old_days={x['day_utc']:x for x in old_manifest['days']};archive_cache={};verified=[];whole_ids=set()
    for key,source in sources.items():
        path=Path(paths[key]).resolve();m=mm[key];sid=digest(source)
        need(path.is_file() and path.stat().st_size==source['size_bytes']<=caps['max_source_bytes'],'current source size differs')
        need(m['schema_version']=='article2_phase16_continuation_projected_source_manifest_v1'
             and m['source']==source and m['source_id']==sid
             and m['parent_attempt_id']==session['parent_attempt_id'] and m['continuation_attempt_id']==session['attempt_id'],'source manifest identity/origin differs')
        origins=grouped[key];records=[x['receipt'] for x in origins]
        inherited_origins=[x for x in origins if x['origin_attempt_id']==session['parent_attempt_id']]
        new_records=[x['receipt'] for x in origins if x['origin_attempt_id']==session['attempt_id']]
        need(m['successful_original_ranges']==records and m['evidence_origins']==origins
             and m['inherited_ranges']==inherited_origins and m['new_ranges']==new_records,'source receipt origins differ')
        whole=m['whole_source_sha256_verified'];need(type(whole)is bool,'whole source evidence flag')
        origin=None
        if whole:
            need(not records and key in expected and key in plan['whole_object_reuse_expectations'],'whole object lacks frozen provenance')
            frozen=plan['whole_object_reuse_expectations'][key];receipt=read(bound(frozen['acquisition_receipt'],repo))
            need(frozen['sha256']==expected[key]['expected_whole_object_sha256'] and receipt['source_key']==key
                 and receipt['sha256']==frozen['sha256'] and all(frozen[k]==receipt[k]==source[k] for k in ('size_bytes','etag_opaque')),'whole-object identity/hash expectation differs')
            need(all(receipt[k]==expected[key][k] for k in ('expected_archive_sha256','expected_original_member_name')),'whole-object archive/member origin differs')
            day=source['day_utc'];need(day in archives and day in old_days and args.expected_original_manifest_sha256,'whole original archive receipt evidence missing')
            origin=helpers.audit_reuse(source,path,expected[key],Path(archives[day]),old_days[day],archive_cache)
            need(m['whole_source_sha256']==origin['whole_source_sha256'],'whole source hash claim differs')
            available=[[0,source['size_bytes']]];whole_ids.add(sid)
        else:
            need(m['whole_source_sha256'] is None and records,'uncovered range source cannot become zero')
            need(path==(root/'cache'/sid/'source.parquet').resolve(),'ranged source outside new cache')
            cache=read(path.parent/'ranges.json')
            need(cache['schema_version']=='article2_phase16_continuation_range_cache_v1' and cache['source']==source
                 and cache['attempt_id']==session['attempt_id'] and cache['parent_attempt_id']==session['parent_attempt_id']
                 and cache['inherited_ranges']==inherited_origins and cache['new_ranges']==new_records,'current range cache lineage differs')
            spans=[[r['start'],r['start']+r['length']] for r in records];available=helpers.union(spans)
            need(sum(b-a for a,b in spans)==sum(b-a for a,b in available),'successful current ranges overlap')
        need(m['available_ranges']==available and m['available_original_bytes']==sum(b-a for a,b in available)
             and m['holes_are_original_bytes'] is False and m['statistics_values_exported_or_used'] is False,'available original byte evidence differs')
        footer=helpers.footer_evidence(path,source,available,caps)
        verified.append({'source_key':key,'source':source,'source_id':sid,'path':str(path),
            'available_ranges':available,'whole_source_sha256_verified':whole,
            'whole_source_sha256':None if origin is None else origin['whole_source_sha256'],
            'successful_range_count':len(records),'range_receipts_canonical_sha256':digest(records),
            'successful_receipt_origins':origins,'original_footer_evidence':footer,'whole_object_origin':origin})
    claimed={x['source_id'] for x in session['cache_or_full_object_reuses'] if x['kind']=='verified_whole_object'}
    need(claimed==whole_ids,'new whole-object accounting differs')
    # Recheck immutable metadata after full byte audit, without modifying A1.
    for name,expected_sha in context['parent_bindings'].items():
        p=parent_path(parent,name)
        need((not p.exists()) if expected_sha is None else p.is_file() and file_sha(p)==expected_sha,'original metadata changed during audit')
    output=Path(args.output);ledger_path=Path(args.ledger_output)
    need(not output.exists() and not ledger_path.exists() and output.resolve()!=ledger_path.resolve(),'audit/ledger destination already exists or aliases')
    need(not output.resolve().is_relative_to(parent) and not ledger_path.resolve().is_relative_to(parent),'audit outputs cannot modify original attempt')
    ledger={'schema_version':'article2_phase16_full_multiattempt_transport_ledger_v1',
        'continuation_amendment_sha256':args.expected_amendment_sha256,'original_source_plan_sha256':plan['original_plan_binding']['sha256'],
        'plan_sha256':plan_sha,'parent_attempt_id':session['parent_attempt_id'],'continuation_attempt_id':session['attempt_id'],
        'original_requests_sha256':context['parent_bindings']['transport/requests.json'],
        'inherited_requests_sha256':file_sha(transport/'inherited_requests.json'),'new_requests_sha256':file_sha(transport/'requests.json'),
        'original_requests':inherited,'continuation_requests':new,
        'accounting':{k:v for k,v in accounting.items() if k not in ('accepted_range_evidence','available_ranges')},
        'automatic_retries':0,'explicit_manual_reacquisitions':session['manual_reacquisition_count'],
        'all_failed_response_bytes_charged':True,'failed_original_bytes_promoted':False}
    ledger_path.parent.mkdir(parents=True,exist_ok=True);ledger_path.write_bytes(canonical(ledger)+b'\n')
    report={'schema_version':'article2_phase16_independent_continuation_transport_audit_v1',
        'status':'PASS_CONTINUATION_TRANSPORT_ORIGINAL_BYTES','completed_utc':datetime.now(timezone.utc).isoformat(),
        'continuation_amendment_sha256':args.expected_amendment_sha256,'original_source_plan_sha256':plan['original_plan_binding']['sha256'],
        'continuation_amendment_path':str(context['amendment_path']),
        'first_attempt_seal_path':str(bound(amendment['first_attempt_seal'],context['amendment_path'].parent)),
        'parent_root':str(parent),
        'first_attempt_seal_sha256':amendment['first_attempt_seal']['sha256'],'exposure_report_sha256':amendment['exposure_report']['sha256'],
        'plan_sha256':plan_sha,'collection_result_sha256':args.expected_result_sha256,
        'transport_sources_sha256':args.expected_transport_sources_sha256,
        'requests_sha256':file_sha(transport/'requests.json'),'inherited_requests_sha256':file_sha(transport/'inherited_requests.json'),
        'accepted_range_evidence_sha256':file_sha(transport/'accepted_range_evidence.json'),
        'session_sha256':file_sha(transport/'session.json'),'runtime_source_paths_sha256':file_sha(root/'runtime_source_paths.json'),
        'multiattempt_ledger_sha256':file_sha(ledger_path),'multiattempt_ledger_path':str(ledger_path.resolve()),
        'auditor_sha256':file_sha(__file__),'independent_byte_helper_sha256':helper_sha,
        'original_attempt_disposition':accounting['original_attempt_disposition'],
        'request_count':accounting['cumulative_request_count'],'retained_response_bytes':accounting['cumulative_response_bytes'],
        'unaccepted_response_bytes':accounting['unaccepted_response_bytes'],'automatic_retries':0,
        'reserved_parent_failed_response_bytes':accounting['reserved_parent_failed_response_bytes'],
        'cumulative_charged_response_bytes':accounting['cumulative_charged_response_bytes'],
        'wire_bytes_measured':False,'timeout_causality_unresolved':accounting['timeout_causality_unresolved'],
        'explicit_manual_reacquisitions':session['manual_reacquisition_count'],'source_count':len(verified),
        'whole_object_reuse_count':len(whole_ids),'verified_sources':verified,'network_requests':0,
        'parquet_rows_decoded':0,'selection_or_scientific_acceptance':False,'receipt_root_verified':False,
        'limits':['Original A1 wall contract remains FAILED; this report covers only the explicitly accepted amended cumulative transport.',
                  'Full source coverage, selections, bundles, replay decisions and references require separate independent audit.']}
    output.parent.mkdir(parents=True,exist_ok=True);output.write_bytes(canonical(report)+b'\n');return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('repo','collection','amendment','output','ledger-output'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('expected-amendment-sha256','expected-result-sha256','expected-transport-sources-sha256'):p.add_argument('--'+name,required=True)
    for name in ('archives','original-manifest'):p.add_argument('--'+name,type=Path)
    p.add_argument('--expected-original-manifest-sha256')
    v=audit(p.parse_args());print(json.dumps({k:v[k] for k in ('status','request_count','retained_response_bytes','source_count','explicit_manual_reacquisitions')}))

if __name__=='__main__':main()
