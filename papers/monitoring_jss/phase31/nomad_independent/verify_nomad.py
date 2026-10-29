#!/usr/bin/env python3
"""Standalone, offline normalized-data and statistical reproducibility audit.

No acquisition, reference labels, exploit code, external package, or live service.
Independently decodes transfer-shaped amounts and reproduces rank/count policies.
"""
import argparse
import collections
import csv
import datetime as dt
import gzip
import hashlib
import json
import re
from pathlib import Path

HERE=Path(__file__).resolve().parent
PAPER=HERE.parents[1]
DAY_NS=86400*10**9
ZERO='0x'+'0'*40
TRANSFER='0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
CATS=('external_in','external_out','internal','mint_from_zero','burn_to_zero')
TX_FIELDS=('chain_id','block_number','block_hash','transaction_hash','transaction_index','event_time_ns')
LOG_FIELDS=('address','topics','data','transaction_index','log_index','transaction_hash','block_number','block_hash','event_time_ns')


def require(cond,msg):
    if not cond: raise AssertionError(msg)

def canon(obj): return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def unique_pairs(pairs):
    out={}
    for k,v in pairs:
        require(k not in out,'duplicate JSON key '+k);out[k]=v
    return out

def loads(s):
    def fail(x):raise ValueError('nonfinite JSON '+x)
    return json.loads(s,object_pairs_hook=unique_pairs,parse_constant=fail)

def readjson(p):return loads(p.read_bytes())
def readjsonl(p):
    with gzip.open(p,'rt',encoding='utf8') as f:
        return [loads(line) for line in f if line.strip()]

def integer(v,name):require(type(v) is int and v>=0,'invalid integer '+name)
def hexval(v,n,name):require(type(v) is str and re.fullmatch('0x[0-9a-f]{'+str(2*n)+'}',v) is not None,'invalid hex '+name)
def day_of(t):return str(dt.date(1970,1,1)+dt.timedelta(days=t//DAY_NS))

def decode_summary(events,core):
    """Full independent ERC20-shaped aggregation; shape is not compliance proof."""
    counts={'logs':len(events),'erc20_shaped':0,'erc721_shaped':0,'opaque':0,'monitored_erc20_shaped':0,'zero_value_transfers':0}
    flows={}
    for e in events:
        topics=e['topics'];data=e['data']
        require(type(topics) is list and len(topics)<=4,'invalid topics list')
        for topic in topics:hexval(topic,32,'topic')
        require(type(data) is str and re.fullmatch(r'0x(?:[0-9a-f]{2})*',data) is not None,'invalid data bytes')
        if not topics or topics[0]!=TRANSFER:
            counts['opaque']+=1;continue
        require(len(topics) in (3,4),'unsupported Transfer topic count')
        require(topics[1][2:26]==topics[2][2:26]=='0'*24,'noncanonical address topic')
        if len(topics)==4:
            require(data=='0x','nonempty ERC721-shaped data');counts['erc721_shaped']+=1;continue
        require(len(data)==66,'ERC20-shaped data word length')
        counts['erc20_shaped']+=1
        value=int(data,16);sender='0x'+topics[1][-40:];recipient='0x'+topics[2][-40:]
        counts['zero_value_transfers']+=value==0
        if sender!=core and recipient!=core:continue
        counts['monitored_erc20_shaped']+=1
        tok=e['address']
        if tok not in flows:
            flows[tok]={'chain_id':1,'token_address':tok,'transfer_log_count':0}
            for category in CATS:
                flows[tok][category+'_raw']=0;flows[tok][category+'_count']=0
        f=flows[tok]
        category=('internal' if sender==recipient==core else 'mint_from_zero' if sender==ZERO else
                  'burn_to_zero' if recipient==ZERO else 'external_in' if recipient==core else 'external_out')
        f[category+'_raw']+=value;f[category+'_count']+=1;f['transfer_log_count']+=1
    for f in flows.values():
        f['net_external_in_raw']=f['external_in_raw']-f['external_out_raw']
        f['net_event_in_raw']=f['net_external_in_raw']+f['mint_from_zero_raw']-f['burn_to_zero_raw']
        for k in f:
            if k.endswith('_raw'):f[k]=str(f[k])
    return counts,[flows[t] for t in sorted(flows)]

def method_trace(rows,method,mode):
    histories=collections.defaultdict(list);recent=[];previous_day=None;previous_candidate=None;out=[]
    for r in rows:
        t=r['transaction']['event_time_ns'];day=t//DAY_NS
        if day!=previous_day:
            recent=[];previous_candidate=None
            if mode=='daily_reset':histories.clear()
            previous_day=day
        ready=False
        if method.startswith('outflow'):
            positive={x['token_address']:int(x['external_out_raw']) for x in r['views']['fixed_core']['token_flows'] if int(x['external_out_raw'])>0}
            denominator=int(method.rsplit('_',1)[-1]);raw=False
            for token,amount in positive.items():
                history=histories[token]
                if mode=='lookback_7d':history[:]=[(when,v) for when,v in history if when>=t-7*DAY_NS]
                if len(history)>=19:
                    ready=True
                    numerator=1+sum(v>=amount for _,v in history)
                    raw |= numerator*denominator<=len(history)+1
            for token,amount in positive.items():histories[token]=(histories[token]+[(t,amount)])[-128:]
        else:
            recent=[(when,n) for when,n in recent if when>t-60*10**9]
            recent.append((t,r['views']['fixed_core']['archived_core_log_count']))
            raw=sum(n for _,n in recent)>=10
        candidate=bool(raw and (previous_candidate is None or t-previous_candidate>=300*10**9))
        if candidate:previous_candidate=t
        out.append({'tx':r['transaction']['transaction_hash'],'time':t,'day':day,'raw':bool(raw),'candidate':candidate,'eligible':ready if method.startswith('outflow') else None})
    return out

def dispatch(trace,policy,budget):
    notified=[];suppressed=0;current_day=None;sent=0;tokens=DAY_NS;previous_time=0
    for x in trace:
        t=x['time'];day=x['day']
        if day!=current_day:current_day=day;sent=0;tokens=DAY_NS;previous_time=day*DAY_NS
        if policy=='token_bucket':tokens=min(DAY_NS,tokens+(t-previous_time)*budget)
        allowance=budget if policy!='paced_cumulative' else min(budget,1+(t-day*DAY_NS)*budget//DAY_NS)
        if x['candidate']:
            if sent<allowance and (policy!='token_bucket' or tokens>=DAY_NS):
                notified.append(x['tx']);sent+=1
                if policy=='token_bucket':tokens-=DAY_NS
            else:suppressed+=1
        previous_time=t
    return notified,suppressed

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--data',required=True,type=Path);parser.add_argument('--results',type=Path);parser.add_argument('--out',type=Path,default=HERE/'AUDIT.json');a=parser.parse_args()
    manifest=readjson(a.data/'acquisition_manifest.json')
    require(manifest['status']=='COMPLETE','incomplete acquisition; no scientific audit result permitted')
    require(manifest['reference_labels_used'] is False and manifest['detector_scores_computed'] is False,'source acquisition not label-blind')
    frame_path=PAPER/'phase28/CANDIDATE_FRAME.json';batch_path=PAPER/'phase28/results/batch_7.json'
    require(manifest['frame_sha256']==sha(frame_path.read_bytes()),'frame digest mismatch')
    require(manifest['census_batch_sha256']==sha(batch_path.read_bytes()),'census digest mismatch')
    frame=readjson(frame_path);case=next(c for c in frame['cases'] if c['id']=='cohort28_15')
    census=next(c for c in readjson(batch_path)['case_results'] if c['id']=='cohort28_15')
    core=case['core_address'];require(manifest['core']==census['core_address']==core,'core mismatch')
    raw=readjsonl(a.data/'raw_selected_bundles.jsonl.gz');rows=readjsonl(a.data/'observations.jsonl.gz')
    require(sha(canon(raw))==manifest['raw_bundles_sha256'],'raw JSONL digest mismatch')
    require(sha(canon(rows))==manifest['observations_sha256'],'observation JSONL digest mismatch')
    require(len(raw)==len(rows)==manifest['selected_transactions']==930,'selected count mismatch')
    daycounts=collections.Counter();corecounts=collections.Counter();identities=[];txhashes=[];eventtotal=0;flowtotal=0;flowpositive=0;positive_events=0;tx_with_positive_events=0
    for i,(b,r) in enumerate(zip(raw,rows)):
        tx=b['transaction'];events=b['events'];identity=tuple(tx[k] for k in TX_FIELDS)
        require(set(tx)==set(TX_FIELDS),'transaction schema mismatch')
        for k in ('chain_id','block_number','transaction_index','event_time_ns'):integer(tx[k],k)
        for k in ('block_hash','transaction_hash'):hexval(tx[k],32,k)
        require(tx['chain_id']==1 and b['core_emitter']==core,'chain/core mismatch')
        require(b['receipt_status']==r['receipt_status']==1 and type(b['receipt_status']) is int,'unsuccessful source status')
        require(tx==r['transaction'],'raw/derived transaction mismatch')
        require(day_of(tx['event_time_ns'])==b['day_utc']==r['day_utc'],'UTC day mismatch')
        require(bool(events),'empty selected bundle')
        require(events==sorted(events,key=lambda e:e['log_index']),'unordered events')
        indices=[]
        for e in events:
            require(set(e)==set(LOG_FIELDS),'log schema mismatch')
            hexval(e['address'],20,'emitter')
            for k in ('block_number','transaction_index','log_index','event_time_ns'):integer(e[k],k)
            for k in ('block_number','transaction_index','block_hash','transaction_hash','event_time_ns'):require(e[k]==tx[k],'mixed event identity '+k)
            indices.append(e['log_index'])
        require(all(y==x+1 for x,y in zip(indices,indices[1:])),'gapped/duplicate log indices')
        require(len(events)==r['all_emitter_log_count'] and sha(canon(events))==r['all_emitter_logs_sha256'],'event count/digest mismatch')
        n=sum(e['address']==core for e in events);require(n>0,'selected core absent')
        require(n==r['core_log_counts']['fixed_core']==r['views']['fixed_core']['archived_core_log_count'],'core count mismatch')
        counts,flows=decode_summary(events,core)
        positive_here=counts['erc20_shaped']-counts['zero_value_transfers']
        positive_events+=positive_here;tx_with_positive_events+=positive_here>0
        require(counts==r['views']['fixed_core']['counts'],'independent shape counts differ at '+str(i))
        require(flows==r['views']['fixed_core']['token_flows'],'independent amount aggregation differs at '+str(i))
        daycounts[b['day_utc']]+=1;corecounts[b['day_utc']]+=n
        identities.append((tx['block_number'],tx['transaction_index']));txhashes.append(tx['transaction_hash'])
        eventtotal+=len(events);flowtotal+=len(flows);flowpositive+=sum(int(f['external_out_raw'])>0 for f in flows)
    require(identities==sorted(set(identities)) and len(set(txhashes))==930,'duplicate or unordered transaction identities')
    require(all(rows[i]['transaction']['event_time_ns']<=rows[i+1]['transaction']['event_time_ns'] for i in range(len(rows)-1)),'nonmonotone event time')
    daily_csv=list(csv.DictReader((PAPER/'phase28/results/CENSUS_DAILY.csv').open()))
    frozen_days=[d for d in daily_csv if d['id']=='cohort28_15']
    require(len(frozen_days)==30 and sum(int(d['tx']) for d in frozen_days)==930,'frozen CSV census differs')
    for d in frozen_days:
        require(daycounts[d['day']]==int(d['tx']),'daily transaction count mismatch')
        require(corecounts[d['day']]==int(d['core_events']),'daily core log count mismatch')
    require([d['day'] for d in manifest['days']]==[d['day'] for d in frozen_days],'manifest day order differs')
    for d,o in zip(manifest['days'],census['days']):
        require(d['selected']==o['distinct_core_selected_tx'],'manifest census mismatch')
        if d['selected']==0:
            require(d['status']=='REUSED_COMPLETE_ZERO_SELECTED_CENSUS' and o['status']=='COMPLETE_ORIGINAL_PROJECTED_SOURCE','zero day ungrounded')
            require(d['source_key']==o['source_key'] and d['source_etag']==o['source_etag'],'zero day source identity mismatch')
        else:
            require(d['status']=='COMPLETE_ORIGINAL_LOG_PAYLOAD_AND_TX_STATUS','nonempty source incomplete')
            require(d['logs_source']['key']==o['source_key'] and d['logs_source']['etag_opaque']==o['source_etag'],'log source identity changed')
    requests=readjson(a.data/'range_capture/requests.json');session=readjson(a.data/'range_capture/session.json');plan=readjson(a.data/'source_plan.json')
    require(session['status']=='COMPLETE','range capture incomplete')
    current_count=manifest.get('new_range_requests',manifest['range_requests'])
    current_bytes=manifest.get('new_range_bytes',manifest['range_bytes'])
    require(session['request_count']==len(requests)==current_count,'request count mismatch')
    require(sum(q['response_bytes'] for q in requests)==session['retained_response_bytes']==current_bytes,'range byte count mismatch')
    require(sha(canon(plan))==session['plan_canonical_sha256'],'range plan digest mismatch')
    require(current_bytes<=plan['caps']['total_response_bytes'] and len(requests)<=plan['caps']['requests'],'current range budget exceeded')
    require(session['wall_seconds_elapsed']<=plan['caps']['wall_seconds'],'current recorded wall budget exceeded')
    attempts=[{'requests':requests,'session':session,'plan':plan,'allows_failed_receipts':False}]
    inherited=None;continuation_limits=None
    if 'previous_attempt_manifest_sha256' in manifest:
        inherited=readjson(a.data/'inherited_attempt_manifest.json')
        require(sha((a.data/'inherited_attempt_manifest.json').read_bytes())==manifest['previous_attempt_manifest_sha256'],'inherited manifest byte hash mismatch')
        require(inherited['status']=='INCOMPLETE' and inherited['reference_labels_used'] is False and inherited['detector_scores_computed'] is False,'prior attempt not incomplete and label blind')
        require(inherited['frame_sha256']==manifest['frame_sha256'] and inherited['census_batch_sha256']==manifest['census_batch_sha256'],'prior frozen source differs')
        limits_path=a.data/('RECOVERY_LIMITS.json' if 'interrupted_attempt_report_sha256' in manifest else 'CONTINUATION_LIMITS.json')
        continuation_limits=readjson(limits_path)
        require(sha(limits_path.read_bytes())==manifest['continuation_limits_sha256'],'continuation limits digest mismatch')
        require(continuation_limits['previous_attempt_manifest_sha256']==manifest['previous_attempt_manifest_sha256'],'continuation limits name different prior attempt')
        require(continuation_limits['detector_scores_computed'] is False and continuation_limits['reference_labels_used'] is False,'resource amendment not source-only')
        require(continuation_limits['cumulative_response_bytes']==5000000000 and continuation_limits['cumulative_requests']==1600 and continuation_limits['cumulative_active_wall_seconds']==3600,'unexpected resource amendment values')
        require(manifest['cumulative_response_byte_cap']==continuation_limits['cumulative_response_bytes'],'manifest amended byte ceiling differs')
        require(dt.datetime.fromisoformat(continuation_limits['prepared_utc'])<=dt.datetime.fromisoformat(session['started_utc']),'resource amendment postdates continuation launch')
        require(sha((a.data.parent/'CONTINUATION_PROTOCOL.md').read_bytes())==manifest['protocol_amendment_sha256'],'continuation protocol digest differs')
        prior_requests=readjson(a.data/'inherited_range_requests.json');prior_session=readjson(a.data/'inherited_range_session.json');prior_plan=readjson(a.data/'inherited_source_plan.json')
        reason=inherited['failure']['reason'];kind=inherited['failure']['type']
        require(reason.startswith('wall cap') or reason=='wall/request cap' or (kind in ('TimeoutError','URLError') and prior_session['wall_seconds_elapsed']>=1799),'prior failure not permitted wall-cap continuation')
        require(prior_session['status']=='INCOMPLETE','prior failed session relabelled complete')
        require(prior_session['request_count']==len(prior_requests)==inherited['range_requests'],'prior request accounting')
        require(sum(q['response_bytes'] for q in prior_requests)==prior_session['retained_response_bytes']==inherited['range_bytes'],'prior byte accounting')
        require(sha(canon(prior_plan))==prior_session['plan_canonical_sha256'],'prior range plan digest mismatch')
        require(prior_plan['caps']['total_response_bytes']==3600000000 and prior_plan['caps']['wall_seconds']==1800,'original attempt resource limits were changed')
        require(plan['caps']['wall_seconds']<=1800,'continuation per-attempt wall ceiling exceeded')
        inherited_days={d['day'] for d in inherited['days']}
        remaining=[d for d in census['days'] if d['day'] not in inherited_days and d['distinct_core_selected_tx']>0]
        require([d['day'] for d in remaining]==continuation_limits['remaining_nonempty_days'],'amendment remaining dates differ from frozen census')
        require(sum(d['distinct_core_selected_tx'] for d in remaining)==continuation_limits['remaining_selected_transactions'],'amendment remaining count differs')
        require(sum(d['source_size'] for d in remaining)==continuation_limits['remaining_full_log_object_bytes'],'amendment source-size estimate differs')
        projected_max=max(sum(r['length'] for r in d['transaction_ranges']) for d in inherited['days'] if d['selected'])
        require(projected_max==continuation_limits['maximum_completed_day_transaction_projection_bytes'],'observed status-projection cost differs')
        require(inherited['range_bytes']+sum(d['source_size'] for d in remaining)+len(remaining)*projected_max==continuation_limits['projected_combined_bytes_at_observed_max_status'],'continuation resource estimate arithmetic differs')
        require(sorted(inherited_days)==manifest['inherited_complete_days'],'inherited day ledger differs')
        require(sha(canon([b for b in raw if b['day_utc'] in inherited_days]))==inherited['raw_bundles_sha256'],'inherited raw day values changed')
        require(sha(canon([r for r in rows if r['day_utc'] in inherited_days]))==inherited['observations_sha256'],'inherited observation values changed')
        require([d for d in manifest['days'] if d['day'] in inherited_days]==inherited['days'],'inherited complete-day provenance changed')
        require(manifest['range_bytes']==current_bytes+inherited['range_bytes'] and manifest['range_requests']==current_count+inherited['range_requests'],'cumulative request/byte accounting')
        require(abs(manifest['source_active_wall_seconds']-prior_session['wall_seconds_elapsed']-session['wall_seconds_elapsed'])<1e-6,'cumulative active wall accounting')
        attempts.insert(0,{'requests':prior_requests,'session':prior_session,'plan':prior_plan,'allows_failed_receipts':True})
    successful_ranges=set();failed_ranges=0
    for attempt in attempts:
        for i,q in enumerate(attempt['requests']):
            src=q['source'];start=q['start'];length=q['length']
            require(q['ordinal']==i+1,'unordered range receipt')
            if not q['transport_ok']:
                require(attempt['allows_failed_receipts'],'failed current range receipt')
                require(0<=q['response_bytes']<=length and 'failure' in q,'invalid failed receipt accounting')
                failed_ranges+=1;continue
            require(q['http_status']==206,'range response status')
            require(q['etag']==src['etag_opaque']==q['request_headers']['If-Match'],'range ETag mismatch')
            require(q['response_bytes']==length and int(q['content_length'])==length,'range length mismatch')
            require(q['content_range']==f"bytes {start}-{start+length-1}/{src['size_bytes']}",'range coordinates mismatch')
            require(re.fullmatch('[0-9a-f]{64}',q['response_sha256']) is not None,'invalid range SHA256')
            successful_ranges.add((src['key'],src['etag_opaque'],start,length,q['response_sha256']))
    for d in manifest['days']:
        if not d['selected']:continue
        for source_key,ranges_key in [('logs_source','logs_ranges'),('transactions_source','transaction_ranges')]:
            src=d[source_key]
            for q in d[ranges_key]:
                require((src['key'],src['etag_opaque'],q['start'],q['length'],q['response_sha256']) in successful_ranges,'admitted day relies on missing or failed source range')
    interrupted_charge_bytes=0;interrupted_charge_requests=0;interrupted_active_upper=0;interrupted_attempts=0
    if 'interrupted_attempt_report_sha256' in manifest:
        interrupted_attempts=1
        ip=a.data/'interrupted_attempt_report.json';interrupted=readjson(ip)
        require(sha(ip.read_bytes())==manifest['interrupted_attempt_report_sha256']==continuation_limits['interrupted_attempt_report_sha256'],'interruption report digest mismatch')
        require(interrupted['status']=='UNRECOVERABLE_PENDING_CAPTURE' and interrupted['cause']=='UNKNOWN_RUNTIME_INTERRUPTION','unsupported interruption status or inferred cause')
        require(interrupted['new_completed_days']==0 and interrupted['new_selected_transactions']==0,'interrupted data unexpectedly admitted')
        require(interrupted['reference_labels_used'] is False and interrupted['detector_scores_computed'] is False,'interrupted acquisition not source-only')
        paths={'plan':a.data/'interrupted_source_plan.json','session':a.data/'interrupted_range_session.json','requests':a.data/'interrupted_range_requests.json'}
        for key,path in paths.items():require(sha(path.read_bytes())==interrupted[key+'_sha256'],'interrupted '+key+' byte hash mismatch')
        ir=readjson(paths['requests']);isess=readjson(paths['session']);iplan=readjson(paths['plan'])
        require(isess['status']=='OPEN_REQUEST_PENDING','interrupted pending status was rewritten')
        require(sha(canon(iplan))==isess['plan_canonical_sha256'],'interrupted plan/session binding')
        require(len(ir)==isess['request_count']==interrupted['known_range_requests']==manifest['interrupted_known_range_requests'],'interrupted request count mismatch')
        known_bytes=sum(q['response_bytes'] for q in ir)
        require(known_bytes==isess['retained_response_bytes']==interrupted['known_retained_range_bytes']==manifest['interrupted_known_range_bytes'],'interrupted known byte accounting')
        pending=[q for q in ir if q['transport_ok'] is not True]
        require(len(pending)==1 and pending[0]['ordinal']==len(ir),'interrupted final pending request expected')
        require(pending[0]['length']==interrupted['pending_request_bytes_upper_bound']==manifest['interrupted_pending_range_bytes_upper_bound'],'interrupted pending byte upper bound differs')
        for i,q in enumerate(ir[:-1]):
            require(q['ordinal']==i+1 and q['transport_ok'] is True and q['http_status']==206 and q['response_bytes']==q['length'],'invalid completed interrupted receipt')
        # The interrupted pending request is already in the known request count.
        # Its full requested body is conservatively charged on top of known bytes.
        require(interrupted['extra_listing_requests_upper_bound']==manifest['interrupted_listing_requests_upper_bound']==1,'interrupted listing request bound')
        require(interrupted['extra_listing_body_bytes_upper_bound']==manifest['interrupted_listing_bytes_upper_bound']==300000,'interrupted listing byte bound')
        require(pending[0]['source']['table']=='transactions','listing bound needs a transaction-table request')
        interrupted_charge_bytes=known_bytes+pending[0]['length']+interrupted['extra_listing_body_bytes_upper_bound']
        interrupted_charge_requests=len(ir)+interrupted['extra_listing_requests_upper_bound']
        interrupted_active_upper=(dt.datetime.fromisoformat(interrupted['observed_absent_by_utc'])-dt.datetime.fromisoformat(isess['started_utc'])).total_seconds()
        require(abs(interrupted_active_upper-interrupted['active_wall_seconds_upper_bound'])<1e-6,'interrupted active wall upper bound arithmetic')
        require(isess['wall_seconds_elapsed']<=interrupted_active_upper,'interrupted wall upper bound below recorded elapsed time')
        require(continuation_limits['interrupted_charged_range_bytes_upper_bound']==known_bytes+pending[0]['length'],'recovery range accounting differs')
        require(continuation_limits['interrupted_listing_bytes_upper_bound']==interrupted['extra_listing_body_bytes_upper_bound'],'recovery listing accounting differs')
        require(abs(continuation_limits['interrupted_active_wall_seconds_upper_bound']-interrupted_active_upper)<1e-6,'recovery wall accounting differs')
    listings=readjson(a.data/'transaction_source_listings.json')
    listing_bytes=sum(len(x['body'].encode()) for x in listings)
    for x in listings:require(sha(x['body'].encode())==x['sha256'],'listing body hash mismatch')
    caps={'total_response_bytes':continuation_limits['cumulative_response_bytes'] if continuation_limits else 3600000000,'requests':1600,'wall_seconds':3600 if inherited else 1800}
    active_wall=sum(x['session']['wall_seconds_elapsed'] for x in attempts)+interrupted_active_upper
    if interrupted_attempts:require(abs(active_wall-manifest['source_active_wall_seconds_upper_bound'])<1e-6,'final recovery active wall upper bound differs')
    require(manifest['range_bytes']+listing_bytes+interrupted_charge_bytes<=caps['total_response_bytes'],'combined recorded byte budget exceeded')
    require(manifest['range_requests']+len(listings)+interrupted_charge_requests<=caps['requests'],'combined recorded request budget exceeded')
    require(active_wall<=caps['wall_seconds'],'combined active wall budget exceeded')
    matched=0
    if a.results:
        published=readjson(a.results/'label_blind_replay.json')
        require(published['source_manifest_sha256']==sha((a.data/'acquisition_manifest.json').read_bytes()),'replay source manifest mismatch')
        require(published['status']=='COMPLETE' and published['reference_labels_used'] is False and published['reference_join_performed'] is False,'result not label blind')
        target={(r['method'],r['init'],r['policy'],r['B']):r for r in published['case_score_rows']}
        require(len(target)==63,'expected exactly63 fixed policy cells')
        for method in ('outflow_rank_1_20','outflow_rank_1_10','core_count_60s_10'):
            for mode in (('daily_reset',) if method.startswith('core_count') else ('daily_reset','lookback_7d','cumulative_in_window')):
                trace=method_trace(rows,method,mode)
                for policy in ('greedy','paced_cumulative','token_bucket'):
                    for budget in (1,5,20):
                        alerts,suppressed=dispatch(trace,policy,budget)
                        actual={'selected_tx':len(trace),'eligible_tx':sum(x['eligible'] for x in trace) if method.startswith('outflow') else None,'raw_triggers':sum(x['raw'] for x in trace),'group_candidates':sum(x['candidate'] for x in trace),'notifications':len(alerts),'suppression_due_to_budget':suppressed,'notified_transactions':alerts}
                        expected=target[(method,mode,policy,budget)]
                        for key,value in actual.items():require(expected[key]==value,'policy cell differs: '+str((method,mode,policy,budget,key)))
                        matched+=1
    result={'schema':'phase31_nomad_standalone_offline_audit_v1','status':'PASS','selected_transactions':len(raw),'full_normalized_log_bundles':len(raw),'total_log_events':eventtotal,'full_amount_summary_matches':len(raw),'token_summary_rows':flowtotal,'positive_outflow_token_rows':flowpositive,'all_emitter_positive_erc20_shaped_events':positive_events,'transactions_with_all_emitter_positive_erc20_shaped_events':tx_with_positive_events,'policy_cells_matched':matched,'reference_labels_used':False,'network_requests_in_audit':0,'source_manifest_sha256':sha((a.data/'acquisition_manifest.json').read_bytes()),'resource_amendment_used':bool(continuation_limits),'cumulative_response_byte_limit':caps['total_response_bytes'],'audit_script_sha256':sha(Path(__file__).read_bytes()),'range_receipts_checked':manifest['range_requests'],'failed_prior_range_receipts_retained':failed_ranges,'acquisition_attempts':len(attempts)+interrupted_attempts,'interrupted_attempts_with_no_admitted_data':interrupted_attempts,'interrupted_resource_bytes_upper_bound':interrupted_charge_bytes,'interrupted_resource_requests_upper_bound':interrupted_charge_requests,'active_wall_seconds':active_wall,'range_response_bytes':manifest['range_bytes'],'listing_requests':len(listings),'listing_response_bytes':listing_bytes,'admitted_attempts_recorded_response_bytes':manifest['range_bytes']+listing_bytes,'cumulative_response_bytes_upper_bound':manifest['range_bytes']+listing_bytes+interrupted_charge_bytes,'cumulative_requests_upper_bound':manifest['range_requests']+len(listings)+interrupted_charge_requests,'all_recorded_response_bytes_within_cap':manifest['range_bytes']+listing_bytes+interrupted_charge_bytes<=caps['total_response_bytes'],'source_completeness_scope':'Saved normalized selected bundles reconcile with frozen30-day census and source range receipts. Original Parquet bodies are not retained for offline byte-to-normalization reconstruction; no receipt-root authentication.','source_provenance_independent_from_attack_labels':True}
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(result,indent=2))

if __name__=='__main__':main()
