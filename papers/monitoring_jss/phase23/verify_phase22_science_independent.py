#!/usr/bin/env python3
"""Independent row-level check of Phase22 score and notification replay.

Uses only published indexed observation artifacts and accepted CSV/JSON; does
not import or execute the detector or scoring/policy implementation. In
particular, references are added only after entire candidate streams are built.
"""
import argparse, collections, csv, datetime, gzip, hashlib, json, zipfile
from fractions import Fraction
from pathlib import Path

DAY=86400*10**9
REFS={'bacon_20220305':'0x7d2296bcb936aa5e2397ddf8ccba59f54a178c3901666b49291d880369dbcf31',
      'rari_pool127_20220430':'0xab486012f21be741c9e674ffda227e30518e8a1e37a5f1d58d0b0d41f6e76530'}
FILES={'bacon_20220305':'Article2_Phase22_IndexedFull_12894646607.zip',
       'rari_pool127_20220430':'Article2_Phase22_IndexedFull_12894666788.zip'}
MODES=['daily_reset','lookback_7d','cumulative_in_window']
POLICIES=['greedy','paced_cumulative','token_bucket']
BUDGETS=[1,5,20]

def hexhash(b):return hashlib.sha256(b).hexdigest()
def cjson(v):return json.dumps(v,ensure_ascii=False,allow_nan=False,sort_keys=True,separators=(',',':')).encode()

def inputs(base):
    out={}
    for case,name in FILES.items():
        with zipfile.ZipFile(base/name) as z:
            manifest=json.loads(z.read('acquisition_manifest.json'))
            lines=gzip.decompress(z.read('indexer_observations.jsonl.gz')).decode().splitlines()
        events=[json.loads(x) for x in lines if x]
        assert manifest['status']=='COMPLETE_30_DAYS'
        assert manifest['requested']==manifest['processed']==len(events)
        assert manifest['selected_rows_sha256']==hexhash(cjson(events))
        assert all(x['source_tier']=='pinned_AWS_selected_identity_and_indexed_Blockscout_all_emitter_logs_v1' for x in events)
        assert REFS[case] in {x['transaction']['transaction_hash'] for x in events}
        out[case]=events
    return out

def build_methods(records,role,mode,rank):
    memory=collections.defaultdict(list)
    last_day=None;anchor=None
    # Deliberately use exact Fraction for independently calculated ranks.
    rows=[]
    for rec in records:
        if role not in rec['views']:continue
        tx=rec['transaction'];t=tx['event_time_ns'];day=t//DAY
        if last_day!=day:
            if mode=='daily_reset':memory.clear()
            anchor=None;last_day=day
        good=False;eligible=False;positive=False;score_trace=[]
        for tok in rec['views'][role]['token_flows']:
            magnitude=int(tok['external_out_raw']);token=tok['token_address']
            if magnitude<=0:continue
            positive=True
            prior=memory[token]
            if mode=='lookback_7d':
                prior=[(at,v) for at,v in prior if at>=t-7*DAY];memory[token]=prior
            n=len(prior)
            value=Fraction(1+sum(magnitude<=v for _,v in prior),n+1)
            e=n>=19;eligible|=e;trigger=e and value<=Fraction(1,rank)
            good|=trigger
            score_trace.append((token,n,str(value),trigger))
        raw=good
        candidate=raw and (anchor is None or t-anchor>=300*10**9)
        if candidate:anchor=t
        rows.append({'day':day,'time':t,'tx':tx['transaction_hash'],'positive':positive,
                     'eligible':eligible,'raw':raw,'candidate':candidate,'scores':score_trace})
        # histories updated strictly after scoring entire transaction
        for token,n,value,trigger in score_trace:
            magnitude=next(int(x['external_out_raw']) for x in rec['views'][role]['token_flows'] if x['token_address']==token)
            memory[token]=(memory[token]+[(t,magnitude)])[-128:]
    return rows

def build_count(records,role):
    ans=[];day=-1;deque=collections.deque();running=0;anchor=None
    for rec in records:
        if role not in rec['views']:continue
        tx=rec['transaction'];t=tx['event_time_ns'];d=t//DAY
        if d!=day:
            day=d;deque.clear();running=0;anchor=None
        while deque and deque[0][0]<=t-60*10**9:
            _,n=deque.popleft();running-=n
        count=rec['views'][role]['archived_core_log_count']
        deque.append((t,count));running+=count
        raw=running>=10
        can=raw and (anchor is None or t-anchor>=300*10**9)
        if can:anchor=t
        ans.append({'day':d,'time':t,'tx':tx['transaction_hash'],
                    'positive':None,'eligible':None,'raw':raw,'candidate':can})
    return ans

def independently_issue(rows,policy,B):
    actual=[];sent_day=-1;sent=0;tokens=DAY;clock=0
    for rec in rows:
        d,t=rec['day'],rec['time']
        if d!=sent_day:
            sent_day=d;sent=0;tokens=DAY;clock=d*DAY
        if policy=='token_bucket':tokens=min(DAY,tokens+B*(t-clock))
        quota=min(B,1+B*(t-d*DAY)//DAY) if policy=='paced_cumulative' else B
        e=rec['candidate'] and sent<B and (policy!='paced_cumulative' or sent<quota) and (policy!='token_bucket' or tokens>=DAY)
        if e:
            sent+=1;actual.append(rec['tx'])
            if policy=='token_bucket':tokens-=DAY
        clock=t
    return actual

def verify(base):
    j=zipfile.ZipFile(base/'Article2_Phase22_CompleteReplay.zip')
    result=json.loads(j.read('full_replay.json'))
    assert result['status']=='COMPLETE' and result['cell_count']==len(result['cells'])==252
    inp=inputs(base)
    checks=0;trace=[];failures=[]
    for c in result['cells']:
        case,role,mode,method,policy,B=(c[k] for k in ['case','core_view','initialization','method','policy','daily_budget'])
        if method.startswith('outflow_rank_'):
            rank=int(method.rsplit('_',1)[-1]);rows=build_methods(inp[case],role,mode,rank)
        else:rows=build_count(inp[case],role)
        notifications=independently_issue(rows,policy,B)
        computed={'selected_tx':len(rows),'raw_triggers':sum(r['raw'] for r in rows),
                  'group_candidates':sum(r['candidate'] for r in rows),
                  'notifications':len(notifications),
                  'known_subset_exact_tx_hits':int(REFS[case] in notifications),
                  'emitted_tx':notifications}
        if method.startswith('outflow_rank_'):
            computed.update({'eligible_tx':sum(r['eligible'] for r in rows),
                'positive_core_outflow_tx':sum(r['positive'] for r in rows)})
        for key,value in computed.items():
            if c[key]!=value:failures.append({'cell':(case,role,mode,method,policy,B),'field':key,'got':value,'expected':c[key]})
        checks+=1
        if policy=='greedy' and B==5 and (method=='outflow_rank_1_20' or method=='core_count_60s_10'):
            trace.append({'case':case,'view':role,'method':method,'mode':mode,
                 'positive':computed.get('positive_core_outflow_tx'),
                 'eligible':computed.get('eligible_tx'),'raw':computed['raw_triggers'],
                 'notified':len(notifications),'hit':computed['known_subset_exact_tx_hits'],
                 'reference':next((r for r in rows if r['tx']==REFS[case]),None)})
    assert not failures,failures[:5]
    assert checks==252
    assert result['source_tier'].startswith('S3_selected_identities_verified')
    return {'status':'PASS','cells_recomputed':checks,'notification_streams_recomputed':checks,'cross_check_failures':0,
            'source_tier':result['source_tier'],'case_families':len(inp),'reference_examples':trace}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--inputs-dir',type=Path,default=Path('/mnt/data'))
    p.add_argument('--output',type=Path,default=Path('/mnt/data/article2_phase22/PHASE22_INDEPENDENT_SCIENCE_AUDIT.json'))
    a=p.parse_args();r=verify(a.inputs_dir);a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(r,indent=2)+'\n');print('PASS:',r['cells_recomputed'],'cells matched; references',len(r['reference_examples']))
