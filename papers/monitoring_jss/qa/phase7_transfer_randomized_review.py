"""Synthetic target-vs-independent-predicate audit; no network or real new logs."""
from pathlib import Path
import hashlib,importlib.util,json,random,sys
W=Path('/workspace/scratch/159bf77d8682');P=W/'monitoring-work/papers/monitoring_jss'
sys.path.insert(0,str(P))
import transfer_observation as target
s=importlib.util.spec_from_file_location('oracle',W/'phase7_transfer_oracle.py');oracle=importlib.util.module_from_spec(s);s.loader.exec_module(oracle)
def canon(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
A='0x'+'11'*20;B='0x'+'22'*20;C='0x'+'33'*20;ZERO='0x'+'00'*20
TOKENS=['0x'+f'{i:02x}'*20 for i in [170,187,204]]
TX='0x'+'12'*32;BLOCK='0x'+'34'*32
rng=random.Random(20261026);cases=0;log_count=0
for n in range(100):
    logs=[];provider=[]
    for index in range(rng.randrange(1,41)):
        sender=rng.choice([A,B,C,ZERO]);recipient=rng.choice([A,B,C,ZERO]);token=rng.choice(TOKENS)
        amount=rng.choice([0,1,2**53+1,2**256-1,rng.getrandbits(256)])
        topic_address=lambda a:'0x'+'0'*24+a[2:]
        kind=rng.randrange(7)
        topics=[oracle.SIG,topic_address(sender),topic_address(recipient)]
        data='0x'+f'{amount:064x}'
        if kind==0:topics.append('0x'+f'{amount:064x}');data='0x'
        elif kind==1:topics=['0x'+'ab'*32];data='0x1234'
        row={'address':token,'topics':topics,'data':data,'log_index':55+index,'block_number':100,
             'block_hash':BLOCK,'transaction_hash':TX,'transaction_index':7,'removed':None}
        logs.append(row)
        provider.append({'address':{'hash':token},'topics':topics+[None]*(4-len(topics)),'data':data,
                         'index':55+index,'block_number':100,'block_hash':BLOCK,'transaction_hash':TX})
    bundle={'schema_version':'transaction_log_bundle_v1','chain_id':1,'block_number':100,'block_hash':BLOCK,
            'transaction_hash':TX,'transaction_index':7,'event_time_ns':1709510400000000000,'receipt_status':1,'logs':logs}
    metadata={'hash':TX,'block_number':100,'position':7,'timestamp':'2024-03-04T00:00:00Z','status':'ok'}
    page={'items':list(reversed(provider)),'next_page_params':None}
    raws={'meta.json':canon(metadata),'logs.json':canon(page)}
    base='https://example.test/api/v2/transactions/'+TX
    src=lambda key,url:{'key':key,'url':url,'sha256':sha(raws[key]),'bytes':len(raws[key])}
    record={'schema_version':'transfer_source_record_v1','source_kind':'blockscout_v2_paginated_transaction_logs',
            'chain_id':1,'requested_transaction_hash':TX,'acquired_at_utc':'2026-10-26T08:00:00Z',
            'normalizer_source_sha256':'a'*64,'selection_manifest_sha256':'b'*64,
            'normalized_bundle_sha256':sha(canon(bundle)),'normalized_bundle_bytes':len(canon(bundle)),
            'expected_block':{k:bundle[k] for k in ['block_hash','block_number','transaction_index','event_time_ns']},
            'raw_receipt_acquired':False,'metadata':src('meta.json',base),
            'pages':[src('logs.json',base+'/logs')|{'request_params':{},'next_page_params':None,'item_count':len(logs)}]}
    expected_counts,expected_flows=oracle.raw_flow_oracle(logs,[A,B],1)
    observed=target.observe_transaction_log_bundle(canon(bundle),record,expected_source_record_sha256=sha(canon(record)),monitored_addresses=[A,B],raw_sources=raws)
    assert canon(observed['counts'])==canon(expected_counts)
    assert canon(observed['token_flows'])==canon(expected_flows)
    cases+=1;log_count+=len(logs)
report={'schema_version':'phase7_transfer_randomized_independent_review_v1','status':'PASS','seed':20261026,
        'synthetic_bundles':cases,'synthetic_logs':log_count,
        'target_source_sha256':sha((P/'transfer_observation.py').read_bytes()),
        'oracle_source_sha256':sha((W/'phase7_transfer_oracle.py').read_bytes()),
        'auditor_source_sha256':sha(Path(__file__).read_bytes()),
        'method':'Target outputs compared against separately written boundary-indicator/signed-contribution oracle; no production routine is used to derive expected values.',
        'coverage':['Three separate token emitters','Two monitored addresses','External and zero-address endpoints','Self and internal transfers','ERC721 shape and opaque topic','Values zero,2^53+1,uint256 maximum and random256bit','Exact decimal-string sums/differences','Descending provider presentation'],
        'actual_provider_data_used':False}
(W/'phase7_transfer_randomized_review.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps({k:report[k] for k in ['status','synthetic_bundles','synthetic_logs','target_source_sha256']}))
