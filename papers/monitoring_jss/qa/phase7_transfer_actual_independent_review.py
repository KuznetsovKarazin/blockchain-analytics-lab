"""Audit retained phase7 HTTP evidence and independently derive all transfer flows.

No network calls and no imports from production observer/collector modules.
"""
import argparse
from collections import Counter,OrderedDict
from datetime import date
import hashlib,importlib.util,json,re
from pathlib import Path
from urllib.parse import parse_qs,urlsplit

WORK=Path('/workspace/scratch/159bf77d8682')
REPO=WORK/'monitoring-work';PAPER=REPO/'papers/monitoring_jss'
CORE='0x27182842e098f60e3d576794a5bffb0777e025d3'
BASE='https://eth.blockscout.com/api/v2/'
PAYLOAD=('chain_id','address','block_number','block_hash','transaction_index','transaction_hash','log_index','event_time_ns','topics','data')
spec=importlib.util.spec_from_file_location('independent_transfer_flow_oracle',WORK/'phase7_transfer_oracle.py')
oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)

def canon(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def sha(data):return hashlib.sha256(data).hexdigest()
def file_sha(path):return sha(Path(path).read_bytes())
def strict_json(data):
    def pairs(items):
        value={}
        for k,v in items:
            assert k not in value,('duplicate JSON key',k)
            value[k]=v
        return value
    def reject(value):raise AssertionError(('nonfinite JSON',value))
    return json.loads(data,object_pairs_hook=pairs,parse_constant=reject)
def read(path):return strict_json(Path(path).read_bytes())
def integer(value,minimum=0):
    assert type(value) is int and value>=minimum
    return value
def quantity(value):
    if type(value) is str:
        assert re.fullmatch(r'0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)',value)
        value=int(value,16)
    return integer(value)
def hexfield(value,size=None):return oracle.exact_hex(value,size)
def timestamp(value):
    assert type(value) is str
    m=re.fullmatch(r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|\+00:00)',value)
    assert m
    y,mo,d,h,mi,se=map(int,m.groups()[:6]);assert h<24 and mi<60 and se<60
    days=(date(y,mo,d)-date(1970,1,1)).days;assert days>=0
    return ((days*24+h)*3600+mi*60+se)*10**9+int((m.group(7) or '').ljust(9,'0'))
def raw_log(item,expected,tx):
    candidates=[]
    for key in ('address','address_hash'):
        value=item.get(key)
        if value is not None:
            if type(value) is dict:value=value['hash']
            candidates.append(hexfield(value,20))
    assert candidates and len(set(candidates))==1
    assert type(item['topics']) is list and len(item['topics'])<=4
    topics=list(item['topics'])
    while topics and topics[-1] is None:topics.pop()
    topics=[hexfield(v,32) for v in topics]
    assert hexfield(item['transaction_hash'],32)==tx
    assert hexfield(item['block_hash'],32)==expected['block_hash']
    assert quantity(item['block_number'])==expected['block_number']
    if 'transaction_index' in item:assert quantity(item['transaction_index'])==expected['transaction_index']
    if item.get('block_timestamp') is not None:assert timestamp(item['block_timestamp'])==expected['event_time_ns']
    removed=item.get('removed');assert removed is None or type(removed) is bool and removed is False
    return {'address':candidates[0],'topics':topics,'data':hexfield(item['data']),
            'log_index':quantity(item['index']),'block_number':expected['block_number'],'block_hash':expected['block_hash'],
            'transaction_hash':tx,'transaction_index':expected['transaction_index'],'removed':removed}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--sample-summary',type=Path,required=True);ap.add_argument('--raw-root',type=Path,required=True);ap.add_argument('--freeze',type=Path,required=True);ap.add_argument('--output',type=Path,default=WORK/'phase7_transfer_actual_independent_review.json');args=ap.parse_args()
    freeze_dir=args.freeze.parent;freeze=read(args.freeze);config=read(freeze_dir/'config.json');selection=read(freeze_dir/'selection.json');run=read(args.sample_summary)
    assert file_sha(freeze_dir/'config.json')==freeze['config_sha256']
    assert file_sha(freeze_dir/'selection.json')==freeze['selection_sha256']
    assert set(freeze['source_sha256'])=={'transfer_observation.py','sample_transfer_observations.py'}
    for name,checksum in freeze['source_sha256'].items():assert file_sha(PAPER/name)==checksum
    for name,checksum in freeze['frozen_file_sha256'].items():assert file_sha(freeze_dir/name)==checksum
    assert run['frozen_bytes_unchanged'] is True and run['source_sha256']==freeze['source_sha256']
    assert run['config_sha256']==freeze['config_sha256'] and run['selection_sha256']==freeze['selection_sha256'] and run['freeze_sha256']==file_sha(args.freeze)
    frozen_ns=timestamp(freeze['frozen_utc']);assert timestamp(run['started_utc'])>=frozen_ns and timestamp(run['completed_utc'])>=timestamp(run['started_utc'])
    assert config['provider_base']==BASE and config['chain_id']==1 and config['monitored_addresses']==[CORE] and config['no_replacements'] is True
    assert config['limits']=={'max_log_pages_per_transaction':10,'max_requests_total':110,'max_response_bytes':1048576,'redirects':False,'retries':0,'timeout_seconds':30,'workers':2}
    source_path=REPO/config['archived_input_path'];assert file_sha(source_path)==freeze['archived_input_sha256']==config['archived_input_sha256']
    rows=[strict_json(line) for line in source_path.read_bytes().splitlines()];assert len(rows)==1247
    grouped=OrderedDict();previous=None
    for r in rows:
        key=(integer(r['block_number']),integer(r['transaction_index']),integer(r['log_index']))
        assert previous is None or previous<key;previous=key
        assert r['chain_id']==1 and r['address']==CORE
        grouped.setdefault(r['transaction_hash'],[]).append({k:r[k] for k in PAYLOAD})
    assert len(grouped)==218
    selected=selection['transactions'];assert len(selected)==10 and [r['transaction_hash'] for r in selected]==list(grouped)[:10]
    assert len(run['transactions'])==10 and run['selected_transactions']==10
    assert selection['new_transaction_provider_calls_before_selection']==0 and selection['new_transfer_results_observed'] is False
    for i,sel in enumerate(selected):
        src=grouped[sel['transaction_hash']]
        assert sel['selection_index']==i and sel['archived_core_logs']==len(src) and sha(canon(src))==sel['archived_core_payload_sha256']
        assert sel['first_log_index']==src[0]['log_index']
        assert all(src[0][k]==v for k,v in sel['expected_block'].items())
    assert sum(r['archived_core_logs'] for r in selected)==58
    aggregate=Counter();core_aggregate=Counter();boundary_tokens=set();per_tx=[];request_rows=[];all_urls=set();accepted=0
    for sel,tx_summary in zip(selected,run['transactions']):
        i=sel['selection_index'];tx=sel['transaction_hash'];folder=args.raw_root/f'tx_{i:02d}'
        summary=read(folder/'transaction_summary.json');assert canon(summary)==canon(tx_summary)
        assert summary['selection_index']==i and summary['transaction_hash']==tx and summary['archived_core_logs']==sel['archived_core_logs']
        receipts={}
        for name in ['metadata.json']+[f'logs_page_{n:03d}.json' for n in range(1,11)]:
            receipt_path=folder/(name+'.receipt.json');body_path=folder/name
            assert receipt_path.exists()==body_path.exists()
            if not receipt_path.exists():continue
            receipt=read(receipt_path);data=body_path.read_bytes();assert receipt['key']==name
            assert receipt['method']=='GET' and receipt['bytes']==len(data)<=1048576 and receipt['sha256']==sha(data)
            assert timestamp(receipt['started_utc'])>=frozen_ns and timestamp(receipt['completed_utc'])>=timestamp(receipt['started_utc'])
            assert type(receipt['elapsed_seconds']) in (int,float) and receipt['elapsed_seconds']>=0
            url=urlsplit(receipt['url']);assert url.scheme=='https' and url.netloc=='eth.blockscout.com' and not url.fragment
            expected_path='/api/v2/transactions/'+tx+('' if name=='metadata.json' else '/logs');assert url.path==expected_path
            params=receipt['request_params'];assert type(params) is dict
            assert parse_qs(url.query,keep_blank_values=True)=={k:[str(v)] for k,v in params.items()}
            assert receipt['url'] not in all_urls;all_urls.add(receipt['url'])
            if 'error' not in receipt:
                assert receipt['status']==200 and receipt['body_complete'] is True
                length=next((v for k,v in receipt['headers'].items() if k.lower()=='content-length'),None)
                if length is not None:assert str(length).isdigit() and int(length)==len(data)
            receipts[name]=(receipt,data);request_rows.append({'selection_index':i,'key':name,'status':receipt.get('status'),'error':receipt.get('error'),'bytes':len(data),'sha256':sha(data)})
        if summary['status']!='accepted_development_observation':
            assert summary['status']=='not_accepted' and type(summary['reason']) is str and summary['reason']
            assert not (folder/'transfer_observation.json').exists() and 'observation_counts' not in summary
            per_tx.append({'selection_index':i,'transaction_hash':tx,'status':'not_accepted','retained_reason':summary['reason'],'requests':len(receipts)})
            continue
        accepted+=1
        assert summary['provider_pagination_exhausted'] is True and summary['archived_core_payloads_match'] is True
        record=read(folder/'source_record.json');bundle_bytes=(folder/'normalized_bundle.json').read_bytes();bundle=strict_json(bundle_bytes);observation=read(folder/'transfer_observation.json')
        assert sha(canon(record))==summary['source_record_sha256'] and sha(bundle_bytes)==summary['normalized_bundle_sha256']==record['normalized_bundle_sha256']
        assert bundle_bytes==canon(bundle) and len(bundle_bytes)==record['normalized_bundle_bytes']
        assert sha(canon(observation))==summary['observation_sha256']
        assert record['selection_manifest_sha256']==freeze['selection_sha256'] and record['normalizer_source_sha256']==freeze['source_sha256']['sample_transfer_observations.py']
        assert record['source_kind']=='blockscout_v2_paginated_transaction_logs' and record['raw_receipt_acquired'] is False and record['observed_time'] is None
        assert record['chain_id']==1 and record['requested_transaction_hash']==tx and record['expected_block']==sel['expected_block']
        assert timestamp(record['acquired_at_utc'])>=frozen_ns
        expected=sel['expected_block'];sources=[record['metadata'],*record['pages']]
        assert len(record['pages'])==summary['provider_log_pages']<=10 and len(sources)==len(receipts)
        for source in sources:
            receipt,data=receipts[source['key']]
            assert all(source[k]==receipt[k] for k in ('key','url','sha256','bytes'))
            assert receipt['body_complete'] is True and receipt['status']==200 and 'error' not in receipt
        metadata=strict_json(receipts[record['metadata']['key']][1]);assert hexfield(metadata['hash'],32)==tx
        assert quantity(metadata['block_number'])==expected['block_number'] and quantity(metadata['position'])==expected['transaction_index'] and timestamp(metadata['timestamp'])==expected['event_time_ns']
        if metadata.get('block_hash') is not None:assert hexfield(metadata['block_hash'],32)==expected['block_hash']
        assert metadata['status'] in ('ok','error');status=int(metadata['status']=='ok')
        normalized=[];cursor={};seen_cursors=set()
        for j,page in enumerate(record['pages']):
            assert page['request_params']==cursor
            marker=canon(cursor);assert marker not in seen_cursors;seen_cursors.add(marker)
            raw_page=strict_json(receipts[page['key']][1]);assert type(raw_page['items']) is list
            assert len(raw_page['items'])==page['item_count']
            assert raw_page['next_page_params']==page['next_page_params']
            next_cursor=raw_page['next_page_params'];assert (next_cursor is None)==(j==len(record['pages'])-1)
            if next_cursor is not None:assert type(next_cursor) is dict and next_cursor and set(next_cursor)<={'index','items_count','block_number'} and all(type(v) is int and v>=0 for v in next_cursor.values())
            normalized.extend(raw_log(item,expected,tx) for item in raw_page['items']);cursor=next_cursor
        normalized.sort(key=lambda item:item['log_index'])
        indices=[r['log_index'] for r in normalized];assert all(b-a==1 for a,b in zip(indices,indices[1:]))
        assert status==1 or not normalized
        expected_bundle={'schema_version':'transaction_log_bundle_v1','chain_id':1,'block_number':expected['block_number'],'block_hash':expected['block_hash'],'transaction_hash':tx,'transaction_index':expected['transaction_index'],'event_time_ns':expected['event_time_ns'],'receipt_status':status,'logs':normalized}
        assert canon(bundle)==canon(expected_bundle)
        core=[{k:(bundle[k] if k in ('chain_id','event_time_ns') else r[k]) for k in PAYLOAD} for r in normalized if r['address']==CORE]
        assert canon(core)==canon(grouped[tx]) and len(core)==sel['archived_core_logs']
        counts,flows=oracle.raw_flow_oracle(normalized,[CORE],1)
        core_counts,_=oracle.raw_flow_oracle(core,[CORE],1);core_aggregate.update(core_counts)
        boundary_tokens.update(r['token_address'] for r in flows)
        assert canon(counts)==canon(observation['counts'])==canon(summary['observation_counts']) and canon(flows)==canon(observation['token_flows'])
        assert observation['raw_amount_encoding']=='base10_integer_string'
        assert observation['transaction']=={'chain_id':1,**expected,'transaction_hash':tx}
        assert observation['population_addresses']==[CORE] and observation['provider_execution_status']==status
        assert observation['status']==('observed_success' if status else 'observed_failed_transaction')
        evidence=observation['evidence'];assert evidence['source_record_sha256']==sha(canon(record))
        assert evidence['selection_manifest_sha256']==freeze['selection_sha256'] and evidence['normalizer_source_sha256']==record['normalizer_source_sha256'] and evidence['provider_page_count']==len(record['pages'])
        for key in ('raw_receipt_acquired','receipt_root_verified','historical_deployed_abi_verified','token_erc20_compliance_verified','full_chain_completeness_verified'):assert evidence[key] is False
        assert evidence['observed_time'] is None and evidence['tier']=='provider_pagination_exhausted_structure_checked'
        aggregate.update(counts)
        per_tx.append({'selection_index':i,'transaction_hash':tx,'status':'independently_verified','provider_logs':len(normalized),'provider_pages':len(record['pages']),'archived_core_logs':len(core),'counts':counts,'token_flow_rows':len(flows),'independent_flow_sha256':sha(canon(flows)),'raw_hashes_verified':len(sources)})
    assert accepted==run['accepted_observations'] and len(request_rows)==run['requests_attempted']<=110
    assert all(r['transaction_hash']==selected[i]['transaction_hash'] for i,r in enumerate(per_tx))
    for name,checksum in freeze['frozen_file_sha256'].items():assert file_sha(freeze_dir/name)==checksum
    for name,checksum in freeze['source_sha256'].items():assert file_sha(PAPER/name)==checksum
    report={'schema_version':'phase7_transfer_actual_independent_review_v1','status':'PASS','auditor_sha256':file_sha(__file__),'oracle_sha256':file_sha(WORK/'phase7_transfer_oracle.py'),'freeze_sha256':file_sha(args.freeze),'sample_summary_sha256':file_sha(args.sample_summary),'frozen_sources_unchanged':True,'selected_transactions':10,'selected_core_logs':58,'accepted_transactions_independently_recomputed':accepted,'not_accepted_transactions':10-accepted,'request_count':len(request_rows),'request_caps_respected':True,'no_replacements':True,'raw_response_hashes_sizes_and_receipts_verified':len(request_rows),'aggregate_counts':dict(aggregate),'archived_core_emitter_shape_counts':dict(core_aggregate),'distinct_monitored_boundary_token_emitters':len(boundary_tokens),'transactions':per_tx,'request_receipts':request_rows,'method':'Original retained provider bytes independently parsed and normalized, all accepted metadata/cursors/identity/core subsets checked, and all counts/amount strings independently recomputed by boundary predicates and signed contributions; no production module imported.','limitations':['Only captured indexer responses and prior archived core subsets are verified. Omitted non-core prefix/suffix logs and receipt-root completeness remain unproven.','First ten ordinary-day development transactions are not representative or adjudicated safe, and this is not an attack detection test.','Source hashes anchor retained consistency, not provider authenticity or the historical server version.','Observation shape and transfer-event arithmetic do not establish token compliance, actual balances or economic values.'],'network_calls_by_auditor':0}
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:report[k] for k in ['status','accepted_transactions_independently_recomputed','not_accepted_transactions','request_count','aggregate_counts']}))
if __name__=='__main__':main()
