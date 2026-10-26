"""Exact owned pure-function extraction from the frozen Phase8 acquirer.

No acquisition, network, CLI or private path code is included. Function bodies and
constants are retained byte-for-byte as source segments; extraction provenance is
recorded separately. Transfer-shape decoding uses the unchanged public decoder.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import sys

PAPER = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PAPER))
from transfer_observation import decode_transfer_shape

TX_FIELDS=('chain_id','block_number','block_hash','transaction_hash','transaction_index','event_time_ns')

LOG_FIELDS=('address','topics','data','transaction_index','log_index','transaction_hash','block_number','block_hash','event_time_ns')

ZERO='0x'+'0'*40

HEX=re.compile(r'0x[0-9a-f]+\Z')

SCHEMA='archive_transfer_observation_v1'

TIER='enumerated_daily_partition_and_transaction_metadata_checked'

SOURCE_SCOPE='aws_public_blockchain_parquet_transaction_subset'

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()

def digest(raw):return hashlib.sha256(raw).hexdigest()

def require(test,message):
    if not test:raise ValueError(message)

def integer(v,name):
    require(type(v) is int and v>=0,'invalid integer '+name)
    return v

def hexvalue(v,n,name):
    require(isinstance(v,str),'invalid hex '+name);v=v.lower()
    require(v.startswith('0x') and len(v)==2+2*n and HEX.fullmatch(v),'invalid hex '+name)
    return v

def log_payload(row):return {k:row[k] for k in LOG_FIELDS}

def normalize_log(row,stamp):
    result={k:row[k] for k in LOG_FIELDS if k!='event_time_ns'}
    for k,n in [('address',20),('transaction_hash',32),('block_hash',32)]:result[k]=hexvalue(result[k],n,k)
    for k in ['transaction_index','log_index','block_number']:result[k]=integer(result[k],k)
    require(isinstance(result['topics'],list) and len(result['topics'])<=4,'invalid topics')
    result['topics']=[hexvalue(x,32,'topic') for x in result['topics']]
    d=result['data'];require(isinstance(d,str),'invalid data');d=d.lower()
    require(d.startswith('0x') and len(d)%2==0 and all(c in '0123456789abcdef' for c in d[2:]),'invalid data')
    result['data']=d;result['event_time_ns']=integer(stamp,'timestamp')
    return result

def validate_transaction(selected,metadata,logs,header,core_rows,population):
    require(logs,'selected core transaction has no source logs');identity={k:selected[k] for k in TX_FIELDS}
    require(metadata['dataset_execution_status']==1 and type(metadata['dataset_execution_status']) is int,'execution status unknown, failed or invalid')
    require(all(metadata[k]==identity[k] for k in TX_FIELDS),'transaction metadata identity mismatch')
    require(header['block_number']==identity['block_number'] and header['block_hash']==identity['block_hash'] and header['event_time_ns']==identity['event_time_ns'],'header mismatch')
    require(identity['transaction_index']<header['transaction_count'],'transaction position outside header')
    require(all(all(row[k]==identity[k] for k in TX_FIELDS if k!='chain_id') for row in logs),'mixed log transaction identity')
    indices=[integer(row['log_index'],'log_index') for row in logs]
    require(all(b==a+1 for a,b in zip(indices,indices[1:])),'duplicate, unsorted or gapped transaction logs')
    found=[log_payload(row) for row in logs if row['address'] in population]
    require(found==[log_payload(row) for row in core_rows],'archived core payload mismatch')
    require(len(found)==selected['archived_core_log_count'] and digest(canonical(found))==selected['archived_core_payload_sha256'],'core selection digest mismatch')
    return identity

def observe(identity,logs,population,core_count,audit_sha,selection_sha,*,dataset_execution_status):
    require(type(dataset_execution_status) is int and dataset_execution_status==1,'actual successful transaction metadata required')
    require(population and len(set(population))==len(population) and ZERO not in population,'invalid population');population=set(population)
    counts={'logs':len(logs),'erc20_shaped':0,'erc721_shaped':0,'opaque':0,'monitored_erc20_shaped':0,'zero_value_transfers':0};flows={}
    for log in logs:
        ev=decode_transfer_shape(log);counts[ev['kind']]+=1
        if ev['kind']!='erc20_shaped':continue
        amount=ev['amount_raw'];a=ev['from_address'];b=ev['to_address'];counts['zero_value_transfers']+=amount==0
        if a not in population and b not in population:continue
        counts['monitored_erc20_shaped']+=1;tok=log['address']
        f=flows.setdefault(tok,{'chain_id':1,'token_address':tok,'transfer_log_count':0,
          **{c+s:0 for c in ('external_in','external_out','internal','mint_from_zero','burn_to_zero') for s in ('_raw','_count')}})
        if a in population and b in population:c='internal'
        elif a==ZERO:c='mint_from_zero'
        elif b==ZERO:c='burn_to_zero'
        elif b in population:c='external_in'
        else:c='external_out'
        f[c+'_raw']+=amount;f[c+'_count']+=1;f['transfer_log_count']+=1
    for f in flows.values():
        f['net_external_in_raw']=f['external_in_raw']-f['external_out_raw']
        f['net_event_in_raw']=f['net_external_in_raw']+f['mint_from_zero_raw']-f['burn_to_zero_raw']
        for key in f:
            if key.endswith('_raw'):f[key]=str(f[key])
    return {'schema_version':SCHEMA,'status':'observed_success','dataset_execution_status':dataset_execution_status,
      'transaction':identity,'population_addresses':sorted(population),'counts':counts,
      'archived_core_log_count':core_count,'raw_amount_encoding':'base10_integer_string',
      'token_flows':[flows[t] for t in sorted(flows)],
      'evidence':{'tier':TIER,'source_kind':'aws_public_blockchain_parquet_transaction_subset',
        'source_audit_manifest_sha256':audit_sha,'selection_manifest_sha256':selection_sha,
        'raw_receipt_acquired':False,'receipt_root_verified':False,'historical_deployed_abi_verified':False,
        'token_erc20_compliance_verified':False,'observed_time':None,'full_chain_completeness_verified':False},
      'unavailable_fields':['actual_balance_change','native_asset_flow','token_decimals','token_price','economic_loss','historical_observed_time','attack_label']}
