#!/usr/bin/env python3
"""Bounded Blockscout fork-date and creation-metadata acquisition; offline replay."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.request

HERE=Path(__file__).resolve().parent
API='https://eth.blockscout.com/api/v2/'

def sha(b): return hashlib.sha256(b).hexdigest()
def write(path, data):
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.tmp')
    with temp.open('wb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    os.replace(temp,path)
def save(path,obj):write(path,(json.dumps(obj,indent=2,sort_keys=True)+'\n').encode())
def read(path):return json.loads(path.read_text())

def fetch(folder,name,url):
    target=folder/(name+'.json'); receipt=folder/(name+'_receipt.json')
    if target.exists() and receipt.exists():
        r=read(receipt); b=target.read_bytes()
        assert r['url']==url and r['status']==200 and sha(b)==r['sha256']
        return json.loads(b)
    folder.mkdir(parents=True,exist_ok=True)
    start=datetime.now(timezone.utc).isoformat()
    req=urllib.request.Request(url,headers={'User-Agent':'article2-phase32-source-metadata/1.0','Accept':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=25) as response:
            assert response.status==200,response.status
            b=response.read(1_000_001);assert len(b)<=1_000_000,'response size cap'
            obj=json.loads(b)
        write(target,b)
        save(receipt,{'url':url,'status':200,'started_utc':start,'sha256':sha(b),'bytes':len(b),'file':target.name})
        return obj
    except Exception as e:
        save(folder/(name+'_failure.json'),{'url':url,'started_utc':start,'error':type(e).__name__+': '+str(e)})
        raise

def acquire_block(block):
    try:
        fetch(HERE/'raw'/'blocks'/str(block),'block',API+'blocks/'+str(block))
        return {'fork_block':block,'status':'FETCHED'}
    except Exception as e:return {'fork_block':block,'status':'UNAVAILABLE','error':str(e)}

def acquire_address(address):
    try:
        folder=HERE/'raw'/'contracts'/address
        a=fetch(folder,'address',API+'addresses/'+address)
        assert a['hash'].lower()==address
        tx=a.get('creation_transaction_hash')
        assert isinstance(tx,str) and re.fullmatch('0x[0-9a-fA-F]{64}',tx),'unknown creation transaction'
        fetch(folder,'creation_transaction',API+'transactions/'+tx)
        return {'core_address':address,'status':'FETCHED'}
    except Exception as e:return {'core_address':address,'status':'UNAVAILABLE','error':str(e)}

def verified(folder,name):
    b=(folder/(name+'.json')).read_bytes();r=read(folder/(name+'_receipt.json'))
    assert r['status']==200 and r['file']==name+'.json' and sha(b)==r['sha256']
    assert r['bytes']==len(b)
    return json.loads(b)

def utc(s):
    t=datetime.fromisoformat(s.replace('Z','+00:00'))
    assert t.utcoffset()==timedelta(0),'not UTC'
    return t

def verify():
    mapping=read(HERE/'SOURCE_MAPPING.json');rows=mapping['rows']
    blocks=[];creations=[]
    for n in sorted({r['fork_block'] for r in rows}):
        result={'fork_block':n,'status':'UNAVAILABLE'}
        try:
            b=verified(HERE/'raw'/'blocks'/str(n),'block')
            assert b.get('height',b.get('number'))==n,'block height mismatch'
            t=utc(b['timestamp']);end=t.date()
            result.update(status='INDEXED_BLOCK_DATE',fork_block_utc=t.isoformat(),block_hash=b.get('hash'),
                          window_first=(end-timedelta(days=29)).isoformat(),window_last_inclusive=end.isoformat())
        except Exception as e:result['error']=type(e).__name__+': '+str(e)
        blocks.append(result)
    for core in sorted({r['recommended_core_address'] for r in rows}):
        result={'core_address':core,'status':'UNAVAILABLE'}
        try:
            folder=HERE/'raw'/'contracts'/core
            a=verified(folder,'address');t=verified(folder,'creation_transaction')
            assert a['hash'].lower()==core and t['hash'].lower()==a['creation_transaction_hash'].lower()
            assert a.get('is_contract') is True and a.get('creation_status')=='success' and t.get('status')=='ok'
            assert type(t['block_number']) is int and t['block_number']>=0
            stamp=utc(t['timestamp'])
            result.update(status='INDEXED_CREATION_METADATA',creation_transaction_hash=t['hash'].lower(),
                          creation_block=t['block_number'],creation_utc=stamp.isoformat(),creation_utc_day=stamp.date().isoformat())
        except Exception as e:result['error']=type(e).__name__+': '+str(e)
        creations.append(result)
    out={'schema':'phase32_catalogue_completion_metadata_v1','source_tier':'BLOCKSCOUT_INDEXED_METADATA_NOT_RECEIPT_ROOT_AUTHENTICATION',
         'mapping_sha256':sha((HERE/'SOURCE_MAPPING.json').read_bytes()),'fork_blocks':blocks,'contract_creations':creations,
         'complete_fork_blocks':sum(r['status']=='INDEXED_BLOCK_DATE' for r in blocks),
         'complete_contract_creations':sum(r['status']=='INDEXED_CREATION_METADATA' for r in creations),
         'limits':'Creation date is indexed contract-address metadata, not proof of all historical code incarnations. Fork-date windows are whole UTC dates, not strictly pre-attack windows.',
         'traffic_acquired':False,'scores_computed':False,'network_requests_during_verification':0}
    out['status']='COMPLETE' if out['complete_fork_blocks']==7 and out['complete_contract_creations']==6 else 'INCOMPLETE'
    save(HERE/'METADATA_AUDIT.json',out)
    return out

def main():
    p=argparse.ArgumentParser();p.add_argument('--acquire',action='store_true');a=p.parse_args()
    rows=read(HERE/'SOURCE_MAPPING.json')['rows']
    if a.acquire:
        with ThreadPoolExecutor(max_workers=4) as pool:
            tasks=[pool.submit(acquire_block,n) for n in sorted({r['fork_block'] for r in rows})]
            tasks += [pool.submit(acquire_address,n) for n in sorted({r['recommended_core_address'] for r in rows})]
            acquired=[f.result() for f in tasks]
        save(HERE/'ACQUISITION.json',{'units':acquired,'request_timeout_seconds':25,'max_response_bytes':1_000_000,'concurrency':4,'automatic_retries':0})
    out=verify();print(json.dumps(out,indent=2))
    if out['status']!='COMPLETE':raise SystemExit(2)

if __name__=='__main__':main()
