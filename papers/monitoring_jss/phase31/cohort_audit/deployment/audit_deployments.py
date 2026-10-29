#!/usr/bin/env python3
"""Bounded indexed creation-time audit; network acquisition is explicit, replay is offline."""
from __future__ import annotations
import argparse,csv,hashlib,json,re,urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
from pathlib import Path
BASE=Path(__file__).resolve().parent
PAPER=BASE.parents[2]
FRAME=PAPER/'phase28/CANDIDATE_FRAME.json'
DAILY=PAPER/'phase28/results/CENSUS_DAILY.csv'
API='https://eth.blockscout.com/api/v2/'

def digest(b): return hashlib.sha256(b).hexdigest()
def save_json(path,x): path.write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
def acquire_one(c):
    folder=BASE/'raw'/c['id'];folder.mkdir(parents=True,exist_ok=True)
    receipts=[]
    def get(name,url):
        started=datetime.now(timezone.utc).isoformat()
        req=urllib.request.Request(url,headers={'User-Agent':'article2-indexed-creation-audit/1.0','Accept':'application/json'})
        with urllib.request.urlopen(req,timeout=25) as r:
            if r.status!=200: raise ValueError(f'HTTP {r.status}')
            b=r.read(1000001)
            if len(b)>1000000: raise ValueError('response cap exceeded')
            receipt={'url':url,'status':r.status,'fetched_at_utc':started,'sha256':digest(b),'bytes':len(b),'file':name+'.json'}
            receipts.append(receipt)
            (folder/(name+'.json')).write_bytes(b)
        return json.loads(b)
    status={'id':c['id'],'status':'UNAVAILABLE','receipts':receipts}
    try:
        a=get('address',API+'addresses/'+c['core_address'])
        if a.get('hash','').lower()!=c['core_address']: raise ValueError('address mismatch')
        h=a.get('creation_transaction_hash')
        if not h or not re.fullmatch('0x[0-9a-fA-F]{64}',h): raise ValueError('creation tx unknown')
        t=get('creation_transaction',API+'transactions/'+h)
        if t.get('hash','').lower()!=h.lower(): raise ValueError('transaction hash mismatch')
        if t.get('status')!='ok': raise ValueError('creation transaction status not ok')
        status['status']='FETCHED'
    except Exception as e:
        status['error']=type(e).__name__+': '+str(e)[:300]
    save_json(folder/'receipt.json',status)
    print(c['id'],status['status'],flush=True)
    return status

def replay(frame):
    daily=list(csv.DictReader(DAILY.open()))
    rows=[]
    for c in frame['cases']:
        folder=BASE/'raw'/c['id'];r={'id':c['id'],'family':c['family'],'core_address':c['core_address'],'status':'UNAVAILABLE'}
        try:
            receipt=json.loads((folder/'receipt.json').read_text())
            if receipt['status']!='FETCHED': raise ValueError(receipt.get('error','acquisition incomplete'))
            for p in receipt['receipts']:
                if digest((folder/p['file']).read_bytes())!=p['sha256']: raise ValueError('raw evidence checksum mismatch')
            a=json.loads((folder/'address.json').read_text());t=json.loads((folder/'creation_transaction.json').read_text())
            if a['hash'].lower()!=c['core_address'] or t['hash'].lower()!=a['creation_transaction_hash'].lower(): raise ValueError('identity mismatch')
            if t['status']!='ok' or a.get('creation_status')!='success': raise ValueError('unsuccessful creation metadata')
            if not isinstance(t.get('block_number'),int) or t['block_number']<0: raise ValueError('invalid creation block')
            dt=datetime.fromisoformat(t['timestamp'].replace('Z','+00:00'))
            if dt.utcoffset().total_seconds()!=0: raise ValueError('timestamp not UTC')
            day=dt.date().isoformat()
            d=[x for x in daily if x['id']==c['id']]
            if len(d)!=30: raise ValueError('wrong daily row count')
            pre=[x for x in d if x['day']<day]; dep=[x for x in d if x['day']==day]; after=[x for x in d if x['day']>day]; inclusive=dep+after
            if any(int(x['tx'])>0 for x in pre): raise ValueError('predeployment emissions conflict with metadata')
            r.update(status='INDEXED_CREATION_METADATA',creation_transaction_hash=t['hash'],creation_block=t.get('block_number'),creation_utc=t['timestamp'],creation_utc_day=day,
              window_first=min(x['day'] for x in d),window_last=max(x['day'] for x in d),predeployment_days=len(pre),deployment_day_in_window=len(dep),fully_postdeployment_days=len(after),
              deployment_day_tx=sum(int(x['tx']) for x in dep),postdeployment_including_partial_days=len(inclusive),postdeployment_including_partial_zero_days=sum(int(x['tx'])==0 for x in inclusive),
              postdeployment_including_partial_below20_days=sum(int(x['tx'])<20 for x in inclusive),fully_postdeployment_below20_days=sum(int(x['tx'])<20 for x in after),
              fully_postdeployment_zero_days=sum(int(x['tx'])==0 for x in after))
        except Exception as e: r['error']=type(e).__name__+': '+str(e)
        rows.append(r)
    accepted=[r for r in rows if r['status']=='INDEXED_CREATION_METADATA']
    out={'schema':'article2_phase31_indexed_creation_audit_v1','source_tier':'BLOCKSCOUT_INDEXED_CREATION_METADATA_NOT_RECEIPT_ROOT_AUTHENTICATION','frame_sha256':digest(FRAME.read_bytes()),'daily_csv_sha256':digest(DAILY.read_bytes()),
      'definition':'Strictly predeployment UTC dates are removed using indexed creation transaction UTC time; the creation date itself is partial exposure and reported separately. Address creation metadata is not a proof of all historical code incarnations.',
      'complete':len(accepted)==len(rows),'accepted':len(accepted),'total':len(rows),'cases':rows}
    if out['complete']:
        keys=['predeployment_days','deployment_day_in_window','fully_postdeployment_days','postdeployment_including_partial_days','postdeployment_including_partial_zero_days','postdeployment_including_partial_below20_days','fully_postdeployment_below20_days','fully_postdeployment_zero_days']
        out['aggregate']={k:sum(r[k] for r in accepted) for k in keys}
        n=out['aggregate']['postdeployment_including_partial_days'];k=out['aggregate']['postdeployment_including_partial_below20_days'];out['aggregate']['postdeployment_including_partial_below20_fraction']=k/n if n else None
        n=out['aggregate']['fully_postdeployment_days'];k=out['aggregate']['fully_postdeployment_below20_days'];out['aggregate']['fully_postdeployment_below20_fraction']=k/n if n else None
    save_json(BASE/'DEPLOYMENT_AUDIT.json',out)
    fields=list(dict.fromkeys(k for r in rows for k in r))
    with (BASE/'DEPLOYMENT_CASES.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,lineterminator="\n");w.writeheader();w.writerows(rows)
    print(json.dumps({k:v for k,v in out.items() if k!='cases'},indent=2))
    return out

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--acquire',action='store_true');args=p.parse_args();frame=json.loads(FRAME.read_text())
    if args.acquire:
        with ThreadPoolExecutor(max_workers=4) as pool: list(pool.map(acquire_one,frame['cases']))
    out=replay(frame)
    if not out['complete']: raise SystemExit(2)
