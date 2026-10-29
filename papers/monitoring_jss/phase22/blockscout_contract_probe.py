#!/usr/bin/env python3
"""Preflight only: discover field shape and bounded completeness of Blockscout API."""
import json,urllib.request,urllib.parse,time,sys
from pathlib import Path
BASE='https://eth.blockscout.com/api/v2/transactions/'
TXS={
 'bacon_reference':'0x7d2296bcb936aa5e2397ddf8ccba59f54a178c3901666b49291d880369dbcf31',
 'rari_reference':'0xab486012f21be741c9e674ffda227e30518e8a1e37a5f1d58d0b0d41f6e76530',
 'bacon_day1':'0x3948a78772786fb8df348dee4af94a0063c54e38422485c68a227cbd092ca874',
 'rari_day1':'0x8a0aecff77dd0809f1ebfc4fc3f4763bda4b9e2d15931ceb9bcf9f4fb2457135'}

def fetch(url):
    with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'blockchain-monitoring-phase22/1','Accept':'application/json'}),timeout=15) as r:
        data=r.read(1_500_001)
        if len(data)>1_500_000: raise ValueError('oversize response')
    return json.loads(data)

out={}
for tag,txid in TXS.items():
    row={'txid':txid}
    try:
        tx=fetch(BASE+txid)
        row.update({'tx_fields':sorted(tx), 'reported_hash':tx.get('hash'),'status':tx.get('status'),
                    'block':tx.get('block'), 'timestamp':tx.get('timestamp'),
                    'transaction_index':tx.get('position')})
        logs=fetch(BASE+txid+'/logs')
        row.update({'logs_fields':sorted(logs) if isinstance(logs,dict) else ['list'],
                    'logs_count':len(logs.get('items',[])) if isinstance(logs,dict) else len(logs),
                    'next_page_params':logs.get('next_page_params') if isinstance(logs,dict) else None,
                    'sample_log_keys':sorted(logs['items'][0]) if isinstance(logs,dict) and logs.get('items') else []})
        if isinstance(logs,dict) and logs.get('items'):
            one=logs['items'][0]
            row['sample_log_redacted']={k:v for k,v in one.items() if k in ('log_index','index','tx_hash','transaction_hash','address','topics','data','block_number')}
        row['state']='AVAILABLE'
    except Exception as ex:row['state']='UNAVAILABLE';row['error']=type(ex).__name__+': '+str(ex)[:180]
    out[tag]=row
    print(tag,row['state'],row.get('logs_count'),row.get('status'),flush=True)
    time.sleep(.2)
Path('blockscout_contract_probe.json').write_text(json.dumps(out,indent=2)+'\n')