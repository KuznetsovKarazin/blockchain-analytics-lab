#!/usr/bin/env python3
"""Descriptive metadata of non-adjudicated notifications; no truth labels or detection claims.

Public Blockscout indexed transaction API is a secondary, fallible source.
A same-sender relation to a reference is NOT proof of exploit association.
Run only on the published Phase23 nineteen-line frozen alert ledger.
"""
import argparse,csv,datetime as dt,hashlib,json,time,urllib.error,urllib.request
from collections import Counter,defaultdict
from pathlib import Path
REFERENCES={
 'lifi_20220320':['0x4b4143cbe7f5475029cf23d6dcbb56856366d91794426f2e33819b9b1aac4e96'],
 'revest_20220327':['0xe0b0c2672b760bef4e2851e91c69c8c0ad135c6987bbf1f43f5846d89e691428','0x19b10c6d38f0b911fdc0e722d681a70a56699d70559eefef3d4d6fe88276c813'],
 'bacon_20220305':['0x7d2296bcb936aa5e2397ddf8ccba59f54a178c3901666b49291d880369dbcf31'],
 'rari_pool127_20220430':['0xab486012f21be741c9e674ffda227e30518e8a1e37a5f1d58d0b0d41f6e76530']}
ENDPOINT='https://eth.blockscout.com/api/v2/transactions/'
def fetch(tx):
    req=urllib.request.Request(ENDPOINT+tx,headers={'User-Agent':'academic-monitoring-audit/1.0'})
    with urllib.request.urlopen(req,timeout=15) as r:
        body=r.read(1000001)
        if len(body)>1000000:raise ValueError('oversize indexed record')
        assert r.status==200
    x=json.loads(body)
    def address(node):
        return node.get('hash','').lower() if isinstance(node,dict) else None
    return {'lookup':'INDEXED','source':'Blockscout_v2','tx':tx,
      'block':x.get('block'),'timestamp':x.get('timestamp'),'status':x.get('status'),
      'from':address(x.get('from')),'to':address(x.get('to')),
      'method':x.get('method'),'function_selector':x.get('raw_input','')[:10] if isinstance(x.get('raw_input'),str) else None,
      'value_wei':x.get('value'),'body_sha256':hashlib.sha256(body).hexdigest()}
def main():
    p=argparse.ArgumentParser();p.add_argument('--ledger',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();rows=list(csv.DictReader(a.ledger.open(newline='',encoding='utf8')))
    assert len(rows)==19 and sum(x['reference_status']=='UNADJUDICATED' for x in rows)==14
    unknown=defaultdict(list)
    for x in rows:
        if x['reference_status']=='UNADJUDICATED':unknown[(x['case'],x['tx'])].append(x)
    assert len(unknown)==12
    names=sorted({tx for case,tx in unknown}|{r for arr in REFERENCES.values() for r in arr})
    looked={}
    for tx in names:
        try: looked[tx]=fetch(tx)
        except Exception as err:looked[tx]={'lookup':'UNAVAILABLE','error':type(err).__name__+': '+str(err)[:180],'tx':tx}
        time.sleep(.15)
    out=[]
    for (case,tx),alert_rows in sorted(unknown.items()):
        item=looked[tx];refs=[looked[y] for y in REFERENCES[case]]
        ref_senders={r['from'] for r in refs if r['lookup']=='INDEXED' and r['from']}
        ref_recipients={r['to'] for r in refs if r['lookup']=='INDEXED' and r['to']}
        known_time=min([dt.datetime.fromisoformat(r['timestamp'].replace('Z','+00:00')) for r in refs if r['lookup']=='INDEXED' and r.get('timestamp')],default=None)
        at=dt.datetime.fromisoformat(item['timestamp'].replace('Z','+00:00')) if item['lookup']=='INDEXED' and item.get('timestamp') else None
        out.append({'case':case,'tx':tx,'alert_views':sorted({r['view'] for r in alert_rows}),
          'alert_modes':sorted({r['mode'] for r in alert_rows}),'alert_utc':alert_rows[0]['utc'],
          'source_status':item['lookup'],
          'indexed_success':item.get('status'),'from_address':item.get('from'),'to_address':item.get('to'),
          'method':item.get('method'),'input_selector':item.get('function_selector'),'value_wei':item.get('value_wei'),
          'same_sender_as_any_known_reference':item.get('from') in ref_senders if item.get('from') and ref_senders else None,
          'same_recipient_as_any_known_reference':item.get('to') in ref_recipients if item.get('to') and ref_recipients else None,
          'minutes_before_first_known_reference':round((known_time-at).total_seconds()/60,2) if known_time and at else None,
          'label':'UNADJUDICATED_NOT_BENIGN','indexed_body_sha256':item.get('body_sha256')})
    result={'schema':'article2_unadjudicated_alert_metadata_v1','status':'METADATA_ONLY_NOT_ADJUDICATION',
      'ledger_sha256':hashlib.sha256(a.ledger.read_bytes()).hexdigest(),'number_ledger_rows':len(rows),
      'unadjudicated_ledger_rows':14,'distinct_unadjudicated_transactions':12,
      'reference_transactions_queried':sum(map(len,REFERENCES.values())),
      'indexed_successful_lookups':sum(x['lookup']=='INDEXED' for x in looked.values()),
      'alerts':out,'references':[{**r,'known_case':case,'source_reference':'prior_verified_execution'} for case,arr in REFERENCES.items() for tx in arr for r in [looked[tx]]],
      'limitation':'Same sender/to does not prove benignity or attack relationship; no traces/call decoding/incident-inventory closure.'}
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print('TRIAGE:',len(out),'distinct unadjudicated transactions; indexed',result['indexed_successful_lookups'])
    print('SENDER MATCH:',[(x['case'],x['tx'][:10],x['same_sender_as_any_known_reference']) for x in out])
if __name__=='__main__':main()