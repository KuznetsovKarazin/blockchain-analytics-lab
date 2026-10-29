#!/usr/bin/env python3
"""Label-free descriptive source-boundary diagnostics; no core substitution."""
import argparse,collections,gzip,hashlib,json,re
from pathlib import Path
TRANSFER='0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
ZERO='0x'+'0'*40

def main():
 p=argparse.ArgumentParser();p.add_argument('--data',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 raw=(a.data/'acquisition_manifest.json').read_bytes();m=json.loads(raw)
 assert m['status']=='COMPLETE' and not m['reference_labels_used'] and not m['detector_scores_computed']
 with gzip.open(a.data/'raw_selected_bundles.jsonl.gz','rt') as f:rows=[json.loads(s) for s in f if s.strip()]
 assert len(rows)==930
 assert hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()==m['raw_bundles_sha256']
 core=m['core'];byday=collections.Counter();out=collections.Counter();into=collections.Counter();events=collections.Counter();tx_any=0;tx_core_out=0;tx_core_in=0;core_topics=collections.Counter()
 for row in rows:
  byday[row['day_utc']]+=1;senders=set();recipients=set();any_positive=False
  for e in row['events']:
   topics=e['topics'];d=e['data']
   if e['address']==core:core_topics[topics[0] if topics else '<no topic0>']+=1
   if not(len(topics)==3 and topics[0]==TRANSFER and re.fullmatch('0x[0-9a-f]{64}',d) and all(re.fullmatch('0x[0-9a-f]{64}',x) and x[2:26]=='0'*24 for x in topics[1:])):continue
   amount=int(d,16)
   if amount<=0:continue
   source='0x'+topics[1][-40:];target='0x'+topics[2][-40:];any_positive=True;events[e['address']]+=1
   if source!=target and source!=ZERO and target!=ZERO:
    senders.add(source);recipients.add(target)
  tx_any+=any_positive;tx_core_out+=core in senders;tx_core_in+=core in recipients
  out.update(senders);into.update(recipients)
 result={'schema':'article2_phase31_nomad_boundary_diagnostics_v1','status':'COMPLETE_DESCRIPTIVE','source_manifest_sha256':hashlib.sha256(raw).hexdigest(),'labels_used':False,'core_changed':False,'selected_transactions':len(rows),'full_selected_log_events':sum(len(r['events']) for r in rows),'positive_erc20_shaped_events':sum(events.values()),'nominated_core':core,'selected_tx_with_any_positive_erc20_shaped_transfer':tx_any,'selected_tx_with_positive_external_transfer_from_nominated_core':tx_core_out,'selected_tx_with_positive_external_transfer_to_nominated_core':tx_core_in,'daily_selected_transactions':dict(sorted(byday.items())),'nominee_emitted_topic0_counts':dict(core_topics),'outside_or_inside_core_senders_by_selected_tx_count':out.most_common(12),'outside_or_inside_core_recipients_by_selected_tx_count':into.most_common(12),'positive_erc20_shaped_events_by_token':dict(events),'interpretation':'Describes the preselected emitter boundary only; not economic loss, alternative-core detector performance, or attack inventory.'}
 a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps({k:v for k,v in result.items() if isinstance(v,(int,str,bool))},sort_keys=True))
if __name__=='__main__':main()
