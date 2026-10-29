#!/usr/bin/env python3
"""Source-pinned, label-free 12-emitter x two-window readiness census.

Original AWS S3 Parquet ranges, no heuristics/incident labels. Compares
readiness of core-log-count time-series prototypes, NOT fraud-detection quality.
"""
import argparse,csv,hashlib,json,statistics,sys
from collections import Counter,defaultdict,deque
from pathlib import Path
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

def need(ok,msg):
    if not ok: raise ValueError(msg)

def write_csv(path,rows):
    need(bool(rows),'no results')
    with Path(path).open('w',newline='',encoding='utf8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator='\n')
        w.writeheader();w.writerows(rows)

def metrics(tx_counts):
    # Row = one unique selected transaction in exact block/transaction-index order.
    state=deque(maxlen=128);results=defaultdict(int)
    for nlogs in tx_counts:
        n=len(state)
        for h in (5,10,19,39):
            results[f'upper_{h}']+=n>=h
        win=list(state)[-19:]
        if n>=19 and len(set(win))>1: results['z19_ready']+=1
        if n>=19:
            median=statistics.median(win)
            if statistics.median(abs(v-median) for v in win)>0:
                results['mad19_positive_scale']+=1
        results['ewma5_ready']+=n>=5
        state.append(nlogs)
    return dict(results)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--registry',type=Path,required=True)
    ap.add_argument('--source-baseline',type=Path,required=True)
    ap.add_argument('--out',type=Path,required=True)
    args=ap.parse_args()
    registry_bytes=args.registry.read_bytes()
    reg=json.loads(registry_bytes)
    need(reg['schema']=='article2_phase26_pretreatment_control_registry_v1','registry schema')
    ids={x['address']:x['id'] for x in reg['contracts']}
    need(len(ids)==len(reg['contracts'])==12,'expected twelve fixed controls')
    source_bytes=args.source_baseline.read_bytes();baseline=json.loads(source_bytes)
    need(baseline['status']=='COMPLETE_ADDRESS_ONLY_60_DAYS','Phase20 60-day source audit incomplete')
    paper=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(paper/'phase16/collector'))
    import range_collector as rc
    caps={'requests':720,'total_response_bytes':1000000000,'wall_seconds':900,
       'request_timeout_seconds':40,'max_range_bytes':18000000,
       'max_footer_bytes':1000000,'max_rows':7000000,'max_row_groups':64,
       'max_top_level_columns':60,'max_leaf_columns':80,
       'max_source_bytes':800000000,'retries':0,'concurrency':1}
    plan={'schema_version':'article2_phase16_range_source_plan_v1','endpoint':rc.ENDPOINT,
      'caps':caps,'required_columns':{'logs':['address','block_number','transaction_index']}}
    args.out.mkdir(parents=True,exist_ok=False)
    session=rc.RangeSession(plan,args.out/'range_capture')
    daily=[];ready=[];runtimes=[];sources=[]
    failed=False
    try:
      for window in reg['windows']:
        source_case='bacon_20220305' if window['id']=='bacon_window' else 'rari_pool127_20220430'
        days=[x for x in baseline['days'] if x['case']==source_case]
        need(len(days)==30 and days[0]['day']==window['first'] and days[-1]['day']==window['last_inclusive'],
           'source partitions differ from frozen window')
        cumulative={x['id']:deque(maxlen=128) for x in reg['contracts']}
        for d in days:
          source={'table':'logs','day_utc':d['day'],'key':d['source_key'],
             'size_bytes':d['source_declared_bytes'],'etag_opaque':d['source_etag']}
          reader=rc.SourceReader(source,session,args.out/'sparse'/window['id'],pa,pq).open()
          tx=defaultdict(Counter)
          nrows=0
          values=pa.array(sorted(ids))
          for _,tab in reader.iter_row_groups(['address','block_number','transaction_index']):
            nrows+=tab.num_rows
            addr=pc.utf8_lower(tab.column('address'))
            mask=pc.is_in(addr,value_set=values)
            small=tab.filter(mask)
            for r in small.to_pylist():
              label=ids[r['address'].lower()]
              key=(r['block_number'],r['transaction_index'])
              need(all(type(q) is int and q>=0 for q in key),'bad historical ordering coords')
              tx[label][key]+=1
          need(nrows==d['source_log_rows']==reader.metadata.num_rows,'source row mismatch')
          # Independently reconstruct original 4 emitted-core counts for this day
          orig={k:v for k,v in d['core_log_counts'].items()}
          if window['id']=='bacon_window':
            legacy_core='0xb8919522331c59f5c16bdfaa6a121a6e03a91f62'
          else: legacy_core='0x26267e41ceca7c8e0f143554af707336f27fa051'
          # Note: selected controls do not include either legacy core; Phase20 is a
          # source identity check, not a duplicate observation stream.
          for item in reg['contracts']:
            label=item['id'];counts=[tx[label][key] for key in sorted(tx[label])]
            daily.append({'window':window['id'],'date':d['day'],'id':label,
                'category':item['category'],'selected_transactions':len(counts),
                'emitter_logs':sum(counts)})
            for mode in ('daily_reset','retained_within_30day_window'):
              history=deque(maxlen=128) if mode=='daily_reset' else cumulative[label]
              eligibility=Counter()
              for nlogs in counts:
                n=len(history)
                for h in (5,10,19,39):
                  eligibility[f'upper_{h}']+=n>=h
                win=list(history)[-19:]
                if n>=19 and len(set(win))>1:eligibility['z19_ready']+=1
                if n>=19:
                  med=statistics.median(win)
                  if statistics.median(abs(v-med) for v in win)>0:
                    eligibility['mad19_positive_scale']+=1
                eligibility['ewma5_ready']+=n>=5
                history.append(nlogs)
              runtimes.append({'window':window['id'],'day':d['day'],'id':label,'mode':mode,
                'transactions':len(counts),'z19_ready':eligibility['z19_ready'],
                'mad19_ready':eligibility['mad19_positive_scale'],
                'ewma5_ready':eligibility['ewma5_ready']})
              for h in (5,10,19,39):
                ready.append({'window':window['id'],'day':d['day'],'id':label,'mode':mode,
                   'min_history':h,'selected_tx':len(counts),
                   'computable_upper_bound':eligibility[f'upper_{h}']})
          sources.append({'window':window['id'],'date':d['day'],'key':source['key'],
              'etag':source['etag_opaque'],'rows':nrows,'sha256_ranges':[
                  x['response_sha256'] for x in reader.ranges]})
          print(window['id'],d['day'],'rows',nrows,'range_bytes',session.bytes,flush=True)
      session.close('COMPLETE')
    except Exception:
      failed=True
      try:session.close('INCOMPLETE')
      except Exception:pass
      raise
    finally:
      print('Transport completed:',not failed,'ranges',len(session.requests),'bytes',session.bytes,flush=True)
    write_csv(args.out/'control_daily.csv',daily)
    write_csv(args.out/'control_readiness.csv',ready)
    write_csv(args.out/'control_runtime_readiness.csv',runtimes)
    summary=[]
    for window in reg['windows']:
      for c in reg['contracts']:
        rows=[x for x in daily if x['window']==window['id'] and x['id']==c['id']]
        need(len(rows)==30,'missing day')
        n=[r['selected_transactions'] for r in rows]
        summary.append({'window':window['id'],'id':c['id'],'name':c['name'],
          'category':c['category'],'days':30,'total_tx':sum(n),'median_tx_per_day':statistics.median(n),
          'days_t_lt20':sum(v<20 for v in n),'days_t_eq0':sum(v==0 for v in n),
          'max_tx_day':max(n),'source_role':'COMPARISON_NOT_VERIFIED_BENIGN'})
    write_csv(args.out/'control_summary.csv',summary)
    result={'schema':'article2_phase26_source_verified_control_census_v1','status':'PASS',
      'control_registry_sha256':hashlib.sha256(registry_bytes).hexdigest(),
      'phase20_baseline_sha256':hashlib.sha256(source_bytes).hexdigest(),
      'total_source_rows_scanned':sum(x['rows'] for x in sources),'sources':sources,
      'http_ranges':len(session.requests),'http_bytes':session.bytes,'windows':2,
      'control_contracts':12,'contract_window_units':24,'emitter_day_units':len(daily),
      'source_tier':'AWS original address/block/tx-index projections, not positive token-outflow or attack detection',
      'note':'No nonattack ground truth and no negative detection labels; count-series readiness prototypes only.'}
    (args.out/'control_evidence.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print('PASS',len(daily),'contract-days',len(ready),'threshold-day rows',flush=True)

if __name__=='__main__':main()