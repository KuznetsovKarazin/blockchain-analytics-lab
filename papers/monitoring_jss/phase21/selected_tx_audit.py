#!/usr/bin/env python3
"""Phase21 independent label-free Ethereum selected-transaction population audit.

No attack labels, token features, or detector scores are accessed. Read all
original S3 log rowgroups for only address, block_number, transaction_index.
The original Phase20 core-log counts are independently matched day by day.
"""
import argparse
import hashlib
import json
import statistics
import sys
from collections import Counter
from datetime import date, timedelta
from pathlib import Path


def require(b, message):
    if not b:
        raise ValueError(message)


def tally_selected(rows, named_cores):
    """Pure independent tally on projected source rows (offline-testable)."""
    counts = Counter()
    grouped = {label: set() for label in named_cores}
    union = set()
    for a, block, tx_index in rows:
        a = a.lower()
        pair = (block, tx_index)
        for label, core in named_cores.items():
            if a == core:
                counts[label] += 1
                grouped[label].add(pair)
                union.add(pair)
    return {k: counts[k] for k in named_cores}, {k: len(grouped[k]) for k in named_cores}, len(union)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', required=True, choices=['bacon_20220305', 'rari_pool127_20220430'])
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()

    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.parquet as pq

    root = Path(__file__).resolve().parents[3]
    phase20 = root / 'papers/monitoring_jss/phase20/source_evidence/core_traffic.json'
    collector = root / 'papers/monitoring_jss/phase16/collector'
    sys.path.insert(0, str(collector))
    import range_collector as rc

    source_bytes = phase20.read_bytes()
    baseline = json.loads(source_bytes)
    require(baseline['status'] == 'COMPLETE_ADDRESS_ONLY_60_DAYS', 'Phase20 incomplete')
    require(baseline['range_requests'] == 306, 'Phase20 source receipt version unexpectedly changed')
    subject = baseline['subjects'][args.case]
    cores = subject['cores']
    days = [d for d in baseline['days'] if d['case'] == args.case]
    require(len(days) == 30, 'exactly thirty days required')
    assert (date.fromisoformat(subject['end']) - date.fromisoformat(subject['start'])).days == 30
    require([d['day'] for d in days] == [(date.fromisoformat(subject['start']) + timedelta(days=i)).isoformat() for i in range(30)], 'nonconsecutive days')

    caps = {'requests': 300, 'total_response_bytes': 850_000_000,
            'wall_seconds': 780, 'request_timeout_seconds': 30,
            'max_range_bytes': 18_000_000, 'max_footer_bytes': 1_000_000,
            'max_rows': 7_000_000, 'max_row_groups': 64,
            'max_top_level_columns': 60, 'max_leaf_columns': 80,
            'max_source_bytes': 800_000_000, 'retries': 0, 'concurrency': 1}
    plan = {'schema_version': 'article2_phase16_range_source_plan_v1', 'endpoint': rc.ENDPOINT,
            'caps': caps, 'required_columns': {'logs': ['address','block_number','transaction_index']}}
    args.output.mkdir(parents=True, exist_ok=False)
    session = rc.RangeSession(plan, args.output / 'range_capture')
    result = {
        'schema': 'phase21_label_free_selected_transaction_audit_v1',
        'case': args.case,
        'source_baseline_sha256': hashlib.sha256(source_bytes).hexdigest(),
        'observation_scope': 'all source log rows projected on address, block_number, transaction_index',
        'matched_source': 'pinned AWS S3 keys and ETags from Phase20; bounded exact byte ranges',
        'contract_roles': cores,
        'history_min_prior': 19,
        'admissions': 0, 'attack_labels_used': False, 'detection_scores_computed': False,
        'all_emitter_bundles_acquired': False, 'windows': {'first':subject['start'],'end_exclusive':subject['end']},
        'per_day': [], 'summary': {}, 'status':'INCOMPLETE', 'source_ranges': []}
    failed = False
    try:
        for day in days:
            row = {'day':day['day'], 'source_key':day['source_key'],'status':'UNAVAILABLE'}
            src={'table':'logs', 'day_utc':day['day'], 'key':day['source_key'],
                 'size_bytes':day['source_declared_bytes'], 'etag_opaque':day['source_etag']}
            start_requests, start_bytes = len(session.requests),session.bytes
            try:
                reader=rc.SourceReader(src,session,args.output/'sparse'/args.case,pa,pq).open()
                log_counts=Counter()
                txs={label:set() for label in cores}
                union=set()
                nr=0
                for rg,tab in reader.iter_row_groups(['address','block_number','transaction_index']):
                    nr+=len(tab)
                    names=pc.utf8_lower(tab.column('address'))
                    for label, addr in cores.items():
                        mask=pc.equal(names,addr)
                        n=pc.sum(pc.cast(mask,pa.int64())).as_py()
                        n=int(n or 0)
                        log_counts[label]+=n
                        if n:
                            selected=tab.filter(mask).select(['block_number','transaction_index'])
                            for row2 in selected.to_pylist():
                                block,index=row2['block_number'],row2['transaction_index']
                                require(isinstance(block,int) and isinstance(index,int) and block>=0 and index>=0,
                                        'invalid selected transaction order coordinates')
                                pair=(block,index)
                                txs[label].add(pair)
                                union.add(pair)
                require(nr==reader.metadata.num_rows==day['source_log_rows'],'source row count mismatch')
                actual_counts={label:int(log_counts[label]) for label in cores}
                require(actual_counts==day['core_log_counts'],
                        'phase20 core log count mismatch: '+repr((actual_counts,day['core_log_counts'])))
                core_tx_counts={k:len(v) for k,v in txs.items()}
                require(all(core_tx_counts[k]<=log_counts[k] for k in cores),'more selected tx than core logs')
                require(max(core_tx_counts.values()) <= len(union) <= sum(core_tx_counts.values()), 'invalid union membership')
                row.update({'status':'COMPLETE_PROJECTED_SELECTION',
                    'source_rows':nr,'source_log_counts':actual_counts,
                    'selected_tx_counts':core_tx_counts, 'candidate_union_selected_tx_count':len(union),
                    'selected_core_tx_keys':{k:sorted([list(p) for p in v]) for k,v in txs.items()},
                    'candidate_union_tx_keys':sorted([list(p) for p in union]),
                    'ranges': [{'start':i['start'],'length':i['length'], 'sha256':i['response_sha256']} for i in reader.ranges],
                    'requests':len(session.requests)-start_requests,'response_bytes':session.bytes-start_bytes})
                print(args.case,day['day'],'source rows',nr,'logs',dict(log_counts),
                      'tx',core_tx_counts,'union',len(union),'range bytes',row['response_bytes'],flush=True)
            except Exception as exc:
                failed=True
                row.update({'error':type(exc).__name__+': '+str(exc)[:400]})
                print('STOP: '+row['error'],flush=True)
            result['per_day'].append(row)
            if failed: break
        for label in cores:
            counts=[x['selected_tx_counts'][label] for x in result['per_day'] if x['status']=='COMPLETE_PROJECTED_SELECTION']
            if len(counts)==30:
                result['summary'][label]={
                    'days':30,'total_selected_transactions':sum(counts),
                    'days_with_fewer_than_20_selected_tx':sum(n<20 for n in counts),
                    'max_selected_tx_per_day':max(counts),
                    'median_selected_tx_per_day':statistics.median(counts)}
        if len(cores)>1 and not failed:
            a=[x['candidate_union_selected_tx_count'] for x in result['per_day']]
            result['summary']['candidate_union_not_admitted']={
                'days':30,'total_selected_transactions':sum(a),
                'days_with_fewer_than_20_selected_tx':sum(n<20 for n in a),
                'median_selected_tx_per_day':statistics.median(a)}
        result['range_requests']=len(session.requests)
        result['response_bytes']=session.bytes
        result['status']='COMPLETE_LABEL_FREE_PROJECTION' if not failed and len(result['per_day'])==30 else 'INCOMPLETE_NO_IMPUTATION'
    finally:
        try:session.close('COMPLETE' if not failed and len(result['per_day'])==30 else 'INCOMPLETE')
        except Exception as e:result['close_error']=str(e)
        (args.output/'selected_tx_result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
        print('FINAL',result['status'], 'requests',result['range_requests'], 'bytes',result['response_bytes'], flush=True)
    if result['status'] != 'COMPLETE_LABEL_FREE_PROJECTION': sys.exit(1)

if __name__=='__main__': main()