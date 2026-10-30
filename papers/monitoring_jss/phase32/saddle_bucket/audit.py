#!/usr/bin/env python3
"""Standalone offline P3/P4 audit from unchanged, V7-audited feature records.

No detector implementation is imported. The post-review burst-capacity
sensitivity is not part of the original fixed-policy results.
"""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
from fractions import Fraction
import gzip
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
PAPER=HERE.parents[1]
NS=10**9
DAY=86400*NS
TOKEN='0x57ab1ec28d129707052df4df418d58a2d46d5f51'
INITIAL='0x2b023d65485c4bb68d781960c2196588d03b871dc9eb1c054f596b7ca6f7da56'
LATER='0xe7e0474793aad11875c131ebd7582c8b73499dd3c5a473b59e6762d4e373d7b8'
RESCUE='0x9549c0cb48ec5a5a2c4703cbbbbea5638028b2d8c8adc103220ef1c7fe5e99a3'
REFERENCE='0x9a6227ef97d7ce75732645bd604ef128bb5dfbc1bfbe0966ad1cd2870d45a20e'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):
    with gzip.open(p,'rt') as f:return [json.loads(line) for line in f]
def order(r):return (r['transaction']['block_number'],r['transaction']['transaction_index'])
def stamp(t):return datetime.fromtimestamp(t//NS,timezone.utc).isoformat()
def amount(r):
    vals=[int(x['external_out_raw']) for x in r['views']['fixed_core']['token_flows'] if x['token_address']==TOKEN]
    assert len(vals)<=1
    return vals[0] if vals else 0

def saddle(rows):
    assert len(rows)==44 and rows==sorted(rows,key=order)
    byhash={r['transaction']['transaction_hash']:r for r in rows}
    result=[]
    for tx in (INITIAL,LATER):
        r=byhash[tx];value=amount(r)
        prior=[p for p in rows if order(p)<order(r) and amount(p)>0]
        large=[p for p in prior if amount(p)>=value]
        n=len(prior);numerator=1+len(large);q=Fraction(numerator,n+1)
        result.append({'transaction_hash':tx,'timestamp_utc':stamp(r['transaction']['event_time_ns']),
          'positive_outflow_raw':str(value),'strictly_prior_same_token_positive_values':n,
          'prior_greater_or_equal_count':len(large),'prior_greater_or_equal_hashes':[p['transaction']['transaction_hash'] for p in large],
          'strict_new_maximum':len(large)==0,'rank_unsimplified':f'{numerator}/{n+1}',
          'rank_exact':str(q),'stage_B_history_ready':n>=19,'descriptive_rank_le_1_20':q<=Fraction(1,20),
          'stage_C_evaluated_in_configured_detector':n>=19,'configured_rank_trigger':n>=19 and q<=Fraction(1,20)})
    first,last=result
    assert first['rank_exact']=='1/17' and first['strictly_prior_same_token_positive_values']==16
    assert first['strict_new_maximum'] and not first['stage_B_history_ready'] and not first['descriptive_rank_le_1_20']
    assert last['rank_unsimplified']=='3/21' and last['stage_B_history_ready'] and not last['configured_rank_trigger']
    assert set(last['prior_greater_or_equal_hashes'])=={INITIAL,RESCUE}
    return {'observations':result,'threshold':'1/20','initial_rank_is_above_threshold':True,
      'initial_shortfall_to_history_minimum':3,
      'later_delete_initial_and_rescue_sensitivity':{'status':'arithmetic_only_not_rescored_detector','previous_values_remaining':18,'rank_exact':'1/19','stage_B_history_ready':False,'descriptive_rank_le_1_20':False},
      'interpretation':'The first event is a strict maximum but its descriptive rank1/17 exceeds1/20; it is not a demonstrated C-pass hidden by B. The later rank is computable but equals3/21, with the initial extraction and rescue supplying the two preceding values >= current. Simply removing those values leaves18 observations and rank1/19, not an eligible detected event.'}

def count_rows(records):
    output=[];last={}
    for i,r in enumerate(records):
        tx=r['transaction'];t=tx['event_time_ns'];day=t//DAY
        c=sum(p['views']['fixed_core']['archived_core_log_count'] for p in records[:i+1]
              if p['transaction']['event_time_ns']//DAY==day and p['transaction']['event_time_ns']>t-60*NS)
        raw=c>=10;candidate=raw and (day not in last or t-last[day]>=300*NS)
        if candidate:last[day]=t
        output.append({'tx':tx['transaction_hash'],'time_ns':t,'time_utc':stamp(t),'day':day,'count_60s':c,'raw_trigger':raw,'candidate':candidate})
    return output

def dispatch(rows,budget,capacity,initial_credit):
    assert 0<=initial_credit<=capacity
    output=[];used=0;credit=Fraction(initial_credit);current_day=None;previous=0
    for row in rows:
        t=row['time_ns'];day=row['day']
        if day!=current_day:current_day=day;used=0;previous=day*DAY;credit=Fraction(initial_credit)
        credit=min(Fraction(capacity),credit+Fraction((t-previous)*budget,DAY));before=credit
        if not row['candidate']:reason='not_candidate'
        elif used>=budget:reason='hard_daily_cap'
        elif credit<1:reason='token_shortage'
        else:reason='emitted';used+=1;credit-=1
        output.append({**row,'budget':budget,'capacity':capacity,'initial_credit':initial_credit,
          'credit_before':str(before),'credit_after':str(credit),'notification_emitted':reason=='emitted','reason':reason,'daily_used_after':used})
        previous=t
    return output

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,default=HERE/'AUDIT.json');a=ap.parse_args()
    paths={'saddle':PAPER/'phase30/indexed/cohort28_07/indexer_observations.jsonl.gz',
           'schnoodle':PAPER/'phase29/indexed/cohort28_10/indexer_observations.jsonl.gz',
           'frozen_dispatch':PAPER/'phase31/replay_audit/results/SCHNOODLE_DISPATCH_TRACE.json',
           'frozen_replay':PAPER/'phase29/results/cohort28_10/label_blind_replay.json'}
    saddle_result=saddle(load(paths['saddle']))
    records=load(paths['schnoodle']);assert len(records)==134 and records==sorted(records,key=order)
    rows=count_rows(records);assert sum(x['raw_trigger'] for x in rows)==28 and sum(x['candidate'] for x in rows)==27
    frozen=json.loads(paths['frozen_dispatch'].read_text());variants=[]
    replay=json.loads(paths['frozen_replay'].read_text())
    original_cells={(x['policy'],x['B']):x for x in replay['case_score_rows'] if x['method']=='core_count_60s_10' and x['init']=='daily_reset'}
    for budget in (1,5,20):
        greedy=[];used=defaultdict(int)
        for r in rows:
            if r['candidate'] and used[r['day']]<budget:greedy.append(r['tx']);used[r['day']]+=1
        assert greedy==original_cells[('greedy',budget)]['notified_transactions']
        for name,cap,start in [('original_unit_capacity',1,1),('capacity_B_initial_one',budget,1),('capacity_B_initial_B',budget,budget)]:
            trace=dispatch(rows,budget,cap,start);emitted=[r['tx'] for r in trace if r['notification_emitted']]
            ref=next(r for r in trace if r['tx']==REFERENCE)
            if name=='original_unit_capacity':
                old=frozen[f'token_bucket_B{budget}'];assert len(emitted)==old['notifications']
                assert emitted==original_cells[('token_bucket',budget)]['notified_transactions']
                assert ref['notification_emitted']==old['reference_trace']['notification_emitted']
                assert ref['credit_before']==old['reference_trace']['token_credit_before']
            if name=='capacity_B_initial_B':assert emitted==greedy
            variants.append({'variant':name,'budget':budget,'capacity':cap,'initial_credit':start,
              'notifications':len(emitted),'reference_notified':ref['notification_emitted'],'reference_trace':ref,
              'emitted_transaction_hashes':emitted,'same_sequence_as_greedy':emitted==greedy})
    b5={r['variant']:r for r in variants if r['budget']==5}
    assert b5['original_unit_capacity']['notifications']==21 and not b5['original_unit_capacity']['reference_notified']
    assert b5['original_unit_capacity']['reference_trace']['credit_before']=='10871/17280'
    assert b5['capacity_B_initial_one']['reference_notified'] and b5['capacity_B_initial_B']['reference_notified']
    report={'schema':'phase32_saddle_bucket_review_audit_v1','status':'PASS','network_requests':0,
      'input_sha256':{str(p.relative_to(PAPER)):sha(p) for p in paths.values()},'script_sha256':sha(Path(__file__)),
      'saddle':saddle_result,'schnoodle':{'selected_transactions':134,'raw_triggers':28,'grouped_candidates':27,
      'sensitivity_timing':'Post-review capacity sensitivity; original rules and published results remain unchanged. All variants retain daily hard cap B and refill B/86400 per second.',
      'variants':variants},
      'limits':['Inputs are retained feature records whose raw-payload audit is documented separately; this script does not repeat source extraction.',
      'The capacity sensitivity does not establish a generally superior budget policy.',
      'The first Saddle rank is descriptive outside the configured domain; missing historical values are not imputed.',
      'Removing incident-linked values would also change the history size; no claim that cleaning history restores detection is made.']}
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('PASS: Saddle1/17>1/20; later3/21; nine bucket capacity/budget variants')
    for x in variants:print(x['variant'],x['budget'],x['notifications'],x['reference_notified'])
if __name__=='__main__':main()
