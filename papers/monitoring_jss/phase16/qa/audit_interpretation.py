"""Validate completed exact-join arithmetic and extract every declared comparison.

Prepared outcome-blind. Run only after root confirms the reference inventory is
sealed. This reads completed join artifacts, never scores, replays, retrieves,
chooses labels, or independently adjudicates primary-source truth.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import date, timedelta
import gzip
import hashlib
import itertools
import json
from pathlib import Path

JOIN_SHA256='deaf7e58715cda8e701ec31bc2f4fcd7e85db5f9199fe23a0b55e195519b1cee'
CASES=('lifi_20220320','revest_20220327')
METHODS=('core_count_60s_10','outflow_rank_1_20','outflow_rank_1_10')
POLICIES=('greedy','paced_cumulative','token_bucket')
BUDGETS=(1,5,20)
CATEGORIES=('UNAVAILABLE_REFERENCE_OR_OBSERVATION_EVIDENCE','OBSERVED_NOT_SELECTED_NO_CORE_EMITTER_LOG',
 'SELECTED_NO_POSITIVE_CORE_OUTFLOW','SELECTED_COLD_START','SELECTED_ELIGIBLE_NO_RAW_TRIGGER',
 'RAW_TRIGGER_GROUPED','CANDIDATE_BUDGET_SUPPRESSED','EXACT_EXECUTION_NOTIFIED')
WINDOW_START={'lifi_20220320':'2022-02-19','revest_20220327':'2022-02-26'}

def need(ok,message):
    if not ok:raise ValueError(message)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def integer(value,name):
    need(type(value)is int and value>=0,'invalid nonnegative integer: '+name);return value
def read(path):
    def pairs(items):
        out={}
        for key,value in items:
            need(key not in out,'duplicate JSON field');out[key]=value
        return out
    return json.loads(Path(path).read_bytes(),object_pairs_hook=pairs,
        parse_constant=lambda value:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def pinned(path,expected):
    need(sha(path)==expected,'bound artifact changed: '+str(path));return read(path)
def fraction(n,d):return {'numerator':n,'denominator':d,'value':n/d if d else None}
def key(cell):return cell['method'],cell['policy'],cell['daily_budget']
def txkey(row):return row['chain_id'],row['transaction_hash']
def stream(path):
    with gzip.open(path,'rb') as handle:
        for line in handle:
            need(line.endswith(b'\n') and line!=b'\n','incomplete joined JSONL')
            yield json.loads(line)


def audit_documents(coverage,inventory,funnel_rows,candidates,expected_study,expected_reference):
    need(coverage['schema_version']=='article2_phase16_exact_reference_join_v1' and coverage['status']=='COMPLETE'
         and coverage['join_code_sha256']==JOIN_SHA256,'completed frozen exact join required')
    need(coverage['decision_study_sha256']==inventory['decision_study_sha256']==expected_study
         and coverage['reference_inventory_sha256']==expected_reference,'decision/reference lineage differs')
    need(inventory['schema_version']=='article2_phase16_reference_inventory_v1'
         and inventory['status']=='SEALED_AFTER_DECISIONS_INDEPENDENTLY_ADJUDICATED','reference inventory is not sealed')
    need([x['case_id'] for x in coverage['cases']]==list(CASES)
         and [x['case_id'] for x in inventory['cases']]==list(CASES),'case population/order differs')
    expected_cells=set(itertools.product(METHODS,POLICIES,BUDGETS))
    positive_keys={};references={};candidate_map={};terminals={}
    for case in inventory['cases']:
        cid=case['case_id'];refs=case['references'];reference_map={txkey(r):r for r in refs}
        need(len(reference_map)==len(refs),'duplicate candidate reference')
        references[cid]=case;positive_keys[cid]={txkey(r) for r in refs if r['adjudication_status']=='VERIFIED_APPLICABLE_EXECUTION'}
        for identity,ref in reference_map.items():candidate_map[cid,identity]=ref
    seen=set()
    for candidate in candidates:
        identity=candidate['case_id'],txkey(candidate)
        need(identity in candidate_map and identity not in seen,'candidate disposition missing/extra/duplicated')
        seen.add(identity);ref=candidate_map[identity]
        need(candidate['execution_inventory_status']==references[identity[0]]['execution_inventory_status'],'candidate inventory scope differs')
        for field in ('reported_role','actual_identity_or_unavailable','success_status_or_unavailable','in_fixed_window',
                      'adjudication_status','reviewer_rationale','source_coverage_audit_binding'):
            need(candidate[field]==ref[field],'candidate disposition changed: '+field)
    need(seen==set(candidate_map),'outer candidate inventory truncated')
    for row in funnel_rows:
        cell=key(row);cid=row['case_id'];identity=txkey(row)
        need(cid in CASES and cell in expected_cells and identity in positive_keys[cid],'funnel row outside declared positive denominator')
        k=cid,cell,identity;need(k not in terminals,'repeated reference/cell row')
        need(row['category'] in CATEGORIES,'unknown funnel category');terminals[k]=row
    pairs=[];all_cells=[];mapped={}
    for case in coverage['cases']:
        cid=case['case_id'];ref=references[cid];total=len(positive_keys[cid]);cells=case['cells']
        need(len(cells)==27 and {key(c) for c in cells}==expected_cells,'27 complete cells required per case')
        need(case['run_status'] in ('COMPLETE','UNAVAILABLE'),'unknown run status')
        need(case['candidate_count']==len(ref['references'])
             and case['reference_dispositions']==dict(sorted(Counter(r['adjudication_status'] for r in ref['references']).items())),
             'candidate disposition totals differ')
        complete=ref['execution_inventory_status']=='COMPLETE_WITH_POSITIVE_CLOSURE_EVIDENCE'
        if complete:need(total>0 and bool(ref['completeness_evidence']),'complete incident inventory lacks positive closure')
        for cell in cells:
            k=key(cell);method,policy,budget=k;semantic=method!=METHODS[0]
            need(cell['case_id']==cid and type(budget)is int,'cell case/budget differs')
            counts=cell['terminal_categories'];need(set(counts)==set(CATEGORIES),'terminal category population differs')
            for category,count in counts.items():integer(count,category)
            need(all((cid,k,identity) in terminals for identity in positive_keys[cid]),'verified reference missing from a cell denominator')
            actual=Counter(terminals[cid,k,identity]['category'] for identity in positive_keys[cid])
            need(all(counts[c]==actual[c] for c in CATEGORIES) and sum(counts.values())==total,'reference funnel denominator not conserved')
            n,u=counts[CATEGORIES[7]],counts[CATEGORIES[0]]
            need(cell['verified_applicable_executions']==total and cell['exact_notified']==n
                 and cell['unknown']==u and cell['known_unnotified']==total-n-u,'coverage decomposition differs')
            need(cell['known_set_lower_bound']==fraction(n,total)
                 and cell['known_set_upper_bound']==fraction(n+u,total)
                 and cell['point_coverage']==(fraction(n,total) if total and not u else None),
                 'empty/unknown denominator or coverage bounds misrepresented')
            incident=('HIT' if n else 'UNAVAILABLE' if case['run_status']!='COMPLETE'
                      else 'VERIFIED_COMPLETE_MISS' if complete and total and not u else 'INDETERMINATE_INCIDENT_COVERAGE')
            need(cell['incident_status']==incident,'incident hit/miss exceeds evidence')
            need(cell['execution_inventory_status']==ref['execution_inventory_status']
                 and cell['coverage_scope']==('COMPLETE_INCIDENT_EXECUTION_INVENTORY' if complete else 'KNOWN_SUBSET_ONLY'),
                 'known subset relabelled as complete incident coverage')
            role='PRIMARY_B5_ALL_POLICIES' if budget==5 and method!=METHODS[2] else 'PREDECLARED_SENSITIVITY'
            need(cell['comparison_role']==role,'sensitivity promoted into primary comparison')
            observed=total-u;selected=observed-counts[CATEGORIES[1]]
            if not semantic:need(counts[CATEGORIES[2]]==counts[CATEGORIES[3]]==0,'count arm assigned semantic ineligibility')
            positive=selected-counts[CATEGORIES[2]] if semantic else None
            eligible=positive-counts[CATEGORIES[3]] if semantic else None
            expected_funnel={'verified_references':total,'source_evidence_available':observed,'selected':selected,
             'positive_core_outflow_semantic_only':positive,'history_eligible_semantic_only':eligible,
             'raw_trigger':sum(counts[CATEGORIES[i]] for i in (5,6,7)),
             'group_candidate':counts[CATEGORIES[6]]+n,'emitted_notification':n}
            need(cell['funnel']==expected_funnel,'funnel stage arithmetic differs')
            load=cell['load'];daily=load['daily'];first=date.fromisoformat(WINDOW_START[cid])
            expected_days=[(first+timedelta(days=i)).isoformat() for i in range(30)]
            need(load['days']==30 and load['offered_slots']==30*budget
                 and [row['day_utc'] for row in daily]==expected_days,'daily load denominator/window differs')
            for row in daily:
                need(row['offered_daily_cap']==budget,'offered budget differs')
                if case['run_status']=='COMPLETE':
                    v=integer(row['notifications'],'daily notifications');known=integer(row['verified_reference_notifications'],'known notifications')
                    unknown=integer(row['unknown_nonreference_notifications'],'unadjudicated notifications')
                    need(known+unknown==v<=budget and row['unused_daily_slots']==budget-v,'realized daily load/cap differs')
                else:
                    need(all(row[x] is None for x in ('notifications','unused_daily_slots','verified_reference_notifications',
                                                     'unknown_nonreference_notifications','suppression_counts')),'unavailable day imputed as zero')
            if case['run_status']=='COMPLETE':
                for field in ('notifications','verified_reference_notifications','unknown_nonreference_notifications'):
                    need(load[field]==sum(row[field] for row in daily),'aggregate notification load differs')
                need(load['verified_reference_notifications']==n,'notified positive count differs from load')
            else:need(all(load[x] is None for x in ('notifications','verified_reference_notifications','unknown_nonreference_notifications')),
                      'unavailable replay aggregate imputed as zero')
            # The original reason stays visible next to the terminal stage.
            loss_rows=[terminals[cid,k,identity] for identity in sorted(positive_keys[cid])]
            summary={field:cell[field] for field in ('case_id','method','policy','daily_budget','comparison_role',
                'execution_inventory_status','coverage_scope','verified_applicable_executions','exact_notified',
                'known_unnotified','unknown','point_coverage','known_set_lower_bound','known_set_upper_bound','incident_status','funnel','terminal_categories')}
            summary['load']={field:load[field] for field in ('days','offered_slots','notifications','verified_reference_notifications','unknown_nonreference_notifications')}
            summary['exact_reference_terminal_rows']=loss_rows
            all_cells.append(summary);mapped[cid,k]=summary
        for policy in POLICIES:
            count=mapped[cid,(METHODS[0],policy,5)];semantic=mapped[cid,(METHODS[1],policy,5)]
            pairs.append({'case_id':cid,'policy':policy,'daily_budget':5,'count':count,'semantic_1_20':semantic,
                'difference_exact_notified_count':semantic['exact_notified']-count['exact_notified'],
                'point_known_set_coverage_difference':(semantic['exact_notified']-count['exact_notified'])/total
                    if total and not semantic['unknown'] and not count['unknown'] else None,
                'realized_notification_load_difference':semantic['load']['notifications']-count['load']['notifications']
                    if case['run_status']=='COMPLETE' else None})
    need(len(terminals)==27*sum(len(v) for v in positive_keys.values()),'reference denominator/cell replication differs')
    across=coverage['across_cases'];need(len(across)==27 and {key(c) for c in across}==expected_cells,'cross-case cell population differs')
    for row in across:
        statuses={cid:mapped[cid,key(row)]['incident_status'] for cid in CASES};hits=sum(x=='HIT' for x in statuses.values())
        unknown=sum(x not in ('HIT','VERIFIED_COMPLETE_MISS') for x in statuses.values())
        need(row['intended_incidents']==2 and row['incident_statuses']==statuses
             and row['point_incident_coverage']==(fraction(hits,2) if not unknown else None)
             and row['incident_coverage_lower_bound']==fraction(hits,2)
             and row['incident_coverage_upper_bound']==fraction(hits+unknown,2),'cross-case uncertainty or incident denominator differs')
    return {'status':'PASS_EXACT_JOIN_INTERPRETATION_ARITHMETIC','primary_B5_comparisons':pairs,
        'all_method_policy_budget_cells':all_cells,'prespecified_sensitivity_cells':[c for c in all_cells if c['comparison_role']=='PREDECLARED_SENSITIVITY'],
        'scientific_incident_families':2,'case_days':60,'distinct_calendar_dates':37,
        'primary_pair_count':6,'total_cell_count':54,'sensitivity_cell_count':42,
        'inference_limits':['Known-subset bounds exclude undiscovered executions.','No precision/FPR inference from unknown notifications.',
            'No significance, equivalence, causal detection, live latency, prevention or economic-loss inference.',
            'No selection of a favourable policy or sensitivity in place of the primary six comparisons.',
            'Hash-bound labels are independently adjudicated inputs; this arithmetic audit does not establish their truth.'],
        'rescoring_or_replay':False,'network_requests':0}


def run(args):
    need(not args.output.exists(),'fresh interpretation output required')
    receipt=pinned(args.join_receipt,args.expected_receipt_sha256)
    need(receipt['schema_version']=='article2_phase16_join_receipt_v1' and receipt['status']=='COMPLETE'
         and receipt['join_code_sha256']==JOIN_SHA256
         and receipt['decision_study_sha256']==args.expected_study_sha256
         and receipt['reference_inventory_sha256']==args.expected_reference_sha256,'final join receipt lineage differs')
    artifacts=receipt['artifacts'];names={'coverage.json','reference_funnel.jsonl.gz','candidate_adjudications.jsonl.gz'}
    need(len(artifacts)==3 and {a['path'] for a in artifacts}==names,'joined artifact population differs')
    for artifact in artifacts:
        p=args.join_receipt.parent/artifact['path']
        need(p.stat().st_size==artifact['bytes'] and sha(p)==artifact['sha256'],'joined artifact bytes differ')
    inventory=pinned(args.reference_inventory,args.expected_reference_sha256)
    result=audit_documents(read(args.join_receipt.parent/'coverage.json'),inventory,
        list(stream(args.join_receipt.parent/'reference_funnel.jsonl.gz')),
        list(stream(args.join_receipt.parent/'candidate_adjudications.jsonl.gz')),
        args.expected_study_sha256,args.expected_reference_sha256)
    result.update(schema_version='phase16_independent_result_interpretation_audit_v1',
        reviewer_sha256=sha(__file__),join_receipt_sha256=args.expected_receipt_sha256,
        decision_study_sha256=args.expected_study_sha256,reference_inventory_sha256=args.expected_reference_sha256,
        inputs_previously_sealed=True)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_bytes(canonical(result)+b'\n');return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('join-receipt','reference-inventory','output'):parser.add_argument('--'+name,type=Path,required=True)
    for name in ('receipt','reference','study'):parser.add_argument('--expected-'+name+'-sha256',required=True)
    result=run(parser.parse_args());print(json.dumps({'status':result['status'],'primary_pairs':6,'cells':54}))
