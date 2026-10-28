"""Invented completed-join arithmetic tests; no detector execution or real output."""
import copy
from datetime import date,timedelta
import importlib.util
import itertools
import json
from pathlib import Path
import sys
import unittest
import audit_interpretation as audit

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'reference'))
import exact_reference_join as join


def fixture(empty=False,no_hit=False,unavailable=False):
    cases=[];refs=[];terminal=[];candidates=[]
    for cid in audit.CASES:
        config={'methods':list(audit.METHODS),'policies':list(audit.POLICIES),'budgets':list(audit.BUDGETS),
                'window':{'start_date_utc':audit.WINDOW_START[cid],
                'end_date_utc_exclusive':(date.fromisoformat(audit.WINDOW_START[cid])+timedelta(days=30)).isoformat()}}
        run={'case_id':cid,'config':config,'status':'UNAVAILABLE' if unavailable else 'COMPLETE',
             'observations':{},'methods':{},'decisions':{},'summaries':[]}
        known=[]
        for i in range(0 if empty else 8):
            tx=(1,'0x'+format(i+1,'064x'))
            ref={'chain_id':1,'transaction_hash':tx[1],'adjudication_status':'VERIFIED_APPLICABLE_EXECUTION',
                '_audit':{'core_selection_status':'UNAVAILABLE' if i==0 else 'OBSERVED_NO_CORE_EMITTER' if i==1 else 'SELECTED'},
                'reported_role':'SUCCESSFUL_UNAUTHORIZED_EXECUTION','actual_identity_or_unavailable':None,
                'success_status_or_unavailable':'SUCCESS','in_fixed_window':True,'reviewer_rationale':'Invented arithmetic fixture only.',
                'source_coverage_audit_binding':{'path':'invented','sha256':'0'*64}}
            known.append(ref)
            if i>=2:run['observations'][tx]={'invented':True}
            for method in audit.METHODS:
                run['methods'][method,tx]={'positive_token_count':0 if i==2 else 1,
                    'eligible_token_count':0 if i in (2,3) else 1,'raw_trigger':i>=5,'group_candidate':i>=6}
                for policy,budget in itertools.product(audit.POLICIES,audit.BUDGETS):
                    emitted=i==7 and not no_hit
                    run['decisions'][(method,policy,budget),tx]={'notification_emitted':emitted,
                        'suppression_reason':'emitted' if emitted else 'not_candidate' if i<6 else 'paced_quota'}
        first=date.fromisoformat(audit.WINDOW_START[cid])
        for day_i in range(30):
            for method,policy,budget in itertools.product(audit.METHODS,audit.POLICIES,audit.BUDGETS):
                hashes=[]
                if day_i==0:
                    if not no_hit:hashes.append('0x'+format(8,'064x'))
                    if budget>1:hashes.append('0x'+format(99,'064x'))
                run['summaries'].append({'day_utc':(first+timedelta(days=day_i)).isoformat(),
                    'method':method,'policy':policy,'daily_budget':budget,'notification_transaction_hashes':hashes,
                    'notifications':len(hashes),'unused_daily_slots':budget-len(hashes),'suppression_counts':{}})
        reference={'case_id':cid,'execution_inventory_status':'KNOWN_SUBSET_ONLY','completeness_evidence':[],
                   'references':known}
        case,rows=join.join_case(run,reference);cases.append(case);terminal.extend(rows);refs.append(reference)
        for ref in known:
            candidates.append({'case_id':cid,'execution_inventory_status':'KNOWN_SUBSET_ONLY',**{k:v for k,v in ref.items() if k!='_audit'}})
    across=[]
    for pair in zip(cases[0]['cells'],cases[1]['cells']):
        statuses={case:cell['incident_status'] for case,cell in zip(audit.CASES,pair)}
        hits=sum(x=='HIT' for x in statuses.values());unknown=sum(x not in ('HIT','VERIFIED_COMPLETE_MISS') for x in statuses.values())
        across.append({**{k:pair[0][k] for k in ('method','policy','daily_budget')},'intended_incidents':2,
            'incident_statuses':statuses,'point_incident_coverage':audit.fraction(hits,2) if not unknown else None,
            'incident_coverage_lower_bound':audit.fraction(hits,2),'incident_coverage_upper_bound':audit.fraction(hits+unknown,2)})
    coverage={'schema_version':'article2_phase16_exact_reference_join_v1','status':'COMPLETE','join_code_sha256':audit.JOIN_SHA256,
              'decision_study_sha256':'a'*64,'reference_inventory_sha256':'b'*64,'cases':cases,'across_cases':across}
    inventory={'schema_version':'article2_phase16_reference_inventory_v1','status':'SEALED_AFTER_DECISIONS_INDEPENDENTLY_ADJUDICATED',
               'decision_study_sha256':'a'*64,'cases':refs}
    return [coverage,inventory,terminal,candidates,'a'*64,'b'*64]


class Checks(unittest.TestCase):
    def test_all_declared_comparisons_and_eight_terminal_categories(self):
        result=audit.audit_documents(*fixture())
        self.assertEqual((6,54,42),(len(result['primary_B5_comparisons']),len(result['all_method_policy_budget_cells']),len(result['prespecified_sensitivity_cells'])))
        semantic=next(x for x in result['all_method_policy_budget_cells'] if x['method']=='outflow_rank_1_20')
        self.assertEqual(set(semantic['terminal_categories'].values()),{1});self.assertIsNone(semantic['point_coverage'])
    def test_sensitivity_cannot_be_promoted(self):
        f=fixture();f[0]['cases'][0]['cells'][0]['comparison_role']='PRIMARY_B5_ALL_POLICIES'
        with self.assertRaisesRegex(ValueError,'sensitivity promoted'):audit.audit_documents(*f)
    def test_omitted_unselected_reference_rejected(self):
        f=fixture();f[2].pop(1)
        with self.assertRaisesRegex(ValueError,'reference missing'):audit.audit_documents(*f)
    def test_empty_denominator_is_undefined(self):
        f=fixture(empty=True);result=audit.audit_documents(*f)
        self.assertTrue(all(x['point_coverage'] is None for x in result['all_method_policy_budget_cells']))
        f[0]['cases'][0]['cells'][0]['point_coverage']=audit.fraction(0,1)
        with self.assertRaisesRegex(ValueError,'denominator'):audit.audit_documents(*f)
    def test_known_subset_no_hit_is_indeterminate(self):
        f=fixture(no_hit=True);result=audit.audit_documents(*f)
        self.assertTrue(all(x['incident_status']=='INDETERMINATE_INCIDENT_COVERAGE' for x in result['all_method_policy_budget_cells']))
        f[0]['cases'][0]['cells'][0]['incident_status']='VERIFIED_COMPLETE_MISS'
        with self.assertRaisesRegex(ValueError,'exceeds evidence'):audit.audit_documents(*f)
    def test_nonreference_notifications_remain_unknown_load(self):
        f=fixture();cell=next(c for c in f[0]['cases'][0]['cells'] if c['daily_budget']==5)
        cell['load']['unknown_nonreference_notifications']=0
        with self.assertRaisesRegex(ValueError,'aggregate notification load'):audit.audit_documents(*f)
    def test_cold_start_not_merged_with_rank_miss(self):
        f=fixture();cell=next(c for c in f[0]['cases'][0]['cells'] if c['method']=='outflow_rank_1_20')
        cell['funnel']['history_eligible_semantic_only']+=1
        with self.assertRaisesRegex(ValueError,'funnel stage'):audit.audit_documents(*f)
    def test_unavailable_replay_not_zero(self):
        f=fixture(unavailable=True);result=audit.audit_documents(*f)
        self.assertTrue(all(x['load']['notifications'] is None for x in result['all_method_policy_budget_cells']))
        f[0]['cases'][0]['cells'][0]['load']['notifications']=0
        with self.assertRaisesRegex(ValueError,'imputed as zero'):audit.audit_documents(*f)
    def test_candidate_dispositions_cannot_be_dropped(self):
        f=fixture();f[3].pop()
        with self.assertRaisesRegex(ValueError,'outer candidate inventory truncated'):audit.audit_documents(*f)
    def test_two_incidents_cannot_be_replaced_with_cells(self):
        f=fixture();f[0]['across_cases'][0]['intended_incidents']=1620
        with self.assertRaisesRegex(ValueError,'incident denominator'):audit.audit_documents(*f)


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Checks))
    report={'status':'PASS_OUTCOME_BLIND_SYNTHETIC_INTERPRETATION_CHECKS' if result.wasSuccessful() else 'FAIL',
        'checks':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
        'reviewer_sha256':audit.sha(audit.__file__),'test_sha256':audit.sha(__file__),
        'actual_detector_metrics_read':False,'actual_reference_inventory_read':False,
        'detector_replay_or_scoring':False,'network_requests':0}
    out=Path(__file__).with_name('interpretation_preflight.json');out.write_bytes(audit.canonical(report)+b'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
