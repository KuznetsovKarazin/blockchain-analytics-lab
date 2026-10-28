"""Independent synthetic reference-join invariants, with no detector replay."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

TARGET=Path(__file__).resolve().parents[1]/'reference'/'exact_reference_join.py'
spec=importlib.util.spec_from_file_location('independent_exact_join_target',TARGET)
j=importlib.util.module_from_spec(spec);spec.loader.exec_module(j)

def fixture():
    config=j.read(j.PAPER/'phase16/protocol/configs/lifi.json')
    run={'case_id':config['case_id'],'status':'COMPLETE','config':config,'observations':{},'methods':{},'decisions':{},'summaries':[]}
    refs=[]
    for i in range(8):
        key=(1,'0x'+format(i+1,'064x'))
        coverage='UNAVAILABLE' if i==0 else 'OBSERVED_NO_CORE_EMITTER' if i==1 else 'SELECTED'
        refs.append({'chain_id':key[0],'transaction_hash':key[1],'adjudication_status':'VERIFIED_APPLICABLE_EXECUTION','_audit':{'core_selection_status':coverage}})
        if i<2:continue
        run['observations'][key]={'transaction':{'chain_id':1,'transaction_hash':key[1]}}
        for method in config['methods']:
            score={'positive_token_count':int(i>=3),'eligible_token_count':int(i>=4),'raw_trigger':i>=5,'group_candidate':i>=6}
            run['methods'][(method,key)]=score
            for policy in config['policies']:
                for budget in config['budgets']:
                    cell=(method,policy,budget)
                    run['decisions'][(cell,key)]={'notification_emitted':i==7,'suppression_reason':'emitted' if i==7 else 'hard_daily_cap' if i==6 else 'not_candidate'}
    for method in config['methods']:
        for policy in config['policies']:
            for budget in config['budgets']:
                for index,day in enumerate(j.driver.expected_days(config)):
                    emitted=int(index==29)
                    run['summaries'].append({'method':method,'policy':policy,'daily_budget':budget,'day_utc':day,'notifications':emitted,'unused_daily_slots':budget-emitted,'notification_transaction_hashes':[refs[-1]['transaction_hash']] if emitted else [],'suppression_counts':{}})
    reference={'case_id':config['case_id'],'execution_inventory_status':'KNOWN_SUBSET_ONLY','references':refs}
    return run,reference

class ReferenceInvariants(unittest.TestCase):
    def test_selected_evidence_survives_unavailable_additional_audit_in_every_cell(self):
        run,ref=fixture();before,rows=j.join_case(run,ref)
        changed=deepcopy(ref)
        for item in changed['references'][2:]:item['_audit']['core_selection_status']='UNAVAILABLE'
        after,changed_rows=j.join_case(run,changed)
        self.assertEqual(after,before);self.assertEqual(changed_rows,rows)
        self.assertEqual(len(after['cells']),27)
        self.assertTrue(all(x['exact_notified']==1 and x['unknown']==1 for x in after['cells']))
    def test_category_partition_and_full_reference_denominator_are_conserved(self):
        run,ref=fixture();joined,rows=j.join_case(run,ref)
        self.assertEqual(len(rows),8*27)
        for cell in joined['cells']:
            with self.subTest(method=cell['method'],policy=cell['policy'],budget=cell['daily_budget']):
                self.assertEqual(sum(cell['terminal_categories'].values()),8)
                self.assertEqual((cell['exact_notified'],cell['known_unnotified'],cell['unknown']),(1,6,1))
                self.assertEqual(cell['known_set_lower_bound'],{'numerator':1,'denominator':8,'value':.125})
                self.assertEqual(cell['known_set_upper_bound'],{'numerator':2,'denominator':8,'value':.25})
                self.assertIsNone(cell['point_coverage'])
                f=cell['funnel'];self.assertEqual((f['verified_references'],f['source_evidence_available'],f['selected'],f['raw_trigger'],f['group_candidate'],f['emitted_notification']),(8,7,6,3,2,1))
                if cell['method']!='core_count_60s_10':
                    self.assertTrue(all(n==1 for n in cell['terminal_categories'].values()))
                    self.assertEqual((f['positive_core_outflow_semantic_only'],f['history_eligible_semantic_only']),(5,4))
                else:
                    self.assertIsNone(f['positive_core_outflow_semantic_only']);self.assertIsNone(f['history_eligible_semantic_only'])
    def test_added_unknown_positive_expands_denominator_without_creating_a_measured_miss(self):
        run,ref=fixture();ref['references']=[ref['references'][-1]]
        before,_=j.join_case(run,ref)
        ref['references'].append({'chain_id':1,'transaction_hash':'0x'+'f'*64,'adjudication_status':'VERIFIED_APPLICABLE_EXECUTION','_audit':{'core_selection_status':'UNAVAILABLE'}})
        after,_=j.join_case(run,ref)
        for old,new in zip(before['cells'],after['cells']):
            self.assertEqual(old['point_coverage']['value'],1)
            self.assertEqual(new['exact_notified'],old['exact_notified'])
            self.assertEqual(new['known_unnotified'],0);self.assertEqual(new['unknown'],1)
            self.assertIsNone(new['point_coverage']);self.assertEqual(new['known_set_lower_bound']['value'],.5)
            self.assertEqual(new['known_set_upper_bound']['value'],1)
            self.assertEqual(new['incident_status'],'HIT')
            self.assertEqual(new['load'],old['load'])

if __name__=='__main__':unittest.main()
