"""Synthetic, label-free guards for Phase22 source and policy replay."""
import unittest
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
PAPER=HERE.parent
sys.path.insert(0,str(HERE));sys.path.insert(0,str(PAPER));sys.path.insert(0,str(PAPER/'phase18'))
from phase22_science_replay import dstr,count_method,compute_mode_diagnostics
from initialization_full_replay import build_method_decisions,apply_policy,DAY_NS

class SourceAndPolicyGuards(unittest.TestCase):
    @staticmethod
    def sample(n,amounts=None):
        from datetime import datetime,timezone
        t=int(datetime(2022,1,1,tzinfo=timezone.utc).timestamp())*10**9
        if amounts is None:amounts=list(range(1,n+1))
        return [{'transaction':{'chain_id':1,'block_number':100+i,'transaction_index':0,
            'block_hash':'0x'+f'{100+i:064x}','transaction_hash':'0x'+f'{200+i:064x}',
            'event_time_ns':t+i*60*10**9},
            'archived_core_log_count':1,
            'token_flows':[{'token_address':'0x'+'a'*40,'external_out_raw':str(x)}]}
            for i,x in enumerate(amounts)]

    def test_rank_not_eligible_until_twentieth_positive_tx(self):
        observations=self.sample(19)
        r=build_method_decisions(observations,'daily_reset',20)
        self.assertFalse(any(x['eligible_count'] for x in r))
        self.assertFalse(any(x['raw_trigger'] for x in r))

    def test_twentieth_record_new_maximum_is_rank_one_twentieth(self):
        r=build_method_decisions(self.sample(20),'daily_reset',20)
        self.assertTrue(r[-1]['raw_trigger'])
        self.assertEqual(r[-1]['scores'][0]['numerator'],1)
        self.assertEqual(r[-1]['scores'][0]['denominator'],20)

    def test_twentieth_record_tied_max_does_not_trigger(self):
        r=build_method_decisions(self.sample(20,list(range(1,20))+[19]),'daily_reset',20)
        self.assertFalse(r[-1]['raw_trigger'])

    def test_count_control_needs_ten_core_logs(self):
        obs=self.sample(2)
        obs[0]['archived_core_log_count']=7;obs[1]['archived_core_log_count']=3
        obs[1]['transaction']['event_time_ns']=obs[0]['transaction']['event_time_ns']+59*10**9
        r=count_method(obs)
        self.assertFalse(r[0]['raw_trigger'])
        self.assertTrue(r[1]['raw_trigger'])

    def test_grouping_and_budget_never_change_known_reference_identity(self):
        r=build_method_decisions(self.sample(22),'daily_reset',10)
        for budget in (1,5,20):
            for p in ('greedy','paced_cumulative','token_bucket'):
                out=apply_policy(r,p,budget)
                self.assertLessEqual(sum(x['notification_emitted'] for x in out),budget)
                self.assertTrue(all(x['tx']==y['tx'] for x,y in zip(r,out)))

    def test_derived_token_day_is_label_free(self):
        x=compute_mode_diagnostics(self.sample(20))
        self.assertEqual(x['positive_token_days'],1)
        self.assertEqual(x['token_days_reaching_twenty_positive_tx'],1)
        self.assertEqual(x['max_positive_transactions_per_token_day'],20)

if __name__=='__main__':unittest.main()