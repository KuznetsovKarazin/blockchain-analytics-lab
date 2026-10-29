import importlib.util
import unittest
from pathlib import Path
from datetime import datetime,timezone

S=importlib.util.spec_from_file_location('p18',Path(__file__).with_name('initialization_full_replay.py'))
m=importlib.util.module_from_spec(S);S.loader.exec_module(m)
START=1647734400*10**9 # UTC midnight
TOKEN='0x'+'1'*40

def obs(i,ns=None,amount=None,token=TOKEN):
    if ns is None: ns=START + i*400*10**9
    return {'transaction': {'event_time_ns':ns,'transaction_hash':f'0x{i:064x}'},
            'token_flows': [] if amount is None else [{'token_address':token,'external_out_raw':str(amount)}]}

class TestPhase18(unittest.TestCase):
    def test_19_history_new_max(self):
        o=[obs(i,amount=i+1) for i in range(20)]
        r=m.build_method_decisions(o,'daily_reset',20)
        self.assertFalse(any(x['raw_trigger'] for x in r[:19]))
        self.assertEqual(r[19]['scores'][0]['n'],19)
        self.assertTrue(r[19]['raw_trigger'])
    def test_19_history_tie_fails(self):
        o=[obs(i,amount=1) for i in range(20)]
        r=m.build_method_decisions(o,'daily_reset',20)
        self.assertEqual(r[19]['scores'][0]['numerator'],20)
        self.assertFalse(r[19]['raw_trigger'])
    def test_per_token_history(self):
        o=[obs(i,amount=i+1,token=TOKEN) for i in range(19)]
        o.append(obs(19,amount=100,token='0x'+'2'*40))
        r=m.build_method_decisions(o,'daily_reset',20)
        self.assertFalse(r[19]['raw_trigger'])
    def test_zero_outflows_do_not_count(self):
        o=[obs(i,amount=0) for i in range(19)]+[obs(19,amount=100)]
        r=m.build_method_decisions(o,'daily_reset',20)
        self.assertEqual(r[-1]['scores'][0]['n'],0)
    def test_reset_at_midnight(self):
        o=[obs(i,ns=START+i*60*10**9,amount=i+1) for i in range(19)]
        o.append(obs(19,ns=START+m.DAY_NS+100*10**9,amount=200))
        d=m.build_method_decisions(o,'daily_reset',20)
        c=m.build_method_decisions(o,'cumulative_in_window',20)
        self.assertEqual(d[-1]['scores'][0]['n'],0)
        self.assertTrue(c[-1]['raw_trigger'])
    def test_7day_boundary(self):
        o=[obs(i,ns=START+i*10**9,amount=i+1) for i in range(19)]
        o.append(obs(19,ns=START+7*m.DAY_NS+19*10**9,amount=200))
        r=m.build_method_decisions(o,'lookback_7d',20)
        self.assertEqual(r[-1]['scores'][0]['n'],0)
    def test_7day_boundary_inclusive(self):
        # 19 positive observations exactly on the retention boundary
        o=[obs(i,ns=START+i*10**9,amount=i+1) for i in range(19)]
        o.append(obs(19,ns=START+7*m.DAY_NS+18*10**9,amount=200))
        r=m.build_method_decisions(o,'lookback_7d',20)
        self.assertEqual(r[-1]['scores'][0]['n'],1)
    def test_grouping_from_last_candidate(self):
        o=[obs(i,ns=START+i*10**9,amount=i+1) for i in range(19)]
        o.extend([obs(19,ns=START+100*10**9,amount=100),
                  obs(20,ns=START+101*10**9,amount=101),
                  obs(21,ns=START+500*10**9,amount=102)])
        r=m.build_method_decisions(o,'daily_reset',20)
        self.assertTrue(r[19]['group_candidate'])
        self.assertTrue(r[20]['raw_trigger'])
        self.assertFalse(r[20]['group_candidate'])
        self.assertTrue(r[21]['group_candidate'])
    def test_budget_cap(self):
        rows=[{'time_ns': START+i*400*10**9,'day':'2022-03-20','tx':str(i),'group_candidate':True} for i in range(10)]
        for policy in m.POLICIES:
            a=m.apply_policy(rows,policy,1)
            self.assertEqual(sum(r['notification_emitted'] for r in a),1)
    def test_token_bucket_spacing(self):
        rows=[{'time_ns': START+i*400*10**9,'day':'2022-03-20','tx':str(i),'group_candidate':True} for i in range(10)]
        self.assertEqual(sum(r['notification_emitted'] for r in m.apply_policy(rows,'token_bucket',5)),1)
    def test_paced_quota_can_withhold(self):
        rows=[{'time_ns': START+i*400*10**9,'day':'2022-03-20','tx':str(i),'group_candidate':True} for i in range(10)]
        self.assertEqual(sum(r['notification_emitted'] for r in m.apply_policy(rows,'paced_cumulative',5)),1)
    def test_budget_reset(self):
        rows=[{'time_ns': START+i*400*10**9,'day':'2022-03-20','tx':str(i),'group_candidate':True} for i in range(2)]
        rows.append({'time_ns': START + m.DAY_NS + 20*10**9,'day':'2022-03-21','tx':'2','group_candidate':True})
        self.assertEqual(sum(r['notification_emitted'] for r in m.apply_policy(rows,'greedy',1)),2)
    def test_rank_threshold_1_10_more_permissive(self):
        o=[obs(i,amount=i+1) for i in range(21)]
        a=m.build_method_decisions(o,'daily_reset',10)
        b=m.build_method_decisions(o,'daily_reset',20)
        self.assertTrue(sum(x['raw_trigger'] for x in a)>=sum(x['raw_trigger'] for x in b))
    def test_empty_positive(self):
        r=m.build_method_decisions([obs(1,amount=None)],'daily_reset',20)
        self.assertEqual(r[0]['grouping_reason'],'no_positive_external_outflow')

if __name__=='__main__': unittest.main()
