"""Candidate continuation tests; synthetic Arrow sources only, never archive rows."""
import contextlib
import copy
from datetime import date, timedelta
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import numpy as np
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq
import continue_pipeline as c


def h(n):
    return '0x'+f'{n:064x}'


class Reader:
    def __init__(self, source, rows, path):
        self.source=source;self.path=path;self.reads=[]
        kind=source['table']
        columns={'blocks':['number','hash','parent_hash','timestamp','transaction_count'],
                 'transactions':['hash','transaction_index','block_hash','block_number','block_timestamp','receipt_status'],
                 'logs':['address','topics','data','transaction_index','log_index','transaction_hash','block_number','block_hash','block_timestamp']}[kind]
        integers={'number','block_number','transaction_index','log_index','receipt_status','transaction_count'}
        schema=pa.schema([(k,pa.timestamp('ms') if k in ('timestamp','block_timestamp') else pa.int64() if k in integers else pa.list_(pa.string()) if k=='topics' else pa.string()) for k in columns])
        table=pa.Table.from_pylist(rows,schema=schema);pq.write_table(table,path,row_group_size=1)
        self.file=pq.ParquetFile(path);self.metadata=self.file.metadata;self.schema=self.file.schema_arrow
    def read_row_group(self,index,columns):
        self.reads.append({'row_group':index,'columns':columns});return self.file.read_row_group(index,columns=columns)
    def iter_row_groups(self,columns):
        for index in range(self.metadata.num_row_groups):yield index,self.read_row_group(index,columns)
    def manifest(self):
        return {'source':self.source,'row_count_metadata':self.metadata.num_rows,'read_projections':self.reads.copy()}


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p=c.original_pipeline()
        cls.original=c.read_json(c.PAPER/'phase16/source_plan.json')
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()
    def plan(self):
        result=copy.deepcopy(self.original);result['schema_version']='article2_phase16_continuation_source_plan_v1';return result
    def test_original_fields_cannot_change(self):
        plan=self.plan();self.assertTrue(c.scientific_scope_unchanged(plan,self.original));plan['collector']['caps']['wall_seconds']=14400
        with self.assertRaisesRegex(ValueError,'original plan field'):c.scientific_scope_unchanged(plan,self.original)
    def test_source_population_cannot_change(self):
        plan=self.plan();plan['source_union']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'original plan field'):c.scientific_scope_unchanged(plan,self.original)
    def test_parser_and_method_config_bindings_cannot_change(self):
        for key,value in [('numpy_version','0'),('case_configs',[])]:
            plan=self.plan();plan[key]=value
            with self.assertRaisesRegex(ValueError,'original plan field'):c.scientific_scope_unchanged(plan,self.original)
    def test_parent_absence_and_hash_are_enforced(self):
        path=self.root/'receipt.json';c.write(path,{'synthetic':True});bindings={'receipt.json':c.file_sha(path),'absent.json':None}
        c.recheck_parent_bindings(self.root,bindings);(self.root/'absent.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'absent parent artifact appeared'):c.recheck_parent_bindings(self.root,bindings)
    def test_unsafe_binding_rejected(self):
        for value in ('../outside','/absolute'):
            with self.assertRaises(ValueError):c.inside(self.root,value)
    def fixture(self):
        plan=self.plan();plan['accepted_header_anchors']=[]
        configs={};shas={}
        for bind in plan['case_configs']:
            cfg=c.read_json(c.REPO/bind['path']);configs[cfg['case_id']]=cfg;shas[cfg['case_id']]=bind['sha256']
        lifi=configs['lifi_20220320']['population_addresses'][0];revest=configs['revest_20220327']['population_addresses'][0]
        days=self.p.days_between('2022-02-18','2022-03-29');rows={};sources=[]
        for index,day in enumerate(days):
            block=1000+index;stamp=self.p.day_start(day)//1000000+1000;study='2022-02-19'<=day<'2022-03-28'
            blockrow={'number':block,'hash':h(block),'parent_hash':h(block-1),'timestamp':stamp,'transaction_count':1 if study else 0}
            daily={'blocks':[blockrow]}
            if study:
                daily['transactions']=[{'hash':h(block*10),'transaction_index':0,'block_hash':h(block),'block_number':block,'block_timestamp':stamp,'receipt_status':1}]
                address=lifi if day=='2022-02-19' else revest if day=='2022-02-26' else None
                daily['logs']=[] if address is None else [{'address':address,'topics':[],'data':'0x','transaction_index':0,'log_index':0,'transaction_hash':h(block*10),'block_number':block,'block_hash':h(block),'block_timestamp':stamp},
                                                        {'address':'0x'+'e'*40,'topics':[],'data':'0x','transaction_index':0,'log_index':1,'transaction_hash':h(block*10),'block_number':block,'block_hash':h(block),'block_timestamp':stamp}]
            for table,records in daily.items():
                key=day+'_'+table;source={'key':key,'table':table,'day_utc':day,'size_bytes':1,'etag_opaque':'"synthetic"','url':'https://synthetic.invalid/'+key};sources.append(source);rows[key]=records
        return plan,{'objects':sources},configs,shas,rows
    def prepare(self,folder,prior=None):
        plan,inventory,configs,shas,rows=self.fixture();folder.mkdir();cache=folder/'synthetic_source_files';cache.mkdir()
        def factory(source):return Reader(source,rows[source['key']],cache/(source['key']+'.parquet'))
        with contextlib.redirect_stdout(io.StringIO()):
            result=c.prepare_sources(plan,inventory,configs,shas,factory,folder,prior or {},self.p,pa,pc,np)
        return result
    def sealed(self,parent,completed=1,partial=True):
        study=self.p.days_between('2022-02-19','2022-03-28');records=[];parts=[]
        for day in study[:completed]:
            records.append({'day_utc':day,'prepared':{'path':f'days/{day}/prepared.json','sha256':c.file_sha(parent/'days'/day/'prepared.json')},'core_selection':{'path':f'days/{day}/core_selection.json','sha256':c.file_sha(parent/'days'/day/'core_selection.json')}})
        if partial:
            day=study[completed];(parent/'days'/day/'prepared.json').unlink();parts=[{'day_utc':day,'core_selection':{'path':f'days/{day}/core_selection.json','sha256':c.file_sha(parent/'days'/day/'core_selection.json')}}]
        return records,parts,study
    def test_37day_repreparation_and_partial_selection_preserved(self):
        old=self.root/'old';first=self.prepare(old);records,parts,study=self.sealed(old)
        prior=c.sealed_prior_days(old,records,study,parts);new=self.root/'new';second=self.prepare(new,prior)
        self.assertEqual(first['study_days'],37);self.assertEqual(second['transport_sources'],113)
        report=c.read_json(new/'prior_completed_day_comparisons.json');self.assertEqual(report['completed_day_count'],1);self.assertEqual(report['partial_core_selection_count'],1)
        self.assertTrue(report['days'][0]['exact_cases_and_payload_match']);self.assertIsNone(report['days'][1]['exact_cases_and_payload_match'])
        for case in first['selection_manifests']:
            self.assertEqual(first['selection_manifests'][case]['sha256'],second['selection_manifests'][case]['sha256'])
    def test_prepared_payload_change_fatal(self):
        old=self.root/'old';self.prepare(old);records,parts,study=self.sealed(old,partial=False);prior=c.sealed_prior_days(old,records,study,parts)
        first=prior[study[0]];prepared=copy.deepcopy(first['prepared']);case=next(iter(prepared['cases']));prepared['cases'][case]['bundles'][0]['logs'][0]['data']='0xff'
        with self.assertRaisesRegex(ValueError,'cases/payload differ'):c.compare_prior_day(first,prepared,old/'days'/study[0])
    def test_partial_seal_change_fatal(self):
        old=self.root/'old';self.prepare(old);records,parts,study=self.sealed(old);prior=c.sealed_prior_days(old,records,study,parts);day=parts[0]['day_utc']
        sealpath=old/'days'/day/'core_selection.json';selection=c.read_json(sealpath);selection['core_payload_sha256']='0'*64;c.write(sealpath,selection)
        with self.assertRaisesRegex(ValueError,'core selection differs'):c.compare_prior_day(prior[day],{'day_utc':day,'cases':{}},old/'days'/day)
    def test_tampered_prior_prepared_binding_rejected(self):
        old=self.root/'old';self.prepare(old);records,parts,study=self.sealed(old,partial=False);(old/records[0]['prepared']['path']).write_text('{}')
        with self.assertRaisesRegex(ValueError,'bound file changed'):c.sealed_prior_days(old,records,study,parts)
    def test_no_source_access_when_continuation_gate_rejects(self):
        def reject(*args,**kwargs):raise ValueError('synthetic rejected amendment')
        helper=SimpleNamespace(validate_amendment=reject)
        args=SimpleNamespace(amendment=self.root/'amendment.json',expected_amendment_sha256='a'*64,expected_protocol_sha256='b'*64,output=self.root/'never-created')
        with patch.object(c,'load_module',return_value=helper),patch.object(c,'original_pipeline') as scientific:
            with self.assertRaisesRegex(ValueError,'rejected amendment'):c.collect(args)
            scientific.assert_not_called()
        self.assertFalse(args.output.exists())
    def test_no_transfer_decode_when_source_ready_gate_rejects(self):
        def reject(*args,**kwargs):raise ValueError('synthetic source audit not PASS')
        helper=SimpleNamespace(validate_amended_source_ready=reject)
        args=SimpleNamespace(amendment=self.root/'amendment.json',expected_amendment_sha256='a'*64,expected_protocol_sha256='b'*64,output=self.root/'never-created',transport_audit=self.root/'transport.json',expected_transport_audit_sha256='c'*64,source_review=self.root/'source.json',expected_source_review_sha256='d'*64,multiattempt_ledger=self.root/'ledger.json',expected_multiattempt_ledger_sha256='e'*64)
        with patch.object(c,'load_module',return_value=helper),patch.object(c,'original_pipeline') as scientific:
            with self.assertRaisesRegex(ValueError,'source audit not PASS'):c.assemble(args)
            scientific.assert_not_called()
        self.assertFalse(args.output.exists())
    def test_two_case_gated_assembly_uses_frozen_driver(self):
        collection=self.root/'collection';payload=self.prepare(collection)
        plan=self.plan();plan['original_plan_binding']={'path':str(c.PAPER/'phase16/source_plan.json'),'sha256':c.file_sha(c.PAPER/'phase16/source_plan.json')}
        plan['continuation_execution_bindings']=[{'path':str((Path(c.__file__).parent/name).relative_to(c.REPO)),'sha256':c.file_sha(Path(c.__file__).parent/name)} for name in ('continue_pipeline.py','collector.py','protocol.py')]
        planpath=self.root/'plan.json';c.write(planpath,plan);plansha=c.file_sha(planpath)
        amendment=self.root/'amendment.json';c.write(amendment,{'synthetic':True});amsha=c.file_sha(amendment)
        case_audits={}
        for bind in plan['case_configs']:
            cfg=c.read_json(c.REPO/bind['path']);case=cfg['case_id'];audit={'schema_version':'fixed_address_source_audit_v1','status':'PASS','config_sha256':bind['sha256'],'selection_manifest_sha256':payload['selection_manifests'][case]['sha256'],'tier':cfg['source_tier'],'cross_day_header_links_checked':True,'endpoint_anchors_checked':True,'days':[]}
            for day in self.p.driver.expected_days(cfg):
                prep=c.read_json(collection/'days'/day/'prepared.json');rows=prep['cases'][case]['selected_transactions'];audit['days'].append({'day_utc':day,'status':'COVERED','selected_transactions':len(rows),'core_log_count':sum(x['archived_core_log_count'] for x in rows),**{k:prep[k] for k in self.p.driver.COVERAGE_HASHES},**{k:True for k in self.p.driver.COVERAGE_CHECKS}})
            path=self.root/(case+'_synthetic_source_audit.json');c.write(path,audit);case_audits[case]={'path':str(path),'sha256':c.file_sha(path)}
        result={'schema_version':'phase16_continuation_collection_result_v1','status':'COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT','plan_sha256':plansha,'continuation_amendment_sha256':amsha,'original_plan_binding':plan['original_plan_binding'],'transfer_decoding_performed':False,'detector_scoring_performed':False,'labels_used':False,**payload}
        c.write(collection/'collection_result.json',result);resultsha=c.file_sha(collection/'collection_result.json')
        source=self.root/'synthetic_source_review.json';transport=self.root/'synthetic_transport_review.json';ledger=self.root/'synthetic_ledger.json'
        c.write(source,{'collection_result_sha256':resultsha,'case_audits':case_audits});c.write(transport,{'collection_result_sha256':resultsha});c.write(ledger,{'synthetic':True})
        args=SimpleNamespace(amendment=amendment,expected_amendment_sha256=amsha,expected_protocol_sha256=c.file_sha(Path(c.__file__).parent/'protocol.py'),output=self.root/'observations',transport_audit=transport,expected_transport_audit_sha256=c.file_sha(transport),source_review=source,expected_source_review_sha256=c.file_sha(source),multiattempt_ledger=ledger,expected_multiattempt_ledger_sha256=c.file_sha(ledger),collection=collection,repo=c.REPO)
        context={'plan':plan,'original_plan':self.original,'plan_path':planpath,'plan_sha256':plansha,'continuation_output_root':collection}
        helper=SimpleNamespace(validate_amended_source_ready=lambda *a,**k:context)
        actual_loader=c.load_module
        def loader(path,expected,name):
            return helper if name=='phase16_continuation_protocol' else actual_loader(path,expected,name)
        with patch.object(c,'load_module',side_effect=loader),contextlib.redirect_stdout(io.StringIO()):assembled=c.assemble(args)
        self.assertEqual(len(assembled['input_manifests']),2);self.assertFalse(assembled['detector_scoring_performed'])
        for bind in assembled['input_manifests'].values():self.assertEqual(set(bind),{'path','sha256'});self.assertEqual(c.file_sha(bind['path']),bind['sha256'])
    def test_collector_receives_accepted_plan_hash_despite_runtime_serialization(self):
        original=copy.deepcopy(self.original);wheel=self.root/'synthetic.whl';wheel.write_bytes(b'synthetic dependency identity only');original['pyarrow_wheel_sha256']=c.file_sha(wheel)
        accepted=self.root/'accepted_original_plan.json';accepted.write_text(json.dumps(original,indent=2)+'\n');accepted_sha=c.file_sha(accepted)
        parent=self.root/'synthetic_parent';parent.mkdir();c.write(parent/'frozen_plan.json',original);runtime_sha=c.file_sha(parent/'frozen_plan.json');self.assertNotEqual(accepted_sha,runtime_sha)
        plan=copy.deepcopy(original);plan['schema_version']='article2_phase16_continuation_source_plan_v1';plan['original_plan_binding']={'path':str(accepted),'sha256':accepted_sha}
        plan['continuation_execution_bindings']=[{'path':str((Path(c.__file__).parent/name).relative_to(c.REPO)),'sha256':c.file_sha(Path(c.__file__).parent/name)} for name in ('continue_pipeline.py','collector.py','protocol.py')]
        planpath=self.root/'new_plan.json';c.write(planpath,plan);amendment=self.root/'synthetic_amendment.json';c.write(amendment,{'synthetic':True})
        output=self.root/'new_output';context={'plan':plan,'original_plan':original,'plan_path':planpath,'plan_sha256':c.file_sha(planpath),'parent_root':parent,'parent_bindings':{'frozen_plan.json':runtime_sha},'first_attempt_seal':{'completed_days':[],'partial_core_selection_seals':[]},'continuation_output_root':output,'absolute_deadline_utc':'2026-01-01T04:00:00+00:00','manual_reacquisition':None}
        helper=SimpleNamespace(validate_amendment=lambda *a,**k:context)
        captured=[]
        def constructor(*args,**kwargs):
            captured.append(kwargs['original_plan_sha256']);self.assertEqual(kwargs['original_plan_sha256'],accepted_sha);self.assertNotEqual(kwargs['original_plan_sha256'],runtime_sha)
            raise ValueError('synthetic stop before any source bytes')
        collector=SimpleNamespace(ContinuationSession=constructor)
        actual_loader=c.load_module
        def loader(path,expected,name):
            if name=='phase16_continuation_protocol':return helper
            if name=='phase16_continuation_collector':return collector
            return actual_loader(path,expected,name)
        args=SimpleNamespace(amendment=amendment,expected_amendment_sha256=c.file_sha(amendment),expected_protocol_sha256=c.file_sha(Path(c.__file__).parent/'protocol.py'),repo=c.REPO,wheel=wheel,dependencies=Path(pa.__file__).parent.parent,reuse_map=None,output=output)
        with patch.object(c,'load_module',side_effect=loader):
            with self.assertRaisesRegex(ValueError,'synthetic stop before any source bytes'):c.collect(args)
        self.assertEqual(captured,[accepted_sha])
        self.assertFalse((output/'collection_result.json').exists())
    def test_nonprefix_completed_days_rejected(self):
        with self.assertRaisesRegex(ValueError,'exact study prefix'):c.sealed_prior_days(self.root,[{'day_utc':'2022-02-20'}],['2022-02-19','2022-02-20'])


if __name__=='__main__':unittest.main()
