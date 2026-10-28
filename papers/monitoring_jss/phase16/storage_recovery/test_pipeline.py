"""Focused synthetic checks for typed compact storage and new resource gates."""
import contextlib
import copy
import io
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import numpy as np
import pyarrow as pa
import pyarrow.compute as pc
import pipeline as s

# Reuse fabricated fixtures, not real datasets or the earlier test suite.
sys.path.insert(0,str(s.PAPER/'phase16/continuation'))
import test_continue_pipeline as fixtures


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p=s.original_pipeline();cls.original=s.read_json(s.PAPER/'phase16/source_plan.json')
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='phase16_storage_pipeline_synthetic_');self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def plan(self):
        result=copy.deepcopy(self.original);result['schema_version']='article2_phase16_storage_recovery_source_plan_v1';return result
    def test_explicit_descriptor_and_whole_storage_kinds(self):
        descriptor=self.root/'source_storage.json';s.write(descriptor,{'synthetic_descriptor':True})
        self.assertEqual(s.source_storage_entry(SimpleNamespace(storage_kind='compact_descriptor',path=descriptor)),{'storage_kind':'compact_descriptor','path':str(descriptor.resolve())})
        whole=self.root/'original.parquet';whole.write_bytes(b'synthetic_whole_identity_only')
        self.assertEqual(s.source_storage_entry(SimpleNamespace(storage_kind='verified_whole_object',path=whole))['storage_kind'],'verified_whole_object')
        with self.assertRaisesRegex(ValueError,'unknown original-byte storage'):s.source_storage_entry(SimpleNamespace(storage_kind='sparse_materialized_parquet',path=whole))
    def test_original_scientific_scope_and_collector_plan_unchanged(self):
        plan=self.plan();self.assertTrue(s.scientific_scope_unchanged(plan,self.original))
        plan['collector']['caps']['wall_seconds']=14400
        with self.assertRaisesRegex(ValueError,'original plan field'):s.scientific_scope_unchanged(plan,self.original)
    def test_new_gate_rejection_never_calls_unused_wall_gate_or_sources(self):
        def reject(*a,**kw):raise ValueError('synthetic storage amendment rejected')
        helper=SimpleNamespace(validate_recovery_amendment=reject)
        args=SimpleNamespace(amendment=self.root/'amendment.json',expected_amendment_sha256='a'*64,expected_protocol_sha256='b'*64,output=self.root/'new_output')
        with patch.object(s,'load_module',return_value=helper),patch.object(s,'original_pipeline') as source,patch.object(s._helpers,'collect') as unused:
            with self.assertRaisesRegex(ValueError,'storage amendment rejected'):s.collect(args)
            source.assert_not_called();unused.assert_not_called()
        self.assertFalse(args.output.exists())
    def test_new_source_gate_rejection_precedes_transfer_decoding(self):
        def reject(*a,**kw):raise ValueError('synthetic compact source audit rejected')
        helper=SimpleNamespace(validate_recovered_source_ready=reject)
        args=SimpleNamespace(amendment=self.root/'amendment.json',expected_amendment_sha256='a'*64,expected_protocol_sha256='b'*64,output=self.root/'new_output',transport_audit=self.root/'transport.json',expected_transport_audit_sha256='c'*64,source_review=self.root/'source.json',expected_source_review_sha256='d'*64,multiattempt_ledger=self.root/'ledger.json',expected_multiattempt_ledger_sha256='e'*64)
        with patch.object(s,'load_module',return_value=helper),patch.object(s,'original_pipeline') as source,patch.object(s._helpers,'assemble') as unused:
            with self.assertRaisesRegex(ValueError,'compact source audit rejected'):s.assemble(args)
            source.assert_not_called();unused.assert_not_called()
    def prepare(self,output,prior=None):
        plan,inventory,configs,shas,rows=fixtures.Tests.fixture(self);output.mkdir();cache=output/'invented_whole_parquet';cache.mkdir()
        def source(item):
            reader=fixtures.Reader(item,rows[item['key']],cache/(item['key']+'.parquet'));reader.storage_kind='verified_whole_object';return reader
        with contextlib.redirect_stdout(io.StringIO()):
            return s.prepare_sources(plan,inventory,configs,shas,source,output,prior or {},self.p,pa,pc,np)
    def test_all113_typed_storage_entries_and19_prior_days_preserved(self):
        old=self.root/'old';before=self.prepare(old)
        completed,partial,study=fixtures.Tests.sealed(self,old,completed=19,partial=True)
        prior=s.sealed_prior_days(old,completed,study,partial);new=self.root/'new';after=self.prepare(new,prior)
        locations=s.read_json(new/'runtime_source_storage.json');self.assertEqual(len(locations),113)
        self.assertFalse((new/'runtime_source_paths.json').exists());self.assertEqual(after['runtime_source_storage_sha256'],s.file_sha(new/'runtime_source_storage.json'))
        self.assertTrue(all(x['storage_kind']=='verified_whole_object' and set(x)=={'path','storage_kind'} for x in locations.values()))
        report=s.read_json(new/'prior_completed_day_comparisons.json');self.assertEqual(report['completed_day_count'],19);self.assertEqual(report['partial_core_selection_count'],1)
        self.assertTrue(all(x['exact_core_selection_match'] for x in report['days']))
        for case in before['selection_manifests']:self.assertEqual(before['selection_manifests'][case]['sha256'],after['selection_manifests'][case]['sha256'])
    def test_resource_session_gets_new_gate_forensics_and_explicit_pending_request(self):
        original=copy.deepcopy(self.original);wheel=self.root/'synthetic.whl';wheel.write_bytes(b'fictional parser wheel identity');original['pyarrow_wheel_sha256']=s.file_sha(wheel)
        accepted=self.root/'accepted_original.json';accepted.write_text(__import__('json').dumps(original,indent=2)+'\n')
        parent=self.root/'parent';parent.mkdir();s.write(parent/'frozen_plan.json',original)
        plan=copy.deepcopy(original);plan['schema_version']='article2_phase16_storage_recovery_source_plan_v1';plan['original_plan_binding']={'path':str(accepted),'sha256':s.file_sha(accepted)}
        planpath=self.root/'new_plan.json';s.write(planpath,plan);amendment=self.root/'new_amendment.json';s.write(amendment,{'synthetic':True})
        output=self.root/'attempt2';pending={'parent_request_ordinal':730,'source_key':'synthetic-only','start':7,'length':11};forensics={'synthetic_closure':{'path':str(self.root/'unread_forensic.json'),'sha256':'f'*64}}
        context={'plan':plan,'original_plan':original,'plan_path':planpath,'plan_sha256':s.file_sha(planpath),'parent_root':parent,'parent_bindings':{'frozen_plan.json':s.file_sha(parent/'frozen_plan.json')},'first_attempt_seal':{'completed_days':[],'partial_core_selection_seals':[]},'recovery_output_root':output,'pinned_runtime_root':output,'absolute_deadline_utc':'2026-01-01T04:00:00Z','manual_reacquisition':pending,'forensic_bindings':forensics}
        calls=[];test=self
        class Session:
            def __init__(self,*a,**kw):
                calls.append('new_resource_session');test.assertEqual(kw['forensic_bindings'],forensics);test.assertEqual(kw['manual_reacquisition'],pending);test.assertEqual(kw['pinned_runtime_root'],output);test.assertEqual(kw['original_plan_sha256'],s.file_sha(accepted));test.assertNotEqual(kw['original_plan_sha256'],s.file_sha(parent/'frozen_plan.json'))
            def reacquire_pending_range(self):calls.append('one_explicit_pending_reacquisition')
            def close(self,status):calls.append('close_'+status)
        helper=SimpleNamespace(validate_recovery_amendment=lambda *a,**k:context);collector=SimpleNamespace(ResourceSession=Session)
        actual_loader=s.load_module
        def loader(path,expected,name):
            if name=='phase16_storage_recovery_protocol':return helper
            if name=='phase16_storage_recovery_collector':return collector
            return actual_loader(path,expected,name)
        def no_sources(*a,**k):calls.append('prepare_boundary');raise ValueError('synthetic stop without reading any source payload')
        args=SimpleNamespace(amendment=amendment,expected_amendment_sha256=s.file_sha(amendment),expected_protocol_sha256='b'*64,repo=s.REPO,wheel=wheel,dependencies=Path(pa.__file__).parent.parent,reuse_map=None,output=output)
        with patch.object(s,'load_module',side_effect=loader),patch.object(s,'execution_sources',return_value='c'*64),patch.object(s,'PINNED_RUNTIME_ROOT',output),patch.object(s,'prepare_sources',side_effect=no_sources):
            with self.assertRaisesRegex(ValueError,'synthetic stop'):s.collect(args)
        self.assertEqual(calls,['new_resource_session','one_explicit_pending_reacquisition','prepare_boundary','close_FAILED'])
        self.assertFalse((output/'collection_result.json').exists())
    def test_pinned_external_runtime_is_not_workspace(self):
        self.assertEqual(str(s.PINNED_RUNTIME_ROOT),'/tmp/article2_phase16_runtime_159bf77d8682/attempt2')
        self.assertFalse(s.PINNED_RUNTIME_ROOT.is_relative_to(s.REPO))


if __name__=='__main__':unittest.main()
