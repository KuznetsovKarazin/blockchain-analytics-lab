"""Candidate-only synthetic continuation lineage/cost faults; no A1 reads."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

TARGET=Path(__file__).with_name('independent_transport_audit.py')
spec=importlib.util.spec_from_file_location('independent_continuation_audit',TARGET)
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

class ContinuationLedgerFaults(unittest.TestCase):
    def setUp(self):
        self.start=datetime(2026,1,1,tzinfo=timezone.utc);self.time=lambda seconds:(self.start+timedelta(seconds=seconds)).isoformat()
        key='v1.0/eth/logs/date=2022-02-19/fixture.parquet'
        self.source={'table':'logs','day_utc':'2022-02-19','key':key,'size_bytes':64,'etag_opaque':'"synthetic"','url':a.ENDPOINT+key};self.sources={key:self.source}
        self.caps={'requests':5000,'total_response_bytes':16*1024**3,'wall_seconds':7200,'max_range_bytes':8,'max_source_bytes':64}
        self.parent=[self.record(1,0,4,0,1),self.record(2,4,8,7199,7201,received=3,ok=False)]
        self.ps={'status':'FAILED','wall_seconds_elapsed':7201,'request_count':2,'retained_response_bytes':7,'started_utc':self.time(0),'attempt_id':'parent'}
        self.new=[self.record(3,4,8,7203,7204),self.record(4,12,4,7205,7206)]
        for record in self.new:record['origin_attempt_id']='continuation'
        self.new[0].update(continuation_request_kind='explicit_manual_reacquisition',reacquisition_of={'attempt_id':'parent','ordinal':2})
        self.new[1]['continuation_request_kind']='previously_unrequested_range'
        self.ns={'status':'COMPLETE','parent_attempt_id':'parent','original_started_utc':self.time(0),'absolute_deadline_utc':self.time(14400),'started_utc':self.time(7203),'attempt_id':'continuation','inherited_request_count':2,'new_request_count':2,'cumulative_request_count':4,'inherited_response_bytes':7,'new_response_bytes':12,'cumulative_response_bytes':19,'manual_reacquisition_count':1}
        self.ns.update(reserved_parent_failed_response_bytes=5,reserved_new_failed_or_pending_response_bytes=0,inherited_charged_response_bytes=12,new_charged_response_bytes=12,cumulative_charged_response_bytes=24)
        self.manual={'parent_request_ordinal':2,'source_key':key,'start':4,'length':8}
    def record(self,ordinal,start,length,begin,end,received=None,ok=True):
        got=length if received is None else received
        out={'ordinal':ordinal,'source':self.source,'start':start,'length':length,'response_bytes':got,'response_sha256':hashlib.sha256(bytes(range(start,start+got))).hexdigest(),'method':'GET','stored_offset':start,'stored_file_name':'source.parquet','request_headers':{'Range':f'bytes={start}-{start+length-1}','If-Match':self.source['etag_opaque'],'Accept-Encoding':'identity'},'transport_ok':ok,'invalid_header_body_read':False,'started_utc':self.time(begin),'completed_utc':self.time(end),'http_status':206,'response_url':self.source['url'],'etag':self.source['etag_opaque'],'content_range':f'bytes {start}-{start+length-1}/64','content_length':str(length),'content_encoding':None}
        if not ok:out['failure']='ValueError: wall cap after range read'
        return out
    def check(self):return a.validate_ledgers(self.parent,self.new,self.ps,self.ns,self.sources,self.caps,self.time(7202),self.manual)
    def test_distinct_origins_and_all_failed_bytes_remain_charged(self):
        got=self.check();self.assertEqual(got['cumulative_response_bytes'],19);self.assertEqual(got['unaccepted_response_bytes'],3)
        evidence=got['accepted_range_evidence'];self.assertEqual([x['origin_ordinal'] for x in evidence],[1,3,4])
        self.assertEqual([x['origin_attempt_id'] for x in evidence],['parent','continuation','continuation'])
        self.assertEqual(evidence[0]['receipt'],self.parent[0]);self.assertNotIn(self.parent[1],[x['receipt'] for x in evidence])
    def test_missing_manual_exception_cannot_promote_failed_interval(self):
        self.manual=None
        with self.assertRaisesRegex(ValueError,'manual exception'):self.check()
    def test_manual_target_cannot_change_range_or_original_request(self):
        self.manual['parent_request_ordinal']=1
        with self.assertRaisesRegex(ValueError,'target differs'):self.check()
    def test_manual_receipt_must_name_exact_original_attempt(self):
        self.new[0]['reacquisition_of']['attempt_id']='other'
        with self.assertRaisesRegex(ValueError,'origin marker'):self.check()
    def test_repeated_reacquisition_is_not_automatic_retry(self):
        self.new[1]=deepcopy(self.new[0]);self.new[1]['ordinal']=4;self.new[1]['started_utc']=self.time(7205);self.new[1]['completed_utc']=self.time(7206)
        with self.assertRaisesRegex(ValueError,'overlapping continuation retry'):self.check()
    def test_non_wall_parent_failure_cannot_be_continued(self):
        self.parent[-1]['failure']='ValueError: ETag changed'
        with self.assertRaisesRegex(ValueError,'ineligible'):self.check()
    def test_open_parent_is_not_a_natural_closed_attempt(self):
        for status in ('OPEN','OPEN_REQUEST_PENDING'):
            self.ps['status']=status
            with self.subTest(status=status),self.assertRaisesRegex(ValueError,'naturally closed'):self.check()
    def test_parent_stopped_before_original_deadline_is_rejected(self):
        self.ps['wall_seconds_elapsed']=7199
        with self.assertRaisesRegex(ValueError,'did not reach'):self.check()
    def test_absolute_deadline_cannot_reset_from_continuation_start(self):
        self.ns['absolute_deadline_utc']=self.time(7203+14400)
        with self.assertRaisesRegex(ValueError,'reset or extended'):self.check()
    def test_cumulative_accounting_cannot_omit_failed_partial_bytes(self):
        self.ns['inherited_response_bytes']=4;self.ns['cumulative_response_bytes']=16
        with self.assertRaisesRegex(ValueError,'byte accounting'):self.check()
    def test_success_after_absolute_deadline_is_not_accepted(self):
        self.new[-1]['completed_utc']=self.time(14401)
        with self.assertRaisesRegex(ValueError,'absolute deadline'):self.check()
    def test_new_request_before_prospective_acceptance_is_rejected(self):
        self.new[0]['started_utc']=self.time(7201)
        with self.assertRaisesRegex(ValueError,'predates'):self.check()
    def test_full_length_wall_failed_body_still_not_successful_evidence(self):
        self.parent[-1]['response_bytes']=8;self.parent[-1]['response_sha256']=hashlib.sha256(bytes(range(4,12))).hexdigest()
        self.ps['retained_response_bytes']=12;self.ns['inherited_response_bytes']=12;self.ns['cumulative_response_bytes']=24
        self.ns['reserved_parent_failed_response_bytes']=0
        got=self.check();self.assertEqual(got['unaccepted_response_bytes'],8)
        self.assertEqual([x['origin_ordinal'] for x in got['accepted_range_evidence']],[1,3,4])
    def test_request_after_failed_continuation_is_rejected(self):
        self.new[0]['transport_ok']=False;self.new[0]['failure']='ValueError: truncated exact range'
        with self.assertRaisesRegex(ValueError,'after failed'):self.check()
    def complete_over_wall(self):
        self.ps['status']='COMPLETE';self.ps['retained_response_bytes']=12
        self.parent[-1]['transport_ok']=True;self.parent[-1].pop('failure');self.parent[-1]['response_bytes']=8
        self.parent[-1]['response_sha256']=hashlib.sha256(bytes(range(4,12))).hexdigest();self.parent[-1]['completed_utc']=self.time(7199.5)
        self.new=[self.new[-1]];self.new[0]['ordinal']=3;self.manual=None
        self.ns.update(inherited_response_bytes=12,new_request_count=1,cumulative_request_count=3,new_response_bytes=4,cumulative_response_bytes=16,manual_reacquisition_count=0)
        self.ns.update(reserved_parent_failed_response_bytes=0,inherited_charged_response_bytes=12,new_charged_response_bytes=4,cumulative_charged_response_bytes=16)
    def test_complete_over_wall_retains_failed_original_contract_disposition(self):
        self.complete_over_wall();got=self.check()
        self.assertEqual(got['original_attempt_disposition'],'producer COMPLETE; original wall contract FAILED')
    def test_complete_over_wall_cannot_hide_a_late_accepted_get(self):
        self.complete_over_wall();self.parent[-1]['completed_utc']=self.time(7201)
        with self.assertRaisesRegex(ValueError,'original deadline'):self.check()
    def timeout(self,message='timed out'):
        self.parent[-1]['failure']='TimeoutError: '+message;self.ps['updated_utc']=self.time(7201)
    def test_narrow_timeout_preserves_uncertainty_and_full_declared_reservation(self):
        for message in ('timed out','The read operation timed out'):
            self.timeout(message);got=self.check()
            self.assertTrue(got['timeout_causality_unresolved']);self.assertIn('exact causal contribution unknown',got['original_attempt_disposition'])
            self.assertEqual((got['cumulative_response_bytes'],got['cumulative_charged_response_bytes']),(19,24))
            self.assertFalse(got['wire_bytes_measured']);self.assertEqual(self.parent[-1]['failure'],'TimeoutError: '+message)
    def test_earlier_or_outside_deadline_timeout_is_not_retriable(self):
        self.timeout()
        for begin,end in ((7139,7201),(7200,7201),(7199,7199.9)):
            self.parent[-1]['started_utc']=self.time(begin);self.parent[-1]['completed_utc']=self.time(end)
            with self.subTest(begin=begin,end=end),self.assertRaisesRegex(ValueError,'ineligible'):self.check()
    def test_timeout_cannot_hide_observed_bad_or_partial_headers(self):
        self.timeout();original=deepcopy(self.parent[-1])
        for field,value in (('etag','"changed"'),('http_status',503),('content_encoding','gzip'),('content_range','bytes 5-12/64')):
            self.parent[-1]=deepcopy(original);self.parent[-1][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'ineligible'):self.check()
        self.parent[-1]=deepcopy(original);self.parent[-1].pop('etag')
        with self.assertRaisesRegex(ValueError,'ineligible'):self.check()
    def test_timeout_without_response_headers_requires_zero_retained_bytes(self):
        self.timeout()
        for field in a.RESPONSE_FIELDS:self.parent[-1].pop(field)
        with self.assertRaisesRegex(ValueError,'ineligible'):self.check()
        self.parent[-1]['response_bytes']=0;self.parent[-1]['response_sha256']=hashlib.sha256(b'').hexdigest()
        self.ps['retained_response_bytes']=4;self.ns.update(inherited_response_bytes=4,cumulative_response_bytes=16,reserved_parent_failed_response_bytes=8)
        got=self.check();self.assertEqual(got['reserved_parent_failed_response_bytes'],8)
    def test_timeout_with_inconsistent_original_clocks_is_rejected(self):
        self.timeout();self.ps['updated_utc']=self.time(7300)
        with self.assertRaisesRegex(ValueError,'ineligible'):self.check()
    def test_timeout_does_not_authorize_other_exception_classes(self):
        self.timeout();self.parent[-1]['failure']='URLError: timed out'
        with self.assertRaisesRegex(ValueError,'ineligible'):self.check()
    def test_exact_urlopen_timeout_wrappers_preserve_outer_exception_and_uncertainty(self):
        self.ps['updated_utc']=self.time(7201)
        for message in ('<urlopen error timed out>','<urlopen error The read operation timed out>'):
            self.parent[-1]['failure']='URLError: '+message;got=self.check()
            self.assertTrue(got['timeout_causality_unresolved']);self.assertEqual(self.parent[-1]['failure'],'URLError: '+message)
        for message in ('<urlopen error DNS lookup timed out>','<urlopen error certificate verify failed>','<urlopen error SSL handshake timed out>'):
            self.parent[-1]['failure']='URLError: '+message
            with self.subTest(message=message),self.assertRaisesRegex(ValueError,'ineligible'):self.check()
    def test_conservative_byte_charge_cannot_be_reported_as_retained_only(self):
        self.ns['cumulative_charged_response_bytes']=self.ns['cumulative_response_bytes']
        with self.assertRaisesRegex(ValueError,'conservative failed-range charge'):self.check()
    def test_full_failed_range_reservation_blocks_get_that_retained_total_would_allow(self):
        # Pure synthetic ledger: no body of this declared size is allocated/read.
        n=a.TOTAL_BYTE_CAP-12;self.source['size_bytes']=a.TOTAL_BYTE_CAP+64
        self.caps.update(max_range_bytes=a.TOTAL_BYTE_CAP,max_source_bytes=a.TOTAL_BYTE_CAP+64)
        self.parent[0].update(length=n,response_bytes=n,response_sha256=hashlib.sha256(b'synthetic-only').hexdigest())
        self.parent[-1].update(start=n,stored_offset=n)
        self.new=[self.new[0]];self.new[0].update(start=n,stored_offset=n)
        self.manual['start']=n
        for r in self.parent+self.new:
            start,length=r['start'],r['length'];r['request_headers']['Range']=f'bytes={start}-{start+length-1}'
            r['content_range']=f'bytes {start}-{start+length-1}/{self.source["size_bytes"]}';r['content_length']=str(length)
        self.ps['retained_response_bytes']=n+3
        self.ns.update(new_request_count=1,cumulative_request_count=3,inherited_response_bytes=n+3,new_response_bytes=8,cumulative_response_bytes=n+11,
                       inherited_charged_response_bytes=n+8,new_charged_response_bytes=8,cumulative_charged_response_bytes=n+16)
        self.assertLess(self.ns['cumulative_response_bytes'],a.TOTAL_BYTE_CAP)
        with self.assertRaisesRegex(ValueError,'reservation exceeds cumulative byte cap'):self.check()

class ContinuationChainFaults(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='phase16_continuation_chain_synthetic_');self.root=Path(self.temp.name)
        self.repo=self.root/'repo';self.repo.mkdir();self.parent=self.root/'A1';self.parent.mkdir()
        self.started=datetime(2026,1,1,tzinfo=timezone.utc);self.time=lambda x:(self.started+timedelta(seconds=x)).isoformat()
        self.write=lambda path,value:self._write(path,value)
        configs=[]
        for case in a.CASES:
            p=self.repo/(case+'.json');self.write(p,{'case_id':case});configs.append({'path':p.name,'sha256':a.file_sha(p)})
        self.original={'schema_version':'article2_phase16_streaming_pipeline_plan_v1','study_start':'2022-02-19','fixed_science':'synthetic immutable threshold',
            'collector':{'caps':{'wall_seconds':7200,'requests':5000,'total_response_bytes':17179869184,'retries':0,'concurrency':1}},'case_configs':configs}
        self.original_path=self.root/'original_plan.json';self.write(self.original_path,self.original)
        self.original_binding=self.bind(self.original_path)
        code=Path(a.__file__).parent
        self.plan={**deepcopy(self.original),'schema_version':'article2_phase16_continuation_source_plan_v1','original_plan_binding':self.original_binding,
            'continuation_transport':{'absolute_deadline_seconds_from_a1_start':14400,'cumulative_get_limit':5000,'cumulative_response_byte_limit':17179869184,'automatic_retries':0,'maximum_explicit_manual_reacquisitions':1,'failed_get_byte_charge':'FULL_DECLARED_RANGE_LENGTH'},
            'continuation_execution_bindings':[self.bind(code/name) for name in ('protocol.py','collector.py','continue_pipeline.py','independent_transport_audit.py','audit_sources.py')]}
        self.plan_path=self.root/'plan.json';self.write(self.plan_path,self.plan)
        self.originals={}
        for case,b in zip(a.CASES,configs):
            gate=self.root/(case+'_gate.json');self.write(gate,{'schema_version':'article2_phase16_bound_source_execution_gate_v1','status':'ROOT_ACCEPTED_AS_PART_OF_DECLARED_MEASUREMENT','source_plan':self.original_binding,'execution_source_bindings':[]})
            accepted=self.root/(case+'_acceptance.json');self.write(accepted,{'schema_version':'fixed_address_measurement_acceptance_v1','status':'ACCEPTED_FOR_DECLARED_FIXED_ADDRESS_MEASUREMENT','accepted_before_affected_payload':True,'all_frame_dispositions_completed':True,'config_sha256':b['sha256'],'accepted_utc':self.time(-1),'gate_bindings':{'source_plan':self.bind(gate)}})
            self.originals[case]=self.bind(accepted)
        session={'schema_version':'article2_phase16_range_capture_v1','status':'FAILED','started_utc':self.time(0),'updated_utc':self.time(7201),'wall_seconds_elapsed':7201,'request_count':0,'retained_response_bytes':0,'attempt_id':a.digest({'plan':a.digest(self.original['collector']),'started_utc':self.time(0)}),'retries':0}
        for path,value in (('frozen_plan.json',self.original),('runtime_acceptances.json',self.originals),('transport/plan.json',self.original['collector']),('transport/session.json',session),('transport/requests.json',[]),('failure.json',{'status':'FAILED_NOT_ACCEPTED','error_type':'ValueError','error':'wall/request cap','transfer_decoding_performed':False,'detector_scoring_performed':False})):
            self.write(self.parent/path,value)
        evidence={str(p.relative_to(self.parent)):a.file_sha(p) for p in self.parent.rglob('*.json')}
        for name in a.REQUIRED_PARENT:evidence.setdefault(name,None)
        self.seal={'schema_version':'article2_phase16_first_attempt_closure_seal_v1','status':'CLOSED_ORIGINAL_ATTEMPT_PRESERVED','parent_root':str(self.parent),'original_plan_sha256':self.original_binding['sha256'],'attempt_id':session['attempt_id'],'started_utc':self.time(0),'closed_utc':self.time(7201),'sealed_utc':self.time(7202),'closure_class':'WALL_LIMIT_FAILED','parent_evidence_bindings':evidence,'completed_days':[],'partial_core_selection_seals':[],'original_request_count':0,'original_response_bytes':0,'original_wall_seconds_elapsed':7201,'original_attempt_compliant_completion':False,'producer_status':'FAILED','original_wall_contract_status':'FAILED'}
        self.seal.update(timeout_causality_unresolved=False,reserved_parent_failed_response_bytes=0,inherited_charged_response_bytes=0)
        self.seal_path=self.root/'seal.json';self.write(self.seal_path,self.seal)
        self.exposure={'schema_version':'article2_phase16_source_only_exposure_report_v1','status':'ROOT_REVIEWED_SOURCE_ONLY_EXPOSURE','first_attempt_seal_sha256':a.file_sha(self.seal_path),'reviewed_utc':self.time(7203),'reviewer':'synthetic-root','exposure_description':'Synthetic gate exercise only.','source_payload_exposed':True,'detector_scoring_started':False,'new_reference_acquisition_started':False,'performance_or_reference_results_examined':False,'completed_days':[],'partial_core_selection_days':[]}
        self.exposure_path=self.root/'exposure.json';self.write(self.exposure_path,self.exposure)
        self.amendment={'schema_version':'article2_phase16_source_continuation_acceptance_v1','status':'ACCEPTED_BEFORE_CONTINUATION_ONLY','accepted_utc':self.time(7204),'continuation_plan':self.bind(self.plan_path),'first_attempt_seal':self.bind(self.seal_path),'exposure_report':self.bind(self.exposure_path),'original_measurement_acceptances':self.originals,'parent_evidence_bindings':evidence,'manual_reacquisition':None,'accepted_before_continuation_requests':True,'source_payload_previously_exposed':True,'continuation_output_root':str(self.root/'A2'),'complete_overwall_source_validity_review':None}
        self.amendment_path=self.root/'amendment.json';self.write(self.amendment_path,self.amendment)
    def _write(self,path,value):path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(a.canonical(value)+b'\n')
    def bind(self,path):return {'path':str(path.resolve()),'sha256':a.file_sha(path)}
    def tearDown(self):self.temp.cleanup()
    def check(self):
        self.write(self.amendment_path,self.amendment)
        return a.validate_chain(self.amendment_path,a.file_sha(self.amendment_path),self.repo)
    def test_full_prospective_chain_binds_code_original_closure_and_exposure(self):
        got=self.check();self.assertEqual(got['parent'],self.parent);self.assertEqual(got['plan']['fixed_science'],self.original['fixed_science'])
    def test_sealed_original_metadata_cannot_change_after_acceptance(self):
        self.write(self.parent/'failure.json',{'modified':True})
        with self.assertRaisesRegex(ValueError,'original metadata changed'):self.check()
    def test_threshold_change_cannot_hide_in_operational_plan(self):
        self.plan['fixed_science']='changed';self.write(self.plan_path,self.plan);self.amendment['continuation_plan']=self.bind(self.plan_path)
        with self.assertRaisesRegex(ValueError,'scientific/source plan'):self.check()
    def test_auditor_must_be_bound_before_continuation(self):
        self.plan['continuation_execution_bindings']=[x for x in self.plan['continuation_execution_bindings'] if Path(x['path']).name!='independent_transport_audit.py']
        self.write(self.plan_path,self.plan);self.amendment['continuation_plan']=self.bind(self.plan_path)
        with self.assertRaisesRegex(ValueError,'auditor binding'):self.check()
    def test_reference_exposure_cannot_be_reclassified_source_only(self):
        self.exposure['new_reference_acquisition_started']=True;self.write(self.exposure_path,self.exposure);self.amendment['exposure_report']=self.bind(self.exposure_path)
        with self.assertRaisesRegex(ValueError,'performance/reference exposure'):self.check()
    def test_acceptance_cannot_predate_exposure_review(self):
        self.amendment['accepted_utc']=self.time(7202)
        with self.assertRaisesRegex(ValueError,'chronology'):self.check()
    def test_accepted_destination_cannot_be_inside_original_attempt(self):
        self.amendment['continuation_output_root']=str(self.parent/'replacement')
        with self.assertRaisesRegex(ValueError,'inside original capture'):self.check()
    def test_end_to_end_synthetic_113_source_byte_audit_preserves_separate_ledgers(self):
        # Tiny invented envelopes only: not actual Parquet rows or historical data.
        raw=b'PAR1'+b'x'*16+b'fake'+(4).to_bytes(4,'little')+b'PAR1'
        sources=[]
        for i in range(113):
            key=f'v1.0/eth/logs/date=2022-02-19/fixture{i:03d}.parquet'
            sources.append({'table':'logs','day_utc':'2022-02-19','key':key,'size_bytes':32,'etag_opaque':'"synthetic"','url':a.ENDPOINT+key})
        inventory=self.repo/'inventory.json';self.write(inventory,{'objects':sources})
        reuse=self.repo/'reuse.json';self.write(reuse,{'objects':[]})
        self.original.update(source_union=self.bind(inventory),reuse_expectations_binding=self.bind(reuse),whole_object_reuse_expectations={},pipeline_sha256='b'*64)
        self.original['collector']['caps'].update(max_source_bytes=32,max_range_bytes=32,max_footer_bytes=32)
        self.write(self.original_path,self.original);self.original_binding=self.bind(self.original_path)
        for k,v in self.original.items():
            if k!='schema_version':self.plan[k]=deepcopy(v)
        self.plan['original_plan_binding']=self.original_binding;self.write(self.plan_path,self.plan)
        for case,b in list(self.originals.items()):
            ap=Path(b['path']);ac=a.read(ap);gp=Path(ac['gate_bindings']['source_plan']['path']);gate=a.read(gp)
            gate['source_plan']=self.original_binding;self.write(gp,gate);ac['gate_bindings']['source_plan']=self.bind(gp)
            self.write(ap,ac);self.originals[case]=self.bind(ap)
        self.write(self.parent/'frozen_plan.json',self.original);self.write(self.parent/'transport/plan.json',self.original['collector'])
        self.write(self.parent/'runtime_acceptances.json',self.originals)
        ps=a.read(self.parent/'transport/session.json');ps['attempt_id']=a.digest({'plan':a.digest(self.original['collector']),'started_utc':ps['started_utc']});ps['cache_or_full_object_reuses']=[]
        self.write(self.parent/'transport/session.json',ps)
        evidence={str(p.relative_to(self.parent)):a.file_sha(p) for p in self.parent.rglob('*.json')}
        for name in a.REQUIRED_PARENT:evidence.setdefault(name,None)
        self.seal.update(original_plan_sha256=self.original_binding['sha256'],attempt_id=ps['attempt_id'],parent_evidence_bindings=evidence)
        self.write(self.seal_path,self.seal);self.exposure['first_attempt_seal_sha256']=a.file_sha(self.seal_path);self.write(self.exposure_path,self.exposure)
        self.amendment.update(continuation_plan=self.bind(self.plan_path),first_attempt_seal=self.bind(self.seal_path),exposure_report=self.bind(self.exposure_path),original_measurement_acceptances=self.originals,parent_evidence_bindings=evidence)
        self.write(self.amendment_path,self.amendment);amendment_sha=a.file_sha(self.amendment_path);plan_sha=a.file_sha(self.plan_path)
        root=Path(self.amendment['continuation_output_root']);root.mkdir();transport=root/'transport';transport.mkdir()
        self.write(root/'frozen_plan.json',self.plan);(root/'continuation_amendment.json').write_bytes(self.amendment_path.read_bytes())
        self.write(transport/'plan.json',self.original['collector']);self.write(transport/'parent_bindings.json',evidence)
        (transport/'inherited_requests.json').write_bytes((self.parent/'transport/requests.json').read_bytes())
        attempt=a.digest({'parent_attempt_id':ps['attempt_id'],'parent_session_sha256':evidence['transport/session.json'],'continuation_plan_sha256':plan_sha,'started_utc':self.time(7205)})
        records=[];origins=[];manifests=[];paths={}
        for i,source in enumerate(sources,1):
            sid=a.digest(source);path=root/'cache'/sid/'source.parquet';path.parent.mkdir(parents=True);path.write_bytes(raw);paths[source['key']]=str(path)
            record={'ordinal':i,'source':source,'start':0,'length':32,'response_bytes':32,'response_sha256':hashlib.sha256(raw).hexdigest(),'method':'GET','stored_offset':0,'stored_file_name':'source.parquet','request_headers':{'Range':'bytes=0-31','If-Match':source['etag_opaque'],'Accept-Encoding':'identity'},'transport_ok':True,'invalid_header_body_read':False,'started_utc':self.time(7205+i*.01),'completed_utc':self.time(7205+i*.01+.005),'http_status':206,'response_url':source['url'],'etag':source['etag_opaque'],'content_range':'bytes 0-31/32','content_length':'32','content_encoding':None,'origin_attempt_id':attempt,'continuation_request_kind':'previously_unrequested_range'}
            origin={'origin_attempt_id':attempt,'origin_ordinal':i,'receipt':record};records.append(record);origins.append(origin)
            self.write(path.parent/'ranges.json',{'schema_version':'article2_phase16_continuation_range_cache_v1','source':source,'attempt_id':attempt,'parent_attempt_id':ps['attempt_id'],'inherited_ranges':[],'new_ranges':[record]})
            manifests.append({'schema_version':'article2_phase16_continuation_projected_source_manifest_v1','source':source,'source_id':sid,'parent_attempt_id':ps['attempt_id'],'continuation_attempt_id':attempt,'successful_original_ranges':[record],'evidence_origins':[origin],'inherited_ranges':[],'new_ranges':[record],'whole_source_sha256_verified':False,'whole_source_sha256':None,'available_ranges':[[0,32]],'available_original_bytes':32,'holes_are_original_bytes':False,'statistics_values_exported_or_used':False})
        session={'schema_version':'article2_phase16_continuation_capture_v1','status':'COMPLETE','attempt_id':attempt,'parent_attempt_id':ps['attempt_id'],'original_started_utc':ps['started_utc'],'started_utc':self.time(7205),'updated_utc':self.time(7207),'absolute_deadline_utc':self.time(14400),'continuation_plan_sha256':plan_sha,'original_collector_plan_canonical_sha256':a.digest(self.original['collector']),'parent_bindings_canonical_sha256':a.digest(evidence),'inherited_request_count':0,'new_request_count':113,'cumulative_request_count':113,'inherited_response_bytes':0,'new_response_bytes':3616,'cumulative_response_bytes':3616,'cumulative_wall_seconds_elapsed':7207,'effective_caps':{**self.original['collector']['caps'],'wall_seconds':14400},'automatic_retries':0,'original_attempt_retry_count':0,'cumulative_retry_count':0,'parent_positive_bodies_verified':True,'manual_reacquisition':None,'manual_reacquisition_count':0,'inherited_cache_or_full_object_reuses':[],'cache_or_full_object_reuses':[],'reserved_parent_failed_response_bytes':0,'reserved_new_failed_or_pending_response_bytes':0,'inherited_charged_response_bytes':0,'new_charged_response_bytes':3616,'cumulative_charged_response_bytes':3616}
        self.write(transport/'requests.json',records);self.write(transport/'session.json',session);self.write(transport/'accepted_range_evidence.json',{'schema_version':'article2_phase16_continuation_accepted_ranges_v1','ranges':origins})
        self.write(root/'runtime_source_paths.json',paths);self.write(root/'transport_sources.json',{'sources':manifests})
        result={'schema_version':'phase16_continuation_collection_result_v1','status':'COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT','plan_sha256':plan_sha,'original_plan_binding':self.original_binding,'continuation_amendment_sha256':amendment_sha,'continuation_number':1,'source_payload_previously_exposed':True,'transfer_decoding_performed':False,'detector_scoring_performed':False,'labels_used':False,'continuation_pipeline_sha256':a.file_sha(Path(a.__file__).with_name('continue_pipeline.py')),'continuation_collector_sha256':a.file_sha(Path(a.__file__).with_name('collector.py')),'prepared_with_original_pipeline_sha256':self.original['pipeline_sha256'],'transport_sources':113}
        self.write(root/'collection_result.json',result)
        args=SimpleNamespace(repo=self.repo,collection=root,amendment=self.amendment_path,expected_amendment_sha256=amendment_sha,expected_result_sha256=a.file_sha(root/'collection_result.json'),expected_transport_sources_sha256=a.file_sha(root/'transport_sources.json'),archives=None,original_manifest=None,expected_original_manifest_sha256=None,output=self.root/'audit.json',ledger_output=self.root/'ledger.json')
        got=a.audit(args);self.assertEqual(got['status'],'PASS_CONTINUATION_TRANSPORT_ORIGINAL_BYTES')
        self.assertEqual((got['source_count'],got['request_count'],got['retained_response_bytes']),(113,113,3616))
        self.assertFalse(got['selection_or_scientific_acceptance']);self.assertFalse(got['wire_bytes_measured'])
        ledger=a.read(args.ledger_output);self.assertEqual(ledger['original_requests'],[]);self.assertEqual(ledger['continuation_requests'],records)

if __name__=='__main__':unittest.main()
