"""New offline synthetic faults for the independent original-byte auditor."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import zipfile

TARGET=Path(__file__).with_name('transport_receipt_audit.py')
spec=importlib.util.spec_from_file_location('independent_receipt_auditor',TARGET)
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

class ReceiptFaults(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='phase16_receipt_audit_synthetic_')
        self.root=Path(self.temp.name);self.path=self.root/'source.parquet'
        self.raw=b'PAR1'+b'x'*16+b'fake'+(4).to_bytes(4,'little')+b'PAR1';self.path.write_bytes(self.raw)
        key='v1.0/eth/blocks/date=2022-02-19/fixture.parquet'
        self.source={'table':'blocks','day_utc':'2022-02-19','key':key,'size_bytes':32,'etag_opaque':'"synthetic"','url':a.ENDPOINT+key}
        self.start=datetime.now(timezone.utc);stamp=self.start.isoformat()
        self.caps={'max_range_bytes':32,'wall_seconds':60,'max_footer_bytes':20}
        self.receipt={'ordinal':1,'source':self.source,'start':0,'length':32,'transport_ok':True,'method':'GET','http_status':206,'response_url':self.source['url'],'etag':self.source['etag_opaque'],'content_range':'bytes 0-31/32','content_length':'32','content_encoding':None,'request_headers':{'Range':'bytes=0-31','If-Match':self.source['etag_opaque'],'Accept-Encoding':'identity'},'response_bytes':32,'stored_file_name':'source.parquet','stored_offset':0,'invalid_header_body_read':False,'started_utc':stamp,'completed_utc':stamp,'response_sha256':hashlib.sha256(self.raw).hexdigest()}
    def tearDown(self):self.temp.cleanup()
    def test_exact_retained_range_is_accepted(self):
        self.assertEqual(a.validate_record(self.receipt,self.source,self.path,self.caps,1,self.start),[0,32])
    def test_changed_retained_byte_is_rejected(self):
        self.path.write_bytes(b'Q'+self.raw[1:])
        with self.assertRaisesRegex(ValueError,'range hash'):
            a.validate_record(self.receipt,self.source,self.path,self.caps,1,self.start)
    def test_wrong_response_identity_rejected_before_hash(self):
        for key,value in (('response_url','https://example.invalid/'),('etag','"other"'),('content_range','bytes 1-32/32'),('content_encoding','gzip'),('stored_offset',1)):
            bad=deepcopy(self.receipt);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                a.validate_record(bad,self.source,self.path,self.caps,1,self.start)
    def test_footer_hole_rejected_even_when_sparse_bytes_look_valid(self):
        with self.assertRaisesRegex(ValueError,'sparse holes'):
            a.footer_evidence(self.path,self.source,[[0,4],[24,32]],self.caps)
        got=a.footer_evidence(self.path,self.source,[[0,4],[20,32]],self.caps)
        self.assertEqual((got['footer_start'],got['footer_length']),(20,4))
    def archive_fixture(self):
        receipt={'acquired_utc':self.start.isoformat(),'bytes':32,'hash_scope':'whole source object','sha256':hashlib.sha256(self.raw).hexdigest(),'source':{'url':self.source['url'],'etag':self.source['etag_opaque'],'size':32,'version_id':None}}
        old={'day_utc':self.source['day_utc'],'source_objects':{'blocks':receipt}}
        p=self.root/'fixture.zip'
        with zipfile.ZipFile(p,'w') as z:
            z.writestr('day_manifest.json',json.dumps(old));z.writestr('headers.parquet',self.raw)
        old['archive']={'sha256':a.file_sha(p),'bytes':p.stat().st_size}
        expected={'source_key':self.source['key'],'source_url':self.source['url'],'size_bytes':32,'etag_opaque':self.source['etag_opaque'],'expected_whole_object_sha256':receipt['sha256'],'expected_archive_sha256':old['archive']['sha256'],'expected_original_member_name':'headers.parquet'}
        return p,old,expected
    def test_original_archive_member_and_receipt_are_bound(self):
        archive,old,expected=self.archive_fixture()
        got=a.audit_reuse(self.source,self.path,expected,archive,old,{})
        self.assertEqual(got['whole_source_sha256'],hashlib.sha256(self.raw).hexdigest())
    def test_changed_original_receipt_cannot_pass_with_correct_payload(self):
        archive,old,expected=self.archive_fixture();old['source_objects']['blocks']['acquired_utc']='2026-01-01T00:00:00+00:00'
        with self.assertRaisesRegex(ValueError,'original acquisition receipt'):
            a.audit_reuse(self.source,self.path,expected,archive,old,{})
    def test_wrong_extracted_whole_object_rejected_against_original_zip(self):
        archive,old,expected=self.archive_fixture();self.path.write_bytes(self.raw[:-1]+b'X')
        with self.assertRaisesRegex(ValueError,'extracted bytes'):
            a.audit_reuse(self.source,self.path,expected,archive,old,{})
    def test_complete_audit_binds_all_evidence_without_claiming_scientific_acceptance(self):
        repo=self.root/'repo';root=self.root/'capture';repo.mkdir();root.mkdir()
        def write(path,value):
            path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value));return a.file_sha(path)
        code=repo/'papers/monitoring_jss/phase16'
        ch=write(code/'collector/range_collector.py',{'synthetic_code':True})
        ph=write(code/'pipeline/streaming_pipeline.py',{'synthetic_code':True})
        ih=write(repo/'inventory.json',{'objects':[self.source]})
        cplan={'caps':{**self.caps,'requests':1,'total_response_bytes':32,'max_source_bytes':32,'retries':0,'concurrency':1}}
        plan={'collector_sha256':ch,'pipeline_sha256':ph,'source_union':{'path':'inventory.json','sha256':ih},'collector':cplan}
        planpath=repo/'plan.json';plan_sha=write(planpath,plan);write(root/'frozen_plan.json',plan)
        actual=root/'cache'/a.digest(self.source)/'source.parquet';actual.parent.mkdir(parents=True);actual.write_bytes(self.raw)
        write(root/'runtime_source_paths.json',{self.source['key']:str(actual)})
        manifest={'source':self.source,'source_id':a.digest(self.source),'whole_source_sha256_verified':False,'whole_source_sha256':None,'successful_original_ranges':[self.receipt],'available_ranges':[[0,32]],'available_original_bytes':32,'holes_are_original_bytes':False,'statistics_values_exported_or_used':False}
        mh=write(root/'transport_sources.json',{'sources':[manifest]})
        result={'status':'COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT','plan_sha256':plan_sha,'transport_sources':1,'transfer_decoding_performed':False,'detector_scoring_performed':False,'labels_used':False}
        rh=write(root/'collection_result.json',result);transport=root/'transport';stamp=self.start.isoformat()
        attempt=a.digest({'plan':a.digest(cplan),'started_utc':stamp})
        session={'status':'COMPLETE','plan_canonical_sha256':a.digest(cplan),'attempt_id':attempt,'started_utc':stamp,'retries':0,'request_count':1,'wall_seconds_elapsed':0.01,'retained_response_bytes':32,'cache_or_full_object_reuses':[]}
        write(transport/'plan.json',cplan);write(transport/'session.json',session);write(transport/'requests.json',[self.receipt])
        write(actual.parent/'ranges.json',{'source':self.source,'attempt_id':attempt,'ranges':[self.receipt]})
        args=SimpleNamespace(repo=repo,collection=root,plan=planpath,expected_plan_sha256=plan_sha,expected_result_sha256=rh,expected_transport_sources_sha256=mh,reuse_expectations=None,expected_reuse_expectations_sha256=None,archives=None,original_manifest=None,expected_original_manifest_sha256=None,output=self.root/'audit.json')
        got=a.audit(args)
        self.assertEqual(got['status'],'PASS_TRANSPORT_ORIGINAL_BYTES')
        self.assertFalse(got['selection_or_scientific_acceptance']);self.assertEqual(got['parquet_rows_decoded'],0)
        verified=got['verified_sources'][0];self.assertEqual(verified['available_ranges'],[[0,32]])
        self.assertIsNone(verified['whole_source_sha256']);self.assertFalse(verified['whole_source_sha256_verified'])
        self.assertEqual(verified['path'],str(actual.resolve()))

if __name__=='__main__':unittest.main()
