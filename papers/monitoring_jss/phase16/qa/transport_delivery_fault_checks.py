"""Independent tiny original-range packaging faults; no real capture reads."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'delivery'))
import pack_range_capture as p
import restore_range_capture as r

class DeliveryFaults(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='phase16_delivery_independent_');self.root=Path(self.temp.name)
        self.repo=self.root/'repo';self.capture=self.root/'capture';self.repo.mkdir();self.capture.mkdir()
        key='v1.0/eth/logs/date=2022-02-19/fixture.parquet'
        self.source={'table':'logs','day_utc':'2022-02-19','key':key,'size_bytes':64,'etag_opaque':'"synthetic"','url':p.ENDPOINT+key}
        self.original=self.capture/'cache'/p.digest(self.source)/'source.parquet';self.original.parent.mkdir(parents=True)
        self.original.write_bytes(bytes(range(64)));p.put(self.capture/'runtime_source_paths.json',{key:str(self.original)})
        inventory=self.repo/'inventory.json';p.put(inventory,{'objects':[self.source]})
        caps={'requests':3,'total_response_bytes':20,'max_range_bytes':8,'retries':0,'concurrency':1}
        self.plan={'schema_version':'article2_phase16_streaming_pipeline_plan_v1','collector':{'caps':caps},'source_union':{'path':'inventory.json','sha256':p.sha(inventory)},'whole_object_reuse_expectations':{}}
        p.put(self.capture/'frozen_plan.json',self.plan);self.plan_sha=p.sha(self.capture/'frozen_plan.json')
        result={'status':'COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT','plan_sha256':self.plan_sha,'transport_sources':1}
        p.put(self.capture/'collection_result.json',result);self.result_sha=p.sha(self.capture/'collection_result.json')
        self.records=[];stamp=datetime.now(timezone.utc).isoformat()
        for ordinal,(start,length) in enumerate(((0,4),(24,8),(56,8)),1):
            self.records.append({'ordinal':ordinal,'source':self.source,'kind':'synthetic','method':'GET','request_headers':{'Range':f'bytes={start}-{start+length-1}','If-Match':self.source['etag_opaque'],'Accept-Encoding':'identity'},'start':start,'length':length,'started_utc':stamp,'completed_utc':stamp,'transport_ok':True,'response_bytes':length,'response_sha256':hashlib.sha256(bytes(range(start,start+length))).hexdigest(),'stored_file_name':'source.parquet','stored_offset':start,'http_status':206,'response_url':self.source['url'],'etag':self.source['etag_opaque'],'content_range':f'bytes {start}-{start+length-1}/64','content_length':str(length),'content_encoding':None,'invalid_header_body_read':False})
        self.session={'schema_version':'article2_phase16_range_capture_v1','status':'COMPLETE','attempt_id':p.digest({'plan':p.digest(self.plan['collector']),'started_utc':stamp}),'started_utc':stamp,'plan_canonical_sha256':p.digest(self.plan['collector']),'request_count':3,'retained_response_bytes':20,'cache_or_full_object_reuses':[],'retries':0}
        p.put(self.capture/'transport/session.json',self.session);p.put(self.capture/'transport/requests.json',self.records);p.put(self.capture/'transport/plan.json',self.plan['collector'])
        manifest={'source':self.source,'source_id':p.digest(self.source),'successful_original_ranges':self.records,'whole_source_sha256_verified':False,'whole_source_sha256':None}
        p.put(self.capture/'transport_sources.json',{'sources':[manifest]});self.manifest_sha=p.sha(self.capture/'transport_sources.json')
    def tearDown(self):self.temp.cleanup()
    def pack(self):
        return p.pack(self.capture,self.repo,self.root/'pack',self.plan_sha,self.result_sha,self.manifest_sha,max_archive_bytes=2000)
    def test_split_zip_roundtrip_retains_only_recorded_offsets_and_original_receipts(self):
        index=self.pack();self.assertGreaterEqual(len(index['archives']),2)
        payload=0
        for archive in index['archives']:
            path=self.root/'pack'/archive['file'];self.assertLessEqual(path.stat().st_size,2000)
            with zipfile.ZipFile(path) as z:
                for info in z.infolist():
                    self.assertEqual(info.compress_type,zipfile.ZIP_STORED)
                    if info.filename!='manifest.json':payload+=info.file_size
        self.assertEqual(payload,20);self.assertFalse(index['sparse_holes_packaged'])
        result=r.restore(self.root/'pack',self.root/'restored',p.sha(self.root/'pack/index.json'))
        self.assertEqual(result['status'],'RESTORED_RECORDED_SOURCE_BYTES');self.assertFalse(result['scientific_acceptance'])
        path=self.root/'restored/cache'/p.digest(self.source)/'source.parquet';expected=bytearray(64)
        for record in self.records:
            start=record['start'];end=start+record['length'];expected[start:end]=bytes(range(start,end))
        self.assertEqual(path.read_bytes(),bytes(expected))
        self.assertEqual(json.loads((self.root/'restored/transport/requests.json').read_bytes()),self.records)
        cache=json.loads(path.with_name('ranges.json').read_bytes());self.assertEqual(cache['ranges'],self.records)
        self.assertEqual(cache['attempt_id'],self.session['attempt_id'])
    def test_changed_original_response_never_produces_complete_index(self):
        with self.original.open('r+b') as handle:handle.seek(24);handle.write(b'X')
        with self.assertRaisesRegex(ValueError,'hash differs'):self.pack()
        self.assertFalse((self.root/'pack/index.json').exists())
    def test_changed_archive_is_rejected_before_restore_output_creation(self):
        index=self.pack();path=self.root/'pack'/index['archives'][0]['file']
        with path.open('r+b') as handle:handle.seek(50);old=handle.read(1);handle.seek(50);handle.write(bytes([old[0]^1]))
        with self.assertRaisesRegex(ValueError,'archive bytes differ'):
            r.restore(self.root/'pack',self.root/'restored',p.sha(self.root/'pack/index.json'))
        self.assertFalse((self.root/'restored').exists())
    def test_embedded_private_failure_path_is_rejected_without_breaking_public_url(self):
        p.portable({'source_url':self.source['url']})
        with self.assertRaisesRegex(ValueError,'private|absolute|path'):
            p.portable({'failure':'FileNotFoundError: /workspace/private/source.parquet'})
    def test_full_length_unaccepted_body_remains_forensic_and_outside_accepted_cache(self):
        self.records[-1]['transport_ok']=False;self.records[-1]['failure']='ValueError: wall cap after response close'
        self.session['status']='FAILED';p.put(self.capture/'transport/session.json',self.session)
        p.put(self.capture/'transport/requests.json',self.records);p.put(self.capture/'failure.json',{'status':'FAILED_NOT_ACCEPTED'})
        index=p.pack(self.capture,self.repo,self.root/'pack',self.plan_sha,p.sha(self.capture/'failure.json'),mode='failed',max_archive_bytes=2000)
        self.assertEqual(index['status'],'FAILED_CAPTURE_FORENSIC_PACK_NOT_ACCEPTED')
        self.assertEqual((index['accepted_response_bytes'],index['unaccepted_response_bytes']),(12,8))
        result=r.restore(self.root/'pack',self.root/'restored',p.sha(self.root/'pack/index.json'))
        self.assertEqual(result['status'],'RESTORED_FAILED_CAPTURE_FORENSICS_NOT_ACCEPTED')
        original=self.root/'restored/cache'/p.digest(self.source)/'source.parquet'
        self.assertEqual(original.read_bytes()[56:64],bytes(range(56,64)))
        cached=json.loads(original.with_name('ranges.json').read_bytes())
        self.assertEqual(cached['ranges'],self.records[:2]);self.assertFalse(result['scientific_acceptance'])

if __name__=='__main__':unittest.main()
