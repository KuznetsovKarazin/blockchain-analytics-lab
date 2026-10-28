"""Focused synthetic delivery tests; never opens a real capture or network."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from pack_range_capture import ENDPOINT, canonical, digest, load, pack, put, sha
from restore_range_capture import restore


class RangePackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.repo = self.root/'repo'; self.collection = self.root/'collection'
        self.repo.mkdir(); self.collection.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def fixture(self, failed=False, reuse=False):
        sources, requests, paths, manifests = [], [], {}, []
        plan = {'schema_version': 'article2_phase16_streaming_pipeline_plan_v1',
                'collector': {'caps': {'requests': 5000, 'total_response_bytes': 17179869184,
                                      'max_range_bytes': 268435456}}, 'whole_object_reuse_expectations': {}}
        session = {'schema_version': 'article2_phase16_range_capture_v1', 'status': 'FAILED' if failed else 'COMPLETE',
                   'started_utc': '2026-10-28T00:00:00+00:00', 'cache_or_full_object_reuses': [],
                   'plan_canonical_sha256': digest(plan['collector'])}
        session['attempt_id'] = digest({'plan': digest(plan['collector']), 'started_utc': session['started_utc']})
        for day in ('2022-02-19','2022-02-20'):
            key = f'v1.0/eth/logs/date={day}/part-00000.parquet'
            source = {'table':'logs','day_utc':day,'key':key,'url':ENDPOINT+key,'size_bytes':1048576,'etag_opaque':'"etag"'}
            sources.append(source); path = self.collection/(day+'.parquet')
            with path.open('wb') as f: f.truncate(source['size_bytes'])
            paths[key] = str(path); records = []
            for start, length in ((0,4096),(8192,4096)):
                ordinal = len(requests)+1; partial = failed and ordinal == 4
                payload = bytes([ordinal])* (300 if partial else length)
                with path.open('r+b') as f: f.seek(start); f.write(payload)
                r = {'ordinal':ordinal,'source':source,'kind':'synthetic','method':'GET',
                     'request_headers':{'Range':f'bytes={start}-{start+length-1}','If-Match':'"etag"','Accept-Encoding':'identity'},
                     'start':start,'length':length,'stored_offset':start,'stored_file_name':path.name,
                     'transport_ok':not partial,'response_bytes':len(payload),'response_sha256':hashlib.sha256(payload).hexdigest(),
                     'http_status':206,'response_url':source['url'],'etag':'"etag"','content_encoding':None,
                     'content_range':f'bytes {start}-{start+length-1}/{source["size_bytes"]}','content_length':str(length)}
                if partial:r['failure']='SyntheticFailure: truncated'
                requests.append(r); records.append(r)
            manifests.append({'source':source,'source_id':digest(source),'successful_original_ranges':[r for r in records if r['transport_ok']],
                              'whole_source_sha256_verified':False,'whole_source_sha256':None})
        if reuse:
            source = {'table':'blocks','day_utc':'2022-02-19','key':'v1.0/eth/blocks/date=2022-02-19/old.parquet',
                      'size_bytes':32,'etag_opaque':'"old"'}; source['url'] = ENDPOINT+source['key']
            sources.append(source); path = self.root/'original-old.parquet'; path.write_bytes(b'x'*32); paths[source['key']] = str(path)
            receipt = {'source_key':source['key'],'sha256':sha(path),'size_bytes':32,'etag_opaque':'"old"',
                       'expected_archive_sha256':'a'*64,'expected_original_member_name':'headers.parquet'}
            put(self.repo/'old_receipt.json',receipt)
            plan['whole_object_reuse_expectations'][source['key']] = {'sha256':sha(path),'size_bytes':32,'etag_opaque':'"old"',
                 'acquisition_receipt':{'path':'old_receipt.json','sha256':sha(self.repo/'old_receipt.json')}}
            session['cache_or_full_object_reuses'].append({'source_id':digest(source),'kind':'verified_whole_object','bytes':32,'sha256':sha(path)})
            manifests.append({'source':source,'source_id':digest(source),'successful_original_ranges':[],
                              'whole_source_sha256_verified':True,'whole_source_sha256':sha(path)})
        put(self.repo/'inventory.json',{'objects':sources})
        plan['source_union'] = {'path':'inventory.json','sha256':sha(self.repo/'inventory.json')}
        session['request_count'] = len(requests); session['retained_response_bytes'] = sum(r['response_bytes'] for r in requests)
        put(self.collection/'frozen_plan.json',plan); put(self.collection/'transport/plan.json',plan['collector'])
        put(self.collection/'transport/session.json',session); put(self.collection/'transport/requests.json',requests)
        put(self.collection/'runtime_source_paths.json',paths); put(self.collection/'transport_sources.json',{'sources':manifests})
        result = {'status':'FAILED_NOT_ACCEPTED'} if failed else {'status':'COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT',
                  'plan_sha256':sha(self.collection/'frozen_plan.json'),'transport_sources':len(sources)}
        put(self.collection/('failure.json' if failed else 'collection_result.json'),result)
        self.requests, self.paths, self.sources = requests, paths, sources

    def package(self, name='pack', failed=False, **kwargs):
        return pack(self.collection,self.repo,self.root/name,sha(self.collection/'frozen_plan.json'),
                    sha(self.collection/('failure.json' if failed else 'collection_result.json')),
                    None if failed else sha(self.collection/'transport_sources.json'),
                    mode='failed' if failed else 'complete',max_archive_bytes=8000,**kwargs)

    def test_roundtrip_offsets_holes_receipts_and_archive_caps(self):
        self.fixture(); index=self.package(); self.assertEqual(4,len(index['archives']))
        self.assertEqual(16384,index['stored_response_bytes'])
        self.assertTrue(all(x['size_bytes']<=8000 for x in index['archives']))
        result=restore(self.root/'pack',self.root/'restored',sha(self.root/'pack/index.json'))
        self.assertEqual('RESTORED_RECORDED_SOURCE_BYTES',result['status'])
        paths=load(self.root/'restored/runtime_source_paths.json')
        for r in self.requests:
            with Path(paths[r['source']['key']]).open('rb') as f:
                f.seek(r['start']);self.assertEqual(r['response_sha256'],hashlib.sha256(f.read(r['length'])).hexdigest())
                f.seek(5000);self.assertEqual(b'\0'*100,f.read(100))
        self.assertEqual((self.collection/'transport/requests.json').read_bytes(),(self.root/'restored/transport/requests.json').read_bytes())

    def test_deterministic_archives_and_index_exclude_private_paths(self):
        self.fixture(); self.package(); self.package('pack2')
        self.assertEqual(sha(self.root/'pack/index.json'),sha(self.root/'pack2/index.json'))
        for p in (self.root/'pack').rglob('*'):
            if p.is_file() and p.suffix=='.json':self.assertNotIn(str(self.root).encode(),p.read_bytes())

    def test_partial_body_is_forensic_and_excluded_from_verified_cache(self):
        self.fixture(failed=True);index=self.package(failed=True)
        self.assertEqual(300,index['unaccepted_response_bytes']);self.assertEqual(12288,index['accepted_response_bytes'])
        result=restore(self.root/'pack',self.root/'restored',sha(self.root/'pack/index.json'))
        self.assertEqual('RESTORED_FAILED_CAPTURE_FORENSICS_NOT_ACCEPTED',result['status'])
        cached=load(self.root/'restored/cache'/digest(self.sources[1])/'ranges.json')
        self.assertEqual([3],[r['ordinal'] for r in cached['ranges']])
        self.assertEqual('FAILED',load(self.root/'restored/transport/session.json')['status'])

    def test_failed_first_open_recovers_canonical_cache_paths_without_runtime_map(self):
        self.fixture(failed=True)
        for source in self.sources:
            target=self.collection/'cache'/digest(source)/'source.parquet';target.parent.mkdir(parents=True)
            Path(self.paths[source['key']]).rename(target)
        (self.collection/'runtime_source_paths.json').unlink()
        index=self.package(failed=True)
        self.assertIsNone(index['original_sourcepaths_sha256'])
        result=restore(self.root/'pack',self.root/'restored',sha(self.root/'pack/index.json'))
        self.assertEqual(300,result['unaccepted_response_bytes'])

    def test_reused_objects_are_provenance_only_and_optional_verified_attachment(self):
        self.fixture(reuse=True); index=self.package();self.assertEqual(16384,index['stored_response_bytes'])
        reference=next(s for s in index['sources'] if s['reuse_reference']);key=reference['source']['key']
        result=restore(self.root/'pack',self.root/'restored',sha(self.root/'pack/index.json'))
        self.assertEqual([key],result['unresolved_whole_object_sources'])
        source=reference['source']; put(self.root/'reuse.json',{key:{'path':self.paths[key],'source_key':key,
            'size_bytes':source['size_bytes'],'etag_opaque':source['etag_opaque'],'sha256':sha(self.paths[key])}})
        result=restore(self.root/'pack',self.root/'restored2',sha(self.root/'pack/index.json'),self.root/'reuse.json')
        self.assertEqual([],result['unresolved_whole_object_sources'])

    def test_recorded_bytes_tamper_rejected(self):
        self.fixture();p=Path(next(iter(self.paths.values())))
        with p.open('r+b') as f:f.write(b'z')
        with self.assertRaisesRegex(ValueError,'hash differs'):self.package()
        self.assertFalse((self.root/'pack/index.json').exists())

    def test_archive_tamper_rejected_before_restore_files(self):
        self.fixture();index=self.package();p=self.root/'pack'/index['archives'][0]['file']
        with p.open('r+b') as f:f.seek(80);f.write(b'bad')
        with self.assertRaisesRegex(ValueError,'archive bytes differ'):
            restore(self.root/'pack',self.root/'restored',sha(self.root/'pack/index.json'))
        self.assertFalse((self.root/'restored').exists())

    def test_complete_rejects_partial_request(self):
        self.fixture();requests=load(self.collection/'transport/requests.json');requests[0]['transport_ok']=False
        put(self.collection/'transport/requests.json',requests)
        with self.assertRaisesRegex(ValueError,'non-successful'):self.package()

    def test_expected_plan_hash_required(self):
        self.fixture()
        with self.assertRaisesRegex(ValueError,'bound metadata hash'):
            pack(self.collection,self.repo,self.root/'pack','0'*64,sha(self.collection/'collection_result.json'),sha(self.collection/'transport_sources.json'))

    def test_accepted_input_plan_and_runtime_serialization_hashes_stay_distinct(self):
        self.fixture();accepted=self.root/'accepted.json'
        accepted.write_text(json.dumps(load(self.collection/'frozen_plan.json'),indent=4)+'\n')
        result=load(self.collection/'collection_result.json');result['plan_sha256']=sha(accepted);put(self.collection/'collection_result.json',result)
        self.assertNotEqual(sha(accepted),sha(self.collection/'frozen_plan.json'))
        with self.assertRaisesRegex(ValueError,'supply exact --accepted-plan'):self.package('rejected')
        index=self.package(accepted_plan=accepted)
        self.assertEqual(sha(accepted),index['accepted_input_plan_sha256'])
        self.assertEqual(sha(self.collection/'frozen_plan.json'),index['runtime_frozen_plan_sha256'])
        restore(self.root/'pack',self.root/'restored',sha(self.root/'pack/index.json'))
        self.assertEqual(accepted.read_bytes(),(self.root/'restored/metadata/accepted_plan.json').read_bytes())

    def test_accepted_input_plan_semantic_change_is_rejected(self):
        self.fixture();accepted=self.root/'accepted.json';value=load(self.collection/'frozen_plan.json');value['changed']=True;put(accepted,value)
        result=load(self.collection/'collection_result.json');result['plan_sha256']=sha(accepted);put(self.collection/'collection_result.json',result)
        with self.assertRaisesRegex(ValueError,'runtime plan values differ'):self.package(accepted_plan=accepted)

    def test_embedded_private_path_in_failure_is_rejected_without_redaction(self):
        self.fixture(failed=True);rs=load(self.collection/'transport/requests.json')
        rs[-1]['failure']='FileNotFoundError: /workspace/private/source.parquet'
        put(self.collection/'transport/requests.json',rs)
        with self.assertRaisesRegex(ValueError,'private absolute path'):self.package(failed=True)
        self.assertFalse((self.root/'pack').exists())

    def test_single_response_archive_overflow_fails_without_output(self):
        self.fixture()
        with self.assertRaisesRegex(ValueError,'single response'):
            pack(self.collection,self.repo,self.root/'pack',sha(self.collection/'frozen_plan.json'),
                 sha(self.collection/'collection_result.json'),sha(self.collection/'transport_sources.json'),max_archive_bytes=100)
        self.assertFalse((self.root/'pack').exists())

    def test_overlapping_request_ranges_rejected(self):
        self.fixture();rs=load(self.collection/'transport/requests.json');r=rs[1];r['start']=0;r['stored_offset']=0
        r['request_headers']['Range']='bytes=0-4095';r['content_range']='bytes 0-4095/1048576';put(self.collection/'transport/requests.json',rs)
        with self.assertRaisesRegex(ValueError,'overlapping'):self.package()


if __name__=='__main__':unittest.main()
