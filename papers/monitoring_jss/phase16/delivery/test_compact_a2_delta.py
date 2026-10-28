"""Synthetic delta selection and archive tests; no live A2 capture access."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import pack_compact_a2_delta as p


def sha(raw):return hashlib.sha256(raw).hexdigest()


class Tests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory(prefix='phase16_delta_test_');self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def fixture(self):
        source={'table':'logs','day_utc':'2022-02-19','key':'synthetic-source','size_bytes':64,'etag_opaque':'"s"','url':'https://synthetic.invalid/source'}
        sid=p.digest(source);old='a'*64;new='b'*64;body=b'A'*16+b'B'*16+b'C'*16+b'D'*16
        inherited=[{'ordinal':i+1,'transport_ok':True,'source':source,'start':i*16,'length':16,'response_bytes':16,'response_sha256':sha(body[i*16:(i+1)*16])} for i in range(2)]
        inherited.append({'ordinal':3,'transport_ok':False,'source':source,'start':32,'length':16,'response_bytes':0})
        new_requests=[];wrappers=[]
        for r in inherited[:2]:
            blob={'path':f"storage/{sid}/blobs/{old}-{r['ordinal']:06d}-{r['response_sha256']}.bin",'size_bytes':16,'sha256':r['response_sha256']}
            wrappers.append({'origin_attempt_id':old,'origin_ordinal':r['ordinal'],'receipt':r,'blob':blob})
        for ordinal,start in [(4,32),(5,48)]:
            digest=sha(body[start:start+16]);blob={'path':f'storage/{sid}/blobs/{new}-{ordinal:06d}-{digest}.bin','size_bytes':16,'sha256':digest}
            r={'ordinal':ordinal,'transport_ok':True,'source':source,'start':start,'length':16,'response_bytes':16,'response_sha256':digest,'blob':blob};new_requests.append(r);wrappers.append({'origin_attempt_id':new,'origin_ordinal':ordinal,'receipt':r,'blob':blob})
        descriptor={'schema_version':'article2_phase16_compact_source_v1','storage_kind':'compact_descriptor','source':source,'source_id':sid,'logical_size_bytes':64,'attempt_id':new,'parent_attempt_id':old,'segments':[]}
        for w in wrappers:
            r=w['receipt'];descriptor['segments'].append({'start':r['start'],'length':r['length'],'blob_path':str(Path(w['blob']['path']).relative_to(Path('storage')/sid)),'blob_sha256':r['response_sha256'],'origin_attempt_id':w['origin_attempt_id'],'origin_ordinal':w['origin_ordinal'],'receipt_sha256':p.digest(r)})
        record={'member':f'attempt1/cache/{sid}/source.parquet','source_identity':source,'logical_bytes':64,'sha256_before':sha(body),'sha256_after':sha(body),'zip_roundtrip_sha256':sha(body)}
        index={'packs':[{'path':'a1.zip','sha256':'d'*64,'members':[record]}]}
        session={'inherited_request_count':3,'new_request_count':2,'parent_attempt_id':old,'attempt_id':new}
        locations={source['key']:{'storage_kind':'compact_descriptor','path':str(self.root/'capture'/'storage'/sid/'source_storage.json')}}
        return session,inherited,new_requests,wrappers,{source['key']:descriptor},locations,index,{},body
    def catalog(self,values=None):return p.recipe_catalog(*(values or self.fixture())[:8])
    def test_exact_delta_has_only_new_bodies_and_parent_recipes(self):
        result=self.catalog();self.assertEqual([x['origin_ordinal'] for x in result['inherited_recipes']],[1,2]);self.assertEqual([x['origin_ordinal'] for x in result['new_blob_entries']],[4,5]);self.assertEqual(result['new_body_bytes'],32)
        self.assertNotIn(3,[x['origin_ordinal'] for x in result['new_blob_entries']+result['inherited_recipes']])
    def test_missing_duplicate_and_pending_wrapper_rejected(self):
        for change in ('missing','duplicate','pending'):
            v=list(self.fixture());v[3]=copy.deepcopy(v[3])
            if change=='missing':v[3].pop()
            elif change=='duplicate':v[3][-1]=v[3][0]
            else:v[3][0]['origin_ordinal']=3
            with self.assertRaises((ValueError,KeyError)):self.catalog(v)
    def test_descriptor_hole_overlap_and_body_digest_tamper_rejected(self):
        for change in ('missing','overlap','digest'):
            v=list(self.fixture());v[4]=copy.deepcopy(v[4]);desc=next(iter(v[4].values()))
            if change=='missing':desc['segments'].pop()
            elif change=='overlap':desc['segments'][1]['start']=0
            else:desc['segments'][0]['blob_sha256']='e'*64
            with self.assertRaises(ValueError):self.catalog(v)
    def test_metadata_snapshot_excludes_parent_blobs_and_preserves_empty_jsonl(self):
        v=self.fixture();catalog=self.catalog(v);root=self.root/'capture';root.mkdir()
        for w in v[3]:
            path=root/w['blob']['path'];path.parent.mkdir(parents=True,exist_ok=True);r=w['receipt'];path.write_bytes(v[8][r['start']:r['start']+r['length']]);path.chmod(0o444)
        descriptor_path=Path(next(iter(v[5].values()))['path']);descriptor_path.write_text(json.dumps(next(iter(v[4].values()))))
        empty=root/'observations'/'empty.jsonl';empty.parent.mkdir();empty.touch()
        ready={'expected_artifacts':{str(empty):sha(b'')},'external':[]}
        entries,metadata,census=p.artifact_entries(root,catalog,ready)
        blobs=[x for x in entries if x['artifact_kind']=='accepted_new_response_blob'];self.assertEqual(len(blobs),2);self.assertTrue(all(x['origin_ordinal']>3 for x in blobs))
        self.assertIn('observations/empty.jsonl',metadata)
        out=self.root/'packs';out.mkdir();groups=p.group_entries(entries,1024*1024)
        packed=[p.z.pack_one(out,name,items,1024*1024) for name,items in groups]
        archived={m['member'] for pack in packed for m in pack['members']}
        self.assertTrue(all('attempt2/'+r['target_path'] not in archived for r in catalog['inherited_recipes']))
        self.assertIn('attempt2/observations/empty.jsonl',archived)
    def test_orphan_blob_and_oversized_metadata_fail_instead_of_skipping(self):
        root=self.root/'capture';root.mkdir();(root/'orphan.bin').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError,'orphan'):p.artifact_entries(root,{'all_blob_paths':set(),'new_blob_entries':[]},{'expected_artifacts':{},'external':[]})
        (root/'orphan.bin').unlink();(root/'large.json').write_bytes(b'x'*20)
        with self.assertRaisesRegex(ValueError,'size cap'):p.artifact_entries(root,{'all_blob_paths':set(),'new_blob_entries':[]},{'expected_artifacts':{},'external':[]},metadata_limit=10)
    def durable_fixture(self):
        entries=[{'file_name':f'a1_{i}.zip','bytes':100+i,'sha256':f'{i+1:064x}','library_file_id':f'libfile_{i}','file_id':f'file_{i}'} for i in range(43)]
        catalog={'schema_version':'article2_phase16_durable_a1_forensic_catalog_v1','status':'ALL_43_LIBRARY_SAVES_CONFIRMED','entries':entries}
        receipt={'results':[{**x,'status':'succeeded'} for x in entries]}
        a1={'status':'COMPLETE_FORENSIC_PRESERVATION_NOT_SOURCE_AUDIT','packs':[{'path':x['file_name'],'bytes':x['bytes'],'sha256':x['sha256']} for x in entries[:42]]}
        archives=[{'sha256':f'{i+101:064x}','bytes':1000,'library_file_id':f'libfile_original_{i}'} for i in range(9)]
        rows=[];expected={}
        for i in range(18):
            key=f'source{i}';h=f'{i+201:064x}';row={'source_key':key,'size_bytes':12,'etag_opaque':'"x"','expected_whole_object_sha256':h,'expected_archive_sha256':archives[i//2]['sha256'],'expected_original_member_name':f'member{i}.parquet'};rows.append(row);expected[key]={'size_bytes':12,'etag_opaque':'"x"','sha256':h}
        return [a1,catalog,receipt,archives,{'objects':rows},{'whole_object_reuse_expectations':expected}]
    def test_durable_origins_cover_exact43_saves_and18_original_members(self):
        normalized=p.dependencies(*self.durable_fixture());self.assertEqual(len(normalized['a1_durable_objects']),43);self.assertEqual(len(normalized['whole_object_origins']),18)
        self.assertTrue(all('url' not in x for x in normalized['a1_durable_objects']))
    def test_unconfirmed_library_save_or_wrong_original_digest_rejected(self):
        values=self.durable_fixture();values[2]['results'][0]['status']='failed'
        with self.assertRaisesRegex(ValueError,'confirmation'):p.dependencies(*values)
        values=self.durable_fixture();values[4]['objects'][0]['expected_whole_object_sha256']='f'*64
        with self.assertRaisesRegex(ValueError,'whole original binding'):p.dependencies(*values)
    def test_unaccepted_gate_stops_before_capture_body_inventory(self):
        args=SimpleNamespace(collection=self.root/'live_capture',output=self.root/'packs',proofs=self.root/'proofs.json',expected_proofs_sha256='a'*64)
        with patch.object(p,'load_ready',side_effect=ValueError('not final')),patch.object(p,'prepare_catalog') as inventory:
            with self.assertRaisesRegex(ValueError,'not final'):p.pack_delta(args)
            inventory.assert_not_called()
        self.assertFalse(args.output.exists())


if __name__=='__main__':unittest.main()
