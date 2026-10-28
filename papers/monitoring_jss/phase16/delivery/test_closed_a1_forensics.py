"""Invented sparse files only; no historical source rows."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import pack_closed_a1_forensics as p


class Tests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory(prefix='phase16_forensic_pack_test_');self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def fixture(self):
        capture=self.root/'capture';(capture/'transport').mkdir(parents=True)
        for i,table in enumerate(('logs','transactions','blocks')):
            folder=capture/'cache'/('source'+str(i));folder.mkdir(parents=True);path=folder/'source.parquet'
            with path.open('wb') as f:f.write(b'PAR1'+bytes([i+1])*100);f.seek(2*1024*1024-8);f.write(b'END!PAR1')
            identity={'table':table,'day_utc':'2022-02-19','key':'synthetic/'+table,'size_bytes':path.stat().st_size,'etag_opaque':'"synthetic"','url':'https://synthetic.invalid/'+table}
            p.write_json(folder/'ranges.json',{'source':identity,'ranges':[],'synthetic':True})
        p.write_json(capture/'transport/session.json',{'status':'OPEN_REQUEST_PENDING'})
        p.write_json(capture/'transport/requests.json',[{'ordinal':1,'transport_ok':True,'response_bytes':104,'length':104,'completed_utc':'synthetic'},{'ordinal':2,'transport_ok':False,'response_bytes':0,'length':8192}])
        (capture/'transport/requests.json.pending').touch()
        external=self.root/'external_closure.json';p.write_json(external,{'synthetic_external_closure':True})
        return capture,external
    def test_roundtrip_preserves_sparse_images_metadata_pending_and_external(self):
        capture,external=self.fixture();session_before=(capture/'transport/session.json').read_bytes();output=self.root/'packs'
        with contextlib.redirect_stdout(io.StringIO()):index=p.pack(capture,output,[external],maximum=8*1024*1024,expected_counts=(3,5))
        self.assertEqual(index['canonical_cache_artifact_count'],3);self.assertEqual(index['canonical_json_count'],5);self.assertEqual(index['external_forensic_file_count'],1)
        self.assertEqual(index['capture_facts']['pending_received_body_length'],'UNKNOWN_NOT_INFERRED_AS_ZERO');self.assertFalse(index['pending_bytes_accepted'])
        images=[r for pack in index['packs'] for r in pack['members'] if 'table' in r]
        self.assertTrue(all(x['sha256_before']==x['sha256_after']==x['zip_roundtrip_sha256'] and x['whole_original_source_sha256'] is None for x in images))
        target=self.root/'restored';p.restore(output/'forensic_archive_index.json',p.file_sha(output/'forensic_archive_index.json'),target)
        for original in capture.rglob('*'):
            if original.is_file():self.assertEqual(p.file_sha(original),p.file_sha(target/'attempt1'/original.relative_to(capture)))
        for row in images:
            restored=target/row['member'];self.assertLess(restored.stat().st_blocks*512,restored.stat().st_size//4)
        self.assertEqual((capture/'transport/session.json').read_bytes(),session_before);self.assertFalse((capture/'failure.json').exists())
        self.assertTrue(all(x['bytes']<=8*1024*1024 for x in index['packs']))
    def test_changed_input_rejected_before_pack(self):
        capture,external=self.fixture();entries=p.inventory(capture,[external],expected_counts=(3,5));external.write_bytes(b'changed');out=self.root/'packs';out.mkdir()
        chosen=[x for x in entries if x['path']==external]
        with self.assertRaisesRegex(ValueError,'changed before pack'):p.pack_one(out,'changed.zip',chosen)
    def test_zip_hard_byte_cap_rejects_incompressible_input(self):
        source=self.root/'random.bin';source.write_bytes(os.urandom(32768));out=self.root/'packs';out.mkdir()
        item={'path':source,'member':'external/random.bin','before_stat':p.snapshot(source),'artifact_kind':'synthetic'}
        with self.assertRaisesRegex(ValueError,'hard pack cap'):p.pack_one(out,'too-large.zip',[item],maximum=1024)
        self.assertFalse((out/'too-large.zip.receipt.json').exists())
    def test_corrupt_zip_rejected_before_restore(self):
        capture,external=self.fixture();out=self.root/'packs'
        with contextlib.redirect_stdout(io.StringIO()):index=p.pack(capture,out,[external],maximum=8*1024*1024,expected_counts=(3,5))
        archive=out/index['packs'][0]['path']
        with archive.open('r+b') as f:f.seek(50);f.write(b'CORRUPTION')
        with self.assertRaisesRegex(ValueError,'archive digest differs'):p.restore(out/'forensic_archive_index.json',p.file_sha(out/'forensic_archive_index.json'),self.root/'bad_restore')
    def test_path_traversal_and_absolute_zip_members_rejected(self):
        for member in ('../escape','/absolute','safe/../../escape','C:/drive','bad\\name'):
            with self.assertRaises(ValueError):p.safe_member(member)
    def test_pending_body_length_never_inferred_from_zero_record(self):
        capture,_=self.fixture();facts=p.capture_facts(capture);self.assertEqual(facts['pending_declared_range_bytes'],8192);self.assertEqual(facts['pending_received_body_length'],'UNKNOWN_NOT_INFERRED_AS_ZERO')
        p.write_json(capture/'failure.json',{'synthetic_terminal_record':True})
        with self.assertRaisesRegex(ValueError,'terminal artifact appeared'):p.capture_facts(capture)


if __name__=='__main__':unittest.main()
