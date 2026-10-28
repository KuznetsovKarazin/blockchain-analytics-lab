"""Focused invented-byte checks; no acquired source or captured row is read."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("independent_compact_reader",
    Path(__file__).with_name("independent_compact_reader.py"))
reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)


class Checks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="compact_reader_invented_")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def blobs(self, ranges):
        result = []
        for index, (start, value) in enumerate(ranges):
            path = self.root / str(index); path.write_bytes(value)
            result.append({"start": start, "length": len(value), "path": str(path),
                           "sha256": hashlib.sha256(value).hexdigest()})
        return result

    def test_exact_adjacent_read_seek_readinto_and_eof(self):
        file = reader.IndependentIntervalFile(12, self.blobs([(0,b"abc"),(3,b"def"),(9,b"xyz")]))
        self.assertEqual(file.read(6), b"abcdef")
        self.assertEqual(file.seek(-3,2),9)
        out=bytearray(8); self.assertEqual(file.readinto(out),3); self.assertEqual(out[:3],b"xyz")
        self.assertEqual(file.read(),b"")
        file.close()
        with self.assertRaises(ValueError):file.read(1)

    def test_hole_request_rejects_without_partial_read_or_position_change(self):
        file=reader.IndependentIntervalFile(12,self.blobs([(0,b"abc"),(8,b"wxyz")]))
        with self.assertRaisesRegex(ValueError,"unacquired interval"):file.read(9)
        self.assertEqual(file.tell(),0);self.assertEqual(file.read_events,[])
        with self.assertRaisesRegex(ValueError,"unacquired interval"):file.read()

    def test_overlap_and_outside_interval_rejected(self):
        with self.assertRaisesRegex(ValueError,"overlapping"):
            reader.IndependentIntervalFile(12,self.blobs([(0,b"abc"),(2,b"def")]))
        with self.assertRaisesRegex(ValueError,"invalid verified interval"):
            reader.IndependentIntervalFile(12,self.blobs([(11,b"xy")]))

    def test_exact_length_and_pre_read_digest_rejected(self):
        blobs=self.blobs([(0,b"abcdef")]); Path(blobs[0]['path']).write_bytes(b"abcde")
        with self.assertRaisesRegex(ValueError,"length differs"):reader.IndependentIntervalFile(12,blobs)
        Path(blobs[0]['path']).write_bytes(b"abcdeg")
        with self.assertRaisesRegex(ValueError,"bytes changed"):reader.IndependentIntervalFile(12,blobs)

    def test_post_open_blob_change_rejected(self):
        blobs=self.blobs([(0,b"abcdef")]);file=reader.IndependentIntervalFile(12,blobs)
        Path(blobs[0]['path']).write_bytes(b"abcdef")
        with self.assertRaisesRegex(ValueError,"changed during source audit"):file.read(3)

    def test_invalid_seek_rejected(self):
        file=reader.IndependentIntervalFile(12,self.blobs([(0,b"abc")]))
        for args in [(-1,), (13,), (0,4), (True,)]:
            with self.assertRaises(ValueError):file.seek(*args)

    def source_fixture(self, whole=False):
        import pyarrow as pa
        import pyarrow.parquet as pq
        stream=pa.BufferOutputStream()
        pq.write_table(pa.table({'selected':[1,2,3,4],'unselected':['x'*1000]*4}),stream,
                       row_group_size=2,compression='snappy')
        data=stream.getvalue().to_pybytes();metadata=pq.ParquetFile(pa.BufferReader(data)).metadata
        footer=len(data)-8-int.from_bytes(data[-8:-4],'little')
        spans=[(0,data[:4])]
        for rg in range(metadata.num_row_groups):
            c=metadata.row_group(rg).column(0)
            start=min(x for x in (c.dictionary_page_offset,c.data_page_offset) if x is not None and x>=4)
            spans.append((start,data[start:start+c.total_compressed_size]))
        spans.append((footer,data[footer:]));blobs=self.blobs(spans)
        identity={'table':'logs','day_utc':'2022-02-19','key':'invented','size_bytes':len(data),
                  'etag_opaque':'invented-etag','url':'https://example.invalid/invented'}
        manifest={'source':identity,'row_count_metadata':4,'row_group_count':2,'row_group_rows':[2,2]}
        transport={'source':identity,'source_key':'invented','storage_kind':'compact_descriptor',
            'verified_blobs':blobs,'available_ranges':[[x['start'],x['start']+x['length']] for x in blobs]}
        if whole:
            path=self.root/'whole';path.write_bytes(data)
            transport.update(storage_kind='verified_whole_object',path=str(path),
                sha256=hashlib.sha256(data).hexdigest(),available_ranges=[[0,len(data)]])
        return identity,manifest,transport,pa,pq

    def test_real_arrow_reads_exact_projected_chunks_across_holes(self):
        source=reader.IndependentCompactSource(*self.source_fixture())
        self.assertEqual(source.read(0,['selected']).to_pydict(),{'selected':[1,2]})
        self.assertEqual(source.read(1,['selected']).to_pydict(),{'selected':[3,4]})
        with self.assertRaisesRegex(ValueError,'unacquired projected column'):
            source.read(0,['unselected'])
        self.assertEqual(len(source.reads),2)

    def test_whole_object_uses_same_strict_byte_interface(self):
        source=reader.IndependentCompactSource(*self.source_fixture(whole=True))
        self.assertEqual(source.read(0,['selected']).to_pydict(),{'selected':[1,2]})
        self.assertEqual(len(source.read(0,['unselected'])),2)

    def test_forged_transport_span_rejected(self):
        args=list(self.source_fixture());args[2]['available_ranges']=[[0,args[0]['size_bytes']]]
        with self.assertRaisesRegex(ValueError,'ranges differ'):reader.IndependentCompactSource(*args)

    def test_source_identity_and_footer_magic_rejected(self):
        args=list(self.source_fixture());args[2]['source']=args[0]|{'etag_opaque':'changed'}
        with self.assertRaisesRegex(ValueError,'identity differs'):reader.IndependentCompactSource(*args)
        args=list(self.source_fixture());blob=args[2]['verified_blobs'][-1];p=Path(blob['path']);v=p.read_bytes()[:-4]+b'NOPE'
        p.write_bytes(v);blob['sha256']=hashlib.sha256(v).hexdigest()
        with self.assertRaisesRegex(ValueError,'footer envelope'):reader.IndependentCompactSource(*args)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--dependencies',required=True);parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args();sys.path.insert(0,args.dependencies)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Checks))
    report={'status':'PASS_SYNTHETIC_COMPACT_READER_ONLY' if result.wasSuccessful() else 'FAIL',
            'checks':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
            'reader_sha256':reader.sha(reader.__file__),'test_sha256':reader.sha(__file__),
            'actual_acquired_sources_read':False,'network_requests':0,'original_bound_files_changed':False}
    args.report.write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
