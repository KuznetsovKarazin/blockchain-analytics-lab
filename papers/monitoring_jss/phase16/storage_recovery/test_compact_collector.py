"""Tiny synthetic compact recovery tests; no actual capture/network reads."""
from datetime import datetime,timedelta,timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import compact_collector as c


class Response:
    def __init__(self,source,start,payload,truncate=False,status=206,callback=None):
        self.status=status;self.url=source['url'];self.body=payload[:-1] if truncate else payload;self.position=0;self.callback=callback
        self.headers={'ETag':source['etag_opaque'],'Content-Range':f'bytes {start}-{start+len(payload)-1}/{source["size_bytes"]}',
                      'Content-Length':str(len(payload))}
    def geturl(self):return self.url
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def read(self,n):
        value=self.body[self.position:self.position+n];self.position+=len(value)
        if self.callback:self.callback();self.callback=None
        return value


class Opener:
    def __init__(self,source,oracle,truncate=False,status=206,callback=None):
        self.source=source;self.oracle=oracle;self.truncate=truncate;self.status=status;self.calls=[];self.callback=callback
    def open(self,request,timeout):
        start,end=map(int,request.get_header('Range').removeprefix('bytes=').split('-'))
        self.calls.append((start,end,timeout));return Response(self.source,start,self.oracle[start:end+1],self.truncate,self.status,self.callback)


class CompactTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='article2_compact_synthetic_');self.root=Path(self.tmp.name)
        self.parent=self.root/'attempt1';self.runtime=self.root/'attempt2';self.repo=self.root/'repo'
        (self.parent/'transport').mkdir(parents=True);self.repo.mkdir()
        self.addCleanup(self.tmp.cleanup)
        self.patch1=patch.object(c,'PINNED_RUNTIME_ROOT',self.runtime);self.patch2=patch.object(c,'PINNED_PARENT_ROOT',self.parent)
        self.patch1.start();self.patch2.start();self.addCleanup(self.patch1.stop);self.addCleanup(self.patch2.stop)
    def fixture(self,oracle=None,accepted=None,pending=None):
        self.plan=json.loads((c.HERE.parent/'collector/source_plan_template.json').read_bytes())
        self.oracle=oracle or bytes(range(64));self.start=datetime.now(timezone.utc)-timedelta(seconds=1000)
        self.source={'table':'logs','day_utc':'2022-02-19','key':'v1.0/eth/logs/date=2022-02-19/part-test.parquet',
                     'size_bytes':len(self.oracle),'etag_opaque':'"fixed"'};self.source['url']=c.base.ENDPOINT+self.source['key']
        accepted=accepted or [(0,4)];pending=pending or (8,8)
        self.original=self.parent/'cache'/c.digest(self.source)/'source.parquet';self.original.parent.mkdir(parents=True)
        with self.original.open('wb') as f:f.truncate(len(self.oracle))
        self.records=[]
        for ordinal,(start,length) in enumerate(accepted,1):
            r=self.record(ordinal,start,length,True);self.records.append(r)
            with self.original.open('r+b') as f:f.seek(start);f.write(self.oracle[start:start+length])
        self.records.append(self.record(len(self.records)+1,*pending,False));last=self.records[-1]
        # Unattributed local bytes may exist at the pending interval; never import them.
        with self.original.open('r+b') as f:f.seek(pending[0]);f.write(b'?'*pending[1])
        self.manual={'parent_request_ordinal':last['ordinal'],'source_key':self.source['key'],'start':last['start'],'length':last['length']}
        c.save(self.repo/'inventory.json',{'objects':[self.source]})
        self.original_plan={'collector':self.plan,'source_union':{'path':'inventory.json','sha256':c.file_sha(self.repo/'inventory.json')}}
        c.save(self.parent/'frozen_plan.json',self.original_plan);c.save(self.parent/'transport/plan.json',self.plan)
        self.prior={'schema_version':'article2_phase16_range_capture_v1','status':'OPEN_REQUEST_PENDING',
            'started_utc':self.start.isoformat(),'updated_utc':(self.start+timedelta(seconds=100)).isoformat(),
            'attempt_id':c.digest({'plan':c.digest(self.plan),'started_utc':self.start.isoformat()}),
            'plan_canonical_sha256':c.digest(self.plan),'request_count':len(self.records),
            'retained_response_bytes':sum(r['response_bytes'] for r in self.records),'wall_seconds_elapsed':100,
            'cache_or_full_object_reuses':[]}
        c.save(self.parent/'transport/session.json',self.prior);c.save(self.parent/'transport/requests.json',self.records)
        c.save(self.parent/'runtime_source_paths.json',{self.source['key']:str(self.original)})
        (self.parent/'transport/requests.json.pending').write_bytes(b'')
        self.forensics={}
        for name in c.FORENSIC_NAMES:
            p=self.root/(name+'.json');c.save(p,{'synthetic':True,'name':name});self.forensics[name]={'path':str(p),'sha256':c.file_sha(p)}
        self.refresh()
    def record(self,ordinal,start,length,ok):
        r={'ordinal':ordinal,'source':self.source,'kind':'synthetic','method':'GET','start':start,'length':length,
           'request_headers':{'Range':f'bytes={start}-{start+length-1}','If-Match':self.source['etag_opaque'],'Accept-Encoding':'identity'},
           'stored_file_name':'source.parquet','stored_offset':start,'started_utc':(self.start+timedelta(seconds=ordinal)).isoformat(),
           'transport_ok':ok,'response_bytes':length if ok else 0}
        if ok:r.update(http_status=206,response_url=self.source['url'],etag=self.source['etag_opaque'],content_encoding=None,
             content_range=f'bytes {start}-{start+length-1}/{self.source["size_bytes"]}',content_length=str(length),
             completed_utc=(self.start+timedelta(seconds=ordinal+.1)).isoformat(),
             response_sha256=hashlib.sha256(self.oracle[start:start+length]).hexdigest())
        return r
    def refresh(self):
        names=['frozen_plan.json','transport/plan.json','transport/session.json','transport/requests.json','runtime_source_paths.json',
               'transport/requests.json.pending','failure.json','collection_result.json']
        self.bindings={n:c.file_sha(self.parent/n) if (self.parent/n).exists() else None for n in names}
    def make(self,opener=None,**changes):
        args={'parent_bindings':self.bindings,'recovery_plan_sha256':'a'*64,'original_plan_sha256':c.file_sha(self.parent/'frozen_plan.json'),
              'forensic_bindings':self.forensics,'manual_reacquisition':self.manual,'pinned_runtime_root':self.runtime,'repo':self.repo,
              'opener':opener or Opener(self.source,self.oracle)};args.update(changes)
        return c.ResourceSession(self.plan,self.runtime/'transport',self.parent,**args)
    def test_import_only_accepted_bytes_no_new_parquet_and_parent_unchanged(self):
        self.fixture();before=c.file_sha(self.original);opener=Opener(self.source,self.oracle);s=self.make(opener)
        self.assertEqual([],opener.calls);self.assertEqual([],list(self.runtime.rglob('*.parquet')))
        blobs=list(s.storage_dir.rglob('*.bin'));self.assertEqual(1,len(blobs));self.assertEqual(4,blobs[0].stat().st_size)
        self.assertEqual(self.oracle[:4],blobs[0].read_bytes());self.assertEqual(before,c.file_sha(self.original))
        self.assertEqual((self.parent/'transport/requests.json').read_bytes(),(s.output/'inherited_requests.json').read_bytes())
        self.assertEqual((4,8,12),(s.bytes,s.reserved_parent_pending_response_bytes,s.cumulative_charged_response_bytes))
    def test_pending_unknown_never_promoted_and_explicit_retry_lineage(self):
        self.fixture();s=self.make();descriptor=s.storage_dir/c.digest(self.source)/'source_storage.json'
        with c.StrictIntervalFile(descriptor) as f:
            f.seek(8)
            with self.assertRaisesRegex(ValueError,'UNAVAILABLE_HOLE'):f.read(8)
        with self.assertRaisesRegex(ValueError,'previously attempted'):s.fetch_range(self.source,'column_chunks',8,8)
        r=s.reacquire_pending_range();s.close();self.assertEqual(3,r['ordinal'])
        self.assertEqual({'attempt_id':s.parent_attempt_id,'ordinal':2},r['reacquisition_of'])
        state=json.loads((s.output/'session.json').read_bytes());self.assertIsNone(state['parent_pending_response_bytes'])
        self.assertFalse(state['actual_cumulative_response_bytes_complete']);self.assertEqual((12,20),(s.bytes,s.cumulative_charged_response_bytes))
        with c.StrictIntervalFile(descriptor) as f:f.seek(8);self.assertEqual(self.oracle[8:16],f.read(8))
        with self.assertRaisesRegex(ValueError,'already consumed'):s.reacquire_pending_range()
    def test_hole_crossing_rejects_before_partial_return_or_position_change(self):
        self.fixture();s=self.make();p=s.storage_dir/c.digest(self.source)/'source_storage.json'
        with c.StrictIntervalFile(p) as f:
            with self.assertRaisesRegex(ValueError,'UNAVAILABLE_HOLE'):f.read(6)
            self.assertEqual(0,f.tell());self.assertEqual(self.oracle[:4],f.read(4))
    def test_changed_original_success_blocks_before_network(self):
        self.fixture();self.original.write_bytes(b'x'*64);opener=Opener(self.source,self.oracle)
        with self.assertRaisesRegex(ValueError,'accepted range hash differs'):self.make(opener)
        self.assertEqual([],opener.calls)
    def test_changed_blob_is_rejected(self):
        self.fixture();s=self.make();blob=next(s.storage_dir.rglob('*.bin'));blob.chmod(0o644);blob.write_bytes(b'bad!')
        with self.assertRaisesRegex(ValueError,'compact original blob differs'):c.StrictIntervalFile(s.storage_dir/c.digest(self.source)/'source_storage.json')
    def test_cached_verified_blob_is_not_rehashed_on_each_view_but_changes_reject(self):
        self.fixture();s=self.make();descriptor=s.storage_dir/c.digest(self.source)/'source_storage.json'
        with patch.object(c,'file_sha',side_effect=AssertionError('unexpected repeated blob hash')):
            for _ in range(3):
                with c.StrictIntervalFile(descriptor,s.verified_blob_cache) as f:self.assertEqual(self.oracle[:4],f.read(4))
        blob=next(s.storage_dir.rglob('*.bin'));blob.chmod(0o644);blob.write_bytes(b'bad!')
        with self.assertRaisesRegex(ValueError,'immutable blob identity changed'):c.StrictIntervalFile(descriptor,s.verified_blob_cache)
    def test_blob_changed_after_view_open_rejects_before_read(self):
        self.fixture();s=self.make();descriptor=s.storage_dir/c.digest(self.source)/'source_storage.json'
        with c.StrictIntervalFile(descriptor,s.verified_blob_cache) as f:
            blob=next(s.storage_dir.rglob('*.bin'));blob.chmod(0o644);blob.write_bytes(b'bad!')
            with self.assertRaisesRegex(ValueError,'changed before read'):f.read(4)
    def test_conservative_pending_reservation_blocks_otherwise_fitting_retry(self):
        self.fixture();opener=Opener(self.source,self.oracle);s=self.make(opener);s.caps['total_response_bytes']=18
        with self.assertRaisesRegex(ValueError,'charged byte cap'):s.reacquire_pending_range()
        self.assertEqual([],opener.calls);self.assertEqual([],s.new_requests)
    def test_partial_new_body_forensic_only_and_failure_latches(self):
        self.fixture();opener=Opener(self.source,self.oracle,truncate=True);s=self.make(opener)
        with self.assertRaisesRegex(ValueError,'truncated exact range'):s.reacquire_pending_range()
        self.assertEqual((11,20),(s.bytes,s.cumulative_charged_response_bytes));self.assertTrue(s.failed)
        self.assertEqual(1,len(list(s.storage_dir.rglob('forensic_blobs/*.bin'))))
        descriptor=json.loads((s.storage_dir/c.digest(self.source)/'source_storage.json').read_bytes());self.assertEqual(1,len(descriptor['segments']))
        with self.assertRaisesRegex(ValueError,'not ready/live'):s.fetch_range(self.source,'column_chunks',24,4)
    def test_wrong_http_headers_read_no_body(self):
        self.fixture();opener=Opener(self.source,self.oracle,status=200);s=self.make(opener)
        with self.assertRaisesRegex(ValueError,'HTTP status'):s.reacquire_pending_range()
        self.assertEqual(0,s.new_requests[0]['received_bytes_known']);self.assertIsNone(s.new_requests[0]['blob'])
    def test_outside_pinned_runtime_root_rejected(self):
        self.fixture()
        with self.assertRaisesRegex(ValueError,'pinned external'):self.make(pinned_runtime_root=self.root/'wrong')
    def test_final_cpu_deadline_cannot_complete(self):
        self.fixture();s=self.make();s.reacquire_pending_range();s.started-=15000
        with self.assertRaisesRegex(ValueError,'deadline/charged'):s.close()
    def test_parent_metadata_change_blocks_completion(self):
        self.fixture();s=self.make();s.reacquire_pending_range();(self.parent/'transport/requests.json.pending').write_text('changed')
        with self.assertRaisesRegex(ValueError,'parent evidence changed'):s.close()
    def test_immutable_blob_cannot_be_overwritten(self):
        self.fixture();s=self.make();r=self.records[0]
        with self.assertRaisesRegex(ValueError,'already exists'):
            s._write_blob(self.source,s.parent_attempt_id,1,self.oracle[:4],r['response_sha256'],True)
    def test_arrow_metadata_and_projected_chunks_without_sparse_source(self):
        import pyarrow as pa
        import pyarrow.parquet as pq
        fields=[('address',pa.string()),('topics',pa.list_(pa.string())),('data',pa.string()),('transaction_index',pa.int64()),
                ('log_index',pa.int64()),('transaction_hash',pa.string()),('block_number',pa.int64()),('block_hash',pa.string()),
                ('block_timestamp',pa.timestamp('ns'))]
        rows=[{'address':'0x'+'1'*40,'topics':[],'data':'0x','transaction_index':0,'log_index':i,'transaction_hash':'0x'+'2'*64,
               'block_number':1,'block_hash':'0x'+'3'*64,'block_timestamp':datetime(2022,2,19)} for i in range(3)]
        table=pa.Table.from_pylist(rows,schema=pa.schema(fields));sink=pa.BufferOutputStream();pq.write_table(table,sink,row_group_size=2)
        raw=sink.getvalue().to_pybytes();size=len(raw);footer=int.from_bytes(raw[-8:-4],'little')
        meta=pq.ParquetFile(pa.BufferReader(raw)).metadata;col=meta.row_group(0).column(0)
        start=min(x for x in (col.dictionary_page_offset,col.data_page_offset) if isinstance(x,int) and x>=4)
        self.fixture(raw,[(0,4),(size-8,8),(size-8-footer,footer)],(start,col.total_compressed_size))
        opener=Opener(self.source,self.oracle);s=self.make(opener);s.reacquire_pending_range()
        reader=c.CompactSourceReader(self.source,s,s.storage_dir,pa,pq).open();before=len(opener.calls)
        self.assertEqual('compact_descriptor',reader.storage_kind);self.assertEqual('source_storage.json',reader.path.name)
        decoded=pa.concat_tables([t for _,t in reader.iter_row_groups([name for name,_ in fields])]);self.assertTrue(table.equals(decoded))
        self.assertGreater(len(opener.calls),before);self.assertEqual([],list(self.runtime.rglob('*.parquet')))
        self.assertEqual('compact_descriptor',reader.manifest()['storage_kind']);s.close()


if __name__=='__main__':unittest.main()
