"""Candidate-only synthetic continuation faults; no real evidence/network."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import collector as c


class Response:
    def __init__(self, source, start, data, *, truncated=False, callback=None, status=206):
        self.status=status;self.url=source['url'];self.data=data[:-1] if truncated else data
        self.pos=0;self.callback=callback
        self.headers={'ETag':source['etag_opaque'],'Content-Range':f'bytes {start}-{start+len(data)-1}/{source["size_bytes"]}',
                      'Content-Length':str(len(data))}
    def geturl(self):return self.url
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def read(self,n):
        b=self.data[self.pos:self.pos+n];self.pos+=len(b)
        if self.callback:self.callback();self.callback=None
        return b


class Opener:
    def __init__(self,response):self.response=response;self.calls=[]
    def open(self,request,timeout):self.calls.append((request.full_url,timeout));return self.response


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.parent=self.root/'a1';self.parent.mkdir();self.repo=self.root/'repo';self.repo.mkdir()
        (self.parent/'transport').mkdir()
    def tearDown(self):self.tmp.cleanup()
    def fixture(self,kind='clean',missing_paths=False):
        self.plan=json.loads((c.HERE.parent/'collector/source_plan_template.json').read_bytes())
        self.now=datetime.now(timezone.utc);self.t0=self.now-timedelta(seconds=7300)
        self.source={'table':'logs','day_utc':'2022-02-19','key':'v1.0/eth/logs/date=2022-02-19/part-test.parquet',
                     'size_bytes':64,'etag_opaque':'"fixed"'}
        self.source['url']=c.base.ENDPOINT+self.source['key'];self.payload=bytes(range(64))
        self.original=self.parent/'cache'/c.digest(self.source)/'source.parquet';self.original.parent.mkdir(parents=True)
        self.original.write_bytes(b'\0'*64)
        c.save(self.repo/'sources.json',{'objects':[self.source]})
        original_plan={'collector':self.plan,'source_union':{'path':'sources.json','sha256':c.file_sha(self.repo/'sources.json')}}
        c.save(self.parent/'frozen_plan.json',original_plan);c.save(self.parent/'transport/plan.json',self.plan)
        self.records=[self.record(1,0,4,4,True)]
        if kind=='partial':self.records.append(self.record(2,8,8,3,False))
        if kind=='late_full':self.records.append(self.record(2,8,8,8,False))
        for r in self.records:
            with self.original.open('r+b') as f:f.seek(r['start']);f.write(self.payload[r['start']:r['start']+r['response_bytes']])
        self.prior={'schema_version':'article2_phase16_range_capture_v1','status':'COMPLETE' if kind=='complete' else 'FAILED',
                    'started_utc':self.t0.isoformat(),'updated_utc':(self.t0+timedelta(seconds=7201)).isoformat(),
                    'attempt_id':c.digest({'plan':c.digest(self.plan),'started_utc':self.t0.isoformat()}),
                    'plan_canonical_sha256':c.digest(self.plan),'wall_seconds_elapsed':7201,
                    'request_count':len(self.records),'retained_response_bytes':sum(r['response_bytes'] for r in self.records),
                    'cache_or_full_object_reuses':[]}
        c.save(self.parent/'transport/session.json',self.prior);c.save(self.parent/'transport/requests.json',self.records)
        if not missing_paths:c.save(self.parent/'runtime_source_paths.json',{self.source['key']:str(self.original)})
        if kind=='complete':
            c.save(self.parent/'collection_result.json',{'status':'COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT',
                 'plan_sha256':c.file_sha(self.parent/'frozen_plan.json')})
        else:
            c.save(self.parent/'failure.json',{'status':'FAILED_NOT_ACCEPTED','error_type':'ValueError',
                   'error':'wall cap after range read' if kind in ('partial','late_full') else 'wall/request cap'})
        self.manual=None if kind not in ('partial','late_full') else {'parent_request_ordinal':2,'source_key':self.source['key'],'start':8,'length':8}
        self.refresh_bindings()
    def record(self,ordinal,start,length,received,success):
        r={'ordinal':ordinal,'source':self.source,'kind':'synthetic','method':'GET',
           'request_headers':{'Range':f'bytes={start}-{start+length-1}','If-Match':self.source['etag_opaque'],'Accept-Encoding':'identity'},
           'start':start,'length':length,'response_bytes':received,'stored_offset':start,'stored_file_name':'source.parquet',
           'transport_ok':success,'started_utc':(self.t0+timedelta(seconds=1 if success else 7199)).isoformat(),
           'completed_utc':(self.t0+timedelta(seconds=2 if success else 7201)).isoformat(),
           'response_sha256':hashlib.sha256(self.payload[start:start+received]).hexdigest(),
           'http_status':206,'response_url':self.source['url'],'etag':self.source['etag_opaque'],
           'content_range':f'bytes {start}-{start+length-1}/{self.source["size_bytes"]}','content_length':str(length),'content_encoding':None}
        if not success:r['failure']='ValueError: wall cap after range read'
        return r
    def refresh_bindings(self):
        names=['frozen_plan.json','transport/plan.json','transport/session.json','transport/requests.json','runtime_source_paths.json']
        names+=['collection_result.json'] if (self.parent/'collection_result.json').exists() else ['failure.json']
        self.bindings={n:c.file_sha(self.parent/n) if (self.parent/n).exists() else None for n in names}
    def make(self,opener=None,**kwargs):
        kwargs.setdefault('original_plan_sha256',c.file_sha(self.parent/'frozen_plan.json'))
        return c.ContinuationSession(self.plan,self.root/'a2/transport',self.parent,parent_bindings=self.bindings,
               continuation_plan_sha256='b'*64,manual_reacquisition=self.manual,opener=opener,repo=self.repo,**kwargs)
    def test_clean_stop_copy_and_cumulative_new_get(self):
        self.fixture();before=c.file_sha(self.original);opener=Opener(Response(self.source,16,self.payload[16:24]));s=self.make(opener)
        p=s.cache_dir/c.digest(self.source)/'source.parquet'
        self.assertEqual(self.payload[:4],p.read_bytes()[:4]);self.assertEqual(b'\0'*8,p.read_bytes()[8:16])
        s.fetch_into(self.source,'column_chunks',16,8,p);s.close()
        value=json.loads((s.output/'session.json').read_bytes())
        self.assertEqual((1,1,2),(value['inherited_request_count'],value['new_request_count'],value['cumulative_request_count']))
        self.assertEqual((4,8,12),(value['inherited_response_bytes'],value['new_response_bytes'],value['cumulative_response_bytes']))
        self.assertEqual(2,s.new_requests[0]['ordinal']);self.assertEqual(1,len(opener.calls));self.assertEqual(before,c.file_sha(self.original))
        self.assertEqual((self.parent/'transport/requests.json').read_bytes(),(s.output/'inherited_requests.json').read_bytes())
    def test_partial_is_not_promoted_manual_retry_is_explicit_and_counted_once(self):
        self.fixture('partial');opener=Opener(Response(self.source,8,self.payload[8:16]));s=self.make(opener)
        p=s.cache_dir/c.digest(self.source)/'source.parquet';self.assertEqual(b'\0'*8,p.read_bytes()[8:16])
        with self.assertRaisesRegex(ValueError,'previously attempted'):s.fetch_into(self.source,'column_chunks',8,8,p)
        self.assertEqual(0,len(opener.calls));s.reacquire_final_failed_range();s.close()
        self.assertEqual((3,15,1),(len(s.requests),s.bytes,s.manual_reacquisition_count))
        self.assertEqual({'attempt_id':s.parent_attempt_id,'ordinal':2},s.new_requests[0]['reacquisition_of'])
        cache=json.loads((p.parent/'ranges.json').read_bytes())
        self.assertEqual([1],[e['origin_ordinal'] for e in cache['inherited_ranges']]);self.assertEqual([3],[r['ordinal'] for r in cache['new_ranges']])
        with self.assertRaisesRegex(ValueError,'no unused'):s.reacquire_final_failed_range()
        self.assertEqual(1,len(opener.calls))
    def test_full_late_parent_response_still_requires_new_get(self):
        self.fixture('late_full');opener=Opener(Response(self.source,8,self.payload[8:16]));s=self.make(opener)
        p=s.cache_dir/c.digest(self.source)/'source.parquet';self.assertEqual(b'\0'*8,p.read_bytes()[8:16])
        s.reacquire_final_failed_range();self.assertEqual(20,s.bytes);self.assertEqual(1,len(opener.calls))
    def test_changed_partial_body_blocks_before_any_new_get(self):
        self.fixture('partial');opener=Opener(None)
        with self.original.open('r+b') as f:f.seek(8);f.write(b'bad')
        with self.assertRaisesRegex(ValueError,'unaccepted parent body changed'):self.make(opener)
        self.assertEqual([],opener.calls)
    def test_changed_accepted_body_blocks_before_any_new_get(self):
        self.fixture();opener=Opener(None)
        with self.original.open('r+b') as f:f.write(b'bad!')
        with self.assertRaisesRegex(ValueError,'accepted range changed'):self.make(opener)
        self.assertEqual([],opener.calls)
    def test_nonwall_failure_rejected(self):
        self.fixture();c.save(self.parent/'failure.json',{'status':'FAILED_NOT_ACCEPTED','error_type':'ValueError','error':'status is not int64'});self.refresh_bindings()
        with self.assertRaisesRegex(ValueError,'exclusively wall expiry'):self.make(Opener(None))
    def test_timeout_before_final60seconds_is_not_eligible(self):
        self.fixture('partial');self.records[-1]['failure']='TimeoutError: timed out';c.save(self.parent/'transport/requests.json',self.records)
        self.records[-1]['started_utc']=(self.t0+timedelta(seconds=7100)).isoformat();c.save(self.parent/'transport/requests.json',self.records)
        c.save(self.parent/'failure.json',{'status':'FAILED_NOT_ACCEPTED','error_type':'TimeoutError','error':'timed out'});self.refresh_bindings()
        with self.assertRaisesRegex(ValueError,'final-deadline interval'):self.make(Opener(None))
    def timeout_fixture(self,headers=True):
        self.fixture('partial');self.records[-1]['failure']='TimeoutError: timed out'
        if not headers:
            for key in ('http_status','response_url','etag','content_range','content_length','content_encoding'):self.records[-1].pop(key)
            self.records[-1]['response_bytes']=0;self.records[-1]['response_sha256']=hashlib.sha256(b'').hexdigest()
            self.prior['retained_response_bytes']=4;c.save(self.parent/'transport/session.json',self.prior)
        c.save(self.parent/'transport/requests.json',self.records)
        c.save(self.parent/'failure.json',{'status':'FAILED_NOT_ACCEPTED','error_type':'TimeoutError','error':'timed out'});self.refresh_bindings()
    def test_deadline_associated_timeout_uncertainty_and_conservative_charge(self):
        self.timeout_fixture();opener=Opener(Response(self.source,8,self.payload[8:16]));s=self.make(opener)
        self.assertEqual('DEADLINE_ASSOCIATED_TIMEOUT_CAUSALITY_UNRESOLVED',s.eligibility)
        self.assertEqual((7,5,12),(s.bytes,s.reserved_parent_failed_response_bytes,s.cumulative_charged_response_bytes))
        s.reacquire_final_failed_range();s.close()
        self.assertEqual((15,20),(s.bytes,s.cumulative_charged_response_bytes))
        state=json.loads((s.output/'session.json').read_bytes());self.assertIn('unknown',state['timeout_causal_statement'])
    def test_deadline_associated_preheader_timeout_requires_zero_retained(self):
        self.timeout_fixture(headers=False);s=self.make(Opener(None));self.assertEqual((4,8,12),(s.bytes,s.reserved_parent_failed_response_bytes,s.cumulative_charged_response_bytes))
    def test_exact_urlerror_timeout_wrapper_is_eligible_with_same_charge(self):
        self.timeout_fixture(headers=False);message='<urlopen error timed out>'
        self.records[-1]['failure']='URLError: '+message;c.save(self.parent/'transport/requests.json',self.records)
        c.save(self.parent/'failure.json',{'status':'FAILED_NOT_ACCEPTED','error_type':'URLError','error':message});self.refresh_bindings()
        s=self.make(Opener(None));self.assertEqual('DEADLINE_ASSOCIATED_TIMEOUT_CAUSALITY_UNRESOLVED',s.eligibility)
        self.assertEqual((4,8,12),(s.bytes,s.reserved_parent_failed_response_bytes,s.cumulative_charged_response_bytes))
    def test_general_urlerror_is_not_eligible_even_at_deadline(self):
        self.timeout_fixture(headers=False);message='<urlopen error Temporary failure in name resolution>'
        self.records[-1]['failure']='URLError: '+message;c.save(self.parent/'transport/requests.json',self.records)
        c.save(self.parent/'failure.json',{'status':'FAILED_NOT_ACCEPTED','error_type':'URLError','error':message});self.refresh_bindings()
        with self.assertRaisesRegex(ValueError,'unrecognized deadline-associated'):self.make(Opener(None))
    def test_timeout_with_invalid_recorded_response_headers_is_rejected(self):
        self.timeout_fixture();self.records[-1]['etag']='"changed"';c.save(self.parent/'transport/requests.json',self.records);self.refresh_bindings()
        with self.assertRaisesRegex(ValueError,'invalid/incomplete headers'):self.make(Opener(None))
    def test_conservative_reservation_can_block_retry_before_http(self):
        self.timeout_fixture();opener=Opener(None);s=self.make(opener)
        s.caps['total_response_bytes']=18  # Tiny synthetic budget: actual15 would fit, conservative20 would not.
        with self.assertRaisesRegex(ValueError,'charged byte cap'):s.reacquire_final_failed_range()
        self.assertEqual([],opener.calls);self.assertEqual([],s.new_requests)
    def test_missing_first_open_runtime_map_uses_canonical_parent_cache(self):
        self.fixture('partial',missing_paths=True);s=self.make(Opener(None));self.assertTrue(s.parent_bytes_verified)
    def test_original_complete_overwall_can_reprepare_without_new_get(self):
        self.fixture('complete');opener=Opener(None);s=self.make(opener);s.close()
        self.assertEqual([],s.new_requests);self.assertEqual([],opener.calls)
    def test_complete_input_plan_hash_can_differ_from_runtime_reserialization(self):
        self.fixture('complete');original=json.loads((self.parent/'frozen_plan.json').read_bytes())
        accepted_bytes=json.dumps(original,separators=(',',':')).encode();accepted_sha=hashlib.sha256(accepted_bytes).hexdigest()
        self.assertNotEqual(c.file_sha(self.parent/'frozen_plan.json'),accepted_sha)
        result=json.loads((self.parent/'collection_result.json').read_bytes());result['plan_sha256']=accepted_sha
        c.save(self.parent/'collection_result.json',result);self.refresh_bindings()
        s=self.make(Opener(None),original_plan_sha256=accepted_sha);s.close()
        self.assertEqual(accepted_sha,s.original_plan_sha256)
    def test_complete_within_original_wall_is_not_eligible(self):
        self.fixture('complete');self.prior['wall_seconds_elapsed']=7199;c.save(self.parent/'transport/session.json',self.prior);self.refresh_bindings()
        with self.assertRaisesRegex(ValueError,'exclusively final-wall'):self.make(Opener(None))
    def test_final_cpu_work_cannot_report_complete_after_aggregate_deadline(self):
        self.fixture();s=self.make(Opener(None));s.started-=7200
        with self.assertRaisesRegex(ValueError,'wall cap at close'):s.close()
    def test_final_checkpoint_cost_cannot_leave_complete_over_deadline(self):
        self.fixture();s=self.make(Opener(None));original=s.checkpoint
        def delayed(status):
            original(status)
            if status=='COMPLETE':s.started-=7200
        s.checkpoint=delayed
        with self.assertRaisesRegex(ValueError,'during final checkpoint'):s.close()
        self.assertEqual('FAILED_CUMULATIVE_WALL_AT_CLOSE',json.loads((s.output/'session.json').read_bytes())['status'])
    def test_new_failed_http_latches_and_keeps_cumulative_partial_cost(self):
        self.fixture('partial');opener=Opener(Response(self.source,8,self.payload[8:16],truncated=True));s=self.make(opener)
        with self.assertRaisesRegex(ValueError,'truncated exact range'):s.reacquire_final_failed_range()
        self.assertEqual(14,s.bytes);self.assertTrue(s.failed);self.assertEqual(1,s.manual_reacquisition_count)
        self.assertEqual((5,1,20),(s.reserved_parent_failed_response_bytes,s.reserved_new_failed_or_pending_response_bytes,s.cumulative_charged_response_bytes))
        p=s.cache_dir/c.digest(self.source)/'source.parquet'
        with self.assertRaisesRegex(ValueError,'not ready/live'):s.fetch_into(self.source,'column_chunks',16,8,p)
        self.assertEqual(1,len(opener.calls))
    def test_contradictory_reacquired_prefix_is_not_verified_evidence(self):
        self.fixture('partial');opener=Opener(Response(self.source,8,b'bad'+self.payload[11:16]));s=self.make(opener)
        with self.assertRaisesRegex(ValueError,'contradict'):s.reacquire_final_failed_range()
        self.assertTrue(s.failed);self.assertFalse(s.new_requests[0]['transport_ok']);self.assertEqual(15,s.bytes)
        cache=json.loads((s.cache_dir/c.digest(self.source)/'ranges.json').read_bytes())
        self.assertEqual([],cache['new_ranges'])
    def test_source_reader_reuses_exact_inherited_evidence_without_get(self):
        self.fixture();opener=Opener(None);s=self.make(opener);r=c.SourceReader(self.source,s,s.cache_dir,None,None)
        r._load_cache();r._ensure_ranges([[0,4]],'synthetic');self.assertEqual([],opener.calls)
        self.assertEqual(self.records,r.ranges)
    def test_parent_metadata_mutation_prevents_completion(self):
        self.fixture();s=self.make(Opener(None));(self.parent/'failure.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'sealed parent evidence changed'):s.close()
    def test_original_parquet_reader_roundtrip_inherited_footer_then_new_columns(self):
        import pyarrow as pa
        import pyarrow.parquet as pq
        self.fixture()
        fields=[('address',pa.string()),('topics',pa.list_(pa.string())),('data',pa.string()),
                ('transaction_index',pa.int64()),('log_index',pa.int64()),('transaction_hash',pa.string()),
                ('block_number',pa.int64()),('block_hash',pa.string()),('block_timestamp',pa.timestamp('ns'))]
        rows=[{'address':'0x'+'1'*40,'topics':[],'data':'0x','transaction_index':0,'log_index':i,
               'transaction_hash':'0x'+'2'*64,'block_number':1,'block_hash':'0x'+'3'*64,
               'block_timestamp':datetime(2022,2,19)} for i in range(3)]
        table=pa.Table.from_pylist(rows,schema=pa.schema(fields));oracle=self.root/'oracle.parquet'
        pq.write_table(table,oracle,row_group_size=2);self.payload=oracle.read_bytes();n=len(self.payload)
        self.source['size_bytes']=n;footer=int.from_bytes(self.payload[-8:-4],'little')
        self.records=[self.record(1,0,4,4,True),self.record(2,n-8,8,8,True),self.record(3,n-8-footer,footer,footer,True)]
        with self.original.open('wb') as f:f.truncate(n)
        for r in self.records:
            with self.original.open('r+b') as f:f.seek(r['start']);f.write(self.payload[r['start']:r['start']+r['length']])
        c.save(self.repo/'sources.json',{'objects':[self.source]})
        original_plan=json.loads((self.parent/'frozen_plan.json').read_bytes())
        original_plan['source_union']['sha256']=c.file_sha(self.repo/'sources.json');c.save(self.parent/'frozen_plan.json',original_plan)
        self.prior['request_count']=3;self.prior['retained_response_bytes']=12+footer
        c.save(self.parent/'transport/session.json',self.prior);c.save(self.parent/'transport/requests.json',self.records);self.refresh_bindings()
        outer=self
        class RangeOpener:
            def __init__(self):self.calls=0
            def open(self,request,timeout):
                self.calls+=1;start,end=map(int,request.get_header('Range').removeprefix('bytes=').split('-'))
                return Response(outer.source,start,outer.payload[start:end+1])
        opener=RangeOpener();s=self.make(opener);r=c.SourceReader(self.source,s,s.cache_dir,pa,pq).open()
        self.assertEqual(0,opener.calls)
        decoded=pa.concat_tables([t for _,t in r.iter_row_groups([name for name,_ in fields])])
        self.assertTrue(table.equals(decoded));self.assertGreater(opener.calls,0)
        self.assertEqual([1,2,3],[x['origin_ordinal'] for x in r.manifest()['inherited_ranges']]);s.close()


if __name__=='__main__':unittest.main()
