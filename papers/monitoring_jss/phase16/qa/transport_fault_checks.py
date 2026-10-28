"""Independent synthetic transport faults; no network or historical row access."""
from __future__ import annotations
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

COLLECTOR = Path(__file__).resolve().parents[1] / 'collector' / 'range_collector.py'
spec = importlib.util.spec_from_file_location('phase16_independent_transport_target', COLLECTOR)
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)

SOURCE = {'table':'logs','day_utc':'2022-02-19','key':'v1.0/eth/logs/date=2022-02-19/fixture.parquet',
          'size_bytes':32,'etag_opaque':'"synthetic-only"'}

def plan(**changes):
    caps=dict(requests=10,total_response_bytes=1024,wall_seconds=60,request_timeout_seconds=5,
              max_range_bytes=32,max_footer_bytes=32,max_rows=100,max_row_groups=10,
              max_top_level_columns=20,max_leaf_columns=20,max_source_bytes=1024,retries=0,concurrency=1)
    caps.update(changes)
    return {'schema_version':'article2_phase16_range_source_plan_v1','endpoint':c.ENDPOINT,
            'caps':caps,'required_columns':{'logs':['address'],'transactions':['receipt_status'],'blocks':['number']}}

class Response:
    def __init__(self, body=b'abcdefgh', **overrides):
        self.status=overrides.pop('status',206)
        self.url=overrides.pop('url',c.ENDPOINT+SOURCE['key'])
        self.headers={'ETag':SOURCE['etag_opaque'],'Content-Range':'bytes 4-11/32','Content-Length':'8'}
        self.headers.update(overrides)
        self.body=io.BytesIO(body);self.read_calls=0
    def geturl(self):return self.url
    def read(self,n):self.read_calls+=1;return self.body.read(n)
    def __enter__(self):return self
    def __exit__(self,*args):return False

class Opener:
    def __init__(self,response):self.response=response;self.calls=[]
    def open(self,request,timeout):self.calls.append((request,timeout));return self.response

class Faults(unittest.TestCase):
    def run_capture(self, response, cfg=None):
        root=Path(self.tmp.name);target=root/'target.parquet';target.write_bytes(b'\0'*32)
        opener=Opener(response);session=c.RangeSession(cfg or plan(),root/'capture',opener=opener)
        return session,target,opener
    def setUp(self):self.tmp=tempfile.TemporaryDirectory(prefix='phase16_transport_synthetic_')
    def tearDown(self):self.tmp.cleanup()
    def test_exact_original_offsets_and_request_binding(self):
        response=Response();session,target,opener=self.run_capture(response)
        record=session.fetch_into(SOURCE,'column_chunks',4,8,target)
        self.assertEqual(target.read_bytes(),b'\0'*4+b'abcdefgh'+b'\0'*20)
        self.assertEqual(record['response_sha256'],hashlib.sha256(b'abcdefgh').hexdigest())
        self.assertEqual(record['response_bytes'],8);self.assertTrue(record['transport_ok'])
        request=opener.calls[0][0]
        self.assertEqual(request.get_header('Range'),'bytes=4-11')
        self.assertEqual(request.get_header('If-match'),SOURCE['etag_opaque'])
        self.assertEqual(session.bytes,8);self.assertEqual(len(session.requests),1)
    def test_invalid_headers_are_counted_without_body_consumption(self):
        variants=[{'status':200},{'url':'https://example.invalid/redirect'}, {'ETag':'"changed"'},
                  {'Content-Range':'bytes 5-12/32'}, {'Content-Length':'9'}, {'Content-Length':None},
                  {'Content-Encoding':'gzip'}]
        for n,change in enumerate(variants):
            with self.subTest(change=change):
                root=Path(self.tmp.name)/str(n);root.mkdir();target=root/'s';target.write_bytes(b'\0'*32)
                response=Response(**change);session=c.RangeSession(plan(),root/'capture',opener=Opener(response))
                with self.assertRaises(ValueError):session.fetch_into(SOURCE,'column_chunks',4,8,target)
                self.assertEqual(response.read_calls,0);self.assertEqual(session.bytes,0)
                self.assertEqual(len(session.requests),1);self.assertFalse(session.requests[0]['transport_ok'])
                self.assertEqual(json.loads((root/'capture/session.json').read_text())['status'],'FAILED_RANGE_ATTEMPT')
    def test_partial_failure_preserves_bytes_and_digest(self):
        session,target,_=self.run_capture(Response(b'abc'))
        with self.assertRaisesRegex(ValueError,'truncated'):session.fetch_into(SOURCE,'column_chunks',4,8,target)
        self.assertEqual(session.bytes,3);self.assertEqual(target.read_bytes()[4:7],b'abc')
        record=session.requests[0];self.assertFalse(record['transport_ok'])
        self.assertEqual(record['response_sha256'],hashlib.sha256(b'abc').hexdigest())
    def test_request_cap_rejects_before_second_network_call(self):
        session,target,opener=self.run_capture(Response(),plan(requests=1))
        session.fetch_into(SOURCE,'column_chunks',4,8,target)
        with self.assertRaisesRegex(ValueError,'cap'):session.fetch_into(SOURCE,'column_chunks',4,8,target)
        self.assertEqual(len(opener.calls),1);self.assertEqual(len(session.requests),1)
    def test_total_byte_cap_rejects_before_network(self):
        session,target,opener=self.run_capture(Response(),plan(total_response_bytes=7))
        with self.assertRaisesRegex(ValueError,'byte cap'):session.fetch_into(SOURCE,'column_chunks',4,8,target)
        self.assertEqual(opener.calls,[]);self.assertEqual(session.bytes,0)
    def test_per_range_cap_rejects_before_network(self):
        session,target,opener=self.run_capture(Response(),plan(max_range_bytes=7))
        with self.assertRaisesRegex(ValueError,'range byte cap'):session.fetch_into(SOURCE,'column_chunks',4,8,target)
        self.assertEqual(opener.calls,[])
    def test_source_identity_rejects_wrong_endpoint_or_table_path(self):
        for source in ({**SOURCE,'url':'https://example.invalid/data'}, {**SOURCE,'key':SOURCE['key'].replace('/logs/','/blocks/')}):
            with self.subTest(source=source),self.assertRaises(ValueError):c.identity(source)
    def test_unacquired_sparse_hole_cannot_be_read(self):
        session,_,_=self.run_capture(Response())
        reader=c.SourceReader(SOURCE,session,Path(self.tmp.name)/'cache',None,None)
        with self.assertRaisesRegex(ValueError,'sparse hole'):reader._read_exact(4,8)
    def test_missing_interval_union_does_not_hide_gaps(self):
        self.assertEqual(c.missing_ranges([[4,20]],[[4,8],[12,16]]),[[8,12],[16,20]])
        self.assertEqual(c.missing_ranges([[4,20]],[[4,8],[8,20]]),[])
    def test_boolean_caps_are_rejected(self):
        with self.assertRaises(ValueError):c.RangeSession(plan(requests=True),Path(self.tmp.name)/'capture')
    def test_clean_resume_preserves_original_counters_and_cap(self):
        cfg=plan(requests=1);session,target,_=self.run_capture(Response(),cfg)
        session.fetch_into(SOURCE,'column_chunks',4,8,target)
        opener=Opener(Response())
        resumed=c.RangeSession(cfg,Path(self.tmp.name)/'capture',opener=opener,resume=True)
        self.assertEqual((resumed.bytes,len(resumed.requests)),(8,1))
        self.assertEqual(resumed.started_utc,session.started_utc)
        self.assertEqual(resumed.attempt_id,session.attempt_id)
        with self.assertRaisesRegex(ValueError,'cap'):resumed.fetch_into(SOURCE,'column_chunks',4,8,target)
        self.assertEqual(opener.calls,[])
    def test_failed_and_pending_attempts_cannot_resume(self):
        session,target,_=self.run_capture(Response(b'abc'))
        with self.assertRaises(ValueError):session.fetch_into(SOURCE,'column_chunks',4,8,target)
        capture=Path(self.tmp.name)/'capture'
        with self.assertRaisesRegex(ValueError,'clean open'):c.RangeSession(plan(),capture,resume=True)
        session.checkpoint('OPEN_REQUEST_PENDING')
        with self.assertRaisesRegex(ValueError,'clean open'):c.RangeSession(plan(),capture,resume=True)
    def test_resume_rejects_changed_plan_and_expired_deadline(self):
        session,_,_=self.run_capture(Response());capture=Path(self.tmp.name)/'capture'
        with self.assertRaisesRegex(ValueError,'plan differs'):c.RangeSession(plan(requests=11),capture,resume=True)
        prior=json.loads((capture/'session.json').read_text())
        prior['started_utc']=(datetime.now(timezone.utc)-timedelta(seconds=61)).isoformat()
        c.save(capture/'session.json',prior)
        with self.assertRaisesRegex(ValueError,'deadline'):c.RangeSession(plan(),capture,resume=True)
    def test_resume_rejects_unaccounted_bytes(self):
        session,target,_=self.run_capture(Response())
        session.fetch_into(SOURCE,'column_chunks',4,8,target);capture=Path(self.tmp.name)/'capture'
        prior=json.loads((capture/'session.json').read_text());prior['retained_response_bytes']=0
        c.save(capture/'session.json',prior)
        with self.assertRaisesRegex(ValueError,'byte accounting'):c.RangeSession(plan(),capture,resume=True)
    def cached_reader(self):
        session,_,_=self.run_capture(Response());cache=Path(self.tmp.name)/'cache'
        reader=c.SourceReader(SOURCE,session,cache,None,None);reader._load_cache()
        record=session.fetch_into(SOURCE,'column_chunks',4,8,reader.path)
        reader.ranges.append(record);reader._persist()
        return reader,session,cache
    def test_cache_cannot_reset_attempt_budget(self):
        reader,_,cache=self.cached_reader()
        fresh=c.RangeSession(plan(),Path(self.tmp.name)/'new_capture',opener=Opener(Response()))
        with self.assertRaisesRegex(ValueError,'attempt differs'):
            c.SourceReader(SOURCE,fresh,cache,None,None)._load_cache()
    def test_cache_receipt_tampering_is_rejected_without_body_change(self):
        reader,session,cache=self.cached_reader()
        value=json.loads(reader.cache_manifest.read_text())
        value['ranges'][0]['response_url']='https://example.invalid/changed'
        c.save(reader.cache_manifest,value)
        with self.assertRaisesRegex(ValueError,'charged capture'):
            c.SourceReader(SOURCE,session,cache,None,None)._load_cache()
    def test_cache_byte_tampering_is_rejected_with_original_receipt(self):
        reader,session,cache=self.cached_reader()
        with reader.path.open('r+b') as handle:handle.seek(4);handle.write(b'X')
        with self.assertRaisesRegex(ValueError,'bytes changed'):
            c.SourceReader(SOURCE,session,cache,None,None)._load_cache()
    def test_crash_before_cache_index_write_recovers_only_charged_range(self):
        session,_,_=self.run_capture(Response());cache=Path(self.tmp.name)/'cache'
        reader=c.SourceReader(SOURCE,session,cache,None,None);reader._load_cache()
        session.fetch_into(SOURCE,'column_chunks',4,8,reader.path)
        self.assertEqual(json.loads(reader.cache_manifest.read_text())['ranges'],[])
        recovered=c.SourceReader(SOURCE,session,cache,None,None);recovered._load_cache()
        self.assertEqual(recovered._read_exact(4,8),b'abcdefgh')
        self.assertEqual(len(recovered.ranges),1);self.assertEqual(session.bytes,8)
    def test_live_failed_attempt_cannot_issue_next_request(self):
        session,target,opener=self.run_capture(Response(b'abc'))
        with self.assertRaises(ValueError):session.fetch_into(SOURCE,'column_chunks',4,8,target)
        opener.response=Response()
        with self.assertRaisesRegex(ValueError,'failed|closed|active|open'):
            session.fetch_into(SOURCE,'column_chunks',4,8,target)
        self.assertEqual(len(opener.calls),1)
    def test_slow_final_read_cannot_be_accepted_after_wall_deadline(self):
        response=Response();session,target,_=self.run_capture(response)
        original_read=response.read
        def slow_read(n):
            body=original_read(n);session.started-=61;return body
        response.read=slow_read
        with self.assertRaisesRegex(ValueError,'wall'):session.fetch_into(SOURCE,'column_chunks',4,8,target)
        self.assertFalse(session.requests[0]['transport_ok'])
        self.assertEqual(session.bytes,8)

if __name__=='__main__':
    unittest.main()
