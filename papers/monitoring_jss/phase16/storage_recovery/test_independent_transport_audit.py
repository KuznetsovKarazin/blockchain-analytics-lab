"""New independent faults; invented bytes/metadata only, never actual captures."""
import copy
from datetime import datetime,timedelta,timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('independent_storage_transport',HERE/'independent_transport_audit.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

def stamp(n):return (datetime(2030,1,1,tzinfo=timezone.utc)+timedelta(seconds=n)).isoformat()
def put(path,value):path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value));return path

def source(size=400000):
    key='v1.0/eth/transactions/date=2030-01-01/part-test.parquet'
    return {'table':'transactions','day_utc':'2030-01-01','key':key,'size_bytes':size,'etag_opaque':'"invented"','url':a.ENDPOINT+key}

def receipt(s,ordinal,start,length,begin,end=None,body=None):
    r={'ordinal':ordinal,'source':s,'start':start,'length':length,'method':'GET',
       'request_headers':{'Range':f'bytes={start}-{start+length-1}','If-Match':s['etag_opaque'],'Accept-Encoding':'identity'},
       'started_utc':stamp(begin),'transport_ok':end is not None,'response_bytes':length if end is not None else 0}
    if end is not None:r.update(completed_utc=stamp(end),response_sha256=hashlib.sha256(body if body is not None else b'x'*length).hexdigest(),
       http_status=206,response_url=s['url'],etag=s['etag_opaque'],content_range=f'bytes {start}-{start+length-1}/{s["size_bytes"]}',
       content_length=str(length),content_encoding=None,invalid_header_body_read=False)
    return r

def fixture():
    s=source();parent=[receipt(s,i,i-1,1,i,i+.1) for i in range(1,730)]
    parent.append(receipt(s,730,729,275821,800))
    old={'schema_version':'article2_phase16_range_capture_v1','status':'OPEN_REQUEST_PENDING','request_count':730,
         'retained_response_bytes':729,'attempt_id':'a'*64,'started_utc':stamp(0),'updated_utc':stamp(800)}
    r=receipt(s,731,729,275821,1001,1002);r.update(received_bytes_known=275821,origin_attempt_id='b'*64,body_storage_kind='immutable_blob',physical_blob_offset=0,
        resource_recovery_request_kind='explicit_pending_reacquisition',reacquisition_of={'attempt_id':old['attempt_id'],'ordinal':730})
    manual={'parent_request_ordinal':730,'source_key':s['key'],'start':729,'length':275821}
    session={'status':'COMPLETE','parent_attempt_id':old['attempt_id'],'attempt_id':'b'*64,'original_started_utc':stamp(0),
      'started_utc':stamp(1000),'updated_utc':stamp(1003),'cumulative_wall_seconds_elapsed':1003,'absolute_deadline_utc':stamp(14400),
      'inherited_request_count':730,'new_request_count':1,'cumulative_request_count':731,'inherited_response_bytes':729,
      'new_response_bytes':275821,'cumulative_response_bytes':276550,'reserved_parent_pending_response_bytes':275821,
      'reserved_new_failed_or_pending_response_bytes':0,'inherited_charged_response_bytes':276550,'new_charged_response_bytes':275821,
      'cumulative_charged_response_bytes':552371,'parent_pending_response_bytes':None,'actual_cumulative_response_bytes_complete':False,
      'response_byte_count_scope':'RECORDED_RETAINED_ONLY_PARENT_PENDING_UNKNOWN','automatic_retries':0,'manual_reacquisition_count':1,'cumulative_retry_count':1}
    caps={'requests':5000,'total_response_bytes':16*1024**3,'wall_seconds':7200,'max_source_bytes':1000000,'max_range_bytes':300000}
    return [parent,[r],old,session,{s['key']:s},caps,stamp(900),manual]

class LedgerTests(unittest.TestCase):
    def test_known_and_unknown_costs_remain_distinct(self):
        v=a.validate_cost_ledgers(*fixture());self.assertEqual(v['known_cumulative_response_bytes'],276550)
        self.assertEqual(v['cumulative_charged_response_bytes'],552371);self.assertIsNone(v['parent_pending_response_bytes'])
        self.assertEqual(len(v['accepted_origins']),730);self.assertNotIn(730,[x['origin_ordinal'] for x in v['accepted_origins']])
    def test_pending_zero_cannot_be_reported_as_measured_zero(self):
        f=fixture();f[3]['parent_pending_response_bytes']=0
        with self.assertRaisesRegex(ValueError,'unknown original bytes'):a.validate_cost_ledgers(*f)
    def test_reservation_cannot_disappear(self):
        f=fixture();f[3]['reserved_parent_pending_response_bytes']=0
        with self.assertRaisesRegex(ValueError,'reservation'):a.validate_cost_ledgers(*f)
    def test_complete_cost_flag_cannot_be_true(self):
        f=fixture();f[3]['actual_cumulative_response_bytes_complete']=True
        with self.assertRaisesRegex(ValueError,'unknown original bytes'):a.validate_cost_ledgers(*f)
    def test_pending_response_header_is_not_success_evidence(self):
        f=fixture();f[0][-1]['http_status']=206
        with self.assertRaisesRegex(ValueError,'placeholder was promoted'):a.validate_cost_ledgers(*f)
    def test_pending_get_cannot_start_at_original_deadline(self):
        f=fixture();f[0][-1]['started_utc']=stamp(7200);f[2]['updated_utc']=stamp(7200)
        with self.assertRaisesRegex(ValueError,'pending original request chronology'):a.validate_cost_ledgers(*f)
    def test_manual_range_must_be_exact(self):
        f=fixture();f[7]['length']-=1
        with self.assertRaisesRegex(ValueError,'manual pending range differs'):a.validate_cost_ledgers(*f)
    def test_reacquisition_is_explicit_first_request(self):
        f=fixture();f[1][0]['resource_recovery_request_kind']='previously_unrequested_range'
        with self.assertRaisesRegex(ValueError,'one explicitly authorized'):a.validate_cost_ledgers(*f)
    def test_original_response_identity_must_match(self):
        f=fixture();f[0][50]['etag']='"changed"'
        with self.assertRaisesRegex(ValueError,'identity differs'):a.validate_cost_ledgers(*f)
    def test_original_prefix_cannot_omit_receipt(self):
        f=fixture();f[0].pop(10)
        with self.assertRaisesRegex(ValueError,'population differs'):a.validate_cost_ledgers(*f)
    def test_full_reservation_blocks_apparently_affordable_get(self):
        f=fixture();f[5]['total_response_bytes']=500000
        with patch.object(a,'BYTE_LIMIT',500000):
            with self.assertRaisesRegex(ValueError,'full request reservation'):a.validate_cost_ledgers(*f)
    def test_complete_preparation_cannot_finish_after_deadline(self):
        f=fixture();f[3]['updated_utc']=stamp(14401);f[3]['cumulative_wall_seconds_elapsed']=14401
        with self.assertRaisesRegex(ValueError,'final preparation'):a.validate_cost_ledgers(*f)
    def test_monotonic_and_utc_completion_must_agree(self):
        f=fixture();f[3]['cumulative_wall_seconds_elapsed']=1006
        with self.assertRaisesRegex(ValueError,'final preparation'):a.validate_cost_ledgers(*f)
    def test_new_receipt_late_body_rejected(self):
        f=fixture();f[1][0]['completed_utc']=stamp(14401)
        with self.assertRaisesRegex(ValueError,'outside declared'):a.validate_cost_ledgers(*f)
    def test_success_with_failure_marker_rejected(self):
        f=fixture();f[1][0]['failure']='OSError: invented'
        with self.assertRaisesRegex(ValueError,'not fully successful'):a.validate_cost_ledgers(*f)

    def test_success_cannot_hide_blob_storage_failure(self):
        f=fixture();f[1][0]['storage_failure']='OSError: invented'
        with self.assertRaisesRegex(ValueError,'storage misrepresented'):a.validate_cost_ledgers(*f)

class CompactTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='invented-compact-audit-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.s=source(24);self.parent='a'*64;self.attempt='b'*64
        self.descriptor=self.root/'storage'/a.digest(self.s)/'source_storage.json';self.rows=[];segments=[]
        pieces=[(0,b'PAR1'),(8,b'footerxx'+(8).to_bytes(4,'little')+b'PAR1')]
        for i,(start,body) in enumerate(pieces,1):
            digest=hashlib.sha256(body).hexdigest();blob=self.descriptor.parent/'blobs'/f'{self.parent}-{i:06d}-{digest}.bin'
            blob.parent.mkdir(parents=True,exist_ok=True);blob.write_bytes(body);blob.chmod(0o444)
            r=receipt(self.s,i,start,len(body),i,i+.1,body)
            self.rows.append({'origin_attempt_id':self.parent,'origin_ordinal':i,'receipt':r,
                'blob':{'path':str(blob.relative_to(self.root)),'size_bytes':len(body),'sha256':digest}})
            segments.append({'start':start,'length':len(body),'blob_path':str(blob.relative_to(self.descriptor.parent)),
                'blob_sha256':digest,'origin_attempt_id':self.parent,'origin_ordinal':i,'receipt_sha256':a.digest(r)})
        self.d={'schema_version':'article2_phase16_compact_source_v1','storage_kind':'compact_descriptor',
            'source':self.s,'source_id':a.digest(self.s),'logical_size_bytes':24,'attempt_id':self.attempt,'parent_attempt_id':self.parent,'segments':segments}
        put(self.descriptor,self.d)
    def run_check(self):return a.verify_compact_descriptor(self.descriptor,self.s,self.rows,self.root,self.attempt,self.parent,1000)
    def test_disjoint_original_offsets_reconstruct_footer_without_holes(self):
        v=self.run_check();self.assertEqual(v['available_ranges'],[[0,4],[8,24]]);self.assertFalse(v['whole_source_sha256_verified'])
        self.assertEqual(v['original_footer_evidence']['footer_start'],8)
    def test_hole_read_fails_even_when_logical_offset_in_bounds(self):
        v=self.run_check()
        with self.assertRaisesRegex(ValueError,'unacquired hole'):a.strict_blob_read(v['verified_blobs'],0,9)
    def test_blob_modified_same_length_is_rejected(self):
        p=self.root/self.rows[0]['blob']['path'];p.chmod(0o644);p.write_bytes(b'FAKE');p.chmod(0o444)
        with self.assertRaisesRegex(ValueError,'bytes changed'):self.run_check()
    def test_writable_blob_is_rejected(self):
        (self.root/self.rows[0]['blob']['path']).chmod(0o644)
        with self.assertRaisesRegex(ValueError,'read-only'):self.run_check()
    def test_wrong_original_receipt_digest_is_rejected(self):
        self.d['segments'][0]['receipt_sha256']='0'*64;put(self.descriptor,self.d)
        with self.assertRaisesRegex(ValueError,'original accepted receipt'):self.run_check()
    def test_descriptor_path_escape_rejected(self):
        self.d['segments'][0]['blob_path']='../../escape.bin';put(self.descriptor,self.d)
        with self.assertRaisesRegex(ValueError,'unsafe relative path'):self.run_check()
    def test_wrapper_cannot_substitute_other_blob(self):
        self.rows[0]['blob']['path']=self.rows[1]['blob']['path']
        with self.assertRaisesRegex(ValueError,'wrapper/blob binding'):self.run_check()
    def test_original_pending_cannot_become_segment(self):
        self.rows[0]['receipt']['transport_ok']=False
        with self.assertRaisesRegex(ValueError,'original accepted receipt'):self.run_check()
    def test_descriptor_overlap_rejected(self):
        self.d['segments'][1]['start']=3;put(self.descriptor,self.d)
        with self.assertRaisesRegex(ValueError,'overlap'):self.run_check()
    def test_truncated_blob_rejected(self):
        p=self.root/self.rows[0]['blob']['path'];p.chmod(0o644);p.write_bytes(b'PAR');p.chmod(0o444)
        with self.assertRaisesRegex(ValueError,'exact-length'):self.run_check()

if __name__=='__main__':unittest.main(verbosity=2)
