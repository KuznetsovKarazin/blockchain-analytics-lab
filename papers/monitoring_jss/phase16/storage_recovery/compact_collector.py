#!/usr/bin/env python3
"""Candidate ENOSPC recovery: immutable response blobs, never sparse Parquet copies.

Real-byte construction is permitted only after the separately validated current
resource-recovery amendment. A1's unresolved final response remains unknown.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import bisect
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
HELPER = HERE.parent/'continuation'/'collector.py'
HELPER_SHA256 = 'bf774e6f6658a8e1607d9bcd494bdf59d91359d78caef3a50aa4c0eb09c537b3'
if hashlib.sha256(HELPER.read_bytes()).hexdigest() != HELPER_SHA256:
    raise ValueError('pinned receipt-validation helper changed')
spec = importlib.util.spec_from_file_location('phase16_pinned_receipt_helpers', HELPER)
helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
base = helper.base
canonical, digest, need, save, identity, file_sha = base.canonical, base.digest, base.need, base.save, base.identity, base.file_sha
integer, sha_value, utc, relative = helper.integer, helper.sha_value, helper.utc, helper.relative
PINNED_RUNTIME_ROOT = Path('/tmp/article2_phase16_runtime_159bf77d8682/attempt2')
PINNED_PARENT_ROOT = PINNED_RUNTIME_ROOT.parent/'attempt1'
TOTAL_WALL = 14400
MIN_FREE_BYTES = 64 * 1024 * 1024
FORENSIC_NAMES = {'metadata_inventory','allocation_review','path_relocation',
                  'external_resource_failure_attestation','accepted_range_review'}


def stat_key(value):
    return (value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)


class StrictIntervalFile(io.RawIOBase):
    """Read only original offsets fully covered by authenticated immutable blobs."""
    def __init__(self, descriptor_path, verified_blobs=None):
        super().__init__()
        self.descriptor_path = Path(descriptor_path)
        value = json.loads(self.descriptor_path.read_bytes())
        need(value['schema_version'] == 'article2_phase16_compact_source_v1'
             and value['storage_kind'] == 'compact_descriptor', 'compact descriptor schema')
        self.source = identity(value['source']); self.size = self.source['size_bytes']
        need(value['source_id'] == digest(self.source) and value['logical_size_bytes'] == self.size,
             'compact logical source identity')
        self.segments = value['segments']; self.starts = []; self.position = 0
        self.verified_blobs = {} if verified_blobs is None else verified_blobs
        previous_end = 0; seen = set()
        for segment in self.segments:
            start, length = integer(segment['start']), integer(segment['length'], 1)
            need(start >= previous_end and start+length <= self.size, 'overlapping/outside compact interval')
            previous_end = start+length; self.starts.append(start)
            key = (segment['origin_attempt_id'], segment['origin_ordinal'])
            need(key not in seen, 'duplicate interval origin'); seen.add(key)
            sha_value(segment['origin_attempt_id']); integer(segment['origin_ordinal'], 1)
            sha_value(segment['receipt_sha256'])
            path = self.descriptor_path.parent/relative(segment['blob_path'])
            need(path.resolve().is_relative_to(self.descriptor_path.parent.resolve())
                 and path.is_file() and path.stat().st_size == length, 'compact original blob differs')
            expected=sha_value(segment['blob_sha256']);key=str(path.resolve());before=stat_key(path.stat())
            if key in self.verified_blobs:
                need(self.verified_blobs[key]==(before,expected),'verified immutable blob identity changed')
            else:
                need(file_sha(path)==expected and stat_key(path.stat())==before,'compact original blob differs')
                self.verified_blobs[key]=(before,expected)

    def readable(self): return True
    def seekable(self): return True
    def writable(self): return False
    def tell(self): self._checkClosed(); return self.position

    def seek(self, offset, whence=0):
        self._checkClosed(); need(type(offset) is int and whence in (0,1,2), 'invalid compact seek')
        value = offset if whence == 0 else (self.position+offset if whence == 1 else self.size+offset)
        need(value >= 0, 'negative compact seek'); self.position = value; return value

    def _pieces(self, start, end):
        if start == end: return []
        i = max(0, bisect.bisect_right(self.starts, start)-1); cursor = start; pieces = []
        while cursor < end:
            need(i < len(self.segments), 'UNAVAILABLE_HOLE')
            segment = self.segments[i]; a, b = segment['start'], segment['start']+segment['length']
            need(a <= cursor < b, 'UNAVAILABLE_HOLE')
            finish = min(end,b); pieces.append((segment,cursor-a,finish-cursor)); cursor = finish; i += 1
        return pieces

    def readinto(self, target):
        self._checkClosed(); view = memoryview(target).cast('B')
        end = min(self.size, self.position+len(view))
        if self.position >= self.size: return 0
        pieces = self._pieces(self.position,end)  # Check all coverage before returning any prefix.
        done = 0
        for segment, offset, count in pieces:
            path = self.descriptor_path.parent/segment['blob_path']
            expected_stat,expected_sha=self.verified_blobs[str(path.resolve())]
            need(expected_sha==segment['blob_sha256'] and stat_key(path.stat())==expected_stat,'verified immutable blob changed before read')
            with path.open('rb') as f:
                need(stat_key(os.fstat(f.fileno()))==expected_stat,'verified immutable blob replaced at open')
                f.seek(offset)
                while count:
                    n = f.readinto(view[done:done+min(1048576,count)])
                    need(n, 'verified compact blob truncated'); done += n; count -= n
                need(stat_key(os.fstat(f.fileno()))==expected_stat,'verified immutable blob changed during read')
        self.position = end; return done

    def read(self, n=-1):
        self._checkClosed(); need(type(n) is int, 'invalid compact read')
        length = max(0,self.size-self.position) if n < 0 else min(n,max(0,self.size-self.position))
        self._pieces(self.position,self.position+length)
        buffer = bytearray(length); got = self.readinto(buffer)
        need(got == length, 'short compact read'); return bytes(buffer)


class ResourceSession:
    """One prospective recovery; all inherited/pending costs remain charged."""
    def __init__(self, collector_plan, capture_dir, parent_capture_dir, *, parent_bindings,
                 recovery_plan_sha256, original_plan_sha256, forensic_bindings,
                 manual_reacquisition, pinned_runtime_root, repo=None, opener=None):
        self.runtime_root = Path(pinned_runtime_root).resolve()
        need(self.runtime_root == PINNED_RUNTIME_ROOT.resolve(), 'bulk runtime root differs from pinned external location')
        self.output = Path(capture_dir).resolve(); self.parent = Path(parent_capture_dir).resolve()
        need(self.output == self.runtime_root/'transport' and self.parent == PINNED_PARENT_ROOT.resolve(), 'recovery/parent location differs')
        need(not self.output.exists(), 'resource recovery capture already exists')
        self.storage_dir = self.runtime_root/'storage'
        need(not self.storage_dir.exists(), 'compact storage must be new')
        self.parent_bindings = dict(parent_bindings); self.forensic_bindings = dict(forensic_bindings)
        required = {'frozen_plan.json','transport/plan.json','transport/session.json','transport/requests.json',
                    'runtime_source_paths.json','transport/requests.json.pending','failure.json','collection_result.json'}
        need(required <= set(self.parent_bindings) and set(self.forensic_bindings) == FORENSIC_NAMES, 'missing forensic/parent bindings')
        self.assert_parent_unchanged()
        def bound(name):
            need(self.parent_bindings[name] is not None, 'required parent metadata absent')
            return json.loads((self.parent/relative(name)).read_bytes())
        self.parent_plan = bound('frozen_plan.json'); self.parent_session = prior = bound('transport/session.json')
        original_requests = bound('transport/requests.json')
        need(self.parent_bindings['failure.json'] is None and self.parent_bindings['collection_result.json'] is None,
             'resource failure must preserve absent producer finalization')
        need(self.parent_bindings['transport/requests.json.pending'] == hashlib.sha256(b'').hexdigest(),
             'failed checkpoint must preserve its empty original bytes')
        self.plan = collector_plan
        need(canonical(self.plan) == canonical(self.parent_plan['collector']) == canonical(bound('transport/plan.json')),
             'original collector plan differs')
        caps = self.plan['caps']
        need(self.plan['schema_version'] == 'article2_phase16_range_source_plan_v1' and self.plan['endpoint'] == base.ENDPOINT,
             'original collector endpoint/schema')
        need(caps['wall_seconds'] == 7200 and caps['requests'] == 5000 and caps['total_response_bytes'] == 17179869184
             and caps['max_range_bytes'] == 268435456 and caps['request_timeout_seconds'] == 60
             and caps['retries'] == 0 and caps['concurrency'] == 1, 'original caps changed')
        need(prior['schema_version'] == 'article2_phase16_range_capture_v1' and prior['status'] == 'OPEN_REQUEST_PENDING',
             'resource parent is not the preserved pending checkpoint')
        self.original_started_utc = prior['started_utc']; origin = utc(self.original_started_utc)
        need(prior['attempt_id'] == digest({'plan':digest(self.plan),'started_utc':prior['started_utc']})
             and prior['plan_canonical_sha256'] == digest(self.plan), 'parent attempt identity')
        self.parent_attempt_id = prior['attempt_id']; self.absolute_deadline_utc = (origin+timedelta(seconds=TOTAL_WALL)).isoformat()
        elapsed = (datetime.now(timezone.utc)-origin).total_seconds()
        need(0 <= elapsed < TOTAL_WALL and elapsed >= prior['wall_seconds_elapsed']-1, 'absolute recovery deadline/clock')
        need(len(original_requests) >= 1 and prior['request_count'] == len(original_requests) <= caps['requests'], 'parent request accounting')
        self.pending_parent_request = pending = original_requests[-1]
        need(pending['transport_ok'] is False and pending['response_bytes'] == 0
             and not ({'completed_utc','response_sha256','failure','http_status','response_url','etag','content_range','content_length','content_encoding'} & set(pending)),
             'last parent record must remain pending with unknown response, not a completed zero-body result')
        need(all(r['transport_ok'] is True for r in original_requests[:-1]), 'earlier parent request not successful')
        exact = {'parent_request_ordinal':pending['ordinal'],'source_key':pending['source']['key'],
                 'start':pending['start'],'length':pending['length']}
        need(canonical(manual_reacquisition) == canonical(exact), 'pending reacquisition must be exact and explicit')
        self.manual_reacquisition = exact
        self.parent_request_count = len(original_requests)
        self.parent_response_bytes = sum(integer(r['response_bytes']) for r in original_requests[:-1])
        need(prior['retained_response_bytes'] == self.parent_response_bytes, 'parent known retained-byte accounting')
        self.reserved_parent_pending_response_bytes = integer(pending['length'],1)
        need(self.parent_response_bytes+self.reserved_parent_pending_response_bytes <= caps['total_response_bytes'], 'parent conservative charge exceeds cap')
        repo = Path(repo) if repo is not None else REPO
        binding = self.parent_plan['source_union']; inventory_path = repo/relative(binding['path'])
        need(file_sha(inventory_path) == binding['sha256'], 'original source inventory changed')
        rows = json.loads(inventory_path.read_bytes())['objects']
        self.sources = {identity(s)['key']:identity(s) for s in rows}; need(len(self.sources) == len(rows), 'duplicate inventory source')
        intervals = {}
        for ordinal,r in enumerate(original_requests,1):
            source = identity(r['source']); start,length = integer(r['start']),integer(r['length'],1)
            need(type(r['ordinal']) is int and r['ordinal'] == ordinal and self.sources.get(source['key']) == source,
                 'parent original source/ordinal')
            need(length <= caps['max_range_bytes'] and start+length <= source['size_bytes']
                 and r['stored_offset'] == start and r['method'] == 'GET', 'parent range/storage')
            need(r['request_headers']['Range'] == f'bytes={start}-{start+length-1}'
                 and r['request_headers']['If-Match'] == source['etag_opaque']
                 and r['request_headers']['Accept-Encoding'] == 'identity', 'parent request headers')
            intervals.setdefault(source['key'],[]).append((start,start+length))
            if ordinal < self.parent_request_count: helper.accepted_receipt(r,source,origin,7200)
        for spans in intervals.values():
            spans.sort(); need(all(a[1] <= b[0] for a,b in zip(spans,spans[1:])), 'parent requested ranges overlap')
        self.original_plan_sha256 = sha_value(original_plan_sha256); self.recovery_plan_sha256 = sha_value(recovery_plan_sha256)
        self.caps = {**caps,'wall_seconds':TOTAL_WALL}; self.requests = list(original_requests); self.bytes = self.parent_response_bytes
        self.started_utc = base.stamp(); self.stage_started = time.monotonic()
        self.started = self.stage_started-(datetime.now(timezone.utc)-origin).total_seconds()
        self.attempt_id = digest({'parent_attempt_id':self.parent_attempt_id,'parent_session_sha256':self.parent_bindings['transport/session.json'],
                                 'recovery_plan_sha256':self.recovery_plan_sha256,'started_utc':self.started_utc})
        self.failed=False; self.inflight=False; self.manual_reacquisition_count=0; self.parent_bytes_verified=False
        self.reused_sources=[]; self.blobs={}; self.verified_blob_cache={}; self._active_manual=False
        self.opener=opener or base.urllib.request.build_opener(base.NoRedirect())
        self.output.mkdir(parents=True,exist_ok=False); self.storage_dir.mkdir()
        save(self.output/'plan.json',self.plan);save(self.output/'parent_bindings.json',self.parent_bindings)
        save(self.output/'forensic_bindings.json',self.forensic_bindings)
        (self.output/'inherited_requests.json').write_bytes((self.parent/'transport/requests.json').read_bytes())
        paths = {} if self.parent_bindings['runtime_source_paths.json'] is None else bound('runtime_source_paths.json')
        try:
            for r in original_requests[:-1]:
                need(time.monotonic()-self.started<TOTAL_WALL,'absolute wall during accepted-range import')
                source=r['source'];path=Path(paths.get(source['key'],self.parent/'cache'/digest(source)/'source.parquet')).resolve()
                need(path.is_relative_to(self.parent) and path.is_file() and path.stat().st_size==source['size_bytes'], 'parent canonical source location/size')
                data=bytearray(r['length']);view=memoryview(data);done=0;h=hashlib.sha256()
                with path.open('rb') as f:
                    f.seek(r['start'])
                    while done<len(data):
                        n=f.readinto(view[done:done+min(1048576,len(data)-done)]);need(n,'parent range truncated')
                        h.update(view[done:done+n]);done+=n
                need(h.hexdigest()==r['response_sha256'],'parent accepted range hash differs')
                self.blobs[r['ordinal']]=self._write_blob(source,self.parent_attempt_id,r['ordinal'],view,r['response_sha256'],True)
                view.release();del data
            self.parent_bytes_verified=True
            for key in {r['source']['key'] for r in original_requests}:self.write_descriptor(self.sources[key])
            self.assert_parent_unchanged();self.checkpoint('OPEN')
        except Exception:
            self.failed=True;self.checkpoint('FAILED_PARENT_RANGE_IMPORT');raise

    @property
    def new_requests(self): return self.requests[self.parent_request_count:]
    @property
    def reserved_new_failed_or_pending_response_bytes(self):
        return sum(r['length']-r['response_bytes'] for r in self.new_requests if r['transport_ok'] is not True)
    @property
    def cumulative_charged_response_bytes(self):
        return self.bytes+self.reserved_parent_pending_response_bytes+self.reserved_new_failed_or_pending_response_bytes

    def assert_parent_unchanged(self):
        for name,expected in self.parent_bindings.items():
            p=self.parent/relative(name);need(p.resolve().is_relative_to(self.parent),'parent binding escape')
            if expected is None:need(not p.exists(),'absent parent evidence appeared')
            else:need(p.is_file() and file_sha(p)==sha_value(expected),'parent evidence changed: '+name)
        for binding in self.forensic_bindings.values():
            need(set(binding)=={'path','sha256'},'forensic binding fields')
            p=Path(binding['path']);need(p.is_file() and file_sha(p)==sha_value(binding['sha256']),'forensic evidence changed')

    def _write_blob(self,source,origin,ordinal,data,expected,accepted):
        need(shutil.disk_usage(self.runtime_root).free >= len(data)+MIN_FREE_BYTES,'insufficient disk margin for compact blob')
        directory=self.storage_dir/digest(source)/('blobs' if accepted else 'forensic_blobs');directory.mkdir(parents=True,exist_ok=True)
        name=f'{origin}-{ordinal:06d}-{expected}.bin';final=directory/name;pending=directory/(name+'.writing')
        need(not final.exists() and not pending.exists(),'immutable blob already exists')
        with pending.open('xb') as f:
            need(f.write(data)==len(data),'short compact blob write');f.flush();os.fsync(f.fileno())
        need(pending.stat().st_size==len(data) and file_sha(pending)==expected,'written compact blob differs')
        pending.chmod(0o444);pending.rename(final)
        self.verified_blob_cache[str(final.resolve())]=(stat_key(final.stat()),expected)
        return {'path':str(final.relative_to(self.runtime_root)),'size_bytes':len(data),'sha256':expected}

    def _origin(self,r):
        return {'origin_attempt_id':self.parent_attempt_id if r['ordinal']<=self.parent_request_count else self.attempt_id,
                'origin_ordinal':r['ordinal'],'receipt':r,'blob':self.blobs[r['ordinal']]}

    def source_records(self,source):
        return [r for r in self.requests if r['source']==source and r['transport_ok'] is True and r['ordinal'] in self.blobs]

    def write_descriptor(self,source):
        directory=self.storage_dir/digest(source);directory.mkdir(parents=True,exist_ok=True)
        records=sorted(self.source_records(source),key=lambda r:r['start']);segments=[];end=0
        for r in records:
            need(r['start']>=end,'accepted compact intervals overlap');end=r['start']+r['length']
            origin=self._origin(r);blob=origin['blob'];path=self.runtime_root/relative(blob['path'])
            segments.append({'start':r['start'],'length':r['length'],'blob_path':str(path.relative_to(directory)),
                'blob_sha256':blob['sha256'],'origin_attempt_id':origin['origin_attempt_id'],
                'origin_ordinal':r['ordinal'],'receipt_sha256':digest(r)})
        path=directory/'source_storage.json'
        save(path,{'schema_version':'article2_phase16_compact_source_v1','storage_kind':'compact_descriptor',
            'source':source,'source_id':digest(source),'logical_size_bytes':source['size_bytes'],
            'attempt_id':self.attempt_id,'parent_attempt_id':self.parent_attempt_id,'segments':segments})
        return path

    def checkpoint(self,status):
        new=self.new_requests;newbytes=sum(r['response_bytes'] for r in new)
        save(self.output/'requests.json',new)
        save(self.output/'accepted_range_evidence.json',{'schema_version':'article2_phase16_compact_accepted_ranges_v1',
             'ranges':[self._origin(r) for r in self.requests if r['transport_ok'] is True and r['ordinal'] in self.blobs]})
        save(self.output/'session.json',{'schema_version':'article2_phase16_storage_recovery_capture_v1','status':status,
            'attempt_id':self.attempt_id,'parent_attempt_id':self.parent_attempt_id,'parent_persisted_status':'OPEN_REQUEST_PENDING',
            'parent_closure':'EXTERNALLY_ATTESTED_ENOSPC_EXIT_WITH_UNRESOLVED_FINAL_RESPONSE',
            'original_started_utc':self.original_started_utc,'started_utc':self.started_utc,'updated_utc':base.stamp(),
            'absolute_deadline_utc':self.absolute_deadline_utc,'recovery_plan_sha256':self.recovery_plan_sha256,
            'original_accepted_plan_sha256':self.original_plan_sha256,'original_collector_plan_canonical_sha256':digest(self.plan),
            'parent_bindings_canonical_sha256':digest(self.parent_bindings),'forensic_bindings_canonical_sha256':digest(self.forensic_bindings),
            'inherited_request_count':self.parent_request_count,'new_request_count':len(new),'cumulative_request_count':len(self.requests),
            'inherited_response_bytes':self.parent_response_bytes,'new_response_bytes':newbytes,'cumulative_response_bytes':self.bytes,
            'response_byte_count_scope':'RECORDED_RETAINED_ONLY_PARENT_PENDING_UNKNOWN','parent_pending_response_bytes':None,
            'actual_cumulative_response_bytes_complete':False,'reserved_parent_pending_response_bytes':self.reserved_parent_pending_response_bytes,
            'reserved_new_failed_or_pending_response_bytes':self.reserved_new_failed_or_pending_response_bytes,
            'inherited_charged_response_bytes':self.parent_response_bytes+self.reserved_parent_pending_response_bytes,
            'new_charged_response_bytes':newbytes+self.reserved_new_failed_or_pending_response_bytes,
            'cumulative_charged_response_bytes':self.cumulative_charged_response_bytes,
            'response_budget_rule':'Known retained bytes plus full unresolved/failed/pending requested-range reservations; no complete wire-byte measurement.',
            'cumulative_wall_seconds_elapsed':time.monotonic()-self.started,'new_stage_wall_seconds_elapsed':time.monotonic()-self.stage_started,
            'effective_caps':self.caps,'automatic_retries':0,'manual_reacquisition':self.manual_reacquisition,
            'manual_reacquisition_count':self.manual_reacquisition_count,'cumulative_retry_count':self.manual_reacquisition_count,
            'parent_positive_bodies_verified':self.parent_bytes_verified,'parent_pending_range_imported':False,
            'runtime_root':str(self.runtime_root),'storage_kind':'IMMUTABLE_RANGE_BLOBS_STRICT_ARROW_VIEW',
            'cache_or_full_object_reuses':self.reused_sources,'inherited_cache_or_full_object_reuses':self.parent_session['cache_or_full_object_reuses']})

    def fetch_range(self,source,kind,start,length):
        source=identity(source);integer(start);integer(length,1)
        need(self.parent_bytes_verified and not self.failed and not self.inflight,'resource recovery is not ready/live')
        need(self.sources.get(source['key'])==source and start+length<=source['size_bytes']
             and source['size_bytes']<=self.caps['max_source_bytes'] and length<=self.caps['max_range_bytes'],'source/range cap')
        need(len(self.requests)<self.caps['requests'] and self.cumulative_charged_response_bytes+length<=self.caps['total_response_bytes'],
             'cumulative request/charged byte cap')
        remaining=TOTAL_WALL-(time.monotonic()-self.started);need(remaining>0,'absolute recovery deadline')
        need(shutil.disk_usage(self.runtime_root).free>=length+MIN_FREE_BYTES,'insufficient disk margin before GET')
        manual=self._active_manual
        if manual:
            p=self.pending_parent_request
            need(self.manual_reacquisition_count==0 and source==p['source'] and start==p['start'] and length==p['length'],
                 'manual pending reacquisition differs')
        for old in self.requests:
            if old['source']==source and start<old['start']+old['length'] and old['start']<start+length:
                need(manual and old is self.pending_parent_request,'GET overlaps previously attempted interval')
        headers={'Range':f'bytes={start}-{start+length-1}','If-Match':source['etag_opaque'],
                 'Accept':'application/octet-stream','Accept-Encoding':'identity','User-Agent':'Article2-compact-resource-recovery/1'}
        r={'ordinal':len(self.requests)+1,'source':source,'kind':kind,'method':'GET','request_headers':headers,
           'start':start,'length':length,'started_utc':base.stamp(),'transport_ok':False,'response_bytes':0,
           'received_bytes_known':0,'body_storage_kind':'immutable_blob','blob':None,'physical_blob_offset':0,
           'invalid_header_body_read':False,
           'origin_attempt_id':self.attempt_id,'requested_timeout_seconds':min(60,remaining),
           'resource_recovery_request_kind':'explicit_pending_reacquisition' if manual else 'previously_unrequested_range'}
        if manual:
            r['reacquisition_of']={'attempt_id':self.parent_attempt_id,'ordinal':self.pending_parent_request['ordinal']}
            self.manual_reacquisition_count=1
        self.requests.append(r);self.inflight=True;self.checkpoint('OPEN_REQUEST_PENDING')
        got=0;h=hashlib.sha256();data=None;http_ok=False;error=None
        try:
            request=base.urllib.request.Request(source['url'],headers=headers)
            try:response=self.opener.open(request,timeout=r['requested_timeout_seconds'])
            except base.urllib.error.HTTPError as exc:response=exc
            with response:
                r.update(http_status=response.status,response_url=response.geturl(),etag=response.headers.get('ETag'),
                    content_range=response.headers.get('Content-Range'),content_length=response.headers.get('Content-Length'),
                    content_encoding=response.headers.get('Content-Encoding'))
                need(response.status==206 and response.geturl()==source['url'],'HTTP status/redirect')
                need(r['etag']==source['etag_opaque'],'ETag changed')
                need(r['content_range']==f'bytes {start}-{start+length-1}/{source["size_bytes"]}','Content-Range mismatch')
                need(r['content_length'] is not None and r['content_length'].isdigit() and int(r['content_length'])==length,'Content-Length mismatch')
                need(r['content_encoding'] in (None,'identity'),'encoded response')
                data=bytearray(length)
                while got<length:
                    need(time.monotonic()-self.started<TOTAL_WALL,'absolute wall before body read')
                    chunk=response.read(min(1048576,length-got))
                    if not chunk:break
                    need(len(chunk)<=length-got,'oversize response chunk')
                    data[got:got+len(chunk)]=chunk;h.update(chunk);got+=len(chunk)
                    need(time.monotonic()-self.started<TOTAL_WALL,'absolute wall after body read')
                need(got==length,'truncated exact range')
            need(time.monotonic()-self.started<TOTAL_WALL,'absolute wall after response close');http_ok=True
        except Exception as exc:error=exc;r['failure']=type(exc).__name__+': '+str(exc)
        finally:
            r['received_bytes_known']=got;r['buffer_sha256']=h.hexdigest()
            if got:
                try:
                    view=memoryview(data)[:got]
                    blob=self._write_blob(source,self.attempt_id,r['ordinal'],view,h.hexdigest(),http_ok)
                    view.release();r['blob']=blob;r['response_bytes']=got;r['response_sha256']=h.hexdigest()
                    self.blobs[r['ordinal']]=blob
                except Exception as exc:
                    error=exc;http_ok=False;r['storage_failure']=type(exc).__name__+': '+str(exc)
            else:r['response_sha256']=hashlib.sha256(b'').hexdigest()
            if http_ok and time.monotonic()-self.started>=TOTAL_WALL:
                error=ValueError('absolute wall after durable body storage');r['failure']='ValueError: '+str(error);http_ok=False
            r['transport_ok']=http_ok;r['completed_utc']=base.stamp()
            self.bytes+=r['response_bytes'];self.inflight=False;self.failed=not http_ok;self._active_manual=False
            self.write_descriptor(source);self.checkpoint('OPEN' if http_ok else 'FAILED_RESOURCE_RECOVERY_GET')
        if error is not None:raise error
        need(http_ok,'resource response was not accepted');return r

    def reacquire_pending_range(self):
        need(self.manual_reacquisition_count==0,'manual pending reacquisition already consumed')
        self._active_manual=True;p=self.pending_parent_request
        try:return self.fetch_range(p['source'],'explicit_pending_reacquisition',p['start'],p['length'])
        finally:self._active_manual=False

    def close(self,status='COMPLETE'):
        need(not self.inflight,'active request cannot close')
        if status=='COMPLETE':
            need(not self.failed and self.manual_reacquisition_count==1 and all(r['transport_ok'] for r in self.new_requests),'incomplete/failed recovery')
            need(time.monotonic()-self.started<=TOTAL_WALL and self.cumulative_charged_response_bytes<=self.caps['total_response_bytes'],
                 'cumulative deadline/charged byte cap at close')
            self.assert_parent_unchanged()
        self.checkpoint(status)
        if status=='COMPLETE' and time.monotonic()-self.started>TOTAL_WALL:
            self.failed=True;self.checkpoint('FAILED_ABSOLUTE_WALL_AT_CLOSE');raise ValueError('absolute wall during final checkpoint')


class CompactSourceReader(base.SourceReader):
    def __init__(self,source,session,storage_dir,pa,pq,reuse=None):
        source=identity(source)
        need(Path(storage_dir).resolve()==session.storage_dir.resolve() and session.sources.get(source['key'])==source,
             'compact storage/source differs')
        if reuse is not None:need(not any(r['source']==source for r in session.requests),'whole reuse cannot replace attempted ranges')
        self.source=source;self.session=session;self.pa=pa;self.pq=pq;self.source_id=digest(source)
        self.directory=session.storage_dir/self.source_id;self.directory.mkdir(parents=True,exist_ok=True)
        self.path=Path(reuse['path']) if reuse is not None else session.write_descriptor(source)
        self.storage_kind='verified_whole_object' if reuse is not None else 'compact_descriptor'
        self.reuse=reuse;self.ranges=[];self.metadata=self.schema=None;self.described_chunks=[];self.reads=[];self.footer_start=None;self._opened=False

    def _persist(self):
        if self.reuse is None:self.path=self.session.write_descriptor(self.source)
    def _load_cache(self):
        self.ranges=self.session.source_records(self.source);self._persist()
    def _ensure_ranges(self,spans,kind):
        if self.reuse is not None:return
        for start,end in base.missing_ranges(spans,[[r['start'],r['start']+r['length']] for r in self.ranges]):
            while start<end:
                length=min(end-start,self.session.caps['max_range_bytes'])
                self.ranges.append(self.session.fetch_range(self.source,kind,start,length));self._persist();start+=length
    def _read_exact(self,start,length):
        if self.reuse is not None:
            with self.path.open('rb') as f:f.seek(start);raw=f.read(length)
        else:
            with StrictIntervalFile(self.path,self.session.verified_blob_cache) as f:f.seek(start);raw=f.read(length)
        need(len(raw)==length,'short original compact read');return raw
    def open_parquet(self):
        need(self._opened,'compact metadata not opened')
        if self.reuse is not None:return self.pq.ParquetFile(str(self.path),pre_buffer=False,memory_map=False,buffer_size=0)
        view=StrictIntervalFile(self.path,self.session.verified_blob_cache);handle=self.pa.PythonFile(view,mode='r')
        pf=self.pq.ParquetFile(handle,metadata=self.metadata,pre_buffer=False,memory_map=False,buffer_size=0)
        pf._compact_handle=handle;pf._compact_view=view;return pf
    def read_row_group(self,index,columns):
        self.ensure_columns(columns,[index]);pf=self.open_parquet()
        try:table=pf.read_row_group(index,columns=list(columns),use_threads=False)
        finally:pf.close()
        need(table.num_rows==self.metadata.row_group(index).num_rows and set(table.column_names)==set(columns),'compact decoded shape differs')
        self.reads.append({'row_group':index,'columns':list(columns),'rows':table.num_rows});return table
    def storage_descriptor(self):return {'storage_kind':self.storage_kind,'path':str(self.path.resolve())}
    def manifest(self):
        value=super().manifest();value['schema_version']='article2_phase16_compact_projected_source_manifest_v1'
        value['storage_kind']=self.storage_kind;value['descriptor_file_name']=None if self.reuse is not None else self.path.name
        value['descriptor_sha256']=None if self.reuse is not None else file_sha(self.path)
        value['evidence_origins']=[self.session._origin(r) for r in self.ranges]
        value['inherited_ranges']=[self.session._origin(r) for r in self.ranges if r['ordinal']<self.session.parent_request_count]
        value['new_ranges']=[r for r in self.ranges if r['ordinal']>self.session.parent_request_count]
        return value
