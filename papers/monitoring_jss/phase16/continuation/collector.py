#!/usr/bin/env python3
"""CANDIDATE: one explicitly accepted, cumulative technical continuation.

No constructor or helper establishes scientific/prospective acceptance. The
continuation pipeline must validate both cases' amendment before invoking this
module on real evidence. Original acquisition code and A1 files remain intact.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
ORIGINAL = HERE.parent/'collector'/'range_collector.py'
ORIGINAL_SHA256 = '13e15e7b770ad40c2e8d286abceb8f7e380d946626b35d0186f43f0001be563f'
if hashlib.sha256(ORIGINAL.read_bytes()).hexdigest() != ORIGINAL_SHA256:
    raise ValueError('frozen original collector changed')
_spec = importlib.util.spec_from_file_location('phase16_original_range_collector', ORIGINAL)
base = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(base)
canonical, digest, need, save, identity, file_sha = base.canonical, base.digest, base.need, base.save, base.identity, base.file_sha
WALL_FAILURES = {'wall cap during range', 'wall cap after range read', 'wall cap after response close'}
TIMEOUT_MESSAGES = {'timed out', 'The read operation timed out'}
TIMEOUT_SIGNATURES = {('TimeoutError', x) for x in TIMEOUT_MESSAGES} | {
    ('URLError', '<urlopen error '+x+'>') for x in TIMEOUT_MESSAGES}
TOTAL_WALL = 14400


def utc(value):
    t = datetime.fromisoformat(value)
    need(t.tzinfo is not None, 'timestamp lacks timezone')
    return t.astimezone(timezone.utc)


def integer(value, minimum=0):
    need(type(value) is int and value >= minimum, 'invalid integer')
    return value


def sha_value(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'invalid SHA256')
    return value


def relative(value):
    need(type(value) is str and value and '\\' not in value and ':' not in value, 'unsafe parent binding')
    path = Path(value)
    need(not path.is_absolute() and '..' not in path.parts, 'unsafe parent binding')
    return path


def accepted_receipt(record, source, origin_start, original_wall):
    start, length = integer(record['start']), integer(record['length'], 1)
    need(record['transport_ok'] is True and record['response_bytes'] == length
         and record['method'] == 'GET' and record['http_status'] == 206
         and record['response_url'] == source['url'] and record['etag'] == source['etag_opaque']
         and record['content_encoding'] in (None, 'identity'), 'unaccepted inherited response')
    need(record['content_range'] == f'bytes {start}-{start+length-1}/{source["size_bytes"]}'
         and type(record['content_length']) is str and record['content_length'].isdigit()
         and int(record['content_length']) == length and not record.get('failure'), 'inherited response headers')
    begin, end = utc(record['started_utc']), utc(record['completed_utc'])
    need(origin_start <= begin <= end <= origin_start+timedelta(seconds=original_wall), 'inherited response outside original deadline')
    sha_value(record['response_sha256'])


def deadline_associated_timeout(record, failure, prior, origin):
    """Narrow operational association, never proof of an unrecorded timeout arg."""
    need((failure['error_type'], failure['error']) in TIMEOUT_SIGNATURES
         and record.get('failure') == failure['error_type']+': '+failure['error'], 'unrecognized deadline-associated timeout')
    begin, end, closed = utc(record['started_utc']), utc(record['completed_utc']), utc(prior['updated_utc'])
    need(origin+timedelta(seconds=7140) <= begin < origin+timedelta(seconds=7200) <= end <= closed,
         'timeout is not the final-deadline interval')
    source = record['source']; start, length = record['start'], record['length']
    fields = {'http_status','response_url','etag','content_range','content_length','content_encoding'}
    present = set(record) & fields
    if present:
        need(present == fields and record['http_status'] == 206 and record['response_url'] == source['url']
             and record['etag'] == source['etag_opaque'] and record['content_encoding'] in (None,'identity')
             and record['content_range'] == f'bytes {start}-{start+length-1}/{source["size_bytes"]}'
             and type(record['content_length']) is str and record['content_length'].isdigit()
             and int(record['content_length']) == length, 'timeout response contains invalid/incomplete headers')
    else:
        need(record['response_bytes'] == 0, 'timeout body lacks accepted response headers')


class ContinuationSession(base.RangeSession):
    """A2 only; internal counters include all A1 attempts and retained bytes.

    ``requests`` is the cumulative in-memory cost ledger needed by the unchanged
    original fetch method. ``new_requests`` and persisted requests.json are A2
    only. Original A1 receipts live separately and are never rewritten.
    """
    def __init__(self, collector_plan, capture_dir, parent_capture_dir, *, parent_bindings,
                 continuation_plan_sha256, manual_reacquisition=None, original_plan_sha256=None, opener=None, repo=None):
        self.output, self.parent = Path(capture_dir), Path(parent_capture_dir)
        need(not self.output.resolve().is_relative_to(self.parent.resolve())
             and not self.parent.resolve().is_relative_to(self.output.resolve()), 'continuation must be outside immutable parent')
        need(not self.output.exists(), 'continuation capture already exists')
        self.parent_bindings = dict(parent_bindings)
        required = {'frozen_plan.json','transport/plan.json','transport/session.json','transport/requests.json','runtime_source_paths.json'}
        need(required <= set(self.parent_bindings), 'missing parent evidence bindings')
        self.assert_parent_unchanged()
        def bound(name):
            need(name in self.parent_bindings and self.parent_bindings[name] is not None, 'required parent evidence absent')
            return json.loads((self.parent/relative(name)).read_bytes())
        self.parent_plan = bound('frozen_plan.json'); prior = bound('transport/session.json')
        self.original_plan_sha256 = None if original_plan_sha256 is None else sha_value(original_plan_sha256)
        self.parent_session = prior; original_requests = bound('transport/requests.json')
        self.plan = collector_plan
        need(canonical(self.plan) == canonical(self.parent_plan['collector']) == canonical(bound('transport/plan.json')),
             'original collector plan changed')
        caps = self.plan['caps']
        need(self.plan['schema_version'] == 'article2_phase16_range_source_plan_v1' and self.plan['endpoint'] == base.ENDPOINT,
             'original collector schema/endpoint')
        need(caps['wall_seconds'] == 7200 and caps['requests'] == 5000 and caps['total_response_bytes'] == 17179869184
             and caps['retries'] == 0 and caps['concurrency'] == 1 and caps['max_range_bytes'] == 268435456
             and caps['request_timeout_seconds'] == 60, 'original transport limits differ')
        need(prior['schema_version'] == 'article2_phase16_range_capture_v1', 'only an original A1 can be continued')
        self.original_started_utc = prior['started_utc']; origin = utc(self.original_started_utc)
        need(prior['attempt_id'] == digest({'plan': digest(self.plan), 'started_utc': prior['started_utc']})
             and prior['plan_canonical_sha256'] == digest(self.plan), 'parent attempt binding')
        self.parent_attempt_id = prior['attempt_id']
        self.absolute_deadline_utc = (origin+timedelta(seconds=TOTAL_WALL)).isoformat()
        elapsed = (datetime.now(timezone.utc)-origin).total_seconds()
        need(math.isfinite(prior['wall_seconds_elapsed']) and elapsed >= prior['wall_seconds_elapsed']-1
             and 7200 <= elapsed < TOTAL_WALL, 'parent clock or cumulative deadline')
        need(abs((utc(prior['updated_utc'])-origin).total_seconds()-prior['wall_seconds_elapsed']) <= 2,
             'parent UTC/monotonic closure clocks differ')
        need(prior['request_count'] == len(original_requests) <= caps['requests'], 'parent request accounting')
        need(prior['retained_response_bytes'] == sum(integer(r['response_bytes']) for r in original_requests)
             <= caps['total_response_bytes'], 'parent byte accounting')
        repo = Path(repo) if repo is not None else REPO
        inventory_binding = self.parent_plan['source_union']; inventory_path = repo/relative(inventory_binding['path'])
        need(file_sha(inventory_path) == inventory_binding['sha256'], 'original source inventory changed')
        rows = json.loads(inventory_path.read_bytes())['objects']
        self.sources = {identity(s)['key']: identity(s) for s in rows}
        need(len(self.sources) == len(rows), 'duplicate source inventory')
        self.inherited_by_source = {}; failed = []
        attempted = {}
        for ordinal, r in enumerate(original_requests, 1):
            source = identity(r['source']); key = source['key']
            need(type(r['ordinal']) is int and r['ordinal'] == ordinal and type(r['transport_ok']) is bool
                 and self.sources.get(key) == source, 'parent request/source identity')
            start, length, received = integer(r['start']), integer(r['length'], 1), integer(r['response_bytes'])
            need(start+length <= source['size_bytes'] and length <= caps['max_range_bytes'] and received <= length,
                 'parent requested/received range bounds')
            need(r['method'] == 'GET' and r['stored_offset'] == start and Path(r['stored_file_name']).name == r['stored_file_name']
                 and r['request_headers']['If-Match'] == source['etag_opaque']
                 and r['request_headers']['Range'] == f'bytes={start}-{start+length-1}'
                 and r['request_headers']['Accept-Encoding'] == 'identity', 'parent request headers/storage')
            attempted.setdefault(key, []).append((start, start+length))
            if r['transport_ok'] is True:
                accepted_receipt(r, source, origin, 7200)
                self.inherited_by_source.setdefault(key, []).append(r)
            else:
                failed.append(r)
            if received:
                sha_value(r['response_sha256'])
        for intervals in attempted.values():
            intervals.sort(); need(all(a[1] <= b[0] for a,b in zip(intervals, intervals[1:])), 'parent requested ranges overlap')
        self.manual_reacquisition = manual_reacquisition
        self.failed_parent_request = None
        if prior['status'] == 'COMPLETE':
            result = bound('collection_result.json')
            need(result['status'] == 'COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT'
                 and self.original_plan_sha256 is not None and result['plan_sha256'] == self.original_plan_sha256
                 and prior['wall_seconds_elapsed'] > 7200 and not failed and manual_reacquisition is None,
                 'parent COMPLETE is not an exclusively final-wall-overrun case')
            self.eligibility = 'PRODUCER_COMPLETE_ORIGINAL_AUDIT_WALL_OVERRUN'
        else:
            result = bound('failure.json')
            need(prior['status'] == 'FAILED' and result['status'] == 'FAILED_NOT_ACCEPTED'
                 and prior['wall_seconds_elapsed'] >= 7200,
                 'parent failure is not a finalized wall expiry')
            if failed:
                need(len(failed) == 1 and failed[0] is original_requests[-1], 'only the final A1 GET may have failed')
                r = failed[0]
                if result['error_type'] in ('TimeoutError', 'URLError'):
                    deadline_associated_timeout(r, result, prior, origin)
                    self.eligibility = 'DEADLINE_ASSOCIATED_TIMEOUT_CAUSALITY_UNRESOLVED'
                else:
                    need(result['error_type'] == 'ValueError' and result['error'] in WALL_FAILURES
                         and r.get('failure') == 'ValueError: '+result['error']
                         and origin+timedelta(seconds=7200) <= utc(r['completed_utc']) <= utc(prior['updated_utc']),
                         'parent GET failure is not explicit wall expiry')
                    self.eligibility = 'FINAL_GET_EXPLICIT_WALL_FAILURE'
                exact = {'parent_request_ordinal': r['ordinal'], 'source_key': r['source']['key'], 'start': r['start'], 'length': r['length']}
                need(canonical(manual_reacquisition) == canonical(exact), 'final wall-failed GET requires exact explicit reacquisition declaration')
                self.failed_parent_request = r
            else:
                need(result['error_type'] == 'ValueError' and result['error'] == 'wall/request cap' and len(original_requests) < caps['requests']
                     and manual_reacquisition is None, 'parent clean stop is not exclusively wall expiry')
                self.eligibility = 'BEFORE_NEXT_GET_WALL_EXPIRY'
        self.parent_request_count = len(original_requests); self.parent_response_bytes = prior['retained_response_bytes']
        self.reserved_parent_failed_response_bytes = sum(r['length']-r['response_bytes'] for r in failed)
        need(self.parent_response_bytes+self.reserved_parent_failed_response_bytes <= caps['total_response_bytes'],
             'parent retained plus conservative failed-range charge exceeds byte cap')
        self.requests = list(original_requests); self.bytes = self.parent_response_bytes
        self.caps = {**caps, 'wall_seconds': TOTAL_WALL}
        self.continuation_plan_sha256 = sha_value(continuation_plan_sha256)
        self.started_utc = base.stamp(); self.stage_started = time.monotonic()
        self.started = self.stage_started-(datetime.now(timezone.utc)-origin).total_seconds()
        self.attempt_id = digest({'parent_attempt_id': self.parent_attempt_id,
            'parent_session_sha256': self.parent_bindings['transport/session.json'],
            'continuation_plan_sha256': self.continuation_plan_sha256, 'started_utc': self.started_utc})
        self.failed = False; self.inflight = False; self.manual_reacquisition_count = 0
        self.reused_sources = []; self._active_request_kind = None
        self.opener = opener or base.urllib.request.build_opener(base.NoRedirect())
        self.cache_dir = self.output.parent/'cache'
        need(not self.cache_dir.exists(), 'continuation sparse cache must be new')
        self.output.mkdir(parents=True, exist_ok=False)
        save(self.output/'plan.json', self.plan)
        save(self.output/'parent_bindings.json', self.parent_bindings)
        (self.output/'inherited_requests.json').write_bytes((self.parent/'transport/requests.json').read_bytes())
        self.parent_source_paths = self._parent_paths(original_requests)
        # Authenticate/copy all A1 accepted bodies before allowing any new GET.
        # Failed positive bodies are rehashed at A1 only and never copied.
        self.parent_bytes_verified = False
        try:
            for r in original_requests:
                source = r['source']; original = self.parent_source_paths[source['key']]
                need(original.is_file() and original.stat().st_size == source['size_bytes'], 'parent sparse source size differs')
                if r['transport_ok']:
                    target = self._ensure_source_file(source)
                    self._copy_verified(original, target, r['start'], r['response_bytes'], r['response_sha256'])
                elif r['response_bytes']:
                    need(file_sha(original, r['start'], r['response_bytes']) == r['response_sha256'], 'unaccepted parent body changed')
            for source_key in {r['source']['key'] for r in original_requests}:
                self._ensure_source_file(self.sources[source_key]); self._write_cache_manifest(self.sources[source_key])
            self.parent_bytes_verified = True; self.assert_parent_unchanged(); self.checkpoint('OPEN')
        except Exception:
            self.failed = True; self.checkpoint('FAILED_PARENT_EVIDENCE'); raise

    @property
    def new_requests(self):
        return self.requests[self.parent_request_count:]

    @property
    def reserved_new_failed_or_pending_response_bytes(self):
        return sum(r['length']-r['response_bytes'] for r in self.new_requests if r['transport_ok'] is not True)

    @property
    def cumulative_charged_response_bytes(self):
        return self.bytes+self.reserved_parent_failed_response_bytes+self.reserved_new_failed_or_pending_response_bytes

    def assert_parent_unchanged(self):
        for name, expected in self.parent_bindings.items():
            path = self.parent/relative(name)
            if expected is None:
                need(not path.exists(), 'previously absent parent metadata appeared')
            else:
                need(path.is_file() and file_sha(path) == sha_value(expected), 'sealed parent evidence changed: '+name)

    def _parent_paths(self, records):
        value = self.parent_bindings['runtime_source_paths.json']
        raw = {} if value is None else json.loads((self.parent/'runtime_source_paths.json').read_bytes())
        return {r['source']['key']: Path(raw.get(r['source']['key'],
                self.parent/'cache'/digest(r['source'])/'source.parquet')) for r in records}

    def _ensure_source_file(self, source):
        directory = self.cache_dir/digest(source); directory.mkdir(parents=True, exist_ok=True)
        path = directory/'source.parquet'
        if not path.exists():
            with path.open('xb') as f: f.truncate(source['size_bytes'])
        need(path.is_file() and path.stat().st_size == source['size_bytes'], 'new sparse source size differs')
        return path

    @staticmethod
    def _copy_verified(original, target, start, length, expected):
        h = hashlib.sha256(); copied = 0
        with original.open('rb') as src, target.open('r+b') as dst:
            src.seek(start); dst.seek(start)
            while copied < length:
                block = src.read(min(1048576, length-copied)); need(block, 'parent accepted range truncated')
                h.update(block); dst.write(block); copied += len(block)
        need(h.hexdigest() == expected, 'parent accepted range changed')

    def _origin(self, record):
        inherited = record['ordinal'] <= self.parent_request_count
        return {'origin_attempt_id': self.parent_attempt_id if inherited else self.attempt_id,
                'origin_ordinal': record['ordinal'], 'receipt': record}

    def _source_records(self, source):
        return [r for r in self.requests if r['source'] == source and r['transport_ok'] is True]

    def _write_cache_manifest(self, source):
        records = self._source_records(source)
        save(self.cache_dir/digest(source)/'ranges.json', {
            'schema_version': 'article2_phase16_continuation_range_cache_v1', 'source': source,
            'attempt_id': self.attempt_id, 'parent_attempt_id': self.parent_attempt_id,
            'inherited_ranges': [self._origin(r) for r in records if r['ordinal'] <= self.parent_request_count],
            'new_ranges': [r for r in records if r['ordinal'] > self.parent_request_count]})

    def checkpoint(self, status):
        if self.inflight:
            record = self.requests[-1]
            if 'continuation_request_kind' not in record:
                record['continuation_request_kind'] = self._active_request_kind
                record['origin_attempt_id'] = self.attempt_id
                if self._active_request_kind == 'explicit_manual_reacquisition':
                    need(self.manual_reacquisition_count == 0, 'second manual reacquisition prohibited')
                    record['reacquisition_of'] = {'attempt_id': self.parent_attempt_id, 'ordinal': self.failed_parent_request['ordinal']}
                    self.manual_reacquisition_count = 1
        new = self.new_requests
        save(self.output/'requests.json', new)
        save(self.output/'accepted_range_evidence.json', {'schema_version': 'article2_phase16_continuation_accepted_ranges_v1',
             'ranges': [self._origin(r) for r in self.requests if r['transport_ok'] is True]})
        save(self.output/'session.json', {
            'schema_version': 'article2_phase16_continuation_capture_v1', 'status': status,
            'attempt_id': self.attempt_id, 'parent_attempt_id': self.parent_attempt_id,
            'original_started_utc': self.original_started_utc, 'started_utc': self.started_utc, 'updated_utc': base.stamp(),
            'absolute_deadline_utc': self.absolute_deadline_utc,
            'continuation_plan_sha256': self.continuation_plan_sha256, 'original_collector_plan_canonical_sha256': digest(self.plan),
            'original_accepted_plan_sha256': self.original_plan_sha256,
            'parent_bindings_canonical_sha256': digest(self.parent_bindings), 'eligibility': self.eligibility,
            'inherited_request_count': self.parent_request_count, 'new_request_count': len(new),
            'cumulative_request_count': len(self.requests), 'inherited_response_bytes': self.parent_response_bytes,
            'new_response_bytes': sum(r['response_bytes'] for r in new), 'cumulative_response_bytes': self.bytes,
            'reserved_parent_failed_response_bytes': self.reserved_parent_failed_response_bytes,
            'reserved_new_failed_or_pending_response_bytes': self.reserved_new_failed_or_pending_response_bytes,
            'inherited_charged_response_bytes': self.parent_response_bytes+self.reserved_parent_failed_response_bytes,
            'new_charged_response_bytes': sum(r['response_bytes'] for r in new)+self.reserved_new_failed_or_pending_response_bytes,
            'cumulative_charged_response_bytes': self.cumulative_charged_response_bytes,
            'response_budget_rule': 'Retained bytes plus full remaining declared length of failed/pending responses; not a complete wire-byte measurement.',
            'cumulative_wall_seconds_elapsed': time.monotonic()-self.started,
            'new_stage_wall_seconds_elapsed': time.monotonic()-self.stage_started,
            'effective_caps': self.caps, 'automatic_retries': 0, 'manual_reacquisition': self.manual_reacquisition,
            'manual_reacquisition_count': self.manual_reacquisition_count,
            'original_attempt_retry_count': 0, 'cumulative_retry_count': self.manual_reacquisition_count,
            'parent_positive_bodies_verified': self.parent_bytes_verified,
            'timeout_causal_statement': ('Final-deadline-associated transport timeout; actual timeout argument was not recorded and exact causal contribution is unknown.'
                 if self.eligibility == 'DEADLINE_ASSOCIATED_TIMEOUT_CAUSALITY_UNRESOLVED' else None),
            'inherited_cache_or_full_object_reuses': self.parent_session['cache_or_full_object_reuses'],
            'cache_or_full_object_reuses': self.reused_sources,
            'body_storage': 'Only successful inherited ranges copied; new responses at original offsets; failed A1 bodies remain unaccepted in immutable parent.'})

    def fetch_into(self, source, kind, start, length, target):
        source = identity(source)
        need(self.parent_bytes_verified and not self.failed and not self.inflight, 'continuation is not ready/live')
        need(self.sources.get(source['key']) == source, 'source outside unchanged inventory')
        integer(start); integer(length, 1)
        need(self.cumulative_charged_response_bytes+length <= self.caps['total_response_bytes'],
             'cumulative charged byte cap including failed/pending range reservations')
        target = Path(target)
        need(target.resolve() == (self.cache_dir/digest(source)/'source.parquet').resolve(), 'new response target outside new sparse cache')
        manual = self._active_request_kind == 'explicit_manual_reacquisition'
        if manual:
            r = self.failed_parent_request
            need(r is not None and self.manual_reacquisition_count == 0 and source == r['source']
                 and start == r['start'] and length == r['length'], 'manual reacquisition differs from exact authorization')
        for r in self.requests:
            if r['source'] == source and start < r['start']+r['length'] and r['start'] < start+length:
                need(manual and r is self.failed_parent_request, 'new GET overlaps previously attempted range')
        if not manual:
            self._active_request_kind = 'previously_unrequested_range'
        try:
            return base.RangeSession.fetch_into(self, source, kind, start, length, target)
        except Exception:
            self.failed = True; raise
        finally:
            self._write_cache_manifest(source)
            self._active_request_kind = None

    def reacquire_final_failed_range(self):
        need(self.failed_parent_request is not None and self.manual_reacquisition_count == 0, 'no unused explicit manual reacquisition')
        r = self.failed_parent_request; target = self._ensure_source_file(r['source'])
        self._active_request_kind = 'explicit_manual_reacquisition'
        receipt = self.fetch_into(r['source'], 'explicit_manual_reacquisition', r['start'], r['length'], target)
        if r['response_bytes']:
            try:
                need(file_sha(target, r['start'], r['response_bytes']) == r['response_sha256'],
                     'reacquired bytes contradict retained failed-response prefix')
            except Exception:
                self.failed = True
                receipt['transport_ok'] = False
                receipt['failure'] = 'ContinuationConsistencyError: reacquired bytes contradict retained failed-response prefix'
                self._write_cache_manifest(r['source'])
                self.checkpoint('FAILED_REACQUISITION_CONSISTENCY'); raise
        return receipt

    def close(self, status='COMPLETE'):
        need(not self.inflight, 'active continuation cannot close')
        if status == 'COMPLETE':
            need(not self.failed and all(r['transport_ok'] for r in self.new_requests), 'failed continuation cannot complete')
            need(self.manual_reacquisition_count == (1 if self.manual_reacquisition else 0), 'declared manual reacquisition not completed')
            need(time.monotonic()-self.started <= TOTAL_WALL, 'cumulative wall cap at close')
            need(self.cumulative_charged_response_bytes <= self.caps['total_response_bytes'], 'cumulative charged byte cap at close')
            self.assert_parent_unchanged()
        self.checkpoint(status)
        if status == 'COMPLETE' and time.monotonic()-self.started > TOTAL_WALL:
            self.failed = True
            self.checkpoint('FAILED_CUMULATIVE_WALL_AT_CLOSE')
            raise ValueError('cumulative wall cap during final checkpoint')


class SourceReader(base.SourceReader):
    """Frozen projection logic with separately authenticated inherited evidence."""
    def __init__(self, source, session, cache_dir, pa, pq, reuse=None):
        need(Path(cache_dir).resolve() == session.cache_dir.resolve(), 'continuation cache directory differs')
        need(session.sources.get(source['key']) == identity(source), 'source outside frozen inventory')
        if reuse is not None:
            need(not any(r['source']['key'] == source['key'] for r in session.requests), 'whole reuse cannot replace a previously attempted range source')
        super().__init__(source, session, cache_dir, pa, pq, reuse=reuse)

    def _persist(self):
        self.session._write_cache_manifest(self.source)

    def _load_cache(self):
        self.session._ensure_source_file(self.source)
        self.ranges = self.session._source_records(self.source)
        spans = []
        for r in self.ranges:
            need(file_sha(self.path, r['start'], r['length']) == r['response_sha256'], 'continuation copied range changed')
            spans.append([r['start'], r['start']+r['length']])
        need(sum(b-a for a,b in spans) == sum(b-a for a,b in base.merge_ranges(spans)), 'accepted continuation ranges overlap')
        self._persist()

    def manifest(self):
        result = super().manifest()
        result['schema_version'] = 'article2_phase16_continuation_projected_source_manifest_v1'
        result['inherited_ranges'] = [self.session._origin(r) for r in self.ranges if r['ordinal'] <= self.session.parent_request_count]
        result['new_ranges'] = [r for r in self.ranges if r['ordinal'] > self.session.parent_request_count]
        result['evidence_origins'] = [self.session._origin(r) for r in self.ranges]
        result['parent_attempt_id'] = self.session.parent_attempt_id
        result['continuation_attempt_id'] = self.session.attempt_id
        return result
