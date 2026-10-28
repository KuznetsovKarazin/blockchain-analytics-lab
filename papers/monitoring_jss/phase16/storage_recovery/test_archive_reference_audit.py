"""Independent synthetic checks of the storage reference wrapper only.

No retained captures, reference inventories, network, or previous test suites
are used. The ledger validator is real; launcher admission is tested separately
with invented bound files. Tiny Parquet bytes test actual compact reader access.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


w = module('storage_archive_wrapper_under_independent_test', 'archive_reference_audit.py')
a = module('storage_archive_transport_dependency_under_test', 'independent_transport_audit.py')
c = module('storage_archive_reader_under_test', 'independent_compact_reader.py')


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + '\n')
    return {'path': str(path.resolve()), 'sha256': w.sha(path)}


def stamp(n):
    return (datetime(2030, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=n)).isoformat()


def source(size=400000):
    key = 'v1.0/eth/transactions/date=2030-01-01/part-invented.parquet'
    return {'table': 'transactions', 'day_utc': '2030-01-01', 'key': key,
            'size_bytes': size, 'etag_opaque': '"synthetic"', 'url': a.ENDPOINT + key}


def receipt(s, ordinal, start, body, begin, *, pending_length=None):
    length = pending_length if pending_length is not None else len(body)
    r = {'ordinal': ordinal, 'source': s, 'start': start, 'length': length,
         'method': 'GET', 'request_headers': {'Range': f'bytes={start}-{start+length-1}',
         'If-Match': s['etag_opaque'], 'Accept-Encoding': 'identity'},
         'started_utc': stamp(begin), 'transport_ok': pending_length is None,
         'response_bytes': 0 if pending_length is not None else length}
    if pending_length is None:
        r.update(completed_utc=stamp(begin + .1), response_sha256=hashlib.sha256(body).hexdigest(),
                 http_status=206, response_url=s['url'], etag=s['etag_opaque'],
                 content_range=f'bytes {start}-{start+length-1}/{s["size_bytes"]}',
                 content_length=str(length), content_encoding=None, invalid_header_body_read=False)
    return r


class TempCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='invented-reference-wrapper-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)


class LedgerTests(TempCase):
    def setUp(self):
        super().setUp()
        s = source()
        self.inherited = [receipt(s, i, i-1, b'x', i) for i in range(1, 730)]
        self.inherited.append(receipt(s, 730, 729, b'', 800, pending_length=275821))
        old = {'schema_version': 'article2_phase16_range_capture_v1', 'status': 'OPEN_REQUEST_PENDING',
               'request_count': 730, 'retained_response_bytes': 729, 'attempt_id': 'a'*64,
               'started_utc': stamp(0), 'updated_utc': stamp(800)}
        new = receipt(s, 731, 729, b'x'*275821, 1001)
        new.update(received_bytes_known=275821, origin_attempt_id='b'*64,
                   body_storage_kind='immutable_blob', physical_blob_offset=0,
                   resource_recovery_request_kind='explicit_pending_reacquisition',
                   reacquisition_of={'attempt_id': 'a'*64, 'ordinal': 730})
        self.new = [new]
        self.session = {'status': 'COMPLETE', 'parent_attempt_id': 'a'*64, 'attempt_id': 'b'*64,
            'original_started_utc': stamp(0), 'started_utc': stamp(1000), 'updated_utc': stamp(1003),
            'cumulative_wall_seconds_elapsed': 1003, 'absolute_deadline_utc': stamp(14400),
            'inherited_request_count': 730, 'new_request_count': 1, 'cumulative_request_count': 731,
            'inherited_response_bytes': 729, 'new_response_bytes': 275821, 'cumulative_response_bytes': 276550,
            'reserved_parent_pending_response_bytes': 275821, 'reserved_new_failed_or_pending_response_bytes': 0,
            'inherited_charged_response_bytes': 276550, 'new_charged_response_bytes': 275821,
            'cumulative_charged_response_bytes': 552371, 'parent_pending_response_bytes': None,
            'actual_cumulative_response_bytes_complete': False,
            'response_byte_count_scope': 'RECORDED_RETAINED_ONLY_PARENT_PENDING_UNKNOWN',
            'automatic_retries': 0, 'manual_reacquisition_count': 1, 'cumulative_retry_count': 1}
        self.sources = {s['key']: s}
        caps = {'requests': 5000, 'total_response_bytes': 16*1024**3, 'wall_seconds': 7200,
                'max_source_bytes': 1000000, 'max_range_bytes': 300000}
        manual = {'parent_request_ordinal': 730, 'source_key': s['key'], 'start': 729, 'length': 275821}
        self.context = {'parent_root': self.root, 'original_plan': {'collector': {'caps': caps}},
                        'amendment': {'accepted_utc': stamp(900)}, 'manual_reacquisition': manual}
        put(self.root/'transport/session.json', old)
        binding = put(self.root/'transport/requests.json', self.inherited)
        cost = a.validate_cost_ledgers(self.inherited, self.new, old, self.session, self.sources, caps, stamp(900), manual)
        origins = cost.pop('accepted_origins')
        self.ledger = dict(cost, schema_version='article2_phase16_storage_recovery_multiattempt_ledger_v1',
            status='VERIFIED_RECORDED_COSTS_WITH_FULL_UNRESOLVED_PENDING_RESERVATION',
            inherited_requests=deepcopy(self.inherited), new_requests=deepcopy(self.new), limits=deepcopy(w.protocol.LIMITS))
        self.transport = dict(cost, inherited_requests_sha256=binding['sha256'])
        self.accepted = {'schema_version': 'article2_phase16_compact_accepted_ranges_v1',
                         'ranges': [dict(row, blob={'synthetic_only': True}) for row in origins]}

    def invoke(self):
        return w.validate_successful_view(self.ledger, self.accepted, self.inherited, self.new,
             self.session, self.transport, self.context, self.sources, a)

    def test_full_pending_reservation_survives_successful_view(self):
        before = deepcopy(self.ledger)
        grouped, costs = self.invoke()
        rows = next(iter(grouped.values()))
        self.assertEqual([r['origin_ordinal'] for r in rows], list(range(1, 730)) + [731])
        self.assertEqual(self.ledger, before)
        self.assertEqual(len(self.ledger['inherited_requests']), 730)
        self.assertIsNone(costs['parent_pending_response_bytes'])
        self.assertFalse(costs['actual_cumulative_response_bytes_complete'])
        self.assertEqual(costs['known_cumulative_response_bytes'], 276550)
        self.assertEqual(costs['cumulative_charged_response_bytes'], 552371)

    def test_unknown_cannot_be_promoted_to_zero_in_bound_ledger(self):
        self.ledger['parent_pending_response_bytes'] = 0
        with self.assertRaisesRegex(ValueError, 'cumulative'): self.invoke()

    def test_full_reservation_cannot_be_lowered_in_report(self):
        self.transport['reserved_parent_pending_response_bytes'] -= 1
        with self.assertRaisesRegex(ValueError, 'cumulative'): self.invoke()

    def test_pending_record_cannot_be_filtered_out(self):
        self.ledger['inherited_requests'].pop()
        with self.assertRaisesRegex(ValueError, 'full unresolved'): self.invoke()

    def test_on_disk_original_prefix_must_remain_exact(self):
        put(self.root/'transport/requests.json', self.inherited[:-1])
        with self.assertRaisesRegex(ValueError, 'filtered or changed'): self.invoke()

    def test_missing_successful_range_is_rejected(self):
        self.accepted['ranges'].pop(7)
        with self.assertRaisesRegex(ValueError, 'exact successful'): self.invoke()

    def test_pending_receipt_cannot_become_accepted_range(self):
        self.accepted['ranges'].insert(-1, {'origin_attempt_id': 'a'*64, 'origin_ordinal': 730,
            'receipt': self.inherited[-1], 'blob': {'synthetic_only': True}})
        with self.assertRaisesRegex(ValueError, 'exact successful'): self.invoke()

    def test_success_origin_cannot_change(self):
        self.accepted['ranges'][-1]['origin_attempt_id'] = 'a'*64
        with self.assertRaisesRegex(ValueError, 'exact successful'): self.invoke()

    def test_closed_complete_recovery_cannot_hide_failed_request(self):
        self.new[0]['transport_ok'] = False
        self.ledger['new_requests'] = deepcopy(self.new)
        with self.assertRaisesRegex(ValueError, 'failed recovery'): self.invoke()


class MetadataTests(TempCase):
    def setUp(self):
        super().setUp()
        self.source = source(24)
        self.descriptor = self.root/'storage/source_storage.json'
        descriptor_binding = put(self.descriptor, {'synthetic': True})
        self.ranges, blobs = [], []
        for ordinal, (start, body) in enumerate(((0, b'PAR1'), (8, b'footerxx'+(8).to_bytes(4,'little')+b'PAR1')), 1):
            path = self.root/'storage'/f'blob-{ordinal}'
            path.write_bytes(body)
            r = receipt(self.source, ordinal, start, body, ordinal)
            row = {'origin_attempt_id': 'a'*64, 'origin_ordinal': ordinal, 'receipt': r,
                   'blob': {'path': str(path.relative_to(self.root)), 'size_bytes': len(body), 'sha256': w.sha(path)}}
            self.ranges.append(row)
            blobs.append({'start': start, 'length': len(body), 'path': str(path), 'sha256': w.sha(path),
                'origin_attempt_id': 'a'*64, 'origin_ordinal': ordinal, 'receipt_sha256': w.frozen.digest(r)})
        self.manifest = {'source': self.source, 'storage_kind': 'compact_descriptor',
            'successful_original_ranges': [r['receipt'] for r in self.ranges], 'evidence_origins': deepcopy(self.ranges),
            'descriptor_sha256': descriptor_binding['sha256'], 'whole_source_sha256_verified': False, 'whole_source_sha256': None}
        self.verified = {'source': self.source, 'source_key': self.source['key'], 'storage_kind': 'compact_descriptor',
            'descriptor_path': str(self.descriptor), 'descriptor_sha256': descriptor_binding['sha256'],
            'range_receipts_canonical_sha256': w.frozen.digest(self.manifest['successful_original_ranges']),
            'verified_blobs': blobs, 'available_ranges': [[0,4], [8,24]]}

    def invoke(self):
        return w.verify_source_metadata(self.source, self.manifest, self.verified, self.ranges, self.root, {})

    def test_exact_origin_metadata_and_reader_preserve_holes(self):
        self.invoke()
        reader = c.IndependentIntervalFile(24, self.verified['verified_blobs'])
        self.assertEqual(reader.read(4), b'PAR1')
        with self.assertRaisesRegex(ValueError, 'unacquired'): reader.read(8)
        self.assertEqual(reader.tell(), 4)
        reader.seek(8)
        self.assertEqual(len(reader.read()), 16)

    def test_metadata_cannot_fill_unacquired_hole(self):
        self.verified['available_ranges'] = [[0,24]]
        with self.assertRaisesRegex(ValueError, 'holes'): self.invoke()

    def test_descriptor_bytes_must_match_audit(self):
        self.descriptor.write_text('changed')
        with self.assertRaisesRegex(ValueError, 'descriptor changed'): self.invoke()

    def test_source_identity_must_match(self):
        self.verified = deepcopy(self.verified)
        self.verified['source']['etag_opaque'] = 'wrong'
        with self.assertRaisesRegex(ValueError, 'identity'): self.invoke()

    def test_blob_binding_cannot_point_at_another_accepted_origin(self):
        self.verified['verified_blobs'][0]['origin_ordinal'] = 999
        with self.assertRaisesRegex(ValueError, 'compact bytes'): self.invoke()

    def test_blob_hash_changed_after_transport_is_detected_before_read(self):
        self.invoke()
        Path(self.verified['verified_blobs'][0]['path']).write_bytes(b'FAKE')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            c.IndependentIntervalFile(24, self.verified['verified_blobs'])

    def test_blob_change_after_reader_creation_is_detected(self):
        reader = c.IndependentIntervalFile(24, self.verified['verified_blobs'])
        Path(self.verified['verified_blobs'][0]['path']).write_bytes(b'FAKE')
        with self.assertRaisesRegex(ValueError, 'changed during'): reader.read(4)

    def test_whole_object_prior_origin_and_current_bytes_are_both_required(self):
        path = self.root/'whole.parquet'
        path.write_bytes(b'PAR1' + b'12345678' + b'foot' + (4).to_bytes(4,'little') + b'PAR1')
        digest = w.sha(path)
        provenance = {'expected': {self.source['key']: {'expected_whole_object_sha256': digest, 'expected_archive_sha256': 'd'*64}},
            'recovery_receipt_sha256': 'a'*64, 'original_manifest_sha256': 'b'*64,
            'prior_independent_acquisition_review_sha256': 'c'*64}
        origin = {k: v for k, v in provenance.items() if k != 'expected'}
        origin.update(prior_verified_archive_sha256='d'*64, fresh_zip_reads=0)
        manifest = {'source': self.source, 'storage_kind': 'verified_whole_object', 'successful_original_ranges': [],
            'evidence_origins': [], 'whole_source_sha256_verified': True, 'whole_source_sha256': digest}
        verified = {'source': self.source, 'source_key': self.source['key'], 'storage_kind': 'verified_whole_object',
            'range_receipts_canonical_sha256': w.frozen.digest([]), 'sha256': digest,
            'available_ranges': [[0,24]], 'whole_object_origin': origin}
        w.verify_source_metadata(self.source, manifest, verified, [], self.root, provenance)
        blobs = [{'start': 0, 'length': 24, 'path': str(path), 'sha256': digest}]
        self.assertEqual(len(c.IndependentIntervalFile(24, blobs).read()), 24)
        verified['whole_object_origin']['prior_verified_archive_sha256'] = 'e'*64
        with self.assertRaisesRegex(ValueError, 'provenance'):
            w.verify_source_metadata(self.source, manifest, verified, [], self.root, provenance)
        path.write_bytes(b'x'*24)
        with self.assertRaisesRegex(ValueError, 'bytes changed'): c.IndependentIntervalFile(24, blobs)


class LauncherTests(TempCase):
    def setUp(self):
        super().setUp()
        self.output = self.root/'sealed'
        self.output.mkdir()
        self.receipt_path = self.output/'replay_launcher_receipt.json'
        self.bindings = {key: put(self.root/(key+'.json'), {'synthetic': key}) for key in
             ('pre_replay_authorization', 'storage_recovery_amendment', 'multiattempt_ledger', 'source_review', 'transport_audit')}
        cases = []
        for case in w.join.CASES:
            row = {'case_id': case, 'status': 'COMPLETE'}
            for field in ('config', 'measurement_acceptance', 'input_manifest', 'run_manifest'):
                row[field] = put(self.root/(case+'_'+field+'.json'), {'synthetic_case': case, 'field': field})
            cases.append(row)
        self.auth = {'replay_launcher_sha256': w.sha(HERE/'run_replays.py'),
                     'replay_output_root': str(self.output), 'accepted_utc': stamp(0)}
        self.auth.update(reference_archive_source_engine_sha256=w.ENGINE_SHA256,
            reference_archive_auditor={'path': str(HERE/'archive_reference_audit.py'), 'sha256': w.sha(w.__file__)},
            reference_compact_reader={'path': str(HERE/'independent_compact_reader.py'), 'sha256': w.sha(c.__file__)})
        self.study = {'cases': deepcopy(cases), 'sealed_utc': stamp(3)}
        self.receipt = {'schema_version': 'article2_phase16_storage_recovery_replay_launcher_receipt_v1',
            'status': 'COMPLETE_BOTH_CASES_SEALED', 'labels_used': False, 'reference_acquisition_performed': False,
            'replay_launcher_sha256': self.auth['replay_launcher_sha256'], 'original_driver_sha256': w.sha(w.join.driver.__file__),
            'protocol_sha256': w.PROTOCOL_SHA256, 'driver_invocations': 2, 'retries': 0,
            **{field: deepcopy(self.auth[field]) for field in ('reference_archive_source_engine_sha256',
                'reference_archive_auditor', 'reference_compact_reader')},
            'started_utc': stamp(1), 'completed_utc': stamp(2), 'cases': cases, **deepcopy(self.bindings)}

    def invoke(self):
        put(self.receipt_path, self.receipt)
        return w.validate_launcher(self.receipt_path, self.study, self.root, self.auth, self.bindings)

    def test_exact_both_case_launcher_lineage_is_accepted(self):
        self.assertEqual(self.invoke()['cases'], self.study['cases'])

    def test_relative_and_absolute_bindings_normalize_to_same_files(self):
        self.receipt['cases'][0]['config']['path'] = '../'+Path(self.receipt['cases'][0]['config']['path']).name
        self.invoke()

    def test_changed_case_binding_rejects_even_if_new_hash_is_valid(self):
        self.receipt['cases'][0]['input_manifest'] = put(self.root/'changed.json', {'synthetic': 'different input'})
        with self.assertRaisesRegex(ValueError, 'exact case'): self.invoke()

    def test_case_order_cannot_change(self):
        self.receipt['cases'].reverse()
        with self.assertRaisesRegex(ValueError, 'case order'): self.invoke()

    def test_same_status_cannot_hide_substituted_full_ledger(self):
        self.receipt['multiattempt_ledger'] = put(self.root/'other_ledger.json', {'synthetic': 'omitted pending'})
        with self.assertRaisesRegex(ValueError, 'lineage'): self.invoke()

    def test_reference_or_labels_used_is_rejected(self):
        for flag in ('labels_used', 'reference_acquisition_performed'):
            with self.subTest(flag=flag):
                self.receipt[flag] = True
                with self.assertRaisesRegex(ValueError, 'unlabelled'): self.invoke()
                self.receipt[flag] = False

    def test_code_pins_reject_changed_launcher_or_driver(self):
        for field in ('replay_launcher_sha256', 'original_driver_sha256'):
            with self.subTest(field=field):
                prior = self.receipt[field]
                self.receipt[field] = '0'*64
                with self.assertRaisesRegex(ValueError, 'code differs'): self.invoke()
                self.receipt[field] = prior

    def test_backdated_replay_and_premature_study_seal_reject(self):
        for field, value in (('started_utc', stamp(-1)), ('completed_utc', stamp(4))):
            with self.subTest(field=field):
                prior = self.receipt[field]
                self.receipt[field] = value
                with self.assertRaisesRegex(ValueError, 'chronology'): self.invoke()
                self.receipt[field] = prior

    def test_output_root_must_match_prospectively_authorized_location(self):
        self.auth['replay_output_root'] = str(self.root/'other')
        with self.assertRaisesRegex(ValueError, 'outside authorized'): self.invoke()

    def test_execution_contract_or_source_engine_changes_are_rejected(self):
        for field, value in (('protocol_sha256', '0'*64), ('driver_invocations', 3), ('retries', 1),
                             ('reference_archive_source_engine_sha256', '0'*64)):
            with self.subTest(field=field):
                old = self.receipt[field]
                self.receipt[field] = value
                with self.assertRaisesRegex(ValueError, 'contract differs'): self.invoke()
                self.receipt[field] = old

    def test_future_reference_reader_or_auditor_cannot_be_substituted(self):
        for field in ('reference_archive_auditor', 'reference_compact_reader'):
            with self.subTest(field=field):
                old = self.receipt[field]
                self.receipt[field] = put(self.root/'other_code.py', {'synthetic': field})
                with self.assertRaisesRegex(ValueError, 'future-reference'): self.invoke()
                self.receipt[field] = old


class GateTests(unittest.TestCase):
    def test_missing_or_wrong_wrapper_and_engine_pins_fail_before_protocol_or_candidates(self):
        correct = {'reference_archive_auditor_sha256': w.sha(w.__file__), 'reference_archive_source_engine_sha256': w.ENGINE_SHA256}
        for field in correct:
            for value in (None, '0'*64):
                study = dict(correct)
                if value is None: study.pop(field)
                else: study[field] = value
                with self.subTest(field=field, value=value), patch.object(w.join, 'load_study', return_value=(study, [])), \
                        patch.object(w.protocol, 'validate_pre_replay_authorization') as admission, \
                        patch.object(w.engine, 'select_candidates') as candidates:
                    with self.assertRaisesRegex(ValueError, 'not pinned'):
                        w.load_context(argparse.Namespace(study_manifest=Path('/synthetic/study'), expected_study_sha256='a'*64))
                    admission.assert_not_called()
                    candidates.assert_not_called()

    def test_original_engine_join_and_protocol_pins_and_scientific_caps_unchanged(self):
        self.assertEqual(w.sha(w.engine.__file__), w.ENGINE_SHA256)
        self.assertEqual(w.sha(w.join.__file__), w.JOIN_SHA256)
        self.assertEqual(w.sha(w.protocol.__file__), w.PROTOCOL_SHA256)
        self.assertEqual(w.engine.CAP, 64)
        self.assertEqual(w.engine.WALL_SECONDS, 1200)


class ParquetReaderTests(TempCase):
    def test_actual_tiny_parquet_projection_never_reads_missing_payload_column(self):
        import pyarrow as pa
        import pyarrow.parquet as pq
        table = pa.table({'transaction_hash': ['0x'+'1'*64], 'address': ['0x'+'a'*40], 'topics': ['unacquired payload']})
        sink = pa.BufferOutputStream()
        pq.write_table(table, sink)
        data = sink.getvalue().to_pybytes()
        meta = pq.ParquetFile(pa.BufferReader(data)).metadata
        footer = len(data)-8-int.from_bytes(data[-8:-4], 'little')
        spans = [(0,4), (footer,len(data))]
        for i in range(meta.row_group(0).num_columns):
            col = meta.row_group(0).column(i)
            if col.path_in_schema == 'topics': continue
            start = min(x for x in (col.dictionary_page_offset, col.data_page_offset) if x is not None and x >= 4)
            spans.append((start, start+col.total_compressed_size))
        blobs = []
        for index, (start,end) in enumerate(sorted(spans)):
            path = self.root/f'chunk{index}'
            path.write_bytes(data[start:end])
            blobs.append({'start': start, 'length': end-start, 'path': str(path), 'sha256': w.sha(path)})
        s = source(len(data))
        manifest = {'source': s, 'row_count_metadata': 1, 'row_group_count': 1, 'row_group_rows': [1]}
        verified = {'source': s, 'source_key': s['key'], 'storage_kind': 'compact_descriptor',
                    'verified_blobs': blobs, 'available_ranges': [[x['start'],x['start']+x['length']] for x in blobs]}
        reader = c.IndependentCompactSource(s, manifest, verified, pa, pq)
        self.assertEqual(reader.read(0, ['transaction_hash', 'address']).to_pylist(), table.select(['transaction_hash','address']).to_pylist())
        with self.assertRaisesRegex(ValueError, 'unacquired projected'): reader.read(0, ['topics'])


class DeadlineTests(TempCase):
    def fixture(self):
        path = self.root/'tiny.bin'
        path.write_bytes(b'invented bytes only')
        compact = SimpleNamespace(sha=lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest())
        original = compact.sha
        compact.IndependentCompactSource = lambda *unused: compact.sha(path)
        return path, compact, original

    def test_bounded_hash_is_identical_and_private_function_is_restored(self):
        path, compact, original = self.fixture()
        value = w.make_source_reader(compact, {}, {}, {}, None, None, None)
        self.assertEqual(value, w.sha(path))
        self.assertIs(compact.sha, original)

    def test_expired_deadline_prevents_constructor_and_restores_function(self):
        _, compact, original = self.fixture()
        with patch.object(compact, 'IndependentCompactSource') as constructor:
            with self.assertRaises(w.engine.AuditDeadlineExceeded):
                w.make_source_reader(compact, {}, {}, {}, None, None, -1)
            constructor.assert_not_called()
        self.assertIs(compact.sha, original)

    def test_deadline_during_hash_propagates_and_restores_function(self):
        _, compact, original = self.fixture()
        checks = []
        def check(deadline):
            checks.append(deadline)
            if len(checks) == 2: raise w.engine.AuditDeadlineExceeded('synthetic during hash')
        with patch.object(w.engine, 'check_deadline', side_effect=check):
            with self.assertRaisesRegex(w.engine.AuditDeadlineExceeded, 'during hash'):
                w.make_source_reader(compact, {}, {}, {}, None, None, 42)
        self.assertEqual(checks, [42,42])
        self.assertIs(compact.sha, original)

    def test_constructor_error_also_restores_private_hash(self):
        _, compact, original = self.fixture()
        with patch.object(compact, 'IndependentCompactSource', side_effect=ValueError('synthetic malformed source')):
            with self.assertRaisesRegex(ValueError, 'malformed'):
                w.make_source_reader(compact, {}, {}, {}, None, None, None)
        self.assertIs(compact.sha, original)

    def test_timed_out_orchestration_keeps_full_ledger_and_null_source_facts(self):
        import pyarrow as pa
        ledger_binding = put(self.root/'full_ledger.json', {'synthetic': True, 'pending_bytes': None, 'reserved': 275821})
        runs = [{'case_id': case} for case in w.join.CASES]
        candidates = [{'case_id': case, 'candidates': [{'chain_id': 1, 'transaction_hash': '0x'+'1'*64,
            'audit_rank': 1, 'within_cap': True}]} for case in w.join.CASES]
        context = {'plan': {'pyarrow_version': '26.0.0', 'numpy_version': '2.3.5'}, 'sources': {}, 'review_days': {},
            'candidates': candidates, 'runs': runs, 'ledger_binding': ledger_binding, 'context_bindings': [ledger_binding],
            'costs': {'parent_pending_response_bytes': None, 'reserved_parent_pending_response_bytes': 275821,
                      'actual_cumulative_response_bytes_complete': False},
            'amendment_sha256': 'a'*64, 'authorization_sha256': 'b'*64}
        args = argparse.Namespace(output=self.root/'timeout_output',
            dependencies=Path(pa.__file__).resolve().parent.parent,
            expected_study_sha256='c'*64, expected_candidates_sha256='d'*64)
        with patch.object(w, 'load_context', return_value=context), \
                patch.object(w.engine, 'check_deadline', side_effect=w.engine.AuditDeadlineExceeded('synthetic timeout')):
            result = w.run(args)
        self.assertEqual(result['status'], 'CLOSED_UNAVAILABLE_TIME_CAP')
        self.assertEqual(result['full_multiattempt_ledger'], ledger_binding)
        evidence = json.loads(Path(result['projection_evidence']['path']).read_text())
        self.assertEqual(evidence['full_cost_accounting'], context['costs'])
        self.assertFalse(evidence['complete_declared_union_scan'])
        for case in result['cases']:
            fact = case['candidates'][0]
            self.assertIsNone(fact['actual_identity_or_unavailable'])
            audit = json.loads(Path(fact['source_coverage_audit_binding']['path']).read_text())
            self.assertIsNone(audit['core_log_count'])
            self.assertFalse(audit['full_core_scan_or_terminal_logs_complete'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dependencies', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.dependencies.resolve()))
    initial = w.sha(w.__file__)
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if initial != w.sha(w.__file__): raise RuntimeError('wrapper changed during tests; rerun required')
    report = {'schema_version': 'article2_phase16_storage_reference_wrapper_synthetic_preflight_v1',
        'status': 'PASS_NEW_SYNTHETIC_CHECKS_ONLY' if result.wasSuccessful() else 'FAIL',
        'tests_run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
        'wrapper_sha256': initial, 'test_sha256': w.sha(__file__),
        'engine_sha256': w.ENGINE_SHA256, 'join_sha256': w.JOIN_SHA256, 'protocol_sha256': w.PROTOCOL_SHA256,
        'compact_reader_sha256': w.sha(HERE/'independent_compact_reader.py'),
        'transport_auditor_sha256': w.sha(HERE/'independent_transport_audit.py'),
        'replay_launcher_sha256': w.sha(HERE/'run_replays.py'),
        'actual_capture_or_reference_files_read': False, 'network_requests': 0, 'old_suites_run': False,
        'detector_scores_computed': 0, 'full_113_source_integration_run': False,
        'scope': ['real complete pending-ledger validator under wrapper', 'exact success subset and full unresolved reservation',
            'source origin metadata plus current synthetic blob/whole bytes', 'real compact Parquet column reads with payload hole',
            'launcher both-case lineage/code/chronology checks', 'early prospective wrapper/engine pin rejection',
            'hash deadline propagates and private reader function restores after success/failure',
            'mock-admitted timeout orchestration preserves full ledger and emits null source facts'],
        'static_review': {'remaining_blockers': [], 'resolved_finding':
            'Reader-constructor hashing originally checked wall time only before/after; wrapper now delegates identical SHA hashing to the frozen engine with per-chunk deadline checks.'},
        'limitations': ['Full load_context with 113 sources and sealed driver runs is not exercised by these focused synthetic tests.',
            'Original row/decision/join suites are not rerun; their unchanged pinned engines are reused.']}
    put(args.report, report)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__': main()
