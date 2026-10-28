"""Independent tiny synthetic checks; never opens any real A1/A2 runtime.

Fixtures are invented here rather than imported from producer tests. Gate
mutation tests mock only the expensive protocol boundary, not ZIP preservation.
"""
import copy
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import pack_compact_a2_delta as p


def h(data):
    return hashlib.sha256(data).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(p.canonical(value) + b'\n')
    return {'path': str(path), 'sha256': p.file_sha(path)}


class IndependentDeltaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='phase16_delta_independent_')
        self.base = Path(self.tmp.name)
        self.root = self.base / 'capture'
        self.root.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def fixture(self):
        source = dict(table='transactions', day_utc='2001-02-03', key='invented/key',
                      size_bytes=12, etag_opaque='invented-etag', url='https://invalid.example/key')
        source_id = p.digest(source)
        parent, current = '1' * 64, '2' * 64
        data = b'old!new!end!'
        inherited = [dict(ordinal=1, transport_ok=True, source=source, start=0,
                          length=4, response_bytes=4, response_sha256=h(data[:4])),
                     dict(ordinal=2, transport_ok=False, source=source, start=4,
                          length=4, response_bytes=0)]
        requests = []
        wrappers = []
        for origin, ordinal, start in [(parent, 1, 0), (current, 3, 4), (current, 4, 8)]:
            raw = data[start:start + 4]
            blob = dict(path=f'storage/{source_id}/blobs/{origin}-{ordinal:06d}-{h(raw)}.bin',
                        size_bytes=4, sha256=h(raw))
            if origin == parent:
                receipt = inherited[0]
            else:
                receipt = dict(ordinal=ordinal, transport_ok=True, source=source, start=start,
                               length=4, response_bytes=4, response_sha256=h(raw), blob=blob)
                requests.append(receipt)
            wrappers.append(dict(origin_attempt_id=origin, origin_ordinal=ordinal,
                                 receipt=receipt, blob=blob))
        descriptor = dict(schema_version='article2_phase16_compact_source_v1',
            storage_kind='compact_descriptor', source=source, source_id=source_id,
            logical_size_bytes=12, attempt_id=current, parent_attempt_id=parent, segments=[])
        for wrapper in wrappers:
            receipt = wrapper['receipt']
            descriptor['segments'].append(dict(start=receipt['start'], length=receipt['length'],
                blob_path='blobs/' + Path(wrapper['blob']['path']).name,
                blob_sha256=receipt['response_sha256'], origin_attempt_id=wrapper['origin_attempt_id'],
                origin_ordinal=receipt['ordinal'], receipt_sha256=p.digest(receipt)))
        member = dict(member=f'attempt1/cache/{source_id}/source.parquet', source_identity=source,
                      logical_bytes=12, sha256_before=h(data), sha256_after=h(data),
                      zip_roundtrip_sha256=h(data))
        index = {'packs': [dict(path='invented_a1.zip', sha256='3' * 64, members=[member])]}
        session = dict(inherited_request_count=2, new_request_count=2,
                       parent_attempt_id=parent, attempt_id=current)
        locations = {source['key']: dict(storage_kind='compact_descriptor',
                     path=str(self.root / 'storage' / source_id / 'source_storage.json'))}
        return [session, inherited, requests, wrappers, {source['key']: descriptor}, locations, index, {}], data

    def populate(self):
        args, data = self.fixture()
        catalog = p.recipe_catalog(*args)
        for wrapper in args[3]:
            path = self.root / wrapper['blob']['path']
            path.parent.mkdir(parents=True, exist_ok=True)
            start = wrapper['receipt']['start']
            if path.exists():
                path.unlink()
            path.write_bytes(data[start:start + 4])
            path.chmod(0o444)
        descpath = Path(next(iter(args[5].values()))['path'])
        write(descpath, next(iter(args[4].values())))
        return catalog, args

    def empty_ready(self):
        return dict(expected_artifacts={}, external=[])

    def test_pending_parent_is_only_recipe_gap_and_never_archived(self):
        args, _ = self.fixture()
        result = p.recipe_catalog(*args)
        self.assertEqual([r['origin_ordinal'] for r in result['inherited_recipes']], [1])
        self.assertEqual([r['origin_ordinal'] for r in result['new_blob_entries']], [3, 4])
        self.assertEqual(result['new_body_bytes'], 8)
        self.assertEqual(result['parent_pending_ordinal'], 2)

    def test_changed_request_receipt_rejected(self):
        args, _ = self.fixture()
        args[3] = copy.deepcopy(args[3])
        args[3][1]['receipt']['response_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'tampered accepted receipt'):
            p.recipe_catalog(*args)

    def test_out_of_range_and_overlapping_new_receipts_rejected(self):
        for start in (3, 10):
            args, _ = self.fixture()
            args[2][-1]['start'] = start  # Wrapper references this same receipt.
            with self.assertRaises(ValueError):
                p.recipe_catalog(*args)

    def test_duplicate_or_missing_a1_artifact_rejected(self):
        for mode in ('duplicate', 'missing'):
            args, _ = self.fixture()
            members = args[6]['packs'][0]['members']
            if mode == 'duplicate':
                members.append(copy.deepcopy(members[0]))
            else:
                members.clear()
            with self.assertRaises((ValueError, KeyError)):
                p.recipe_catalog(*args)

    def test_inherited_blob_is_never_opened_by_inventory(self):
        catalog, _ = self.populate()
        inherited = self.root / catalog['inherited_recipes'][0]['target_path']
        original_open = Path.open
        def guarded(path, *args, **kwargs):
            if path == inherited:
                raise AssertionError('inherited body unexpectedly opened')
            return original_open(path, *args, **kwargs)
        with patch.object(Path, 'open', guarded):
            entries, _, _ = p.artifact_entries(self.root, catalog, self.empty_ready())
        self.assertFalse(any(item['path'] == inherited for item in entries))

    def test_writable_or_missing_accepted_blob_rejected(self):
        for change in ('writable', 'missing'):
            with self.subTest(change=change):
                catalog, _ = self.populate()
                blob = self.root / catalog['new_blob_entries'][0]['path']
                if change == 'writable':
                    blob.chmod(0o644)
                else:
                    blob.unlink()
                with self.assertRaises(ValueError):
                    p.artifact_entries(self.root, catalog, self.empty_ready())

    def test_symlink_outside_capture_is_rejected(self):
        target = self.base / 'external.json'
        target.write_text('{}')
        (self.root / 'link.json').symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'leaves A2 root'):
            p.artifact_entries(self.root, {'all_blob_paths': set(), 'new_blob_entries': []}, self.empty_ready())

    def test_external_final_report_keeps_sealed_digest(self):
        report = self.base / 'final-report.json'
        report.write_bytes(b'{"result":1}')
        sealed = p.file_sha(report)
        ready = dict(expected_artifacts={str(report): sealed}, external=[report])
        report.write_bytes(b'{"result":2}')
        # Either reject immediately or preserve the original expected SHA so ZIP
        # verification rejects later. Rebinding to the new SHA is forbidden.
        try:
            entries, _, _ = p.artifact_entries(self.root,
                {'all_blob_paths': set(), 'new_blob_entries': []}, ready)
        except ValueError:
            return
        self.assertEqual(entries[0]['expected_sha256'], sealed)

    def test_inventory_keeps_empty_observation_file(self):
        empty = self.root / 'covered_empty.jsonl'
        empty.touch()
        entries, metadata, _ = p.artifact_entries(self.root,
            {'all_blob_paths': set(), 'new_blob_entries': []}, self.empty_ready())
        self.assertEqual(metadata, ['covered_empty.jsonl'])
        self.assertEqual(entries[0]['before_stat']['logical_bytes'], 0)

    def test_gate_bound_internal_artifact_cannot_disappear_before_inventory(self):
        missing = self.root / 'required-final-report.json'
        ready = dict(expected_artifacts={str(missing): h(b'{}')}, external=[])
        with self.assertRaises(ValueError):
            p.artifact_entries(self.root,
                {'all_blob_paths': set(), 'new_blob_entries': []}, ready)

    def test_source_or_archive_file_cannot_masquerade_as_internal_metadata(self):
        for filename in ('source.parquet', 'retained.ZIP'):
            with self.subTest(filename=filename):
                path = self.root / filename
                path.write_bytes(b'invented-small-payload')
                with self.assertRaisesRegex(ValueError, 'payload cannot be a small metadata'):
                    p.artifact_entries(self.root,
                        {'all_blob_paths': set(), 'new_blob_entries': []}, self.empty_ready())
                path.unlink()

    def test_known_whole_object_cannot_masquerade_as_external_report(self):
        whole = self.base / 'misnamed-report.json'
        whole.write_bytes(b'invented-whole-object-bytes')
        catalog = dict(all_blob_paths=set(), new_blob_entries=[], source_locations={
            'invented-source': dict(storage_kind='verified_whole_object', original_path=str(whole))})
        ready = dict(expected_artifacts={str(whole): p.file_sha(whole)}, external=[whole])
        with self.assertRaisesRegex(ValueError, 'payload cannot be a small metadata'):
            p.artifact_entries(self.root, catalog, ready)

    def test_gate_bound_compressed_jsonl_is_preserved_as_scientific_artifact(self):
        payload = gzip.compress(b'{"invented_observation":true}\n', mtime=0)
        report = self.root / 'replay' / 'decisions.jsonl.gz'
        report.parent.mkdir()
        report.write_bytes(payload)
        expected = p.file_sha(report)
        ready = dict(expected_artifacts={str(report): expected}, external=[])
        entries, metadata, _ = p.artifact_entries(self.root,
            {'all_blob_paths': set(), 'new_blob_entries': []}, ready)
        self.assertEqual(metadata, ['replay/decisions.jsonl.gz'])
        self.assertEqual(entries[0]['artifact_kind'], 'exact_final_metadata_or_observation')
        self.assertEqual(entries[0]['expected_sha256'], expected)
        output = self.base / 'jsonl-pack'
        output.mkdir()
        result = p.z.pack_one(output, 'scientific.zip', entries, 1024 * 1024)
        self.assertEqual(result['members'][0]['sha256_before'], expected)
        with zipfile.ZipFile(output / 'scientific.zip') as archive:
            self.assertEqual(archive.read('attempt2/replay/decisions.jsonl.gz'), payload)

    def test_unbound_compressed_jsonl_and_bound_other_archives_are_rejected(self):
        for filename, bound in [('decisions.jsonl.gz', False), ('source.parquet.gz', True),
                                ('backup.tar.gz', True), ('evidence.zip', True)]:
            with self.subTest(filename=filename, bound=bound):
                target = self.root / filename
                target.write_bytes(gzip.compress(b'invented', mtime=0))
                ready = dict(expected_artifacts={str(target): p.file_sha(target)} if bound else {}, external=[])
                with self.assertRaises(ValueError):
                    p.artifact_entries(self.root,
                        {'all_blob_paths': set(), 'new_blob_entries': []}, ready)
                target.unlink()

    def test_external_compressed_jsonl_records_original_path_and_bound_digest(self):
        target = self.base / 'external-decisions.jsonl.gz'
        target.write_bytes(gzip.compress(b'{"invented":1}\n', mtime=0))
        expected = p.file_sha(target)
        ready = dict(expected_artifacts={str(target): expected}, external=[target])
        entries, _, _ = p.artifact_entries(self.root,
            {'all_blob_paths': set(), 'new_blob_entries': []}, ready)
        self.assertEqual(entries[0]['expected_sha256'], expected)
        self.assertEqual(entries[0]['original_external_path'], str(target.resolve()))
        output = self.base / 'external-jsonl-pack'
        output.mkdir()
        packed = p.z.pack_one(output, 'external.zip', entries, 1024 * 1024)
        self.assertEqual(packed['members'][0]['original_external_path'], str(target.resolve()))
        with zipfile.ZipFile(output / 'external.zip') as archive:
            manifest = json.loads(archive.read(p.z.MANIFEST_NAME))
            self.assertEqual(manifest['members'][0]['original_external_path'], str(target.resolve()))

    def test_changed_bound_compressed_jsonl_cannot_get_complete_index(self):
        catalog, _ = self.populate()
        ready, args = self.pack_ready()
        report = self.root / 'decisions.jsonl.gz'
        report.write_bytes(gzip.compress(b'{"invented":1}\n', mtime=0))
        ready['expected_artifacts'][str(report)] = p.file_sha(report)
        report.write_bytes(gzip.compress(b'{"invented":2}\n', mtime=0))
        with patch.object(p, 'RUNTIME_ROOT', self.base), patch.object(p, 'load_ready', return_value=ready), \
             patch.object(p, 'prepare_catalog', return_value=catalog):
            with self.assertRaisesRegex(ValueError, 'bound receipt/report'):
                p.pack_delta(args)
        self.assertFalse((args.output / 'a2_delta_index.json').exists())

    def dependency_fixture(self):
        entries = [dict(file_name=f'a1_part_{i:02d}.zip', bytes=100 + i,
                        sha256=f'{i + 1:064x}', library_file_id=f'libfile_fake_{i}',
                        file_id=f'file_fake_{i}') for i in range(43)]
        values = dict(a1_index=dict(status='COMPLETE_FORENSIC_PRESERVATION_NOT_SOURCE_AUDIT',
                                  packs=[dict(path=e['file_name'], bytes=e['bytes'], sha256=e['sha256']) for e in entries[:42]]),
            catalog=dict(schema_version='article2_phase16_durable_a1_forensic_catalog_v1',
                         status='ALL_43_LIBRARY_SAVES_CONFIRMED', entries=entries),
            upload_receipt=dict(results=[dict(**e, status='succeeded') for e in entries]),
            original_archives=[dict(sha256=f'{100 + i:064x}', bytes=1000,
                                    library_file_id=f'libfile_original_fake_{i}') for i in range(9)],
            reuse_expectations={'objects': []}, original_plan={'whole_object_reuse_expectations': {}})
        for i in range(18):
            key = f'invented_source_{i}'
            assertion = dict(sha256=f'{200 + i:064x}', size_bytes=16, etag_opaque='fake')
            values['original_plan']['whole_object_reuse_expectations'][key] = assertion
            values['reuse_expectations']['objects'].append(dict(source_key=key, size_bytes=16,
                etag_opaque='fake', expected_whole_object_sha256=assertion['sha256'],
                expected_archive_sha256=values['original_archives'][i // 2]['sha256'],
                expected_original_member_name=f'member_{i}.parquet'))
        return values

    def test_dependency_creation_rejects_unfrozen_member_map(self):
        values = self.dependency_fixture()
        args = SimpleNamespace(output=self.base / 'dependencies.json', catalog_library_file_id='libfile_invented_catalog')
        for name in values:
            setattr(args, name, self.base / (name + '.json'))
        write(args.a1_index, values['a1_index'])
        values['catalog']['forensic_index_sha256'] = p.file_sha(args.a1_index)
        frozen_binding = write(args.reuse_expectations, values['reuse_expectations'])
        values['original_plan']['reuse_expectations_binding'] = frozen_binding
        # Source SHA/size/ETag and all archive IDs remain correct; only the
        # restore member map has been substituted after its original freeze.
        values['reuse_expectations']['objects'][0]['expected_original_member_name'] = 'wrong-member.parquet'
        for name, value in values.items():
            write(getattr(args, name), value)
        with self.assertRaises(ValueError):
            p.make_dependencies(args)
        self.assertFalse(args.output.exists())

    def pack_ready(self):
        proof = self.base / 'proof.json'
        proof.write_bytes(b'{}')
        ready = dict(context=dict(parent_root=self.base / 'parent', plan_sha256='a' * 64),
            dependencies={}, final_snapshot_sha256='b' * 64,
            proof={name: {'sha256': 'c' * 64} for name in ('amendment', 'transport_audit', 'source_review', 'assembly_result')},
            transport={'collection_result_sha256': 'd' * 64}, expected_artifacts={}, external=[])
        return ready, SimpleNamespace(collection=self.root, output=self.base / 'packs',
                         proofs=proof, expected_proofs_sha256=p.file_sha(proof))

    def test_tampered_new_body_cannot_get_complete_index(self):
        catalog, _ = self.populate()
        blob = self.root / catalog['new_blob_entries'][0]['path']
        blob.chmod(0o644); blob.write_bytes(b'bad!'); blob.chmod(0o444)
        ready, args = self.pack_ready()
        with patch.object(p, 'RUNTIME_ROOT', self.base), patch.object(p, 'load_ready', return_value=ready), \
             patch.object(p, 'prepare_catalog', return_value=catalog):
            with self.assertRaisesRegex(ValueError, 'bound receipt/report'):
                p.pack_delta(args)
        self.assertFalse((args.output / 'a2_delta_index.json').exists())
        self.assertEqual(json.loads((args.output / 'delta_failure.json').read_text())['status'], 'INCOMPLETE_DELTA_NOT_VERIFIED')

    def test_complete_delta_archives_only_new_bodies_and_exact_metadata(self):
        catalog, _ = self.populate()
        ready, args = self.pack_ready()
        report = self.root / 'final.json'
        report.write_bytes(b'{"invented":true}\n')
        ready['expected_artifacts'][str(report)] = p.file_sha(report)
        with patch.object(p, 'RUNTIME_ROOT', self.base), patch.object(p, 'load_ready', return_value=ready), \
             patch.object(p, 'prepare_catalog', return_value=catalog):
            index = p.pack_delta(args)
        self.assertEqual(index['status'], 'COMPLETE_DELTA_PRESERVATION_NOT_NEW_SOURCE_AUDIT')
        self.assertEqual(index['new_body_bytes'], 8)
        self.assertEqual(index['inherited_body_bytes_duplicated'], 0)
        self.assertFalse(index['pending_parent_bytes_accepted'])
        archived = {}
        for pack in index['packs']:
            self.assertEqual(p.file_sha(args.output / pack['path']), pack['sha256'])
            with zipfile.ZipFile(args.output / pack['path']) as archive:
                for member in archive.namelist():
                    if member.startswith('attempt2/'):
                        archived[member] = archive.read(member)
        self.assertEqual(archived['attempt2/final.json'], report.read_bytes())
        self.assertEqual(sorted(v for k, v in archived.items() if k.endswith('.bin')), [b'end!', b'new!'])
        self.assertNotIn('attempt2/' + catalog['inherited_recipes'][0]['target_path'], archived)

    def test_changed_final_inventory_cannot_get_complete_index(self):
        catalog, _ = self.populate()
        ready, args = self.pack_ready()
        original_pack = p.z.pack_one
        def mutate_after_pack(*a, **kw):
            packed = original_pack(*a, **kw)
            (self.root / 'late-report.json').write_bytes(b'{}')
            return packed
        with patch.object(p, 'RUNTIME_ROOT', self.base), patch.object(p, 'load_ready', return_value=ready), \
             patch.object(p, 'prepare_catalog', return_value=catalog), patch.object(p.z, 'pack_one', side_effect=mutate_after_pack):
            with self.assertRaisesRegex(ValueError, 'inventory changed'):
                p.pack_delta(args)
        self.assertFalse((args.output / 'a2_delta_index.json').exists())


if __name__ == '__main__':
    unittest.main()
