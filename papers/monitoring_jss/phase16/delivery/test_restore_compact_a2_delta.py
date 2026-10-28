"""Invented byte-only restoration tests; never access a real collection."""
import copy
import gzip
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest

import pack_closed_a1_forensics as z
import pack_compact_a2_delta as p
import restore_compact_a2_delta as r


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='phase16_delta_restore_synthetic_')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def fixture(self, external_origin=False):
        root = self.root
        source = {'table': 'logs', 'day_utc': '2022-03-01', 'key': 'synthetic/logs',
                  'size_bytes': 1024, 'etag_opaque': '"invented"', 'url': 'https://synthetic.invalid/logs'}
        sid = r.digest(source); parent = 'a' * 64; current = 'b' * 64
        body = bytes(i % 251 for i in range(1024)); a1root = root / 'a1_restored'
        a1file = a1root / 'cache' / sid / 'source.parquet'; a1file.parent.mkdir(parents=True)
        a1file.write_bytes(body)
        a1packs = root / 'a1_packs'; a1packs.mkdir()
        a1member = f'attempt1/cache/{sid}/source.parquet'
        a1pack = z.pack_one(a1packs, 'a1.zip', [{'path': a1file, 'member': a1member,
                          'before_stat': z.snapshot(a1file), 'source_id': sid, 'source_identity': source,
                          'artifact_kind': 'canonical_sparse_cache_image_not_complete_source'}], 1024 * 1024)
        a1index = {'schema_version': 'phase16_closed_a1_forensic_archive_index_v1',
                   'status': 'COMPLETE_FORENSIC_PRESERVATION_NOT_SOURCE_AUDIT', 'packs': [a1pack]}
        a1path = a1packs / 'a1_forensic_index.json'; z.write_json(a1path, a1index)
        a1sha = r.file_sha(a1path)
        deps = {'a1_index_sha256': a1sha, 'a1_durable_objects': [
            {'file_name': 'a1.zip', 'sha256': a1pack['sha256'], 'bytes': a1pack['bytes'], 'library_file_id': 'libfile_synthetic_zip'},
            {'file_name': a1path.name, 'sha256': a1sha, 'bytes': a1path.stat().st_size, 'library_file_id': 'libfile_synthetic_index'}],
            'whole_object_origins': {}}
        original_root = '/synthetic/original_attempt2'; source_dir = Path('storage') / sid
        descriptors = {'schema_version': 'article2_phase16_compact_source_v1', 'storage_kind': 'compact_descriptor',
                       'source': source, 'source_id': sid, 'logical_size_bytes': len(body),
                       'attempt_id': current, 'parent_attempt_id': parent, 'segments': []}
        wrappers, inherited, new = [], [], []
        for ordinal, start, length, origin in [(1, 0, 8, parent), (2, 80, 7, parent), (731, 200, 8, current)]:
            payload = body[start:start + length]; bodysha = sha(payload)
            path = f'storage/{sid}/blobs/{origin}-{ordinal:06d}-{bodysha}.bin'
            blob = {'path': path, 'size_bytes': length, 'sha256': bodysha}
            receipt = {'ordinal': ordinal, 'source': source, 'start': start, 'length': length,
                       'transport_ok': True, 'response_bytes': length, 'response_sha256': bodysha}
            if origin == current: receipt['blob'] = blob
            item = {'path': path, 'sha256': bodysha, 'size_bytes': length, 'origin_ordinal': ordinal,
                    'origin_attempt_id': origin, 'source_key': source['key'], 'source_id': sid,
                    'start': start, 'length': length, 'receipt_sha256': r.digest(receipt)}
            wrappers.append({'origin_attempt_id': origin, 'origin_ordinal': ordinal, 'receipt': receipt, 'blob': blob})
            descriptors['segments'].append({'start': start, 'length': length,
                'blob_path': str(Path(path).relative_to(source_dir)), 'blob_sha256': bodysha,
                'origin_attempt_id': origin, 'origin_ordinal': ordinal, 'receipt_sha256': r.digest(receipt)})
            if origin == parent:
                inherited.append({'target_path': path, **{k: v for k, v in item.items() if k not in ('path', 'size_bytes')},
                    'a1_member': a1member, 'a1_archive': {'path': a1pack['path'], 'sha256': a1pack['sha256']},
                    'a1_artifact_sha256': sha(body), 'a1_artifact_logical_bytes': len(body)})
            else: new.append(item)
        locations = {source['key']: {'storage_kind': 'compact_descriptor',
            'original_path': f'{original_root}/{source_dir}/source_storage.json',
            'descriptor_relative_path': f'{source_dir}/source_storage.json'}}
        whole_bytes = b'invented original whole object'; whole = root / 'whole.parquet'; whole.write_bytes(whole_bytes)
        wholekey = 'synthetic/whole'; wholesha = sha(whole_bytes)
        deps['whole_object_origins'][wholekey] = {'size_bytes': len(whole_bytes), 'etag_opaque': '"whole"',
            'sha256': wholesha, 'archive_sha256': 'd' * 64, 'archive_bytes': 234,
            'archive_library_file_id': 'libfile_synthetic_whole_archive', 'member_name': 'logs.parquet'}
        locations[wholekey] = {'storage_kind': 'verified_whole_object', 'original_path': '/synthetic/whole.parquet',
                               'whole_object_sha256': wholesha}
        map_path = root / 'whole_map.json'; z.write_json(map_path, {wholekey: str(whole)})
        small = root / 'source_attempt2'; small.mkdir()
        content = {'transport/session.json': r.canonical({'schema_version': 'article2_phase16_storage_recovery_capture_v1',
            'status': 'COMPLETE', 'attempt_id': current, 'parent_attempt_id': parent}) + b'\n',
            'transport/accepted_range_evidence.json': r.canonical({'schema_version': 'article2_phase16_compact_accepted_ranges_v1',
            'ranges': wrappers}) + b'\n',
            f'{source_dir}/source_storage.json': r.canonical(descriptors) + b'\n',
            'observations/empty.jsonl': b'', new[0]['path']: body[200:208]}
        entries = []
        for relative, data in content.items():
            path = small / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            entries.append({'path': path, 'member': 'attempt2/' + relative, 'before_stat': z.snapshot(path)})
        proof = root / 'external_proof.json'; proof.write_bytes(b'{"synthetic_only":true}\n')
        external = {'path': proof, 'member': 'delivery_control/001_external_proof.json', 'before_stat': z.snapshot(proof)}
        if external_origin: external['original_external_path'] = '/synthetic/historical/external_proof.json'
        entries.append(external)
        packs = root / 'delta_packs'; packs.mkdir()
        pack = z.pack_one(packs, 'delta.zip', entries, 1024 * 1024)
        index = {'schema_version': 'phase16_compact_a2_delta_index_v1',
            'status': 'COMPLETE_DELTA_PRESERVATION_NOT_NEW_SOURCE_AUDIT', 'packs': [pack],
            'dependencies': deps, 'inherited_recipes': inherited, 'new_blob_entries': new,
            'original_runtime_root': original_root, 'source_locations': locations}
        path = packs / 'a2_delta_index.json'; z.write_json(path, index)
        return {'index': index, 'index_path': path, 'a1_index': a1index, 'a1_path': a1path, 'a1_sha': a1sha,
                'a1_root': a1root, 'a1_file': a1file, 'a1_pack_root': a1packs, 'map_path': map_path,
                'whole': whole, 'content': content, 'body': body, 'new': new, 'inherited': inherited,
                'wrappers': wrappers, 'descriptor': descriptors}

    def restore(self, fixture, mode='zip', output='restored'):
        kwargs = {'a1_pack_root': fixture['a1_pack_root']} if mode == 'zip' else {'a1_restored_root': fixture['a1_root']}
        return r.restore(fixture['index_path'], r.file_sha(fixture['index_path']), fixture['a1_path'], fixture['a1_sha'],
                         fixture['map_path'], self.root / output, **kwargs)

    def rewrite_index(self, fixture):
        z.write_json(fixture['index_path'], fixture['index'])

    def test_zip_restore_exact_readonly_blobs_and_verbatim_metadata(self):
        f = self.fixture(); receipt = self.restore(f)
        self.assertEqual(receipt['status'], 'PASS_COMPACT_DELTA_BYTE_RESTORATION_NOT_NEW_SOURCE_AUDIT')
        out = self.root / 'restored' / 'attempt2'
        for relative, content in f['content'].items(): self.assertEqual((out / relative).read_bytes(), content)
        for row in f['inherited'] + f['new']:
            path = out / row.get('target_path', row.get('path'))
            self.assertEqual(path.read_bytes(), f['body'][row['start']:row['start'] + row['length']])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
        self.assertEqual(receipt['inherited_response_count'], 2)
        self.assertEqual(receipt['new_response_count'], 1)
        self.assertEqual(len(receipt['inherited_members']), 1)
        self.assertEqual(receipt['inherited_members'][0]['artifact_logical_bytes_streamed'], 1024)
        self.assertEqual((self.root / 'restored/delivery_control/001_external_proof.json').read_bytes(), b'{"synthetic_only":true}\n')
        self.assertFalse((out / 'cache').exists())
        self.assertFalse(any(x.name == 'whole.parquet' for x in out.rglob('*')))
        self.assertEqual(receipt['whole_objects_verified_without_copy']['synthetic/whole']['path'], str(f['whole']))
        mapping = json.loads((self.root / 'restored/relocation_map.json').read_bytes())
        self.assertFalse(mapping['original_metadata_rewritten'])
        self.assertFalse(mapping['historical_audits_reexecuted'])

    def test_restored_a1_mode_is_byte_identical(self):
        f = self.fixture(); a = self.restore(f, output='zip'); b = self.restore(f, 'restored', output='raw')
        self.assertEqual(a['inherited_members'], b['inherited_members'])
        for row in f['inherited'] + f['new']:
            relative = row.get('target_path', row.get('path'))
            self.assertEqual((self.root / 'zip/attempt2' / relative).read_bytes(), (self.root / 'raw/attempt2' / relative).read_bytes())

    def test_external_relocation_preserves_bytes_and_rejects_duplicate_origins(self):
        f = self.fixture(external_origin=True); self.restore(f)
        mapping = json.loads((self.root / 'restored/relocation_map.json').read_bytes())
        original = '/synthetic/historical/external_proof.json'
        destination = self.root / 'restored/delivery_control/001_external_proof.json'
        self.assertEqual(mapping['external_artifact_paths'], {original: str(destination)})
        self.assertEqual(destination.read_bytes(), b'{"synthetic_only":true}\n')
        index = copy.deepcopy(f['index']); duplicate = copy.deepcopy(index['packs'][0]['members'][-1])
        duplicate['member'] = 'delivery_control/002_duplicate_proof.json'
        index['packs'][0]['members'].append(duplicate)
        with self.assertRaisesRegex(ValueError, 'duplicate external original path'):
            r.validate_indices(index, f['a1_index'], f['a1_sha'], f['a1_path'].stat().st_size)

    def test_producer_artifact_inventory_and_groups_restore_without_schema_changes(self):
        f = self.fixture(); source = self.root / 'source_attempt2'
        for row in f['inherited']:
            path = source / row['target_path']; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f['body'][row['start']:row['start'] + row['length']]); path.chmod(0o444)
        for row in f['new']: (source / row['path']).chmod(0o444)
        catalog = {'all_blob_paths': {row['target_path'] for row in f['inherited']} | {row['path'] for row in f['new']},
                   'new_blob_entries': f['new']}
        external = self.root / 'external_proof.json'
        compressed = self.root / 'sealed_decisions.jsonl.gz'
        compressed.write_bytes(gzip.compress(b'{"synthetic_decision":true}\n', mtime=0))
        entries, metadata, census = p.artifact_entries(source, catalog,
            {'expected_artifacts': {str(path.resolve()): r.file_sha(path) for path in (external, compressed)},
             'external': [external, compressed]})
        packs = [p.z.pack_one(f['index_path'].parent, name, group, 1024 * 1024)
                 for name, group in p.group_entries(entries, 1024 * 1024)]
        f['index']['packs'] = packs; self.rewrite_index(f)
        receipt = self.restore(f)
        self.assertEqual(receipt['metadata_files_restored_verbatim'], len(metadata) + 2)
        self.assertEqual(receipt['inherited_response_count'], 2)
        mapping = json.loads((self.root / 'restored/relocation_map.json').read_bytes())
        restored_compressed = Path(mapping['external_artifact_paths'][str(compressed)])
        self.assertEqual(restored_compressed.read_bytes(), compressed.read_bytes())
        self.assertTrue(all('attempt2/' + row['target_path'] not in {m['member'] for pack in packs for m in pack['members']}
                            for row in f['inherited']))

    def test_outside_range_a1_tamper_rejected_before_old_blob_commit(self):
        f = self.fixture(); body = bytearray(f['a1_file'].read_bytes()); body[900] ^= 1; f['a1_file'].write_bytes(body)
        with self.assertRaisesRegex(ValueError, 'full canonical'): self.restore(f, 'restored')
        self.assertFalse((self.root / 'restored/restore_receipt.json').exists())
        self.assertTrue((self.root / 'restored/restore_failure.json').exists())
        for row in f['inherited']: self.assertFalse((self.root / 'restored/attempt2' / row['target_path']).exists())

    def test_overlap_pending_missing_new_and_traversal_rejected(self):
        f = self.fixture()
        for mutation, message in [('overlap', 'overlapping'), ('pending', 'pending/origin'), ('missing', 'missing from delta'), ('traversal', 'unsafe relative')]:
            with self.subTest(mutation=mutation):
                index = copy.deepcopy(f['index'])
                if mutation == 'overlap': index['inherited_recipes'][1]['start'] = 1
                elif mutation == 'pending': index['new_blob_entries'][0]['origin_ordinal'] = 730
                elif mutation == 'missing': index['packs'][0]['members'] = [m for m in index['packs'][0]['members'] if not m['member'].endswith('.bin')]
                else: index['packs'][0]['members'][0]['member'] = 'attempt2/../escape.json'
                with self.assertRaisesRegex(ValueError, message):
                    r.validate_indices(index, f['a1_index'], f['a1_sha'], f['a1_path'].stat().st_size)

    def test_tampered_archive_rejected_before_output(self):
        f = self.fixture(); archive = f['index_path'].parent / 'delta.zip'
        data = bytearray(archive.read_bytes()); data[-1] ^= 1; archive.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'archive size/digest'): self.restore(f)
        self.assertFalse((self.root / 'restored').exists())

    def test_tampered_whole_rejected_before_output(self):
        f = self.fixture(); f['whole'].write_bytes(b'changed whole object')
        with self.assertRaisesRegex(ValueError, 'whole object digest/size'): self.restore(f)
        self.assertFalse((self.root / 'restored').exists())

    def test_missing_and_tampered_descriptor_or_receipt_rejected(self):
        f = self.fixture(); validated = r.validate_indices(f['index'], f['a1_index'], f['a1_sha'], f['a1_path'].stat().st_size)
        small = self.root / 'source_attempt2'
        accepted_path = small / 'transport/accepted_range_evidence.json'
        original = accepted_path.read_bytes(); accepted = json.loads(original); accepted['ranges'].pop()
        z.write_json(accepted_path, accepted)
        with self.assertRaisesRegex(ValueError, 'omits a restored origin'): r.validate_restored_metadata(f['index'], validated, small)
        accepted_path.write_bytes(original)
        relative = next(x['descriptor_relative_path'] for x in f['index']['source_locations'].values() if x['storage_kind'] == 'compact_descriptor')
        desc = copy.deepcopy(f['descriptor']); desc['segments'][0]['blob_sha256'] = 'f' * 64
        z.write_json(small / relative, desc)
        with self.assertRaisesRegex(ValueError, 'descriptor range differs'): r.validate_restored_metadata(f['index'], validated, small)

    def test_unindexed_and_inherited_payload_in_delta_rejected(self):
        f = self.fixture()
        for inherited in (False, True):
            index = copy.deepcopy(f['index']); record = copy.deepcopy(index['packs'][0]['members'][0])
            record['member'] = 'attempt2/' + (f['inherited'][0]['target_path'] if inherited else 'unindexed.bin')
            index['packs'][0]['members'].append(record)
            with self.assertRaisesRegex(ValueError, 'redundantly includes|unindexed payload'):
                r.validate_indices(index, f['a1_index'], f['a1_sha'], f['a1_path'].stat().st_size)

    def test_exact_bound_indices_and_fresh_output_required(self):
        f = self.fixture()
        with self.assertRaisesRegex(ValueError, 'bound JSON digest'):
            r.restore(f['index_path'], 'f' * 64, f['a1_path'], f['a1_sha'], f['map_path'], self.root / 'restored', a1_pack_root=f['a1_pack_root'])
        (self.root / 'restored').mkdir()
        with self.assertRaisesRegex(ValueError, 'fresh restore'): self.restore(f)


if __name__ == '__main__':
    unittest.main()
