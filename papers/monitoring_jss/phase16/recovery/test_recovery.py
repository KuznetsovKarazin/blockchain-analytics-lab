"""Focused synthetic archive and gate checks; no real archive or row is read."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile

import verify_recovered_archives as recovery

HERE = Path(__file__).resolve().parent
INPUT_DIGESTS = {'inventory_sha256': recovery.file_sha(HERE/'source_union.json'),
                 'reuse_sha256': recovery.file_sha(HERE/'reuse_expectations.json')}


class RecoveryChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='phase16_recovery_synthetic_')
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def fixture(self, extras=()):
        payloads = {'headers.parquet': b'SYNTHETIC HEADER BYTES', 'logs.parquet': b'SYNTHETIC LOG BYTES'}
        path = self.directory/'synthetic.zip'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(path, 'w') as archive:
                for name, payload in [*payloads.items(), *extras]:
                    archive.writestr(name, payload)
        archive_record = {'bytes': path.stat().st_size, 'sha256': recovery.file_sha(path), 'members': 2+len(extras)}
        objects = [{'table': table, 'expected_original_member_name': name,
                    'size_bytes': len(payloads[name]), 'expected_whole_object_sha256': hashlib.sha256(payloads[name]).hexdigest(),
                    'source_key': 'synthetic/'+table, 'etag_opaque': '"synthetic-opaque-etag"'}
                   for table, name in [('blocks', 'headers.parquet'), ('logs', 'logs.parquet')]]
        output = self.directory/'extracted'; output.mkdir()
        return path, archive_record, objects, output

    def test_valid_exact_members(self):
        path, record, objects, output = self.fixture()
        rows = recovery.extract_one(path, record, objects, output)
        self.assertEqual(len(rows), 2)
        self.assertEqual({x['source_key'] for x in rows}, {'synthetic/blocks', 'synthetic/logs'})
        for row in rows:
            self.assertEqual(recovery.file_sha(row['path']), row['sha256'])
            self.assertEqual(Path(row['path']).stat().st_size, row['size_bytes'])
        keyed = recovery.build_reuse_map(rows)
        self.assertEqual(set(keyed), {'synthetic/blocks', 'synthetic/logs'})
        self.assertEqual(keyed['synthetic/blocks']['source_key'], 'synthetic/blocks')
        with self.assertRaisesRegex(ValueError, 'duplicate recovered source key'):
            recovery.build_reuse_map(rows+[rows[0]])

    def test_wrong_archive_identity_before_extraction(self):
        path, record, objects, output = self.fixture()
        for field, value, error in [('bytes', record['bytes']+1, 'archive size'), ('sha256', '0'*64, 'archive SHA256')]:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, error):
                recovery.extract_one(path, dict(record, **{field: value}), objects, output)
            self.assertEqual(list(output.iterdir()), [])

    def test_unsafe_or_duplicate_member_before_extraction(self):
        for name in ('../escape', '/absolute', 'bad\\member', 'headers.parquet'):
            with self.subTest(name=name):
                path, record, objects, output = self.fixture([(name, b'bad')])
                with self.assertRaisesRegex(ValueError, 'unsafe archive|duplicate/member'):
                    recovery.extract_one(path, record, objects, output)
                self.assertEqual(list(output.iterdir()), [])
                output.rmdir()

    def test_member_identity_and_symlink(self):
        path, record, objects, output = self.fixture()
        for field, value, error in [('size_bytes', 12345, 'member size/type'), ('expected_whole_object_sha256', '0'*64, 'member SHA256/length')]:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, error):
                altered = copy.deepcopy(objects); altered[0][field] = value
                recovery.extract_one(path, record, altered, output)
            self.assertFalse((output/'blocks.parquet').exists())
        (output/'blocks.partial').unlink()
        link = zipfile.ZipInfo('headers.parquet'); link.create_system = 3; link.external_attr = 0o120777 << 16
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr(link, b'SYNTHETIC HEADER BYTES')
            archive.writestr('logs.parquet', b'SYNTHETIC LOG BYTES')
        record.update(bytes=path.stat().st_size, sha256=recovery.file_sha(path))
        with self.assertRaisesRegex(ValueError, 'symlink'):
            recovery.extract_one(path, record, objects, output)

    def test_opaque_source_identity_bound(self):
        expectations = json.loads((HERE/'reuse_expectations.json').read_text())
        inventory = json.loads((HERE/'source_union.json').read_text())
        archives, days = recovery.validate_expectations(expectations, inventory)
        self.assertEqual((len(archives), sum(map(len, days.values()))), (9, 18))
        expectations['objects'][0]['etag_opaque'] = '"different-opaque-etag"'
        with self.assertRaisesRegex(ValueError, 'source identity differs'):
            recovery.validate_expectations(expectations, inventory)

    def synthetic_acceptances(self):
        spec = importlib.util.spec_from_file_location('phase16_synthetic_acceptance_builder', HERE.parent/'protocol/prepare_measurement_acceptance.py')
        builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
        plan = self.directory/'SYNTHETIC_SOURCE_PLAN.json'
        plan.write_text(json.dumps({'synthetic_test_only': True, 'real_payload_authorized': False,
            'inventory_binding': {'path': 'papers/monitoring_jss/phase16/recovery/source_union.json', 'sha256': INPUT_DIGESTS['inventory_sha256']},
            'reuse_expectations_binding': {'path': 'papers/monitoring_jss/phase16/recovery/reuse_expectations.json', 'sha256': INPUT_DIGESTS['reuse_sha256']}}))
        records = {}
        for case in ('lifi', 'revest'):
            output = self.directory/('SYNTHETIC_'+case)
            receipt = builder.prepare(case=case, source_plan=plan, execution_sources=[HERE/'verify_recovered_archives.py'], output=output, confirm_before_payload=True)
            records[case] = {'config_path': str(output/'config.json'), 'acceptance_path': str(output/'measurement_acceptance.json'), 'acceptance_sha256': receipt['acceptance_sha256']}
        return records

    def test_both_exact_case_acceptances_and_shared_plan(self):
        records = self.synthetic_acceptances()
        result = recovery.validate_acceptances(records, **INPUT_DIGESTS)
        self.assertEqual(set(result), {'lifi', 'revest'})
        self.assertEqual(len({x['source_plan_sha256'] for x in result.values()}), 1)
        with self.assertRaisesRegex(ValueError, 'both case acceptances required'):
            recovery.validate_acceptances({'lifi': records['lifi']}, **INPUT_DIGESTS)
        with self.assertRaisesRegex(ValueError, 'wrong accepted case'):
            recovery.validate_acceptances({'lifi': records['revest'], 'revest': records['lifi']}, **INPUT_DIGESTS)
        with self.assertRaisesRegex(ValueError, 'recovery input not bound'):
            recovery.validate_acceptances(records, **dict(INPUT_DIGESTS, reuse_sha256='0'*64))
        records['lifi']['acceptance_sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'root acceptance digest mismatch'):
            recovery.validate_acceptances(records, **INPUT_DIGESTS)


if __name__ == '__main__':
    unittest.main(verbosity=2)
