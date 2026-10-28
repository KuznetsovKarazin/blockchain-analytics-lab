"""Bounded tests of publication relocation and archive failure handling only."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

import verify_public_evidence as verifier


class PublicEvidenceChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.payload = b'{"synthetic":true}\n'
        self.archive = self.root / 'fixture.zip'
        with zipfile.ZipFile(self.archive, 'w') as z:
            z.writestr('runtime/fixture.json', self.payload)
        self.manifest = {'capsule': {'bytes': self.archive.stat().st_size,
                                    'sha256': verifier.digest(self.archive)},
                         'files': [{'path': 'runtime/fixture.json', 'bytes': len(self.payload),
                                    'sha256': hashlib.sha256(self.payload).hexdigest()}]}

    def test_exact_synthetic_archive_roundtrip(self):
        out = self.root / 'out'
        verifier.extract_verified(self.archive, self.manifest, out)
        self.assertEqual((out / 'runtime/fixture.json').read_bytes(), self.payload)

    def test_wrong_container_hash_rejected_before_output(self):
        self.manifest['capsule']['sha256'] = '0' * 64
        out = self.root / 'out'
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            verifier.extract_verified(self.archive, self.manifest, out)
        self.assertFalse(out.exists())

    def test_wrong_member_hash_rejected(self):
        self.manifest['files'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'member SHA256'):
            verifier.extract_verified(self.archive, self.manifest, self.root / 'out')

    def test_traversal_member_rejected_before_output(self):
        self.manifest['files'][0]['path'] = '../escape.json'
        with self.assertRaisesRegex(ValueError, 'stay relative'):
            verifier.extract_verified(self.archive, self.manifest, self.root / 'out')
        self.assertFalse((self.root / 'escape.json').exists())

    def test_extra_zip_member_rejected(self):
        with zipfile.ZipFile(self.archive, 'a') as z:
            z.writestr('extra.json', b'{}')
        self.manifest['capsule'] = {'bytes': self.archive.stat().st_size, 'sha256': verifier.digest(self.archive)}
        with self.assertRaisesRegex(ValueError, 'extra member'):
            verifier.extract_verified(self.archive, self.manifest, self.root / 'out')

    def test_original_binding_hash_check_survives_relocation(self):
        path = self.root / 'actual.json'
        path.write_bytes(self.payload)
        spec = importlib.util.spec_from_file_location('test_capsule_frozen_join', verifier.REPO / verifier.JOIN_REL)
        join = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(join)
        original_driver_binding = join.driver.bound_file
        original, adapter = verifier.make_binding_adapter(join, {'/historical/fixture.json': path}, {path.resolve()})
        good = {'path': '/historical/fixture.json', 'sha256': verifier.digest(path)}
        self.assertEqual(adapter(good, self.root), path)
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            adapter(dict(good, sha256='0' * 64), self.root)
        self.assertIs(join.binding, original)
        self.assertIs(join.driver.bound_file, original_driver_binding)

    def test_unenumerated_path_rejected_before_original_reader(self):
        class Stub:
            class driver:
                @staticmethod
                def exact_keys(value, expected, name):
                    assert set(value) == set(expected)
            @staticmethod
            def nonempty(value, name):
                assert value
            @staticmethod
            def binding(value, folder):
                raise AssertionError('unenumerated file must never be read')
        _, adapter = verifier.make_binding_adapter(Stub, {}, set())
        for path in ('/unrelated/private.json', '../private.json'):
            with self.assertRaises(ValueError):
                adapter({'path': path, 'sha256': '0' * 64}, self.root)


if __name__ == '__main__':
    unittest.main()
