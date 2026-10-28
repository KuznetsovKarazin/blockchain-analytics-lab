"""Independent finalizer checks against invented temporary repositories only."""
import contextlib
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import create_final_delta_snapshot as c


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(c.canonical(value) + b'\n')
    return {'path': str(path), 'sha256': c.sha(path)}


class FinalSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='phase16_finalizer_independent_')
        self.base = Path(self.temp.name)
        self.repo, self.runtime, self.workspace = [self.base / n for n in ('repo', 'runtime', 'workspace')]
        for path in (self.repo, self.runtime, self.workspace): path.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Synthetic Fixture')
        self.git('config', 'user.email', 'synthetic@example.invalid')
        phase = self.repo / c.PHASE
        public = [phase / 'manuscript/EXTERNAL_CASE_RESULTS.md', phase / 'manuscript/EXTERNAL_CASE_AGGREGATES.json']
        public[0].parent.mkdir(parents=True)
        public[0].write_text('Invented public result.\n')
        save(public[1], {'invented': True})
        self.git('add', '.')
        self.git('commit', '-qm', 'Invented fixture')
        self.commit = self.git('rev-parse', 'HEAD')
        self.public = public
        self.packer = phase / 'delivery/pack_compact_a2_delta.py'
        self.packer.parent.mkdir()
        self.packer.write_text('# invented packer placeholder; never executed\n')
        self.packer_sha = c.sha(self.packer)
        for group in ('replays', 'decision_audits', 'independent_source_audit', 'reference_work',
                      'reference_archive_audit', 'reference_join', 'scientific_results'):
            (self.runtime / group).mkdir()
        (self.workspace / 'phase16_storage_recovery_audit').mkdir()
        statuses = {'reference_work/reference_inventory.json': 'SEALED_AFTER_DECISIONS_INDEPENDENTLY_ADJUDICATED',
                    'reference_work/independent_reference_review.json': 'APPROVED_FOR_EXACT_REFERENCE_JOIN',
                    'reference_join/join_receipt.json': 'COMPLETE', 'reference_join/coverage.json': 'COMPLETE',
                    'scientific_results/independent_interpretation.json': 'PASS_EXACT_JOIN_INTERPRETATION_ARITHMETIC',
                    'scientific_results/reference_mechanisms.json': 'DERIVED_FROM_SEALED_ROWS_NO_NEW_EXPERIMENT'}
        for rel, status in statuses.items(): save(self.runtime / rel, {'status': status})
        self.qa = self.runtime / 'scientific_results/qa_interpretation.md'
        self.qa.write_text('Invented final interpretation.\n')
        self.historical = phase / 'continuation/historical_candidate.json'
        save(self.historical, {'binding_not_current': {'path': '/invented/missing.json', 'sha256': 'a' * 64}})
        invalid = self.repo / c.INVALID
        invalid.parent.mkdir(exist_ok=True)
        invalid.touch()
        for name in ('recovery_receipt.json', 'reuse_map.json', 'progress.json'):
            save(self.runtime / 'original_sources' / name, {})
        for name in ('phase16_storage_recovery_runtime.jsonl', 'phase16_recovery_github_autoreview_rejection.json',
                     'phase16_private_recovery_plan.json', 'phase16_archive_paths.json',
                     'phase16_runtime_acceptances.json', 'phase16_recovery_acceptances.json'):
            save(self.workspace / name, {})
        self.derived = self.base / 'derive.py'
        self.derived.write_text('# invented derivation placeholder\n')
        index = save(self.base / 'a1_index.json', {'packs': []})
        self.deps = dict(a1_durable_objects=[], original_archive_objects=[], whole_object_origins={},
                         raw_metadata_bindings={'a1_index': index})
        deps_binding = save(self.runtime / 'dependencies.json', self.deps)
        save(self.runtime / 'attempt2/transport/accepted_range_evidence.json', {'ranges': []})
        proposal = self.runtime / 'ready_proposal.json'
        proposal_binding = save(proposal, dict(schema_version='phase16_compact_a2_delta_ready_inputs_v1',
            proposal_status='INVENTED_PROPOSAL', dependencies=deps_binding, final_snapshot={'path': 'placeholder', 'sha256': '0' * 64}))
        reviewed = [dict(**c.binding(path), size_bytes=path.stat().st_size)
                    for path in public + [self.runtime / 'scientific_results/reference_mechanisms.json']]
        review = self.workspace / 'report_review.json'
        review_binding = save(review, dict(schema_version='phase16_independent_public_result_report_review_v1',
            status='PASS_PUBLIC_RESULT_REPORT', reviewed_artifacts=reviewed))
        publication = self.workspace / 'publication.json'
        pub_binding = save(publication, dict(status='PUBLISHED_AND_REMOTE_VERIFIED', commit_sha=self.commit,
            reviewed_report=review_binding, artifacts=[{'path': str(path.relative_to(self.repo)), 'sha256': c.sha(path)} for path in public]))
        self.args = SimpleNamespace(all_writers_closed=True, published_commit=self.commit,
            report_review=review, expected_report_review_sha256=review_binding['sha256'],
            publication_receipt=publication, expected_publication_receipt_sha256=pub_binding['sha256'],
            ready_proposal=proposal, expected_ready_proposal_sha256=proposal_binding['sha256'],
            snapshot=self.runtime / 'final_snapshot.json', proof=self.runtime / 'final_proof.json',
            closure_manifest=self.runtime / 'closure_manifest.json')

    def tearDown(self): self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.DEVNULL).decode().strip()

    @contextlib.contextmanager
    def isolated(self):
        real_path = Path
        def path(value):
            return self.derived if str(value) == '/tmp/phase16_derive_reference_mechanisms.py' else real_path(value)
        with patch.object(c, 'Path', side_effect=path), patch.object(c, 'PACKER_SHA', self.packer_sha):
            yield

    def create(self):
        with self.isolated():
            return c.create(self.args, repo=self.repo, runtime=self.runtime, workspace=self.workspace)

    def census(self):
        with self.isolated():
            return c.inventory(self.repo, self.runtime, self.workspace, self.args.publication_receipt, self.args.report_review)

    def assert_no_outputs(self):
        self.assertFalse(self.args.snapshot.exists())
        self.assertFalse(self.args.proof.exists())
        self.assertFalse(self.args.closure_manifest.exists())

    def test_valid_closure_includes_qa_operations_and_preserves_proposal_fields(self):
        original = c.read(self.args.ready_proposal)
        result = self.create()
        self.assertEqual(result['status'], 'FINAL_SNAPSHOT_AND_PROOF_CREATED_NO_PACK')
        snapshot = c.read(self.args.snapshot)
        paths = {b['path'] for b in snapshot['artifact_bindings']}
        self.assertIn(str(self.qa), paths)
        self.assertIn(str(self.historical), paths)
        self.assertNotIn(str(self.public[0]), paths)
        self.assertNotIn(str(self.repo / c.INVALID), paths)
        proof = c.read(self.args.proof)
        original.pop('proposal_status')
        original['final_snapshot'] = c.binding(self.args.snapshot)
        self.assertEqual(proof, original)
        self.assertEqual(result['proof'], c.binding(self.args.proof))
        self.assertTrue(any(x['reason'] == 'EXACT_PUBLISHED_GIT_BYTES' for x in c.read(self.args.closure_manifest)['explicit_exclusions']))

    def test_explicit_writer_closure_is_required_before_any_reads(self):
        self.args.all_writers_closed = False
        with patch.object(c, 'sha', side_effect=AssertionError('read before closure gate')):
            with self.assertRaisesRegex(ValueError, 'explicitly attest'):
                self.create()
        self.assert_no_outputs()

    def test_wrong_published_head_and_changed_tracked_bytes_rejected(self):
        with self.assertRaises(ValueError): c.public_tree(self.repo, 'f' * 40)
        self.public[0].write_text('Changed published bytes\n')
        with self.assertRaisesRegex(ValueError, 'tracked files differ'):
            c.public_tree(self.repo, self.commit)

    def test_missing_required_group_and_nonempty_invalid_report_rejected(self):
        (self.runtime / 'replays').rmdir()
        with self.assertRaisesRegex(ValueError, 'required final directory'): self.census()
        (self.runtime / 'replays').mkdir()
        (self.repo / c.INVALID).write_text('{}')
        with self.assertRaisesRegex(ValueError, 'invalid wall report'): self.census()

    def test_raw_primary_copies_and_python_cache_excluded(self):
        raw = self.runtime / 'reference_work/internal_raw/page.json'
        cache = self.runtime / 'replays/__pycache__/state.json'
        save(raw, {'invented': True}); save(cache, {'invented': True})
        result = self.census()
        self.assertNotIn(raw, result); self.assertNotIn(cache, result)

    def test_symlink_in_census_rejected_before_target_is_archived(self):
        unrelated = self.base / 'unrelated.json'
        save(unrelated, {'not_authorized_by_runtime_group': True})
        (self.runtime / 'replays/link.json').symlink_to(unrelated)
        with self.assertRaisesRegex(ValueError, 'symlink'): self.census()

    def test_closure_direct_symlink_rejected(self):
        unrelated = self.base / 'other.json'; save(unrelated, {})
        alias = self.base / 'alias.json'; alias.symlink_to(unrelated)
        closure = c.Closure(self.repo, self.runtime, self.commit, set(), self.deps)
        with self.assertRaisesRegex(ValueError, 'symlink'): closure.add(alias)

    def test_unapproved_review_wrong_mechanism_and_unverified_publication_rejected(self):
        for target in ('review', 'mechanism', 'publication'):
            with self.subTest(target=target):
                path = {'review': self.args.report_review, 'mechanism': self.runtime / 'scientific_results/reference_mechanisms.json',
                        'publication': self.args.publication_receipt}[target]
                old = path.read_bytes(); value = c.read(path); value['status'] = 'NOT_APPROVED'; save(path, value)
                with self.assertRaises(ValueError): self.create()
                self.assert_no_outputs(); path.write_bytes(old)

    def test_status_and_receipt_changes_after_validation_rejected(self):
        original_inventory = c.inventory
        for path in (self.args.report_review, self.args.publication_receipt, self.runtime / 'reference_join/coverage.json'):
            with self.subTest(path=path.name):
                old = path.read_bytes(); calls = 0
                def changed(*args, **kwargs):
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        value = c.read(path); value['status'] = 'CHANGED_AFTER_VALIDATION'; save(path, value)
                    return original_inventory(*args, **kwargs)
                with patch.object(c, 'inventory', side_effect=changed):
                    with self.assertRaisesRegex(ValueError, 'binding changed'): self.create()
                self.assert_no_outputs(); path.write_bytes(old)

    def test_file_change_during_hashing_rejected(self):
        target = self.base / 'stable.json'; save(target, {'value': 1}); original_sha = c.sha
        def changed(path):
            value = original_sha(path)
            if Path(path) == target: target.write_text('{"value":2}')
            return value
        with patch.object(c, 'sha', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'changed while hashing'): c.stable_binding(target)

    def test_late_new_file_rejects_global_census(self):
        original = c.inventory; calls = 0
        def changed(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2: save(self.runtime / 'scientific_results/late.json', {})
            return original(*args, **kwargs)
        with patch.object(c, 'inventory', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'global final file census changed'): self.create()
        self.assert_no_outputs()

    def test_existing_file_changed_after_closure_rejected(self):
        original = c.inventory; calls = 0
        def changed(*args, **kwargs):
            nonlocal calls
            calls += 1; result = original(*args, **kwargs)
            if calls == 2: self.qa.write_text('Changed during final census\n')
            return result
        with patch.object(c, 'inventory', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'final metadata changed'): self.create()
        self.assert_no_outputs()

    def test_output_paths_must_be_distinct(self):
        self.args.proof = self.args.snapshot
        with self.assertRaises(ValueError): self.create()
        self.assert_no_outputs()

    def test_missing_graph_binding_fails_but_durable_body_is_not_opened(self):
        closure = c.Closure(self.repo, self.runtime, self.commit, set(), self.deps)
        gate = self.runtime / 'gate.json'
        save(gate, {'required': {'path': 'absent.json', 'sha256': 'f' * 64}})
        closure.add(gate)
        with self.assertRaisesRegex(ValueError, 'missing required metadata graph'): closure.follow()
        bodyhash = hashlib.sha256(b'not-stored-body').hexdigest()
        self.deps['whole_object_origins']['invented'] = dict(sha256=bodyhash,
            archive_library_file_id='libfile_synthetic', member_name='source.parquet')
        closure = c.Closure(self.repo, self.runtime, self.commit, set(), self.deps)
        save(gate, {'required': {'path': '/invented/unavailable-source.parquet', 'sha256': bodyhash}})
        closure.add(gate); closure.follow()
        self.assertEqual(closure.excluded[-1]['reason'], 'ALREADY_DURABLE_DEPENDENCY')

    def test_exact_published_json_is_terminal_but_private_missing_binding_still_fails(self):
        historical = self.repo / c.PHASE / 'published_historical.json'
        save(historical, {'old_acquisition': {'path': '/invented/unavailable_history/headers.jsonl',
                                            'sha256': 'e' * 64}})
        self.git('add', str(historical.relative_to(self.repo)))
        self.git('commit', '-qm', 'Invented historical durable node')
        commit = self.git('rev-parse', 'HEAD')
        closure = c.Closure(self.repo, self.runtime, commit, c.public_tree(self.repo, commit), self.deps)
        closure.add(historical, c.sha(historical))
        closure.follow()
        self.assertNotIn(str(historical), closure.files)
        self.assertTrue(any(item['reason'] == 'EXACT_PUBLISHED_GIT_BYTES'
                            and item['commit_sha'] == commit
                            and item['sha256'] == c.sha(historical)
                            for item in closure.excluded))
        private = self.runtime / 'current_private_gate.json'
        save(private, {'required_current_metadata': {'path': 'missing_current_metadata.json',
                                                    'sha256': 'f' * 64}})
        closure.add(private, c.sha(private))
        with self.assertRaisesRegex(ValueError, 'missing required metadata graph'):
            closure.follow()


if __name__ == '__main__': unittest.main()
