"""Close the private delivery census only after the root's explicit writer closure.

No source body reads, scientific computation, packing, network, or uploads.
The already reviewed delta packer remains a separate, hash-pinned operation.
"""
from __future__ import annotations
import argparse
from collections import deque
import datetime
import hashlib
import json
from pathlib import Path
import subprocess

PACKER_SHA = 'ad832803b4c5406b61f4bbb38e9400fb85a46b08234c7a2d4f6b3d7aaacc0e3e'
RUNTIME = Path('/tmp/article2_phase16_runtime_159bf77d8682')
WORKSPACE = Path('/workspace/scratch/159bf77d8682')
REPO = WORKSPACE / 'monitoring-work'
PHASE = 'papers/monitoring_jss/phase16'
INVALID = PHASE + '/continuation/independent_scope_preflight.json'
MAX_METADATA = 128 * 1024 * 1024


def need(ok, message):
    if not ok: raise ValueError(message)


def read(path): return json.loads(Path(path).read_bytes())
def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for data in iter(lambda: f.read(1024 * 1024), b''): h.update(data)
    return h.hexdigest()


def signature(path):
    s = Path(path).stat()
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def binding(path): return {'path': str(Path(path).resolve()), 'sha256': sha(path)}
def git(repo, *args): return subprocess.check_output(['git', '-C', str(repo), *args]).decode().strip()


def public_tree(repo, commit):
    need(len(commit) == 40 and all(c in '0123456789abcdef' for c in commit), 'full published commit required')
    need(git(repo, 'rev-parse', 'HEAD') == commit, 'HEAD differs from verified published commit')
    need(not git(repo, 'diff', '--name-only', 'HEAD'), 'tracked files differ from published HEAD')
    raw = subprocess.check_output(['git', '-C', str(repo), 'ls-files', '-z'])
    return {x.decode() for x in raw.split(b'\0') if x}


def safe_metadata(path):
    path = Path(path)
    need(not path.is_symlink(), 'metadata symlink is not a frozen file')
    need(path.is_file() and path.stat().st_size <= MAX_METADATA, 'missing or oversized metadata')
    need('internal_raw' not in path.parts and '__pycache__' not in path.parts, 'raw page or cache is excluded')
    need(path.suffix in ('.json', '.jsonl', '.md', '.py', '.csv', '.txt', '.sh')
         or path.name.endswith('.jsonl.gz'), 'source/archive payload is not final metadata')
    need(path.name not in ('.env', 'credentials', 'credentials.json', 'token.json'), 'credential file excluded')


def stable_binding(path, expected=None):
    safe_metadata(path); before = signature(path); digest = sha(path)
    need(signature(path) == before, 'metadata changed while hashing')
    need(expected is None or digest == expected, 'required metadata binding changed')
    return {'path': str(Path(path).resolve()), 'sha256': digest}, before


def file_bindings(value):
    """Follow explicit file-binding dictionaries, not arbitrary text paths."""
    if isinstance(value, dict):
        p, h = value.get('path'), value.get('sha256')
        if isinstance(p, str) and isinstance(h, str) and len(h) == 64 and all(c in '0123456789abcdef' for c in h):
            yield {'path': p, 'sha256': h}
        for child in value.values(): yield from file_bindings(child)
    elif isinstance(value, list):
        for child in value: yield from file_bindings(child)


def inventory(repo, runtime, workspace, publication_receipt, report_review):
    groups = [runtime / n for n in ('replays', 'decision_audits', 'independent_source_audit',
              'reference_work', 'reference_archive_audit', 'reference_join', 'scientific_results')]
    groups += [workspace / 'phase16_storage_recovery_audit']
    paths = set()
    for folder in groups:
        need(folder.is_dir(), 'required final directory missing: ' + str(folder))
        for path in folder.rglob('*'):
            if path.is_file() and 'internal_raw' not in path.parts and '__pycache__' not in path.parts:
                need(not path.is_symlink(), 'metadata file symlink in final census')
                paths.add(path.resolve())
    raw = subprocess.check_output(['git', '-C', str(repo), 'ls-files', '--others', '--exclude-standard', '-z', PHASE])
    for value in raw.split(b'\0'):
        if not value: continue
        rel = value.decode(); path = repo / rel
        need(not path.is_symlink(), 'untracked metadata file symlink')
        if rel == INVALID:
            need(path.stat().st_size == 0, 'invalid wall report unexpectedly changed'); continue
        if '__pycache__' not in path.parts and path.suffix in ('.py', '.md', '.json'): paths.add(path.resolve())
    explicit = [publication_receipt, report_review, runtime / 'original_sources/recovery_receipt.json',
                runtime / 'original_sources/reuse_map.json', runtime / 'original_sources/progress.json',
                workspace / 'phase16_storage_recovery_runtime.jsonl',
                workspace / 'phase16_recovery_github_autoreview_rejection.json',
                Path('/tmp/phase16_derive_reference_mechanisms.py')]
    explicit += [workspace / n for n in ('phase16_private_recovery_plan.json', 'phase16_archive_paths.json',
                                         'phase16_runtime_acceptances.json', 'phase16_recovery_acceptances.json')]
    for path in explicit:
        need(Path(path).is_file() and not Path(path).is_symlink(), 'required provenance absent or linked: ' + str(path)); paths.add(Path(path).resolve())
    return paths


def validate_final_reviews(repo, runtime, review_path, review_sha, publication_path, publication_sha, commit):
    trusted = {}
    def checked(path, expected=None):
        b, s = stable_binding(path, expected); value = read(path)
        need(signature(path) == s, 'validated final JSON changed while reading')
        trusted[b['path']] = b['sha256']; return value
    review = checked(review_path, review_sha)
    need(review['schema_version'] == 'phase16_independent_public_result_report_review_v1'
         and review['status'] == 'PASS_PUBLIC_RESULT_REPORT', 'independent final report review not approved')
    reviewed = review['reviewed_artifacts']
    need(isinstance(reviewed, list) and len(reviewed) == 3, 'review must bind both public files and mechanism evidence')
    required = {str((repo / PHASE / 'manuscript/EXTERNAL_CASE_RESULTS.md').resolve()),
                str((repo / PHASE / 'manuscript/EXTERNAL_CASE_AGGREGATES.json').resolve()),
                str((runtime / 'scientific_results/reference_mechanisms.json').resolve())}
    need({str(Path(x['path']).resolve()) for x in reviewed} == required, 'reviewed final artifact population differs')
    for item in reviewed:
        stable_binding(item['path'], item['sha256'])
        trusted[str(Path(item['path']).resolve())] = item['sha256']
        need(Path(item['path']).stat().st_size == item['size_bytes'], 'reviewed size differs')
    publication = checked(publication_path, publication_sha)
    need(publication['status'] == 'PUBLISHED_AND_REMOTE_VERIFIED' and publication['commit_sha'] == commit,
         'publication not verified at expected commit')
    need(publication['reviewed_report']['sha256'] == review_sha, 'publication refers to another report review')
    need(len(publication['artifacts']) == 2, 'publication must preserve exactly two aggregate files')
    public_paths = set()
    for item in publication['artifacts']:
        path = (repo / item['path']).resolve(); need(path.is_relative_to(repo.resolve()), 'publication path escapes repository')
        stable_binding(path, item['sha256']); public_paths.add(str(path)); trusted[str(path)] = item['sha256']
    need(public_paths == required - {str((runtime / 'scientific_results/reference_mechanisms.json').resolve())},
         'published aggregate paths differ')
    checks = [('reference_work/reference_inventory.json', 'SEALED_AFTER_DECISIONS_INDEPENDENTLY_ADJUDICATED'),
              ('reference_work/independent_reference_review.json', 'APPROVED_FOR_EXACT_REFERENCE_JOIN'),
              ('reference_join/join_receipt.json', 'COMPLETE'),
              ('reference_join/coverage.json', 'COMPLETE'),
              ('scientific_results/independent_interpretation.json', 'PASS_EXACT_JOIN_INTERPRETATION_ARITHMETIC'),
              ('scientific_results/reference_mechanisms.json', 'DERIVED_FROM_SEALED_ROWS_NO_NEW_EXPERIMENT')]
    for rel, status in checks: need(checked(runtime / rel)['status'] == status, 'required final result not closed: ' + rel)
    return review, publication, trusted


class Closure:
    def __init__(self, repo, runtime, commit, tracked, deps):
        self.repo, self.runtime, self.commit, self.tracked = repo, runtime, commit, tracked
        self.files = {}; self.signatures = {}; self.excluded = []; self.queue = deque(); self.scanned = set()
        self.durable = {}
        for item in deps['a1_durable_objects']:
            self.durable[item['sha256']] = {'kind': 'DURABLE_A1_ARCHIVE', 'library_file_id': item['library_file_id'], 'name': item['file_name']}
        for item in deps['original_archive_objects']:
            self.durable[item['sha256']] = {'kind': 'DURABLE_ORIGINAL_ARCHIVE', 'library_file_id': item['library_file_id']}
        for key, item in deps['whole_object_origins'].items():
            self.durable[item['sha256']] = {'kind': 'DURABLE_ORIGINAL_WHOLE_OBJECT', 'source_key': key,
                'archive_library_file_id': item['archive_library_file_id'], 'member_name': item['member_name']}
        index = read(deps['raw_metadata_bindings']['a1_index']['path'])
        for pack in index['packs']:
            for member in pack['members']:
                self.durable.setdefault(member['sha256_before'], {'kind': 'DURABLE_A1_MEMBER', 'archive': pack['path'],
                    'archive_sha256': pack['sha256'], 'member': member['member']})
        self.body_hashes = {w['blob']['sha256'] for w in read(runtime / 'attempt2/transport/accepted_range_evidence.json')['ranges']}

    def add(self, path, expected=None, *, follow=True):
        need(not Path(path).is_symlink(), 'metadata binding points to file symlink')
        path = Path(path).resolve(); key = str(path)
        if key in self.files:
            need(expected is None or self.files[key]['sha256'] == expected, 'conflicting metadata graph binding')
            if follow and path.suffix == '.json' and key not in self.scanned: self.queue.append(path)
            return
        b, stat = stable_binding(path, expected)
        if path.is_relative_to(self.repo):
            rel = path.relative_to(self.repo).as_posix()
            if rel in self.tracked:
                raw = subprocess.check_output(['git', '-C', str(self.repo), 'show', self.commit + ':' + rel])
                need(hashlib.sha256(raw).hexdigest() == b['sha256'], 'tracked binding differs from published bytes')
                self.excluded.append({**b, 'reason': 'EXACT_PUBLISHED_GIT_BYTES', 'commit_sha': self.commit, 'repo_path': rel})
                # The exact published tree is a durable dependency boundary.
                # Its older experiments are not inputs to this private closure.
                self.signatures[key] = stat
                return
        self.files[key] = b; self.signatures[key] = stat
        if follow and path.suffix == '.json': self.queue.append(path)

    def follow(self):
        while self.queue:
            parent = self.queue.popleft(); key = str(parent)
            if key in self.scanned: continue
            self.scanned.add(key)
            for b in file_bindings(read(parent)):
                rawpath = Path(b['path']); candidates = [rawpath] if rawpath.is_absolute() else [parent.parent/rawpath, self.repo/rawpath, self.runtime/rawpath]
                if any('internal_raw' in p.parts for p in candidates):
                    self.excluded.append({**b, 'referenced_by': key, 'reason': 'FULL_PRIMARY_PAGE_COPY_EXCLUDED'}); continue
                if b['sha256'] in self.durable:
                    self.excluded.append({**b, 'referenced_by': key, 'reason': 'ALREADY_DURABLE_DEPENDENCY',
                                          'locator': self.durable[b['sha256']]}); continue
                if b['sha256'] in self.body_hashes and any(p.suffix == '.bin' for p in candidates):
                    self.excluded.append({**b, 'referenced_by': key, 'reason': 'A2_ACCEPTED_BODY_HANDLED_BY_DELTA_RECIPES'}); continue
                existing = []
                for p in candidates:
                    if p.is_file():
                        need(not p.is_symlink(), 'metadata graph binding points to file symlink')
                        if p.resolve() not in existing: existing.append(p.resolve())
                need(existing, 'missing required metadata graph binding: ' + b['path'])
                matches = []
                for p in existing:
                    safe_metadata(p)
                    if sha(p) == b['sha256']: matches.append(p)
                need(len(matches) == 1, 'missing, ambiguous or changed metadata graph binding: ' + b['path'])
                self.add(matches[0], b['sha256'])


def create(args, *, repo=REPO, runtime=RUNTIME, workspace=WORKSPACE):
    repo, runtime, workspace = Path(repo).resolve(), Path(runtime).resolve(), Path(workspace).resolve()
    need(args.all_writers_closed is True, 'root must explicitly attest all writers closed')
    need(sha(repo / PHASE / 'delivery/pack_compact_a2_delta.py') == PACKER_SHA, 'reviewed delta packer changed')
    tracked = public_tree(repo, args.published_commit)
    need(len({p.resolve() for p in (args.snapshot,args.proof,args.closure_manifest)}) == 3,
         'snapshot, proof and closure manifest must be distinct outputs')
    for path in (args.snapshot, args.proof, args.closure_manifest):
        need(not path.exists() and path.parent.resolve() == runtime, 'fresh final outputs in runtime root required')
    review, publication, trusted = validate_final_reviews(repo, runtime, args.report_review, args.expected_report_review_sha256,
                           args.publication_receipt, args.expected_publication_receipt_sha256, args.published_commit)
    proposal_binding, _ = stable_binding(args.ready_proposal, args.expected_ready_proposal_sha256)
    proof = read(args.ready_proposal); need(proof['schema_version'] == 'phase16_compact_a2_delta_ready_inputs_v1', 'ready proposal schema')
    deps_binding = proof['dependencies']; stable_binding(deps_binding['path'], deps_binding['sha256']); deps = read(deps_binding['path'])
    initial = inventory(repo, runtime, workspace, args.publication_receipt, args.report_review)
    closure = Closure(repo, runtime, args.published_commit, tracked, deps)
    for p in sorted(initial):
        # Historical candidate reports/templates are preserved, not falsely
        # treated as current gate facts. Current executed seals are followed.
        follow = not p.is_relative_to(repo) or p.is_relative_to(repo / PHASE / 'storage_recovery/actual')
        closure.add(p, trusted.get(str(p)), follow=follow)
    for name, b in proof.items():
        if name == 'final_snapshot' or not isinstance(b, dict): continue
        closure.add(b['path'], b['sha256'])
    for path, expected in trusted.items(): closure.add(path, expected)
    closure.follow()
    need(inventory(repo, runtime, workspace, args.publication_receipt, args.report_review) == initial,
         'global final file census changed during closure')
    for p, stat in closure.signatures.items(): need(signature(p) == stat, 'final metadata changed during closure')
    public_tree(repo, args.published_commit)
    need(sha(args.ready_proposal) == proposal_binding['sha256'], 'ready proposal changed during closure')
    excluded = closure.excluded + [{'path': str(runtime/'reference_work/internal_raw'), 'reason': 'FULL_PRIMARY_PAGES_EXCLUDED'},
                                  {'path': str(repo/INVALID), 'reason': 'EMPTY_INVALID_UNUSED_WALL_PREFLIGHT_NOT_EVIDENCE'}]
    report = {'schema_version': 'phase16_final_delivery_metadata_closure_v1', 'status': 'COMPLETE_METADATA_BINDING_CLOSURE',
              'created_utc': stamp(), 'published_git_commit': args.published_commit, 'private_artifact_count': len(closure.files),
              'private_artifact_bindings': sorted(closure.files.values(), key=lambda x:x['path']),
              'explicit_exclusions': excluded, 'missing_required_bindings': [], 'source_body_bytes_read': 0,
              'historical_candidate_reports_followed_as_current_gates': False, 'finalizer_sha256': sha(__file__)}
    args.closure_manifest.write_bytes(canonical(report)+b'\n')
    artifacts = list(closure.files.values()) + [binding(args.closure_manifest)]
    snapshot = {'schema_version': 'phase16_final_delivery_snapshot_v1', 'status': 'CLOSED_FINAL_DELIVERY_SNAPSHOT',
                'all_scientific_processes_stopped': True, 'no_additional_A2_files_expected': True,
                'case_ids': ['lifi_20220320', 'revest_20220327'], 'created_utc': stamp(),
                'published_git_commit': args.published_commit, 'artifact_bindings': sorted(artifacts,key=lambda x:x['path'])}
    args.snapshot.write_bytes(canonical(snapshot)+b'\n')
    proof.pop('proposal_status', None); proof['final_snapshot'] = binding(args.snapshot)
    args.proof.write_bytes(canonical(proof)+b'\n')
    result = {'status': 'FINAL_SNAPSHOT_AND_PROOF_CREATED_NO_PACK', 'snapshot': binding(args.snapshot),
              'proof': binding(args.proof), 'closure_manifest': binding(args.closure_manifest),
              'external_artifact_count': len(artifacts), 'packer_sha256': PACKER_SHA}
    print(json.dumps(result), flush=True); return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--all-writers-closed', action='store_true')
    p.add_argument('--published-commit', required=True)
    for name in ('report-review','publication-receipt','ready-proposal','snapshot','proof','closure-manifest'):
        p.add_argument('--'+name, type=Path, required=True)
    for name in ('report-review','publication-receipt','ready-proposal'):
        p.add_argument('--expected-'+name+'-sha256', required=True)
    return create(p.parse_args())


if __name__ == '__main__': main()
