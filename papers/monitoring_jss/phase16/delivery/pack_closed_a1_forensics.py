"""Byte-only forensic ZIP preservation of a closed, incomplete source capture.

Sparse cache images are forensic artifacts, not complete original source files.
No Parquet parsing, transfer decoding, scoring, references or network operations.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import zipfile

CHUNK = 1024 * 1024
MAX_PACK = 500 * 1024 * 1024
MANIFEST_NAME = 'forensic_pack_manifest.json'


def need(value, message):
    if not value: raise ValueError(message)


def stamp(): return datetime.now(timezone.utc).isoformat()


def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def write_json(path, value):
    path = Path(path); temporary = path.with_name(path.name + '.writing')
    temporary.write_bytes(canonical(value) + b'\n'); os.replace(temporary, path)
    return file_sha(path)


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(CHUNK), b''): h.update(chunk)
    return h.hexdigest()


def snapshot(path):
    path = Path(path); need(not path.is_symlink(), 'symlink input prohibited')
    s = path.stat(); need(stat.S_ISREG(s.st_mode), 'regular file required')
    return {'logical_bytes': s.st_size, 'physical_bytes': s.st_blocks * 512,
            'device': s.st_dev, 'inode': s.st_ino, 'mtime_ns': s.st_mtime_ns, 'ctime_ns': s.st_ctime_ns,
            'mode': stat.S_IMODE(s.st_mode)}


def same_snapshot(before, after):
    return all(before[k] == after[k] for k in ('logical_bytes', 'device', 'inode', 'mtime_ns', 'ctime_ns'))


def safe_member(name):
    need(type(name) is str and name and '\\' not in name, 'unsafe ZIP member')
    p = PurePosixPath(name)
    need(not p.is_absolute() and '..' not in p.parts and str(p) == name and ':' not in name, 'unsafe ZIP member')
    return p


def inventory(root, external_files, *, expected_counts=None):
    root = Path(root).resolve(); need(root.is_dir(), 'capture root absent')
    cache_files = sorted(root.glob('cache/*/source.parquet'))
    json_files = sorted(root.rglob('*.json'))
    pending_file = root / 'transport/requests.json.pending'
    need(pending_file.is_file() and pending_file.stat().st_size == 0, 'empty pending checkpoint artifact required')
    canonical_files = sorted(set(cache_files + json_files + [pending_file]))
    need(len(canonical_files) == len(cache_files) + len(json_files) + 1, 'canonical inventory overlaps')
    if expected_counts is not None:
        need((len(cache_files), len(json_files)) == tuple(expected_counts), 'canonical inventory counts differ')
    entries = []
    for path in canonical_files:
        relative = path.relative_to(root).as_posix(); safe_member(relative)
        need(path.resolve().is_relative_to(root), 'capture path leaves root')
        entry = {'path': path, 'member': 'attempt1/' + relative, 'before_stat': snapshot(path),
                 'artifact_kind': 'preserved_original_metadata_or_pending_artifact'}
        if path in cache_files:
            metadata = json.loads((path.parent / 'ranges.json').read_bytes())
            identity = metadata['source']; need(identity['table'] in ('blocks', 'logs', 'transactions'), 'unknown source table')
            need(entry['before_stat']['logical_bytes'] == identity['size_bytes'], 'canonical sparse logical length differs')
            entry.update(artifact_kind='canonical_sparse_cache_image_not_complete_source', source_identity=identity,
                         table=identity['table'], day_utc=identity['day_utc'], source_id=path.parent.name)
        entries.append(entry)
    for i, path in enumerate(external_files, 1):
        path = Path(path).resolve(); need(path.is_file() and not path.is_relative_to(root), 'external forensic file invalid')
        member = 'external/' + f'{i:02d}_' + path.name; safe_member(member)
        entries.append({'path': path, 'member': member, 'before_stat': snapshot(path),
                        'artifact_kind': 'explicit_external_forensic_evidence', 'external_basename': path.name})
    need(len({x['member'] for x in entries}) == len(entries), 'duplicate archive member')
    return entries


def pack_groups(entries, maximum=MAX_PACK):
    need(type(maximum) is int and maximum >= 64 * 1024, 'pack cap too small')
    blocks = [x for x in entries if x.get('table') == 'blocks']
    separate = [x for x in entries if x.get('table') in ('logs', 'transactions')]
    metadata = [x for x in entries if 'table' not in x]
    result = []
    for x in sorted(separate, key=lambda x: (x['day_utc'], x['table'], x['source_id'])):
        need(x['before_stat']['logical_bytes'] < maximum, 'single source logical size exceeds pack cap')
        name = f"a1_{x['day_utc'].replace('-', '')}_{x['table']}_{x['source_id'][:12]}.zip"
        result.append((name, [x]))
    # Keep overhead/headroom below the hard final ZIP cap even with DEFLATE expansion.
    limit = maximum - max(8192, maximum // 100)
    for label, items in [('blocks', blocks), ('metadata_and_external_forensics', metadata)]:
        group, size, ordinal = [], 0, 1
        for item in items:
            n = item['before_stat']['logical_bytes']; need(n <= limit, 'group member exceeds planning bound')
            if group and size + n > limit:
                result.append((f'a1_{label}_{ordinal:03d}.zip', group)); group, size, ordinal = [], 0, ordinal + 1
            group.append(item); size += n
        if group: result.append((f'a1_{label}_{ordinal:03d}.zip', group))
    need(len({n for n, _ in result}) == len(result), 'duplicate pack name')
    return result


class LimitedWriter:
    def __init__(self, path, limit): self.handle = Path(path).open('xb'); self.limit = limit
    def write(self, data):
        need(self.handle.tell() + len(data) <= self.limit, 'ZIP exceeded hard pack cap')
        return self.handle.write(data)
    def seek(self, *args): return self.handle.seek(*args)
    def tell(self): return self.handle.tell()
    def flush(self): return self.handle.flush()
    def close(self): return self.handle.close()
    def seekable(self): return True


def pack_one(output, name, entries, maximum=MAX_PACK):
    output = Path(output); target = output / name; partial = output / (name + '.partial')
    need(not target.exists() and not partial.exists(), 'pack output already exists')
    records = []; manifest_raw = None; started = stamp(); writer = LimitedWriter(partial, maximum)
    try:
        with zipfile.ZipFile(writer, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=1, allowZip64=True) as archive:
            for item in entries:
                path = item['path']; before = item['before_stat']; need(same_snapshot(before, snapshot(path)), 'source changed before pack')
                info = zipfile.ZipInfo(item['member'], date_time=(1980, 1, 1, 0, 0, 0)); info.compress_type = zipfile.ZIP_DEFLATED
                info._compresslevel = 1; info.external_attr = (0o100600 << 16); info.file_size = before['logical_bytes']
                h = hashlib.sha256(); length = 0
                with path.open('rb') as source, archive.open(info, 'w', force_zip64=True) as member:
                    for chunk in iter(lambda: source.read(CHUNK), b''):
                        length += len(chunk); need(length <= before['logical_bytes'], 'source grew while packing')
                        h.update(chunk); member.write(chunk)
                need(length == before['logical_bytes'] and same_snapshot(before, snapshot(path)), 'source changed during packing')
                record = {k: v for k, v in item.items() if k not in ('path', 'before_stat')}
                record.update(logical_bytes=length, physical_bytes_before=before['physical_bytes'],
                              sha256_before=h.hexdigest(), before_hash_method='streamed_canonical_file_bytes_during_archive_ingest',
                              original_stat=before, whole_original_source_sha256=None if 'table' in item else 'not_applicable',
                              holes_are_source_evidence=False)
                records.append(record)
            manifest = {'schema_version': 'phase16_forensic_zip_member_manifest_v1', 'members': records,
                        'semantics': 'SHA values identify exact local artifact bytes. Sparse holes and unverified/pending regions are not accepted source evidence.'}
            manifest_raw = canonical(manifest) + b'\n'; archive.writestr(MANIFEST_NAME, manifest_raw, compress_type=zipfile.ZIP_DEFLATED, compresslevel=1)
        writer.flush()
    finally: writer.close()
    need(partial.stat().st_size <= maximum, 'ZIP cap exceeded')
    os.replace(partial, target)
    with zipfile.ZipFile(target, 'r') as archive:
        need(archive.namelist() == [x['member'] for x in records] + [MANIFEST_NAME], 'ZIP member inventory differs')
        need(archive.read(MANIFEST_NAME) == manifest_raw, 'ZIP manifest roundtrip differs')
        for record in records:
            h = hashlib.sha256(); count = 0
            with archive.open(record['member'], 'r') as source:
                for chunk in iter(lambda: source.read(CHUNK), b''): h.update(chunk); count += len(chunk)
            need(count == record['logical_bytes'] and h.hexdigest() == record['sha256_before'], 'ZIP byte roundtrip hash differs')
            record['zip_roundtrip_sha256'] = h.hexdigest()
    for item, record in zip(entries, records):
        after = snapshot(item['path']); need(same_snapshot(item['before_stat'], after), 'source changed before postpack hash')
        record['sha256_after'] = file_sha(item['path']); record['physical_bytes_after'] = after['physical_bytes']
        need(record['sha256_after'] == record['sha256_before'] and same_snapshot(after, snapshot(item['path'])), 'source changed after packing')
    receipt = {'schema_version': 'phase16_closed_a1_forensic_pack_receipt_v1',
               'status': 'PASS_ZIP_ROUNDTRIP_AND_UNCHANGED_SOURCE_BYTES', 'archive': name,
               'archive_sha256': file_sha(target), 'archive_bytes': target.stat().st_size,
               'maximum_archive_bytes': maximum, 'members': records, 'started_utc': started, 'completed_utc': stamp(),
               'compression': 'ZIP_DEFLATED_LEVEL_1', 'source_payload_decoded': False, 'producer_status_rewritten': False}
    receipt_name = name + '.receipt.json'; receipt_sha = write_json(output / receipt_name, receipt)
    return {'path': name, 'sha256': receipt['archive_sha256'], 'bytes': receipt['archive_bytes'],
            'receipt': {'path': receipt_name, 'sha256': receipt_sha}, 'members': records}


def capture_facts(root):
    session = json.loads((root / 'transport/session.json').read_bytes())
    requests = json.loads((root / 'transport/requests.json').read_bytes())
    pending = [x for x in requests if x.get('transport_ok') is not True]
    need(session['status'] == 'OPEN_REQUEST_PENDING', 'unexpected original producer status')
    need(not (root / 'failure.json').exists() and not (root / 'collection_result.json').exists(), 'original terminal artifact appeared')
    need(len(pending) == 1 and pending[0] is requests[-1] and not pending[0].get('completed_utc'), 'expected single final pending request')
    return {'producer_status_observed': session['status'], 'producer_status_rewritten': False,
            'request_count': len(requests), 'successful_receipt_count': sum(x.get('transport_ok') is True for x in requests),
            'known_successful_response_bytes': sum(x.get('response_bytes', 0) for x in requests if x.get('transport_ok') is True),
            'pending_request_ordinal': pending[0]['ordinal'], 'pending_declared_range_bytes': pending[0]['length'],
            'pending_received_body_length': 'UNKNOWN_NOT_INFERRED_AS_ZERO', 'pending_bytes_accepted': False,
            'failure_json_present': False, 'collection_result_json_present': False}


def pack(root, output, external_files, *, maximum=MAX_PACK, expected_counts=(70, 173)):
    root = Path(root).resolve(); output = Path(output).resolve()
    need(not output.exists() and not output.is_relative_to(root), 'fresh pack directory outside original capture required')
    entries = inventory(root, external_files, expected_counts=expected_counts); groups = pack_groups(entries, maximum)
    facts = capture_facts(root); output.mkdir(parents=True); started = stamp(); results = []
    write_json(output / 'packing_plan.json', {'schema_version': 'phase16_closed_a1_forensic_plan_v1',
        'source_root_alias': 'attempt1', 'canonical_file_count': len(entries) - len(external_files),
        'external_file_count': len(external_files), 'packs': [{'path': name, 'members': [x['member'] for x in items]} for name, items in groups],
        'capture_facts': facts, 'maximum_pack_bytes': maximum, 'packer_sha256': file_sha(__file__)})
    try:
        for name, members in groups:
            result = pack_one(output, name, members, maximum); results.append(result)
            write_json(output / 'packing_progress.json', {'status': 'IN_PROGRESS', 'completed_pack_count': len(results),
                'planned_pack_count': len(groups), 'completed_archive_bytes': sum(x['bytes'] for x in results),
                'last_pack': result['path']})
            print(json.dumps({'verified_pack': result['path'], 'bytes': result['bytes'], 'completed': len(results), 'total': len(groups)}), flush=True)
        for item in entries: need(same_snapshot(item['before_stat'], snapshot(item['path'])), 'original artifact changed after verified pack')
        need(capture_facts(root) == facts, 'original producer metadata changed')
        index = {'schema_version': 'phase16_closed_a1_forensic_archive_index_v1',
            'status': 'COMPLETE_FORENSIC_PRESERVATION_NOT_SOURCE_AUDIT', 'started_utc': started, 'completed_utc': stamp(),
            'packer_sha256': file_sha(__file__), 'capture_facts': facts, 'maximum_pack_bytes': maximum,
            'archive_count': len(results), 'archive_bytes_total': sum(x['bytes'] for x in results),
            'canonical_cache_artifact_count': sum('table' in x for x in entries),
            'canonical_json_count': sum(x['member'].startswith('attempt1/') and x['member'].endswith('.json') for x in entries),
            'preserved_empty_pending_file_count': 1, 'external_forensic_file_count': len(external_files),
            'canonical_logical_bytes': sum(x['before_stat']['logical_bytes'] for x in entries if x['member'].startswith('attempt1/')),
            'canonical_physical_bytes': sum(x['before_stat']['physical_bytes'] for x in entries if x['member'].startswith('attempt1/')),
            'packs': results, 'holes_are_source_evidence': False, 'sparse_cache_hash_is_original_source_hash': False,
            'pending_bytes_accepted': False, 'source_payload_decoded': False, 'detector_scores_computed': False,
            'restore_semantics': 'Verify index, ZIP and uncompressed member hashes; skip zero 4KiB pages on restore. Logical bytes exact; filesystem extent allocation is not recreated.',
            'excluded_scope': 'Noncanonical relocation working artifacts and unrelated files were not included.'}
        digest = write_json(output / 'forensic_archive_index.json', index)
        write_json(output / 'packing_progress.json', {'status': index['status'], 'archive_count': len(results), 'index_sha256': digest})
        print(json.dumps({'status': index['status'], 'index_sha256': digest, 'archive_count': len(results), 'archive_bytes_total': index['archive_bytes_total']}), flush=True)
        return index
    except Exception as exc:
        write_json(output / 'packing_failure.json', {'status': 'INCOMPLETE_NOT_VERIFIED', 'error_type': type(exc).__name__,
            'error': str(exc), 'completed_verified_packs': len(results), 'producer_status_rewritten': False})
        raise


def restore(index_path, expected_sha256, output):
    index_path = Path(index_path); need(file_sha(index_path) == expected_sha256, 'index digest differs')
    index = json.loads(index_path.read_bytes()); need(index['status'] == 'COMPLETE_FORENSIC_PRESERVATION_NOT_SOURCE_AUDIT', 'incomplete forensic index')
    output = Path(output).resolve(); need(not output.exists(), 'fresh restore destination required'); output.mkdir(parents=True)
    restored = []
    for pack in index['packs']:
        archive_path = index_path.parent / safe_member(pack['path'])
        need(file_sha(archive_path) == pack['sha256'], 'archive digest differs')
        with zipfile.ZipFile(archive_path) as archive:
            need(archive.namelist() == [x['member'] for x in pack['members']] + [MANIFEST_NAME], 'archive inventory differs')
            for record in pack['members']:
                relative = safe_member(record['member']); target = output.joinpath(*relative.parts)
                need(target.resolve().is_relative_to(output) and not target.exists(), 'unsafe/duplicate restore target')
                target.parent.mkdir(parents=True, exist_ok=True); h = hashlib.sha256(); count = 0
                with archive.open(record['member']) as source, target.open('xb') as destination:
                    while True:
                        page = source.read(4096)
                        if not page: break
                        count += len(page); need(count <= record['logical_bytes'], 'restored member exceeds bound'); h.update(page)
                        if page.count(0) == len(page): destination.seek(len(page), os.SEEK_CUR)
                        else: destination.write(page)
                    destination.truncate(count)
                need(count == record['logical_bytes'] and h.hexdigest() == record['sha256_before'] == record['sha256_after'], 'restored bytes differ')
                restored.append({'member': record['member'], 'sha256': h.hexdigest(), 'logical_bytes': count,
                                 'restored_physical_bytes': target.stat().st_blocks * 512})
    write_json(output / 'forensic_restore_receipt.json', {'status': 'PASS_EXACT_LOGICAL_BYTES_SPARSE_ZERO_PAGE_RESTORE',
        'index_sha256': expected_sha256, 'restored': restored, 'holes_are_source_evidence': False, 'pending_bytes_accepted': False,
        'original_producer_status_rewritten': False, 'source_payload_decoded': False})
    return restored


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); subs = parser.add_subparsers(dest='command', required=True)
    create = subs.add_parser('pack'); create.add_argument('--source', type=Path, required=True); create.add_argument('--output', type=Path, required=True)
    create.add_argument('--external-file', type=Path, action='append', default=[])
    recover = subs.add_parser('restore'); recover.add_argument('--index', type=Path, required=True); recover.add_argument('--expected-index-sha256', required=True); recover.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == 'pack': return pack(args.source, args.output, args.external_file)
    return restore(args.index, args.expected_index_sha256, args.output)


if __name__ == '__main__': main()
