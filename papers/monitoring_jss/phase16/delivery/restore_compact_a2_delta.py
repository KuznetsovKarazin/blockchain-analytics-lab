"""Restore a compact A2 delta using bound A1 artifacts and existing whole objects.

All original metadata stays byte-identical. The result is byte restoration, not a
new source audit or authorization to replay. No network or Parquet row decoding.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

CHUNK = 1024 * 1024
PENDING_ORDINAL = 730
MANIFEST_NAME = 'forensic_pack_manifest.json'


def need(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sha_value(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'invalid SHA256')
    return value


def integer(value, minimum=0):
    need(type(value) is int and value >= minimum, 'invalid integer')
    return value


def safe_relative(name):
    need(type(name) is str and bool(name) and '\\' not in name and ':' not in name, 'unsafe relative path')
    path = PurePosixPath(name)
    need(not path.is_absolute() and '..' not in path.parts and str(path) == name and name != '.', 'unsafe relative path')
    return path


def inside(root, relative):
    path = Path(root).joinpath(*safe_relative(relative).parts)
    need(path.resolve().is_relative_to(Path(root).resolve()), 'path leaves declared root')
    return path


def stat_key(path):
    st = Path(path).stat()
    need(stat.S_ISREG(st.st_mode), 'regular file required')
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def file_sha(path):
    path = Path(path); before = stat_key(path); result = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b''):
            result.update(chunk)
    need(stat_key(path) == before, 'input changed while hashing')
    return result.hexdigest()


def read_json(path, expected=None):
    path = Path(path)
    if expected is not None:
        need(file_sha(path) == sha_value(expected), 'bound JSON digest differs')
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    return json.loads(path.read_bytes(), object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def write_json(path, value):
    path = Path(path)
    with path.open('xb') as handle:
        handle.write(canonical(value) + b'\n')
    return file_sha(path)


def immutable_input(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), 'regular nonsymlink artifact required')
    return stat_key(path)


def member_digest(record):
    expected = sha_value(record['sha256_before'])
    need(record['sha256_after'] == expected and record.get('zip_roundtrip_sha256', expected) == expected,
         'archive member verification hashes disagree')
    integer(record['logical_bytes'])
    safe_relative(record['member'])
    return expected


def validate_indices(index, a1, a1_sha, a1_index_bytes):
    need(index['schema_version'] == 'phase16_compact_a2_delta_index_v1'
         and index['status'] == 'COMPLETE_DELTA_PRESERVATION_NOT_NEW_SOURCE_AUDIT', 'incomplete/wrong delta index')
    need(a1['schema_version'] == 'phase16_closed_a1_forensic_archive_index_v1'
         and a1['status'] == 'COMPLETE_FORENSIC_PRESERVATION_NOT_SOURCE_AUDIT', 'wrong A1 forensic index')
    deps = index['dependencies']
    need(deps['a1_index_sha256'] == a1_sha, 'delta A1 dependency differs')
    catalog = deps['a1_durable_objects']
    names = {}
    for item in catalog:
        name = item['file_name']; path = safe_relative(name)
        need(len(path.parts) == 1 and name not in names, 'duplicate/non-basename durable object')
        integer(item['bytes']); sha_value(item['sha256'])
        need(type(item['library_file_id']) is str and bool(item['library_file_id']), 'durable Library identity missing')
        names[name] = item
    a1_packs, a1_members = {}, {}
    for pack in a1['packs']:
        name = pack['path']; safe_relative(name)
        need(name not in a1_packs and name in names, 'A1 durable archive missing/repeated')
        need(pack['sha256'] == names[name]['sha256'] and pack['bytes'] == names[name]['bytes'], 'A1 durable archive identity differs')
        a1_packs[name] = pack
        for member in pack['members']:
            need(member['member'] not in a1_members, 'A1 member appears in multiple archives')
            member_digest(member)
            a1_members[member['member']] = (pack, member)
    other = [x for name, x in names.items() if name not in a1_packs]
    need(len(other) == 1 and other[0]['sha256'] == a1_sha and other[0]['bytes'] == a1_index_bytes,
         'durable catalog must exactly cover A1 ZIPs and index')
    need(len(catalog) == len(a1_packs) + 1, 'unexpected A1 durable dependencies')
    entries, inherited, new, intervals = {}, [], [], defaultdict(list)
    origin_keys = set()
    for old, rows in ((True, index['inherited_recipes']), (False, index['new_blob_entries'])):
        for original in rows:
            row = dict(original); target = row['target_path'] if old else row['path']
            sid = sha_value(row['source_id']); origin = sha_value(row['origin_attempt_id']); expected = sha_value(row['sha256'])
            ordinal = integer(row['origin_ordinal'], 1); start = integer(row['start']); length = integer(row['length'], 1)
            need(ordinal < PENDING_ORDINAL if old else ordinal > PENDING_ORDINAL, 'pending/origin ordinal is not allowed')
            need(type(row['source_key']) is str and row['source_key'], 'source key absent')
            sha_value(row['receipt_sha256'])
            expected_path = f'storage/{sid}/blobs/{origin}-{ordinal:06d}-{expected}.bin'
            need(target == expected_path, 'blob path does not bind source/origin/hash')
            need(target not in entries and (origin, ordinal) not in origin_keys, 'duplicate blob target or origin')
            origin_keys.add((origin, ordinal)); row['_path'] = target; row['_inherited'] = old
            row['_origin'] = (origin, ordinal); entries[target] = row
            intervals[row['source_key']].append((start, start + length))
            if old:
                member_name = row['a1_member']
                need(member_name == f'attempt1/cache/{sid}/source.parquet' and member_name in a1_members,
                     'inherited canonical A1 member missing')
                pack, member = a1_members[member_name]
                need(row['a1_archive'] == {'path': pack['path'], 'sha256': pack['sha256']}, 'inherited A1 archive binding differs')
                need(row['a1_artifact_sha256'] == member_digest(member)
                     and row['a1_artifact_logical_bytes'] == member['logical_bytes'], 'inherited A1 artifact binding differs')
                need(member['source_id'] == sid and member['source_identity']['key'] == row['source_key'], 'A1 artifact source identity differs')
                need(start + length <= member['logical_bytes'], 'inherited range outside canonical artifact')
                inherited.append(row)
            else:
                need(row['size_bytes'] == length, 'new response byte length differs')
                new.append(row)
    for spans in intervals.values():
        spans.sort()
        need(all(a[1] <= b[0] for a, b in zip(spans, spans[1:])), 'overlapping restored source intervals')
    members, delta_packs, external_origins = {}, [], {}
    for pack in index['packs']:
        safe_relative(pack['path']); sha_value(pack['sha256']); integer(pack['bytes'])
        need(pack['path'] not in {x['path'] for x in delta_packs}, 'duplicate delta archive')
        delta_packs.append(pack)
        for record in pack['members']:
            member = record['member']; relative = safe_relative(member)
            need(relative.parts[0] in ('attempt2', 'delivery_control') and len(relative.parts) > 1, 'delta member leaves allowed roots')
            need(member not in members, 'duplicate delta member')
            member_digest(record); members[member] = record
            if relative.parts[0] == 'delivery_control':
                need(len(relative.parts) == 2 and not member.endswith('.bin'), 'external proof is not small metadata')
                if 'original_external_path' in record:
                    original = record['original_external_path']
                    need(type(original) is str and Path(original).is_absolute()
                         and str(Path(original)) == original and '..' not in Path(original).parts,
                         'external original path must be canonical and absolute')
                    need(original not in external_origins, 'duplicate external original path mapping')
                    external_origins[original] = member
                continue
            need('original_external_path' not in record, 'external original path on a runtime member')
            target = '/'.join(relative.parts[1:])
            if target in entries:
                row = entries[target]
                need(not row['_inherited'], 'delta redundantly includes inherited payload')
                need(record['logical_bytes'] == row['length'] and member_digest(record) == row['sha256'], 'new blob archive binding differs')
            else:
                need(not ('storage' == relative.parts[1] and ('blobs' in relative.parts or 'forensic_blobs' in relative.parts))
                     and not target.endswith('.bin'), 'unindexed payload in delta')
    need(all('attempt2/' + row['_path'] in members for row in new), 'new blob missing from delta')
    need(type(index['original_runtime_root']) is str and Path(index['original_runtime_root']).is_absolute(), 'original runtime root must be absolute')
    return {'entries': entries, 'inherited': inherited, 'new': new, 'a1_packs': a1_packs,
            'a1_members': a1_members, 'members': members, 'delta_packs': delta_packs,
            'external_origins': external_origins}


def verify_archives(root, packs):
    result = {}
    for pack in packs:
        path = inside(root, pack['path']); before = immutable_input(path)
        need(before[2] == pack['bytes'] and file_sha(path) == pack['sha256'], 'archive size/digest differs')
        result[pack['path']] = (path, before)
    return result


def extract_delta(output, validated, archive_inputs):
    root = output / 'attempt2'; root.mkdir()
    metadata_count = 0
    for pack in validated['delta_packs']:
        path, before = archive_inputs[pack['path']]
        with zipfile.ZipFile(path) as archive:
            need(archive.namelist() == [x['member'] for x in pack['members']] + [MANIFEST_NAME], 'delta ZIP inventory differs')
            inner = json.loads(archive.read(MANIFEST_NAME))
            need(inner['schema_version'] == 'phase16_forensic_zip_member_manifest_v1', 'delta ZIP manifest schema')
            need([(x['member'], x['logical_bytes'], x['sha256_before']) for x in inner['members']]
                 == [(x['member'], x['logical_bytes'], x['sha256_before']) for x in pack['members']], 'delta ZIP manifest differs')
            need([x.get('original_external_path') for x in inner['members']]
                 == [x.get('original_external_path') for x in pack['members']], 'external ZIP provenance differs')
            for record in pack['members']:
                info = archive.getinfo(record['member'])
                need(info.file_size == record['logical_bytes'] and not stat.S_ISLNK(info.external_attr >> 16)
                     and not info.is_dir(), 'unsupported ZIP member shape')
                target = inside(output, record['member']); target.parent.mkdir(parents=True, exist_ok=True)
                need(not target.exists(), 'duplicate restore output')
                h = hashlib.sha256(); length = 0
                with archive.open(info) as source, target.open('xb') as dest:
                    for chunk in iter(lambda: source.read(CHUNK), b''):
                        length += len(chunk); need(length <= record['logical_bytes'], 'ZIP member exceeds bound')
                        h.update(chunk); dest.write(chunk)
                need(length == record['logical_bytes'] and h.hexdigest() == member_digest(record), 'restored delta member differs')
                relative = str(target.relative_to(root)) if target.is_relative_to(root) else None
                if relative in validated['entries']:
                    target.chmod(0o444)
                else:
                    metadata_count += 1
        need(stat_key(path) == before, 'delta ZIP changed during restore')
    return metadata_count


def validate_restored_metadata(index, validated, root):
    accepted = read_json(root / 'transport/accepted_range_evidence.json')
    session = read_json(root / 'transport/session.json')
    need(accepted['schema_version'] == 'article2_phase16_compact_accepted_ranges_v1', 'accepted evidence schema')
    need(session['schema_version'] == 'article2_phase16_storage_recovery_capture_v1' and session['status'] == 'COMPLETE', 'unclosed restored source capture')
    need(sha_value(session['parent_attempt_id']) != sha_value(session['attempt_id']), 'parent and new attempt identities coincide')
    entries = validated['entries']; origins = {row['_origin']: row for row in entries.values()}
    wrappers = accepted['ranges']; seen = set()
    for wrapper in wrappers:
        key = (wrapper['origin_attempt_id'], wrapper['origin_ordinal'])
        need(key in origins and key not in seen, 'accepted evidence has missing/duplicate/unindexed origin'); seen.add(key)
        row = origins[key]; receipt = wrapper['receipt']
        need(wrapper['origin_attempt_id'] == (session['parent_attempt_id'] if row['_inherited'] else session['attempt_id']), 'accepted origin attempt differs')
        need(receipt['ordinal'] == row['origin_ordinal'] and receipt['source']['key'] == row['source_key']
             and digest(receipt['source']) == row['source_id'] and receipt['start'] == row['start']
             and receipt['length'] == receipt['response_bytes'] == row['length'] and receipt['transport_ok'] is True
             and receipt['response_sha256'] == row['sha256'] and digest(receipt) == row['receipt_sha256'], 'accepted receipt differs from restore recipe')
        need(wrapper['blob'] == {'path': row['_path'], 'size_bytes': row['length'], 'sha256': row['sha256']}, 'accepted blob binding differs')
    need(seen == set(origins), 'accepted evidence omits a restored origin')
    locations = index['source_locations']; compact_seen = set(); whole_seen = set(); source_by_key = {}
    for key, location in locations.items():
        need(type(location['original_path']) is str and Path(location['original_path']).is_absolute(), 'original source location not absolute')
        if location['storage_kind'] == 'verified_whole_object':
            whole_seen.add(key); continue
        need(location['storage_kind'] == 'compact_descriptor', 'unknown source storage kind')
        relative = safe_relative(location['descriptor_relative_path'])
        need(len(relative.parts) == 3 and relative.parts[0] == 'storage' and relative.parts[2] == 'source_storage.json', 'noncanonical descriptor path')
        need(location['original_path'] == str(Path(index['original_runtime_root']) / str(relative)), 'original compact location differs from runtime root')
        sid = sha_value(relative.parts[1]); desc = read_json(inside(root, str(relative)))
        source = desc['source']; source_by_key[key] = source
        need(desc['schema_version'] == 'article2_phase16_compact_source_v1' and desc['storage_kind'] == 'compact_descriptor'
             and source['key'] == key and digest(source) == desc['source_id'] == sid
             and desc['logical_size_bytes'] == source['size_bytes'] and desc['attempt_id'] == session['attempt_id']
             and desc['parent_attempt_id'] == session['parent_attempt_id'], 'compact descriptor identity differs')
        previous = 0; local = set()
        for segment in desc['segments']:
            origin = (segment['origin_attempt_id'], segment['origin_ordinal'])
            need(origin in origins and origin not in compact_seen and origin not in local, 'descriptor origin missing/repeated')
            row = origins[origin]; local.add(origin); compact_seen.add(origin)
            need(row['source_key'] == key and row['source_id'] == sid and previous <= segment['start'], 'descriptor source/overlap differs')
            need(segment['start'] == row['start'] and segment['length'] == row['length']
                 and segment['blob_sha256'] == row['sha256'] and segment['receipt_sha256'] == row['receipt_sha256'], 'descriptor range differs')
            resolved = (PurePosixPath(str(relative)).parent / safe_relative(segment['blob_path'])).as_posix()
            need(resolved == row['_path'], 'descriptor blob path differs')
            previous = segment['start'] + segment['length']; need(previous <= source['size_bytes'], 'descriptor range outside source')
        need(local, 'empty compact descriptor')
    need(compact_seen == set(origins), 'restored descriptor population incomplete')
    need(whole_seen == set(index['dependencies']['whole_object_origins']), 'whole-object dependency population differs')
    for row in validated['inherited']:
        _, artifact = validated['a1_members'][row['a1_member']]
        need(artifact['source_identity'] == source_by_key[row['source_key']], 'A1/new descriptor source identity differs')
    return session


def reconstruct_member(source, recipes, output, expected_sha, expected_bytes):
    """One pass over a canonical image; write only accepted, disjoint ranges."""
    rows = sorted(recipes, key=lambda row: row['start']); need(rows, 'empty inherited member request')
    need(all(a['start'] + a['length'] <= b['start'] for a, b in zip(rows, rows[1:])), 'overlapping inherited recipes')
    staging = output / 'restore_staging'; staging.mkdir(exist_ok=True)
    active = []
    try:
        for row in rows:
            target = inside(output / 'attempt2', row['_path']); need(not target.exists(), 'inherited target already exists')
            temporary = staging / (digest(row['_path']) + '.writing')
            handle = temporary.open('xb')
            active.append({'row': row, 'target': target, 'temp': temporary, 'handle': handle,
                           'hash': hashlib.sha256(), 'count': 0})
        h = hashlib.sha256(); position = 0; first = 0
        while True:
            chunk = source.read(CHUNK)
            if not chunk: break
            end = position + len(chunk); need(end <= expected_bytes, 'A1 member exceeds declared logical length'); h.update(chunk)
            while first < len(active) and active[first]['row']['start'] + active[first]['row']['length'] <= position:
                first += 1
            cursor = first
            while cursor < len(active) and active[cursor]['row']['start'] < end:
                item = active[cursor]; row = item['row']; lo = max(position, row['start']); hi = min(end, row['start'] + row['length'])
                if hi > lo:
                    part = chunk[lo-position:hi-position]; item['handle'].write(part); item['hash'].update(part); item['count'] += len(part)
                cursor += 1
            position = end
        need(position == expected_bytes and h.hexdigest() == expected_sha, 'full canonical A1 artifact digest differs')
        for item in active:
            item['handle'].close(); row = item['row']
            need(item['count'] == row['length'] and item['hash'].hexdigest() == row['sha256'], 'inherited response range digest differs')
        # Commit only after the complete image and every range have verified.
        for item in active:
            item['target'].parent.mkdir(parents=True, exist_ok=True); item['temp'].chmod(0o444); item['temp'].rename(item['target'])
        return {'a1_member': rows[0]['a1_member'], 'artifact_sha256': h.hexdigest(),
                'artifact_logical_bytes_streamed': position, 'restored_ranges': len(rows),
                'restored_response_bytes': sum(x['length'] for x in rows)}
    finally:
        for item in active:
            if not item['handle'].closed: item['handle'].close()


def reconstruct_inherited(validated, output, *, a1_restored_root=None, a1_archive_inputs=None):
    grouped = defaultdict(list)
    for row in validated['inherited']: grouped[row['a1_member']].append(row)
    results = []
    for member, recipes in sorted(grouped.items()):
        _, record = validated['a1_members'][member]
        if a1_restored_root is not None:
            relative = safe_relative(member); need(relative.parts[0] == 'attempt1', 'A1 member prefix differs')
            path = inside(a1_restored_root, '/'.join(relative.parts[1:])); before = immutable_input(path)
            need(before[2] == record['logical_bytes'], 'restored A1 logical length differs')
            with path.open('rb') as source:
                results.append(reconstruct_member(source, recipes, output, member_digest(record), record['logical_bytes']))
            need(stat_key(path) == before, 'A1 artifact changed during reconstruction')
        else:
            pack_name = recipes[0]['a1_archive']['path']; path, before = a1_archive_inputs[pack_name]
            with zipfile.ZipFile(path) as archive:
                need(archive.namelist().count(member) == 1, 'A1 ZIP member missing/repeated')
                info = archive.getinfo(member)
                need(info.file_size == record['logical_bytes'] and not stat.S_ISLNK(info.external_attr >> 16), 'A1 ZIP member shape differs')
                with archive.open(info) as source:
                    results.append(reconstruct_member(source, recipes, output, member_digest(record), record['logical_bytes']))
            need(stat_key(path) == before, 'A1 ZIP changed during reconstruction')
    return results


def verify_whole_objects(index, whole_map):
    expected = index['dependencies']['whole_object_origins']
    need(type(whole_map) is dict and set(whole_map) == set(expected), 'whole-object map population differs')
    result, archives, members = {}, {}, set()
    for key, origin in expected.items():
        expected_sha = sha_value(origin['sha256']); size = integer(origin['size_bytes'], 1)
        archive_sha = sha_value(origin['archive_sha256']); archive_bytes = integer(origin['archive_bytes'], 1)
        need(type(origin['etag_opaque']) is str and origin['etag_opaque'], 'whole source ETag absent')
        need(type(origin['archive_library_file_id']) is str and origin['archive_library_file_id'], 'whole archive Library identity absent')
        member = str(safe_relative(origin['member_name'])); archive_identity = (archive_bytes, origin['archive_library_file_id'])
        need(archive_sha not in archives or archives[archive_sha] == archive_identity, 'whole archive durable identities conflict')
        archives[archive_sha] = archive_identity
        need((archive_sha, member) not in members, 'duplicate whole archive member'); members.add((archive_sha, member))
        location = index['source_locations'][key]
        need(location['storage_kind'] == 'verified_whole_object' and location['whole_object_sha256'] == expected_sha, 'whole source location digest differs')
        need(type(whole_map[key]) is str and whole_map[key], 'whole-object path absent')
        path = Path(whole_map[key]).resolve(); before = stat_key(path)
        need(before[2] == size and file_sha(path) == expected_sha, 'existing whole object digest/size differs')
        result[key] = {'storage_kind': 'verified_whole_object', 'path': str(path), 'sha256': expected_sha, 'size_bytes': size, '_stat': before}
    return result


def restore(index_path, expected_index_sha256, a1_index_path, expected_a1_index_sha256, whole_map_path, output,
            *, a1_restored_root=None, a1_pack_root=None):
    index_path, a1_index_path, output = Path(index_path), Path(a1_index_path), Path(output).resolve()
    need((a1_restored_root is None) != (a1_pack_root is None), 'choose exactly one A1 reconstruction input')
    index = read_json(index_path, expected_index_sha256); a1 = read_json(a1_index_path, expected_a1_index_sha256)
    validated = validate_indices(index, a1, expected_a1_index_sha256, a1_index_path.stat().st_size)
    need(not output.exists(), 'fresh restore destination required')
    # Full whole sources remain at explicit caller-provided verified paths; no copy.
    whole = verify_whole_objects(index, read_json(whole_map_path))
    delta_archives = verify_archives(index_path.parent, validated['delta_packs'])
    a1_archives = verify_archives(a1_pack_root, list(validated['a1_packs'].values())) if a1_pack_root is not None else None
    if a1_restored_root is not None: a1_restored_root = Path(a1_restored_root).resolve()
    output.mkdir(parents=True)
    try:
        metadata_count = extract_delta(output, validated, delta_archives)
        root = output / 'attempt2'; validate_restored_metadata(index, validated, root)
        old = reconstruct_inherited(validated, output, a1_restored_root=a1_restored_root, a1_archive_inputs=a1_archives)
        locations = {}
        for key, value in index['source_locations'].items():
            locations[key] = {'storage_kind': 'compact_descriptor', 'path': str(inside(root, value['descriptor_relative_path']).resolve())} if value['storage_kind'] == 'compact_descriptor' else {'storage_kind': 'verified_whole_object', 'path': whole[key]['path']}
        old_paths = {}
        for key, value in index['source_locations'].items():
            previous = old_paths.setdefault(value['original_path'], locations[key]['path'])
            need(previous == locations[key]['path'], 'ambiguous original source relocation')
        mapping = {'schema_version': 'phase16_compact_delta_relocation_map_v1', 'original_runtime_root': index['original_runtime_root'],
                   'restored_runtime_root': str(root), 'delta_index_sha256': expected_index_sha256,
                   'a1_index_sha256': expected_a1_index_sha256, 'source_locations': locations,
                   'original_to_restored_source_paths': old_paths,
                   'external_artifact_paths': {original: str(inside(output, member))
                       for original, member in validated['external_origins'].items()},
                   'original_metadata_rewritten': False, 'historical_audits_reexecuted': False}
        map_sha = write_json(output / 'relocation_map.json', mapping)
        need(file_sha(index_path) == expected_index_sha256 and file_sha(a1_index_path) == expected_a1_index_sha256, 'bound index changed during restore')
        # The archived metadata is still exact, including absolute historical paths.
        for member, record in validated['members'].items():
            target = inside(output, member)
            if not member.startswith('attempt2/') or member.removeprefix('attempt2/') not in validated['entries']:
                need(file_sha(target) == member_digest(record), 'restored delta member changed')
        for row in validated['entries'].values():
            target = inside(root, row['_path']); before = immutable_input(target)
            need(before[2] == row['length'] and not target.stat().st_mode & 0o222
                 and file_sha(target) == row['sha256'], 'restored immutable response blob differs')
        for value in whole.values():
            need(stat_key(value['path']) == value.pop('_stat'), 'whole object changed during restoration')
        receipt = {'schema_version': 'phase16_compact_a2_delta_restore_receipt_v1',
                   'status': 'PASS_COMPACT_DELTA_BYTE_RESTORATION_NOT_NEW_SOURCE_AUDIT',
                   'completed_utc': datetime.now(timezone.utc).isoformat(), 'restorer_sha256': file_sha(__file__),
                   'delta_index_sha256': expected_index_sha256, 'a1_index_sha256': expected_a1_index_sha256,
                   'relocation_map_sha256': map_sha, 'inherited_members': old,
                   'inherited_response_count': len(validated['inherited']), 'inherited_response_bytes': sum(x['length'] for x in validated['inherited']),
                   'new_response_count': len(validated['new']), 'new_response_bytes': sum(x['length'] for x in validated['new']),
                   'whole_objects_verified_without_copy': whole, 'metadata_files_restored_verbatim': metadata_count,
                   'pending_ordinal_730_accepted': False, 'original_metadata_rewritten': False,
                   'historical_audits_reexecuted': False, 'source_rows_decoded': 0, 'network_requests': 0,
                   'a1_full_sparse_images_materialized': False}
        staging = output / 'restore_staging'
        if staging.exists(): staging.rmdir()
        write_json(output / 'restore_receipt.json', receipt)
        return receipt
    except Exception as exc:
        write_json(output / 'restore_failure.json', {'status': 'INCOMPLETE_NOT_ACCEPTED_AS_RESTORED',
                   'error_type': type(exc).__name__, 'error': str(exc), 'historical_audits_reexecuted': False})
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('index', 'a1-index', 'whole-object-map', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-index-sha256', required=True); parser.add_argument('--expected-a1-index-sha256', required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--a1-restored-root', type=Path); source.add_argument('--a1-pack-root', type=Path)
    args = parser.parse_args(argv)
    result = restore(args.index, args.expected_index_sha256, args.a1_index, args.expected_a1_index_sha256,
                     args.whole_object_map, args.output, a1_restored_root=args.a1_restored_root, a1_pack_root=args.a1_pack_root)
    print(json.dumps({'status': result['status'], 'inherited_response_count': result['inherited_response_count'],
                      'new_response_count': result['new_response_count']}))
    return result


if __name__ == '__main__': main()
