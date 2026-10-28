#!/usr/bin/env python3
"""Verify a pinned range pack and reconstruct source offsets without decoding."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

from pack_range_capture import (canonical, copy_exact, digest, hexsha, identity, integer,
                               load, need, portable, put, relative, sha, validate_request,
                               MAX_ARCHIVE)


def restore(pack_dir, output, expected_index_sha256, reuse_map=None):
    pack_dir, output = Path(pack_dir), Path(output)
    need(not output.exists(), 'restore output already exists')
    index = load(pack_dir/'index.json', expected_index_sha256); portable(index)
    need(index['schema_version'] == 'phase16_range_pack_index_v1' and index['mode'] in ('complete','failed'), 'range pack schema/mode')
    need(index['scientific_acceptance'] is False and index['sparse_holes_packaged'] is False
         and index['whole_reused_objects_duplicated'] is False, 'pack scope differs')
    integer(index['archive_cap_bytes'], 1); need(index['archive_cap_bytes'] <= MAX_ARCHIVE, 'archive cap')
    metadata = {}
    for name, binding in index['metadata'].items():
        path = pack_dir/relative(name)
        need(path.stat().st_size == binding['size_bytes'] and sha(path) == hexsha(binding['sha256']), 'metadata bytes differ')
        metadata[name] = load(path); portable(metadata[name])
    plan = metadata['frozen_plan.json']; session = metadata['transport/session.json']
    requests = metadata['transport/requests.json']
    need(session['attempt_id'] == index['attempt_id'] == digest({'plan': digest(plan['collector']), 'started_utc': session['started_utc']})
         and session['plan_canonical_sha256'] == digest(plan['collector'])
         and canonical(metadata['transport/plan.json']) == canonical(plan['collector']), 'attempt/plan differs')
    if index['mode'] == 'complete':
        result = metadata['collection_result.json']
        accepted_name = 'metadata/accepted_plan.json' if 'metadata/accepted_plan.json' in metadata else 'frozen_plan.json'
        accepted_sha = index['metadata'][accepted_name]['sha256']
        need(session['status'] == 'COMPLETE' and result['status'] == 'COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT'
             and result['plan_sha256'] == accepted_sha
             and canonical(metadata[accepted_name]) == canonical(plan), 'complete capture accepted-plan binding differs')
        need(index.get('accepted_input_plan_sha256', accepted_sha) == accepted_sha
             and index.get('runtime_frozen_plan_sha256', index['metadata']['frozen_plan.json']['sha256'])
                 == index['metadata']['frozen_plan.json']['sha256'], 'accepted/runtime plan hash distinction differs')
    else:
        need(session['status'] != 'COMPLETE' and metadata['failure.json']['status'] == 'FAILED_NOT_ACCEPTED', 'failed capture status differs')
    catalog = index['sources']; sources = {s['source']['key']: identity(s['source']) for s in catalog}
    need(len(catalog) == len(sources), 'duplicate source')
    for ordinal, r in enumerate(requests, 1):
        validate_request(r, ordinal, sources, index['mode'])
    need(session['request_count'] == len(requests) and session['retained_response_bytes'] ==
         index['stored_response_bytes'] == sum(r['response_bytes'] for r in requests), 'stored byte accounting')
    need(index['accepted_response_bytes'] == sum(r['response_bytes'] for r in requests if r['transport_ok'])
         and index['unaccepted_response_bytes'] == sum(r['response_bytes'] for r in requests if not r['transport_ok']), 'acceptance accounting')
    for s in catalog:
        need(s['source_id'] == digest(s['source']) and s['request_ordinals'] ==
             [r['ordinal'] for r in requests if r['source']['key'] == s['source']['key']], 'source catalog differs')
        intervals = sorted((r['start'], r['start']+r['length']) for r in requests if r['source']['key'] == s['source']['key'])
        need(all(a[1] <= b[0] for a,b in zip(intervals, intervals[1:])), 'overlapping source ranges')
        if s['reuse_reference']:
            need(not s['request_ordinals'], 'reused source contains ranges')
            ref = s['reuse_reference']; receipt = metadata[ref['receipt_file']]
            need(index['metadata'][ref['receipt_file']]['sha256'] == ref['receipt_sha256']
                 and receipt['sha256'] == ref['original_member_sha256']
                 and receipt['expected_archive_sha256'] == ref['original_archive_sha256']
                 and receipt['expected_original_member_name'] == ref['original_member_name'], 'reuse provenance differs')
    archives = index['archives']; names = [a['file'] for a in archives]
    need(len(names) == len(set(names)), 'duplicate archive')
    listed = [o for a in archives for o in a['request_ordinals']]
    expected_ordinals = [r['ordinal'] for r in requests if r['response_bytes']]
    need(len(listed) == len(set(listed)) and sorted(listed) == expected_ordinals, 'archive request coverage differs')
    # Verify every archive hash before constructing any sparse source.
    for archive in archives:
        path = pack_dir/relative(archive['file'])
        need(path.stat().st_size == archive['size_bytes'] <= index['archive_cap_bytes']
             and sha(path) == hexsha(archive['sha256']), 'archive bytes differ')
    supplied = {} if reuse_map is None else load(reuse_map)
    reusable = {s['source']['key']: s for s in catalog if s['reuse_reference']}
    need(type(supplied) is dict and set(supplied) <= set(reusable), 'unexpected runtime whole-object reuse')
    paths, unresolved = {}, []
    for key, entry in reusable.items():
        if key not in supplied:
            unresolved.append(key); continue
        value = supplied[key]; source = entry['source']; ref = entry['reuse_reference']; path = Path(value['path'])
        need(value['source_key'] == key and value['size_bytes'] == source['size_bytes']
             and value['etag_opaque'] == source['etag_opaque'] and value['sha256'] == ref['original_member_sha256']
             and path.stat().st_size == source['size_bytes'] and sha(path) == value['sha256'], 'runtime whole-object bytes differ')
        paths[key] = str(path.resolve())
    output.mkdir(parents=True)
    for entry in catalog:
        if entry['reuse_reference']:
            continue
        path = output/'cache'/entry['source_id']/'source.parquet'; path.parent.mkdir(parents=True)
        with path.open('xb') as f:
            f.truncate(entry['source']['size_bytes'])
        paths[entry['source']['key']] = str(path.resolve())
    for archive in archives:
        with zipfile.ZipFile(pack_dir/archive['file']) as z:
            infos = z.infolist(); need(len(infos) == len({i.filename for i in infos}), 'duplicate ZIP member')
            need(all(i.compress_type == zipfile.ZIP_STORED and not i.flag_bits & 1 for i in infos), 'non-stored or encrypted ZIP member')
            raw = z.read('manifest.json'); need(hashlib.sha256(raw).hexdigest() == archive['manifest_sha256'], 'archive manifest differs')
            manifest = json.loads(raw)
            need(manifest['schema_version'] == 'phase16_range_archive_v1' and manifest['day_utc'] == archive['day_utc']
                 and manifest['part'] == archive['part'] and manifest['attempt_id'] == index['attempt_id']
                 and manifest['holes_are_original_bytes'] is False, 'archive metadata differs')
            entries = manifest['entries']
            need([e['receipt']['ordinal'] for e in entries] == archive['request_ordinals']
                 and {i.filename for i in infos} == {'manifest.json', *(e['member'] for e in entries)}, 'ZIP membership differs')
            for entry in entries:
                r = entry['receipt']; need(r == requests[r['ordinal']-1], 'archive receipt differs from original')
                need(r['source']['day_utc'] == archive['day_utc'] and entry['member'] == f'ranges/{r["ordinal"]:06d}.bin'
                     and entry['stored_bytes'] == r['response_bytes']
                     and entry['accepted_original_response'] is (r['transport_ok'] is True), 'member range identity differs')
                info = z.getinfo(entry['member']); need(info.file_size == info.compress_size == entry['stored_bytes'], 'member length differs')
                with z.open(entry['member']) as src, Path(paths[r['source']['key']]).open('r+b') as dst:
                    dst.seek(r['stored_offset']); copy_exact(src, dst, entry['stored_bytes'], r['response_sha256'])
                    need(src.read(1) == b'', 'extra member bytes')
    for entry in catalog:
        if not entry['reuse_reference']:
            accepted = [r for r in requests if r['source']['key'] == entry['source']['key'] and r['transport_ok']]
            put(output/'cache'/entry['source_id']/'ranges.json', {'schema_version': 'article2_phase16_source_range_cache_v1',
                'source': entry['source'], 'attempt_id': index['attempt_id'], 'ranges': accepted})
    for name in metadata:
        target = output/relative(name); target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((pack_dir/name).read_bytes())
    put(output/'runtime_source_paths.json', paths)
    status = 'RESTORED_NEW_RANGES_REUSE_REFERENCES_ONLY' if unresolved else 'RESTORED_RECORDED_SOURCE_BYTES'
    if index['mode'] == 'failed':
        status = 'RESTORED_FAILED_CAPTURE_FORENSICS_NOT_ACCEPTED'
    result = {'schema_version': 'phase16_range_restore_v1', 'status': status, 'scientific_acceptance': False,
              'index_sha256': expected_index_sha256, 'capture_mode': index['mode'],
              'accepted_response_bytes': index['accepted_response_bytes'], 'unaccepted_response_bytes': index['unaccepted_response_bytes'],
              'unresolved_whole_object_sources': unresolved,
              'scope': 'Sparse source evidence only. Unrecorded holes are unavailable; partial responses are excluded from range cache receipts. Original session is preserved, not reset or reopened.'}
    put(output/'restore_result.json', result); return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pack', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--expected-index-sha256', required=True); p.add_argument('--reuse-map', type=Path)
    a = p.parse_args(); print(json.dumps(restore(a.pack, a.output, a.expected_index_sha256, a.reuse_map)))


if __name__ == '__main__':
    main()
