#!/usr/bin/env python3
"""Portable byte-range evidence packaging. No network, Parquet decode or scoring.

Only recorded response bytes are copied. Original sparse-file holes and reused
whole objects are never packaged. This delivery code is outside measurement.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import zipfile

MAX_ARCHIVE = 500 * 1024 * 1024
ENDPOINT = 'https://aws-public-blockchain.s3.us-east-2.amazonaws.com/'
FIELDS = ('table', 'day_utc', 'key', 'size_bytes', 'etag_opaque', 'url')


def need(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def integer(value, minimum=0):
    need(type(value) is int and value >= minimum, 'invalid integer')
    return value


def hexsha(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'invalid SHA256')
    return value


def relative(value):
    p = Path(value)
    need(type(value) is str and value and not p.is_absolute() and '..' not in p.parts
         and '\\' not in value and ':' not in value, 'unsafe relative path')
    return p


def portable(value):
    if isinstance(value, dict):
        for k, v in value.items():
            portable(k); portable(v)
    elif isinstance(value, list):
        for v in value:
            portable(v)
    elif isinstance(value, str):
        # Exception strings can embed private paths after prose or quotes.
        # Keep exact evidence: reject such metadata rather than redact it.
        text = re.sub(r'https://[^\s<>\"\']+', '', value)
        need(not text.startswith(('/', '\\'))
             and not re.search(r'(?<![A-Za-z0-9_./])/(?=[A-Za-z0-9_.~])|[A-Za-z]:[\\/]|(?:file|vscode)://|\\\\[A-Za-z0-9]', text),
             'private absolute path in portable metadata')


def put(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value) + b'\n')


def load(path, expected=None):
    path = Path(path)
    if expected is not None:
        need(sha(path) == hexsha(expected), 'bound metadata hash differs: ' + path.name)
    return json.loads(path.read_bytes())


def identity(value):
    s = {k: value[k] for k in FIELDS}
    need(s['table'] in ('blocks', 'logs', 'transactions'), 'source table')
    need(date.fromisoformat(s['day_utc']).isoformat() == s['day_utc'], 'source date')
    need(re.fullmatch(r'v1\.0/eth/' + s['table'] + '/date=' + s['day_utc'] +
                      r'/[A-Za-z0-9_.-]+\.parquet', s['key']), 'source key')
    need(s['url'] == ENDPOINT + s['key'], 'source URL')
    integer(s['size_bytes'], 12)
    need(type(s['etag_opaque']) is str and s['etag_opaque'], 'source ETag')
    return s


def validate_request(r, ordinal, sources, mode):
    need(r['ordinal'] == ordinal, 'request ordinal')
    source = identity(r['source']); key = source['key']
    need(key in sources and source == sources[key], 'request source differs')
    start, length = integer(r['start']), integer(r['length'], 1)
    received = integer(r['response_bytes'])
    need(start + length <= source['size_bytes'] and received <= length, 'response bounds')
    need(r['stored_offset'] == start and Path(r['stored_file_name']).name == r['stored_file_name'], 'stored range identity')
    headers = r['request_headers']
    need(r['method'] == 'GET' and headers['Range'] == f'bytes={start}-{start+length-1}'
         and headers['If-Match'] == source['etag_opaque'] and headers['Accept-Encoding'] == 'identity',
         'request headers differ')
    accepted = r.get('transport_ok') is True
    if accepted:
        need(received == length and r['http_status'] == 206 and r['response_url'] == source['url']
             and r['etag'] == source['etag_opaque'] and r['content_encoding'] in (None, 'identity')
             and r['content_range'] == f'bytes {start}-{start+length-1}/{source["size_bytes"]}'
             and type(r['content_length']) is str and r['content_length'].isdigit()
             and int(r['content_length']) == length and not r.get('failure'), 'unaccepted successful receipt')
    else:
        need(mode == 'failed', 'non-successful request in complete capture')
    if received or accepted:
        hexsha(r['response_sha256'])
    return accepted


def read_inputs(collection, repo, expected_plan, expected_result, expected_sources, mode, accepted_plan=None):
    collection, repo = Path(collection), Path(repo)
    result_name = 'collection_result.json' if mode == 'complete' else 'failure.json'
    paths = {'frozen_plan.json': collection/'frozen_plan.json', result_name: collection/result_name,
             'transport/session.json': collection/'transport/session.json',
             'transport/requests.json': collection/'transport/requests.json',
             'transport/plan.json': collection/'transport/plan.json'}
    plan = load(paths['frozen_plan.json'], expected_plan)
    result = load(paths[result_name], expected_result)
    session = load(paths['transport/session.json']); requests = load(paths['transport/requests.json'])
    need(plan['schema_version'] == 'article2_phase16_streaming_pipeline_plan_v1', 'pipeline plan schema')
    need(session['schema_version'] == 'article2_phase16_range_capture_v1', 'session schema')
    need(canonical(load(paths['transport/plan.json'])) == canonical(plan['collector'])
         and session['plan_canonical_sha256'] == digest(plan['collector']), 'collector plan differs')
    need(session['attempt_id'] == digest({'plan': digest(plan['collector']), 'started_utc': session['started_utc']}), 'attempt identity')
    if mode == 'complete':
        need(result['status'] == 'COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT'
             and session['status'] == 'COMPLETE', 'capture not complete')
        need(expected_sources is not None, 'complete capture needs transport_sources hash')
        # The pipeline reserializes its runtime frozen_plan copy; its file hash
        # need not equal the accepted input hash recorded by collection_result.
        accepted_path = paths['frozen_plan.json'] if accepted_plan is None else Path(accepted_plan)
        need(sha(accepted_path) == result['plan_sha256'], 'accepted input plan differs; supply exact --accepted-plan bytes')
        need(canonical(load(accepted_path)) == canonical(plan), 'accepted input and runtime plan values differ')
        paths['metadata/accepted_plan.json'] = accepted_path
    else:
        need(result['status'] == 'FAILED_NOT_ACCEPTED' and session['status'] != 'COMPLETE', 'capture not failed')
        need(accepted_plan is None, '--accepted-plan applies only to complete captures')
    sourcepaths_path = collection/'runtime_source_paths.json'
    need(mode == 'failed' or sourcepaths_path.exists(), 'complete capture source paths absent')
    sourcepaths = load(sourcepaths_path) if sourcepaths_path.exists() else {}
    sourcepaths_sha = sha(sourcepaths_path) if sourcepaths_path.exists() else None
    bind = plan['source_union']; inventory_path = repo/relative(bind['path'])
    inventory = load(inventory_path, bind['sha256']); paths['metadata/source_union.json'] = inventory_path
    inventory_sources = [identity(s) for s in inventory['objects']]
    all_sources = {s['key']: s for s in inventory_sources}
    need(len(all_sources) == len(inventory_sources) and set(sourcepaths) <= set(all_sources), 'source inventory/paths')
    sources = {k: all_sources[k] for k in sourcepaths}
    if mode == 'failed':
        # open_reader publishes its runtime path only after open() succeeds.
        # First-header/footer failures can therefore have recorded cache bytes
        # without an entry (or any file) in runtime_source_paths.json.
        for r in requests:
            source = identity(r['source']); key = source['key']
            need(all_sources.get(key) == source, 'failed request differs from frozen inventory')
            sources[key] = source
            if key not in sourcepaths:
                candidate = collection/'cache'/digest(source)/'source.parquet'
                need(candidate.is_file() and candidate.stat().st_size == source['size_bytes'], 'failed-open canonical sparse source missing')
                sourcepaths[key] = str(candidate.resolve())
        by_id = {digest(s): s for s in inventory_sources}
        for reuse in session['cache_or_full_object_reuses']:
            if reuse['kind'] == 'verified_whole_object':
                need(reuse['source_id'] in by_id, 'failed reuse absent from frozen inventory')
                source = by_id[reuse['source_id']]; sources[source['key']] = source
    if mode == 'complete':
        need(set(sources) == set(all_sources) and result['transport_sources'] == len(sources), 'complete source population')
    manifests = None
    if expected_sources is not None:
        paths['transport_sources.json'] = collection/'transport_sources.json'
        manifests = load(paths['transport_sources.json'], expected_sources)['sources']
    need(session['request_count'] == len(requests)
         and session['retained_response_bytes'] == sum(integer(r['response_bytes']) for r in requests), 'session accounting')
    caps = plan['collector']['caps']
    need(len(requests) <= caps['requests'] and session['retained_response_bytes'] <= caps['total_response_bytes'], 'session cap')
    grouped = defaultdict(list)
    for ordinal, r in enumerate(requests, 1):
        validate_request(r, ordinal, sources, mode)
        need(r['length'] <= caps['max_range_bytes'], 'per-response cap')
        grouped[r['source']['key']].append(r)
    catalog = []
    reuses = {x['source_id']: x for x in session['cache_or_full_object_reuses'] if x['kind'] == 'verified_whole_object'}
    need(len(reuses) == sum(x['kind'] == 'verified_whole_object' for x in session['cache_or_full_object_reuses']), 'duplicate whole reuse')
    for key, source in sorted(sources.items()):
        records = grouped[key]; previous_end = -1
        for r in sorted(records, key=lambda x: x['start']):
            need(r['start'] >= previous_end, 'overlapping requested ranges')
            previous_end = r['start'] + r['length']
        sid = digest(source); reuse = reuses.get(sid); reference = None
        if reuse:
            need(not records and reuse['bytes'] == source['size_bytes'], 'mixed reused/range source')
            expectation = plan['whole_object_reuse_expectations'][key]
            need(reuse['sha256'] == expectation['sha256'] and expectation['size_bytes'] == source['size_bytes']
                 and expectation['etag_opaque'] == source['etag_opaque'], 'reuse expectation differs')
            binding = expectation['acquisition_receipt']; receipt_path = repo/relative(binding['path'])
            receipt = load(receipt_path, binding['sha256'])
            need(receipt['source_key'] == key and receipt['sha256'] == reuse['sha256']
                 and receipt['size_bytes'] == source['size_bytes'] and receipt['etag_opaque'] == source['etag_opaque'], 'reuse provenance differs')
            reference = {'original_archive_sha256': hexsha(receipt['expected_archive_sha256']),
                         'original_member_name': str(relative(receipt['expected_original_member_name'])),
                         'original_member_sha256': reuse['sha256'], 'original_member_bytes': reuse['bytes'],
                         'receipt_file': 'metadata/reuse/'+sid+'.json', 'receipt_sha256': binding['sha256'],
                         'new_whole_object_verification_by_packager': False}
            paths[reference['receipt_file']] = receipt_path
        catalog.append({'source': source, 'source_id': sid, 'request_ordinals': [r['ordinal'] for r in records],
                        'reuse_reference': reference})
    need(set(reuses) <= {x['source_id'] for x in catalog}, 'unknown reused source')
    if manifests is not None:
        bykey = {identity(m['source'])['key']: m for m in manifests}
        need(len(bykey) == len(manifests) and set(bykey) == set(sources), 'source manifest population')
        for entry in catalog:
            key = entry['source']['key']; m = bykey[key]
            accepted = [r for r in grouped[key] if r['transport_ok']]
            need(identity(m['source']) == entry['source'] and m['source_id'] == entry['source_id']
                 and sorted(m['successful_original_ranges'], key=lambda r:r['ordinal']) == accepted, 'source receipts differ')
            need(m['whole_source_sha256_verified'] is bool(entry['reuse_reference']), 'whole source verification flag')
            if entry['reuse_reference']:
                need(m['whole_source_sha256'] == entry['reuse_reference']['original_member_sha256'], 'whole source SHA differs')
            else:
                need(m['whole_source_sha256'] is None, 'sparse source misrepresented as whole')
    for path in paths.values():
        portable(load(path))
    return paths, plan, session, requests, catalog, sourcepaths, sourcepaths_sha


def archive_manifest(day, part, attempt, entries):
    return {'schema_version': 'phase16_range_archive_v1', 'day_utc': day, 'part': part,
            'attempt_id': attempt, 'entries': entries, 'holes_are_original_bytes': False}


def archive_bytes(manifest):
    # Seekable ZIP_STORED output, ASCII names, no ZIP64/extras/comments/descriptors.
    return 22 + sum(e['stored_bytes'] + 76 + 2*len(e['member']) for e in manifest['entries']) + \
           len(canonical(manifest)+b'\n') + 76 + 2*len('manifest.json')


def schedule(requests, attempt, cap):
    byday = defaultdict(list)
    for r in requests:
        if r['response_bytes']:
            byday[r['source']['day_utc']].append({'member': f'ranges/{r["ordinal"]:06d}.bin',
                'stored_bytes': r['response_bytes'], 'accepted_original_response': r['transport_ok'] is True,
                'receipt': r})
    result = []
    for day, entries in sorted(byday.items()):
        part, current = 1, []
        for entry in entries:
            candidate = archive_manifest(day, part, attempt, current+[entry])
            if current and archive_bytes(candidate) > cap:
                result.append(archive_manifest(day, part, attempt, current)); part += 1; current = []
            current.append(entry)
            need(archive_bytes(archive_manifest(day, part, attempt, current)) <= cap, 'single response exceeds archive cap')
        if current:
            result.append(archive_manifest(day, part, attempt, current))
    return result


def zipinfo(name, size):
    info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)); info.file_size = size
    info.compress_type = zipfile.ZIP_STORED; info.create_system = 3; info.external_attr = 0o100644 << 16
    return info


def copy_exact(source, target, length, expected):
    h = hashlib.sha256(); copied = 0
    while copied < length:
        block = source.read(min(1048576, length-copied)); need(block, 'recorded source bytes truncated')
        target.write(block); h.update(block); copied += len(block)
    need(h.hexdigest() == expected, 'recorded source bytes hash differs')


def pack(collection, repo, output, expected_plan, expected_result, expected_sources=None,
         mode='complete', max_archive_bytes=MAX_ARCHIVE, runtime_manifest=None, accepted_plan=None):
    need(mode in ('complete', 'failed'), 'pack mode')
    integer(max_archive_bytes, 1); need(max_archive_bytes <= MAX_ARCHIVE, 'archive cap exceeds500MiB')
    output = Path(output); need(not output.exists(), 'pack output already exists')
    runtime = Path(runtime_manifest) if runtime_manifest else output.with_name(output.name+'.runtime.json')
    need(not runtime.exists() and not runtime.resolve().is_relative_to(output.resolve()), 'runtime manifest must be new and outside portable pack')
    values = read_inputs(collection, repo, expected_plan, expected_result, expected_sources, mode, accepted_plan)
    paths, plan, session, requests, catalog, sourcepaths, sourcepaths_sha = values
    manifests = schedule(requests, session['attempt_id'], max_archive_bytes)
    output.mkdir(parents=True); metadata = {}
    for name, path in paths.items():
        raw = path.read_bytes(); target = output/relative(name); target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw); metadata[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw)}
    need(metadata['frozen_plan.json']['sha256'] == expected_plan
         and metadata['collection_result.json' if mode == 'complete' else 'failure.json']['sha256'] == expected_result
         and (expected_sources is None or metadata['transport_sources.json']['sha256'] == expected_sources),
         'pinned metadata changed while copying')
    need(load(output/'transport/session.json') == session and load(output/'transport/requests.json') == requests,
         'capture checkpoint changed while copying')
    if mode == 'complete':
        need(metadata['metadata/accepted_plan.json']['sha256'] == load(output/'collection_result.json')['plan_sha256']
             and canonical(load(output/'metadata/accepted_plan.json')) == canonical(plan), 'accepted plan changed while copying')
    archives = []
    for manifest in manifests:
        name = f'ranges-{manifest["day_utc"]}-{manifest["part"]:03d}.zip'; path = output/name
        with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_STORED, allowZip64=False) as z:
            for entry in manifest['entries']:
                r = entry['receipt']; original = Path(sourcepaths[r['source']['key']])
                need(original.is_file() and original.stat().st_size == r['source']['size_bytes'], 'source sparse size differs')
                with original.open('rb') as src, z.open(zipinfo(entry['member'], entry['stored_bytes']), 'w') as dst:
                    src.seek(r['stored_offset']); copy_exact(src, dst, entry['stored_bytes'], r['response_sha256'])
            raw = canonical(manifest)+b'\n'; z.writestr(zipinfo('manifest.json', len(raw)), raw)
        need(path.stat().st_size == archive_bytes(manifest) <= max_archive_bytes, 'archive size/accounting differs')
        archives.append({'file': name, 'sha256': sha(path), 'size_bytes': path.stat().st_size,
                         'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'day_utc': manifest['day_utc'],
                         'part': manifest['part'], 'request_ordinals': [e['receipt']['ordinal'] for e in manifest['entries']]})
    index = {'schema_version': 'phase16_range_pack_index_v1', 'mode': mode,
             'status': 'COMPLETE_BYTE_EVIDENCE_PACK' if mode == 'complete' else 'FAILED_CAPTURE_FORENSIC_PACK_NOT_ACCEPTED',
             'scientific_acceptance': False, 'attempt_id': session['attempt_id'],
             'runtime_frozen_plan_sha256': metadata['frozen_plan.json']['sha256'],
             'accepted_input_plan_sha256': metadata['metadata/accepted_plan.json']['sha256'] if mode == 'complete' else None,
             'original_sourcepaths_sha256': sourcepaths_sha, 'metadata': metadata, 'sources': catalog,
             'archives': archives, 'archive_cap_bytes': max_archive_bytes,
             'stored_response_bytes': sum(r['response_bytes'] for r in requests),
             'accepted_response_bytes': sum(r['response_bytes'] for r in requests if r['transport_ok']),
             'unaccepted_response_bytes': sum(r['response_bytes'] for r in requests if not r['transport_ok']),
             'whole_reused_objects_duplicated': False, 'sparse_holes_packaged': False,
             'restore_scope': 'Original recorded ranges and provenance only; prepared/scored result artifacts require separate preservation.'}
    original_paths = Path(collection)/'runtime_source_paths.json'
    need(all(sha(path) == metadata[name]['sha256'] for name, path in paths.items())
         and (sha(original_paths) if original_paths.exists() else None) == sourcepaths_sha, 'capture metadata changed during pack')
    portable(index)
    # The final index is the completion marker. No index is published for a failed pack.
    put(runtime, {'schema_version': 'phase16_range_pack_private_runtime_v1', 'collection': str(Path(collection).resolve()),
                  'pack': str(output.resolve()), 'index_sha256': hashlib.sha256(canonical(index)+b'\n').hexdigest(), 'source_paths': sourcepaths})
    put(output/'index.json', index)
    return index


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('collection', 'repo', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    for name in ('expected-plan-sha256', 'expected-result-sha256'):
        p.add_argument('--'+name, required=True)
    p.add_argument('--expected-transport-sources-sha256'); p.add_argument('--mode', choices=('complete','failed'), default='complete')
    p.add_argument('--accepted-plan', type=Path, help='Exact accepted input plan; required if runtime frozen_plan.json serialization differs')
    p.add_argument('--max-archive-bytes', type=int, default=MAX_ARCHIVE); p.add_argument('--runtime-manifest', type=Path)
    a = p.parse_args(); result = pack(a.collection, a.repo, a.output, a.expected_plan_sha256,
        a.expected_result_sha256, a.expected_transport_sources_sha256, a.mode, a.max_archive_bytes, a.runtime_manifest, a.accepted_plan)
    print(json.dumps({'status': result['status'], 'archives': len(result['archives']),
                      'stored_response_bytes': result['stored_response_bytes'], 'index_sha256': sha(a.output/'index.json')}))


if __name__ == '__main__':
    main()
