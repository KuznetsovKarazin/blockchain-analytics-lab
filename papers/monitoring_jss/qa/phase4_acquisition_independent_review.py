#!/usr/bin/env python3
"""Offline, independent audit of the frozen 30-day emitter acquisition.

Imports no collector/replay modules. Reads canonical whole Parquet objects from
sealed private archives through bounded seekable views, with no raw extraction.
Every address is inspected, and every selected payload is reconstructed from
source columns. This proves listed-partition projection, not receipt completeness.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import struct
import time
import traceback
import xml.etree.ElementTree as ET
import zipfile

import pyarrow as pa
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[3]
BASE = 'https://aws-public-blockchain.s3.us-east-2.amazonaws.com/'
NS = {'s': 'http://s3.amazonaws.com/doc/2006-03-01/'}
HEX32 = re.compile(r'0x[0-9a-f]{64}\Z')
HEXDATA = re.compile(r'0x(?:[0-9a-f]{2})*\Z')
SCALE = {'s': 10**9, 'ms': 10**6, 'us': 1000, 'ns': 1}
PINNED_CONFIG = 'deb0bed056df051a3c90d511f3a64f20aac36782b3382526f82e4b570117eaa4'
EXPECTED_POPULATIONS = {
    'euler_core': ['0x27182842e098f60e3d576794a5bffb0777e025d3'],
    'beanstalk_diamond': ['0xc1e088fc1323b20bcbee9bd1b9fc9546db5624c5'],
}


class StoredMember(io.RawIOBase):
    """Read-only, seekable window over one already CRC/SHA-verified ZIP_STORED member."""
    def __init__(self, archive, info):
        super().__init__()
        require(info.compress_type == zipfile.ZIP_STORED and not info.flag_bits & 1, 'direct ZIP view requires unencrypted stored member')
        self.file = open(archive, 'rb')
        self.file.seek(info.header_offset)
        header = self.file.read(30)
        require(len(header) == 30 and header[:4] == b'PK\x03\x04', 'ZIP local header')
        name_length, extra_length = struct.unpack_from('<HH', header, 26)
        self.start = info.header_offset + 30 + name_length + extra_length
        self.length = info.file_size
        self.position = 0

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.position

    def seek(self, offset, whence=0):
        target = offset if whence == 0 else self.position + offset if whence == 1 else self.length + offset if whence == 2 else -1
        if target < 0: raise ValueError('invalid seek')
        self.position = target
        return target

    def read(self, size=-1):
        available = max(0, self.length - self.position)
        n = available if size is None or size < 0 else min(size, available)
        self.file.seek(self.start + self.position)
        b = self.file.read(n)
        self.position += len(b)
        return b

    def readinto(self, target):
        b = self.read(len(target)); target[:len(b)] = b; return len(b)

    def close(self):
        if hasattr(self, 'file'): self.file.close()
        super().close()


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(4 * 1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def hash_bytes(b):
    return hashlib.sha256(b).hexdigest()


def load(path):
    return json.loads(Path(path).read_text())


def jsonlines(b):
    return [json.loads(x) for x in b.splitlines() if x]


def utc(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))


def integer(v):
    return type(v) is int and v >= 0


def timestamp_values(column):
    require(pa.types.is_timestamp(column.type), 'timestamp source type')
    factor = SCALE[column.type.unit]
    vals = column.cast(pa.int64()).to_pylist()
    require(all(integer(x) for x in vals), 'null/noninteger source timestamp')
    return [x * factor for x in vals]


def audit_inventory(config, inventory):
    base = (ROOT / config['inventory_path']).parent
    all_objects = {}
    page_evidence = []
    for listing in inventory['metadata_listings']:
        require(listing['all_pages_complete'] is True, 'unfinished listing')
        actual = []
        for ix, page in enumerate(listing['pages']):
            p = base / page['snapshot']
            b = p.read_bytes()
            require(len(b) == page['bytes'] and hash_bytes(b) == page['sha256'], 'listing XML hash')
            tree = ET.fromstring(b)
            require(tree.findtext('s:Prefix', namespaces=NS) == listing['prefix'], 'listing prefix')
            truncated = tree.findtext('s:IsTruncated', namespaces=NS) == 'true'
            require(truncated == page['is_truncated'], 'listing truncation metadata')
            require(truncated == (ix + 1 < len(listing['pages'])), 'listing pagination incomplete')
            for c in tree.findall('s:Contents', NS):
                actual.append({'key': c.findtext('s:Key', namespaces=NS),
                               'size': int(c.findtext('s:Size', namespaces=NS)),
                               'etag': c.findtext('s:ETag', namespaces=NS),
                               'last_modified': c.findtext('s:LastModified', namespaces=NS)})
            page_evidence.append({'path': str(p.relative_to(ROOT)), 'sha256': page['sha256'], 'bytes': len(b)})
        require(actual == listing['objects'], 'XML inventory objects differ')
        for obj in actual:
            require(obj['key'] not in all_objects, 'duplicate listed source key')
            all_objects[obj['key']] = obj
    selected = []
    for day in inventory['days']:
        for table in ('logs', 'blocks'):
            matches = [o for k, o in all_objects.items() if k.startswith(f'v1.0/eth/{table}/date={day["day"]}/')]
            require(matches == [day[table]], f'exact daily source inventory: {day["day"]}/{table}')
            selected.append(day[table])
    require(len(selected) == 60 and len({o['key'] for o in selected}) == 60, '60 unique sources required')
    require(sum(o['size'] for o in selected) == inventory['whole_source_bytes_total'], 'source total size')
    return {'listing_pages': page_evidence, 'selected_source_objects': 60,
            'selected_source_bytes': sum(o['size'] for o in selected)}


def check_headers(rows, day):
    require(bool(rows), 'empty header day')
    start = int(utc(day + 'T00:00:00Z').timestamp()) * 10**9
    seen_n, seen_h = set(), set()
    previous = None
    for r in rows:
        require(set(r) == {'block_number', 'block_hash', 'parent_hash', 'event_time_ns', 'transaction_count'}, 'header fields')
        require(all(integer(r[k]) for k in ('block_number', 'event_time_ns', 'transaction_count')), 'header integer')
        require(HEX32.fullmatch(r['block_hash']) and HEX32.fullmatch(r['parent_hash']), 'header hash syntax')
        require(start <= r['event_time_ns'] < start + 86400 * 10**9, 'header UTC day')
        require(r['block_number'] not in seen_n and r['block_hash'] not in seen_h, 'duplicate header')
        if previous:
            require(r['block_number'] == previous['block_number'] + 1 and r['parent_hash'] == previous['block_hash'], 'within-day parent chain')
            require(r['event_time_ns'] > previous['event_time_ns'], 'header timestamp order')
        seen_n.add(r['block_number']); seen_h.add(r['block_hash']); previous = r


def check_logs(rows, headers, addresses, day):
    by_block = {h['block_number']: h for h in headers}
    identities, positions, tx_positions = set(), {}, {}
    previous = None
    for r in sorted(rows, key=lambda x: (x['block_number'], x['transaction_index'], x['log_index'])):
        require(r['chain_id'] == 1 and r['address'] in addresses, 'chain/emitter membership')
        require(r['observed_time'] is None and r['label_available_time'] is None, 'invented historical observation/label clock')
        require('removed' not in r or r['removed'] is False or r['removed'] is None, 'removed true/nonbool selected')
        require(all(integer(r[k]) for k in ('block_number', 'event_time_ns', 'transaction_index', 'log_index', 'source_global_row_index', 'source_row_group', 'source_row_index')), 'log integer field')
        require(HEX32.fullmatch(r['block_hash']) and HEX32.fullmatch(r['transaction_hash']), 'log hash syntax')
        require(HEXDATA.fullmatch(r['data']) and isinstance(r['topics'], list) and len(r['topics']) <= 4 and all(HEX32.fullmatch(t) for t in r['topics']), 'data/topics syntax')
        h = by_block[r['block_number']]
        require(r['block_hash'] == h['block_hash'] and r['event_time_ns'] == h['event_time_ns'], 'header hash/time join')
        require(r['transaction_index'] < h['transaction_count'], 'transaction index range')
        key = (r['block_hash'], r['log_index'])
        require(key not in identities, 'duplicate chain/block/log identity'); identities.add(key)
        pos = (r['block_number'], r['transaction_index'])
        require(positions.setdefault(pos, r['transaction_hash']) == r['transaction_hash'], 'tx position conflicting hash')
        require(tx_positions.setdefault(r['transaction_hash'], pos) == pos, 'tx hash at multiple positions')
        if previous and r['block_number'] == previous['block_number']:
            require(r['log_index'] > previous['log_index'], 'global log index ordering')
        previous = r


def audit_day(record, inventory_day, config, run, raw_root):
    day = record['day_utc']
    archive = Path(record['archive']['path'])
    initial_stat = archive.stat()
    require(initial_stat.st_size == record['archive']['bytes'], 'archive byte count')
    archive_sha = sha(archive)
    require(archive_sha == record['archive']['sha256'], 'archive SHA256')
    loose = raw_root / day
    expected = {'day_manifest.json', 'config.json', 'inventory.json', 'headers.jsonl',
                'logs.parquet', 'headers.parquet', 'logs.parquet.receipt.json', 'headers.parquet.receipt.json'}
    expected |= {p + '_logs.jsonl' for p in EXPECTED_POPULATIONS}
    expected |= {'source_snapshot/' + n for n in config['source_hashes']}
    member_stats = {}
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        require(len(names) == len(set(names)), 'duplicate archive names')
        require(expected | {'ARCHIVE_MANIFEST.json'} <= set(names), 'missing canonical archive members')
        require(len(names) == record['archive']['members'], 'archive member count')
        seal = json.loads(z.read('ARCHIVE_MANIFEST.json'))
        listed = {r['path']: r for r in seal['files']}
        require(len(listed) == len(seal['files']) and set(listed) | {'ARCHIVE_MANIFEST.json'} == set(names), 'seal exact member inventory')
        require(seal['whole_source_objects'] is True and seal['raw_redistribution_authorization'] is False, 'seal scope')
        for name in names:
            if name == 'ARCHIVE_MANIFEST.json':
                continue
            require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'unsafe member path')
            h = hashlib.sha256(); n = 0
            with z.open(name) as f:
                for b in iter(lambda: f.read(4 * 1024 * 1024), b''):
                    h.update(b); n += len(b)
            require(h.hexdigest() == listed[name]['sha256'] and n == listed[name]['bytes'], 'member SHA/bytes: ' + name)
            member_stats[name] = {'sha256': h.hexdigest(), 'bytes': n}
        require(member_stats['config.json']['sha256'] == PINNED_CONFIG, 'archive config identity')
        require(member_stats['inventory.json']['sha256'] == config['inventory_sha256'], 'archive inventory identity')
        for name, digest in config['source_hashes'].items():
            require(member_stats['source_snapshot/' + name]['sha256'] == digest, 'archive frozen source identity')
        dm = json.loads(z.read('day_manifest.json'))
        require(dm == load(loose / 'day_manifest.json'), 'loose vs archived day manifest')
        require(dm == {k:v for k,v in record.items() if k not in ('archive', 'acquisition_manifest_path')}, 'top manifest daily projection')
        require(dm['status'] == 'complete' and dm['day_utc'] == day and dm['config_sha256'] == PINNED_CONFIG, 'daily completion/config')
        require(dm['source_hashes'] == config['source_hashes'], 'daily source hashes')
        for table, name in (('logs', 'logs.parquet'), ('blocks', 'headers.parquet')):
            receipt = json.loads(z.read(name + '.receipt.json'))
            obj = inventory_day[table]
            require(receipt == dm['source_objects'][table], 'source receipt differs from day manifest')
            require(receipt['source'] == {'url': BASE + obj['key'], 'size': obj['size'], 'etag': obj['etag'], 'version_id': obj.get('version_id')}, 'source identity differs from XML inventory')
            require(receipt['bytes'] == obj['size'] == member_stats[name]['bytes'], 'whole source length')
            require(receipt['sha256'] == member_stats[name]['sha256'] and receipt['hash_scope'] == 'whole source object', 'whole source hash')
        with StoredMember(archive, z.getinfo('headers.parquet')) as header_view:
            htable = pq.ParquetFile(header_view).read(columns=['number', 'hash', 'parent_hash', 'timestamp', 'transaction_count'], use_threads=False)
        hcols = {n: htable[n].to_pylist() for n in ('number', 'hash', 'parent_hash', 'transaction_count')}
        times = timestamp_values(htable['timestamp'])
        headers = sorted([{'block_number': hcols['number'][i], 'block_hash': hcols['hash'][i].lower(),
                           'parent_hash': hcols['parent_hash'][i].lower(), 'transaction_count': hcols['transaction_count'][i],
                           'event_time_ns': t} for i,t in enumerate(times)], key=lambda h: h['block_number'])
        require(headers == jsonlines(z.read('headers.jsonl')), 'headers exact Parquet projection')
        check_headers(headers, day)
        ho = dm['headers_output']
        require(ho['complete'] is True and ho['rows'] == len(headers) == dm['full_header_count'] and dm['parent_links_checked'] == len(headers) - 1, 'header counts')
        require(dm['first_header'] == headers[0] and dm['last_header'] == headers[-1], 'header boundaries')
        require(ho['sha256'] == member_stats['headers.jsonl']['sha256'] == sha(loose / 'headers.jsonl') and ho['bytes'] == member_stats['headers.jsonl']['bytes'], 'headers loose/output hash')
        selected = {}; counts = {}; output_meta = {}
        require(len(dm['population_outputs']) == 2, 'two explicit daily populations')
        for out in dm['population_outputs']:
            pid = out['population_id']; name = pid + '_logs.jsonl'
            require(pid in EXPECTED_POPULATIONS and pid not in counts and out['path'] == name and out['complete'] is True, 'population identity/completion')
            b = z.read(name); rows = jsonlines(b)
            require(out['rows'] == len(rows) and out['bytes'] == len(b) and out['sha256'] == hash_bytes(b) == sha(loose / name), 'explicit output count/hash')
            require(rows == sorted(rows, key=lambda r: (r['block_number'], r['transaction_index'], r['log_index'])), 'output order')
            for row in rows:
                require(row['address'] in EXPECTED_POPULATIONS[pid], 'cross-population membership')
                key = row['source_global_row_index']; require(key not in selected, 'duplicate source ordinal'); selected[key] = row
            counts[pid] = len(rows); output_meta[pid] = out
        require(set(counts) == set(EXPECTED_POPULATIONS), 'missing vs zero population')
        check_logs(list(selected.values()), headers, {a for aa in EXPECTED_POPULATIONS.values() for a in aa}, day)
        log_view = StoredMember(archive, z.getinfo('logs.parquet'))
        pf = pq.ParquetFile(log_view)
        fields = ['address', 'topics', 'data', 'transaction_index', 'log_index', 'transaction_hash', 'block_number', 'block_hash', 'block_timestamp']
        has_removed = 'removed' in pf.schema_arrow.names
        require(dm['source_missing_removed'] == (not has_removed), 'removed availability metadata')
        if has_removed: fields.append('removed')
        pending = dict(selected); rg_info = []; total = 0; selected_n = 0
        addresses = {a for aa in EXPECTED_POPULATIONS.values() for a in aa}
        # Independent bounded batching. Every address is inspected in Python;
        # payload columns are decoded from the complete canonical Parquet object.
        for rg in range(pf.num_row_groups):
            offset = 0; matches = 0
            for batch in pf.iter_batches(batch_size=32768, row_groups=[rg], columns=fields, use_threads=False):
                values = batch.column('address').to_pylist()
                require(all(isinstance(v, str) for v in values), 'null/invalid source address makes membership unknown')
                indices = [i for i,v in enumerate(values) if v.lower() in addresses]
                if indices:
                    subset = batch.take(pa.array(indices, type=pa.int32()))
                    cols = {n: subset.column(n).to_pylist() for n in fields if n != 'block_timestamp'}
                    ts = timestamp_values(subset.column('block_timestamp'))
                    for j, original in enumerate(indices):
                        glob = total + offset + original
                        expected_row = {'address': cols['address'][j].lower(), 'topics': [x.lower() for x in cols['topics'][j]],
                                        'data': cols['data'][j].lower(), 'transaction_index': cols['transaction_index'][j],
                                        'log_index': cols['log_index'][j], 'transaction_hash': cols['transaction_hash'][j].lower(),
                                        'block_number': cols['block_number'][j], 'block_hash': cols['block_hash'][j].lower(),
                                        'event_time_ns': ts[j], 'chain_id': 1, 'source_row_group': rg,
                                        'source_row_index': offset + original, 'source_global_row_index': glob,
                                        'observed_time': None, 'label_available_time': None}
                        if has_removed: expected_row['removed'] = cols['removed'][j]
                        require(pending.pop(glob, None) == expected_row, f'exact selected payload differs at source ordinal {glob}')
                    matches += len(indices)
                offset += len(values)
            require(offset == pf.metadata.row_group(rg).num_rows, 'row group not fully scanned')
            rg_info.append({'row_group': rg, 'source_row_start': total, 'address_rows_scanned': offset, 'matching_rows': matches, 'address_null_rows': 0})
            total += offset; selected_n += matches
        require(not pending, 'selected rows absent from source scan')
        require(total == pf.metadata.num_rows == dm['complete_address_rows_scanned'], 'complete source address count')
        require(rg_info == dm['row_groups'], 'row-group accounting')
        require(selected_n == len(selected) == dm['union_selected_logs'] == sum(counts.values()), 'exact union count')
        extras = [{**member_stats[n], 'path': n} for n in sorted(set(names) - expected - {'ARCHIVE_MANIFEST.json'})]
        row_group_count = pf.num_row_groups
        pf.close(); log_view.close()
    final_stat = archive.stat()
    require((initial_stat.st_size, initial_stat.st_mtime_ns) == (final_stat.st_size, final_stat.st_mtime_ns), 'archive changed during audit')
    return {'day': day, 'status': 'PASS', 'archive': {'path': str(archive.relative_to(ROOT)), 'sha256': archive_sha, 'bytes': initial_stat.st_size, 'members': len(names)},
            'canonical_whole_source_hashes': {n: member_stats[n] for n in ('logs.parquet', 'headers.parquet')},
            'all_archive_members_crc_sha_bytes_verified': True, 'unexpected_archive_members': extras,
            'address_rows_scanned': total, 'row_groups_scanned': row_group_count,
            'population_counts': counts, 'explicit_zero_populations': [p for p,n in counts.items() if n == 0],
            'population_outputs': output_meta, 'full_headers': len(headers), 'within_day_parent_links': len(headers) - 1,
            'first_header': headers[0], 'last_header': headers[-1], 'removed_field_present': has_removed}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run', required=True)
    ap.add_argument('--output', default='papers/monitoring_jss/qa/phase4_acquisition_independent_review.json')
    args = ap.parse_args()
    run = (ROOT / args.run).resolve(); output = (ROOT / args.output).resolve()
    started = time.perf_counter(); cpu = time.process_time()
    report = {'schema': 'phase4_independent_acquisition_review_v1', 'status': 'RUNNING', 'auditor': str(Path(__file__).relative_to(ROOT)),
              'auditor_sha256': sha(__file__), 'run': str(run.relative_to(ROOT)), 'started_utc': datetime.now(timezone.utc).isoformat(),
              'imports_production_modules': False, 'network_requests': 0, 'days': [], 'failures': [],
              'limitations': ['Completeness is relative to the frozen, completely listed upstream partitions; no independent full-chain receipt acquisition.',
                              'Window edges are not anchored to independently acquired blocks outside the window.',
                              'Historical observed time, label availability, and absent removed fields remain unknown.',
                              'This is acquisition QA only; no benign-background, attack recall, false-positive, or independent-test claim.']}
    def persist():
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    try:
        manifest_path = run / 'manifest.json'; manifest_hash = sha(manifest_path); m = load(manifest_path)
        c = load(run / 'config.json'); inv = load(run / 'inventory.json')
        require(m['status'] == 'complete' and len(m['days']) == 30, 'only complete 30-day manifest eligible')
        require(sha(run / 'config.json') == m['config_sha256'] == PINNED_CONFIG, 'pinned configuration')
        require({p['population_id']: p['addresses'] for p in c['populations']} == EXPECTED_POPULATIONS, 'frozen two-emitter population')
        require(c['labels_in_input'] is False and c['topics'] == 'all', 'all-topic label-free source selection')
        for key in ('inventory', 'population_contract', 'study_design_freeze'):
            require(sha(ROOT / c[key + '_path']) == c[key + '_sha256'], key + ' hash')
        require(sha(run / 'inventory.json') == c['inventory_sha256'], 'run inventory identity')
        for name, digest in c['source_hashes'].items():
            require(sha(run / 'source_snapshot' / name) == digest, 'frozen source SHA')
        contract = load(ROOT / c['population_contract_path'])
        require({a for p in contract['populations'] for a in p['emitter_addresses']} == {a for v in EXPECTED_POPULATIONS.values() for a in v}, 'population contract address membership')
        require(contract['primary_window']['start_utc_inclusive'] == c['start_utc'] and contract['primary_window']['end_utc_exclusive'] == c['end_utc_exclusive'], 'population contract window')
        require(utc(load(ROOT / c['study_design_freeze_path'])['frozen_utc']) < utc(m['started_utc']), 'design freeze chronology')
        days = [(utc(c['start_utc']) + timedelta(days=n)).date().isoformat() for n in range(30)]
        require(c['start_utc'] == '2022-03-19T00:00:00Z' and c['end_utc_exclusive'] == '2022-04-18T00:00:00Z', 'fixed window')
        require([d['day'] for d in inv['days']] == days == [d['day_utc'] for d in m['days']], 'exact continuous daily inventory')
        report['inventory_review'] = audit_inventory(c, inv)
        report['config_sha256'] = PINNED_CONFIG; report['manifest_sha256'] = manifest_hash
        report['population_contract_sha256'] = c['population_contract_sha256']; report['frozen_source_hashes'] = c['source_hashes']
        raw_root = ROOT / m['raw_storage']
        for rec, inventory_day in zip(m['days'], inv['days'], strict=True):
            try:
                result = audit_day(rec, inventory_day, c, run, raw_root)
                report['days'].append(result)
                print(json.dumps({'day': result['day'], 'status': 'PASS', 'address_rows': result['address_rows_scanned'], 'populations': result['population_counts'], 'extras': len(result['unexpected_archive_members'])}), flush=True)
            except Exception as e:
                report['failures'].append({'day': rec['day_utc'], 'error': str(e), 'traceback': traceback.format_exc()})
                print(json.dumps({'day': rec['day_utc'], 'status': 'FAIL', 'error': str(e)}), flush=True)
            persist()
        require(len(report['days']) == 30 and not report['failures'], 'all 30 days must independently pass')
        for prev, cur in zip(report['days'], report['days'][1:]):
            a, b = prev['last_header'], cur['first_header']
            require(b['block_number'] == a['block_number'] + 1 and b['parent_hash'] == a['block_hash'] and b['event_time_ns'] > a['event_time_ns'], 'cross-day header chain')
        for p in m['populations']:
            require(len(p['inputs']) == 30 and p['addresses'] == EXPECTED_POPULATIONS[p['population_id']], 'manifest population completeness')
            for inp, day in zip(p['inputs'], report['days'], strict=True):
                meta = day['population_outputs'][p['population_id']]
                require(inp['day_utc'] == day['day'] and inp['status'] == 'complete' and inp['complete'] is True, 'zero vs missing input status')
                require({k:inp[k] for k in ('bytes','rows','sha256','population_id')} == {k:meta[k] for k in ('bytes','rows','sha256','population_id')}, 'manifest output hashes/counts')
                expected_path = raw_root / day['day'] / meta['path']
                require(ROOT / inp['path'] == expected_path and ROOT / inp['shared_headers_path'] == expected_path.parent / 'headers.jsonl' and ROOT / inp['acquisition_manifest_path'] == expected_path.parent / 'day_manifest.json', 'manifest input paths')
        require(sha(manifest_path) == manifest_hash, 'top manifest changed during audit')
        report['totals'] = {'days': 30, 'population_days': 60, 'full_source_objects': 60,
            'address_rows_scanned': sum(d['address_rows_scanned'] for d in report['days']),
            'full_headers': sum(d['full_headers'] for d in report['days']),
            'within_day_parent_links': sum(d['within_day_parent_links'] for d in report['days']), 'cross_day_parent_links': 29,
            'population_logs': {p: sum(d['population_counts'][p] for d in report['days']) for p in EXPECTED_POPULATIONS},
            'archive_bytes': sum(d['archive']['bytes'] for d in report['days']),
            'archive_members': sum(d['archive']['members'] for d in report['days']),
            'unexpected_archive_members': sum(len(d['unexpected_archive_members']) for d in report['days']),
            'unexpected_archive_bytes': sum(e['bytes'] for d in report['days'] for e in d['unexpected_archive_members'])}
        report['status'] = 'PASS'
        if report['totals']['unexpected_archive_members']:
            report['findings'] = [{'severity': 'nonblocking_storage/provenance', 'finding': 'Additional collector-unrequested files were included by recursive sealing; all are inventoried and CRC/SHA checked. Only canonical named sources feed the independent projection. Cause not established; originals preserved.', 'count': report['totals']['unexpected_archive_members']}]
    except Exception as e:
        report['status'] = 'FAIL'; report['failures'].append({'error': str(e), 'traceback': traceback.format_exc()})
    report['finished_utc'] = datetime.now(timezone.utc).isoformat()
    report['audit_resource_scope'] = 'This independent auditor process only, including sequential full ZIP reads and bounded direct ZIP_STORED member views, with no raw extraction; excludes collection/replay.'
    report['audit_wall_seconds'] = time.perf_counter() - started; report['audit_process_cpu_seconds'] = time.process_time() - cpu
    report['audit_peak_rss_bytes'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    persist()
    print(json.dumps({'status': report['status'], 'output': str(output), 'totals': report.get('totals'), 'failures': report['failures']}), flush=True)
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
