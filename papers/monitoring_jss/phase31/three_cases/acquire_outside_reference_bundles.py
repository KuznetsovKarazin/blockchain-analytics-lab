#!/usr/bin/env python3
"""Retain indexer metadata/log bytes for role-adjudicated nonselected references.

This is reference-only corroboration, not a source-population expansion and not
input to the frozen monitor. Bounded to three specified historical transactions.
"""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import time
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
BASE = 'https://eth.blockscout.com/api/v2/transactions/'
TARGETS = {
    '0xabfcfaf3620bbb2d41a3ffea6e31e93b9b5f61c061b9cfc5a53c74ebe890294d':
        ('cohort28_11', '0xb14b3b9682990ccc16f52eb04146c3ceab01169a'),
    '0x51cbfd46f21afb44da4fa971f220bd28a14530e1d5da5009cfbdfee012e57e35':
        ('cohort28_11', '0xb14b3b9682990ccc16f52eb04146c3ceab01169a'),
    '0x82fc23992c7433fffad0e28a1b8d11211dc4377de83e88088d79f24f4a3f28b3':
        ('cohort28_14', '0x4deca517d6817b6510798b7328f2314d3003abac'),
}


def main():
    out = HERE/'outside_reference_bundles'
    out.mkdir(exist_ok=True)
    manifest = {'schema': 'phase31_offstream_indexer_reference_bundles_v1',
                'scope': 'Reference corroboration only; no monitor rescoring or sample expansion.',
                'receipt_root_verified': False, 'rows': []}
    for tx, (case, core) in TARGETS.items():
        folder = out/tx
        folder.mkdir(exist_ok=True)
        receipts = []

        def fetch(url, name):
            path = folder/name
            if path.exists():
                payload = path.read_bytes()
                cached = True
            else:
                req = urllib.request.Request(url, headers={
                    'User-Agent': 'article2-indexed-creation-audit/1.0', 'Accept': 'application/json'})
                with urllib.request.urlopen(req, timeout=25) as response:
                    assert response.status == 200
                    payload = response.read(2_000_001)
                assert len(payload) <= 2_000_000
                path.write_bytes(payload)
                cached = False
                time.sleep(0.16)
            receipts.append({'url': url, 'file': str(path.relative_to(out)), 'bytes': len(payload),
                             'sha256': hashlib.sha256(payload).hexdigest(),
                             'cached_local_bytes': cached})
            return json.loads(payload)

        metadata = fetch(BASE+tx, 'metadata.json')
        assert metadata['hash'].lower() == tx and metadata['status'] == 'ok'
        items, cursor, seen = [], None, set()
        for page in range(10):
            url = BASE+tx+'/logs'
            if cursor:
                url += '?' + urllib.parse.urlencode(cursor)
            data = fetch(url, f'logs_{page+1:02}.json')
            items.extend(data['items'])
            cursor = data.get('next_page_params')
            if cursor is None:
                break
            frozen = json.dumps(cursor, sort_keys=True)
            assert frozen not in seen
            seen.add(frozen)
        else:
            raise AssertionError('Pagination cap reached')
        assert len({x['index'] for x in items}) == len(items)
        assert all(x['transaction_hash'].lower() == tx and
                   x['block_number'] == metadata['block_number'] for x in items)
        core_count = sum((x['address']['hash'] if isinstance(x['address'], dict) else x['address']).lower() == core
                         for x in items)
        manifest['rows'].append({'case': case, 'tx': tx, 'timestamp_utc': metadata['timestamp'],
                                 'block_number': metadata['block_number'],
                                 'transaction_index': metadata['position'],
                                 'execution_status': metadata['status'],
                                 'all_emitter_logs': len(items), 'core_emitter_logs': core_count,
                                 'bundle_complete': True, 'source': 'Blockscout_v2', 'receipts': receipts})
        (out/'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2)+'\n')
        print(case, tx, len(items), 'logs;', core_count, 'fixed-core logs', flush=True)


if __name__ == '__main__':
    main()
