#!/usr/bin/env python3
"""Offline audit of frozen original studies, without acquisition or original edits.

Use from any working directory. The source-root defaults to this checkout.
Preserves historical bytes; normalizes CSV CRLF only for semantic comparison.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    paper = Path(__file__).resolve().parent.parent
    repo = paper.parents[1]
    audit = {'schema': 'article2_phase31_original_offline_audit_v1',
             'network_requests': 0, 'checks': [],
             'limits': 'Recomputes retained inputs and verifies source receipts; does not repeat remote acquisition or authenticate receipt roots.'}
    def run(name, args):
        result = subprocess.run([sys.executable, *map(str, args)], cwd=repo,
                                capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(name + '\n' + result.stdout + result.stderr)
        audit['checks'].append({'name': name, 'status': 'PASS'})
        return result
    with tempfile.TemporaryDirectory(prefix='article2-offline-') as tmp:
        tmp = Path(tmp)
        run('phase16_sealed_capsule_and_exact_reference_join', [paper/'phase16/public_evidence/verify_public_evidence.py', '--output', tmp/'phase16'])
        audit['phase16'] = json.loads((tmp/'phase16/verification_report.json').read_text())
        # Keep operational path/time fields outside the portable scientific report.
        audit['phase16'].pop('completed_utc', None)
        run('phase18_causal_initialization_replay', [paper/'phase18/initialization_full_replay.py', '--evidence-zip', paper/'phase16/public_evidence/sealed_evidence.zip', '--out', tmp/'base/article2_work/phase18/results'])
        expectations = {'full_replay_summary.json': 'f8db7c0a8f4b478135e98e9c13a97e522b7b104b3c0ccebb0f8d2577367fdcf5',
                        'recomputed_transaction_decisions.jsonl': '61ae2b607658600190aa5062a000fb7a9e5f2f506cf8f99b5600acb51b1aaea6'}
        for n, expected in expectations.items():
            got = sha(tmp/'base/article2_work/phase18/results'/n)
            assert got == expected, (n, got, expected)
        audit['phase18_exact_output_sha256'] = expectations
        src = paper/'phase25/data'
        manifest = json.loads((src/'public_source_manifest.json').read_text())
        for obj in manifest['archives'].values():
            f = src/obj['name']
            assert sha(f) == obj['sha256'], obj['name']
            with zipfile.ZipFile(f) as z:
                for n, expected in obj['member_sha256'].items():
                    assert hashlib.sha256(z.read(n)).hexdigest() == expected, n
            shutil.copy2(f, tmp/'base'/f.name)
        audit['phase25_archives_and_members_verified'] = 3
        shutil.copy2(paper/'phase16/public_evidence/sealed_evidence.zip', tmp/'base/article2_work/sealed_evidence.zip')
        run('phase22_independent_252_cells', [paper/'phase23/verify_phase22_science_independent.py', '--inputs-dir', tmp/'base', '--output', tmp/'phase22.json'])
        audit['phase22'] = json.loads((tmp/'phase22.json').read_text())
        run('phase23_cross_case_tables', [paper/'phase23/build_phase23_tables.py', '--base', tmp/'base', '--out', tmp/'tables'])
        original = paper/'phase23/results'
        expected_tables = json.loads((original/'audit_manifest.json').read_text())['outputs_sha256']
        for n, expected in expected_tables.items():
            f = tmp/'tables'/n
            assert sha(f) == expected, (n, sha(f), expected)
            assert f.read_bytes().replace(b'\r\n', b'\n') == (original/n).read_bytes().replace(b'\r\n', b'\n'), n
        audit['phase23_exact_output_sha256'] = expected_tables
        run('phase21_distinct_transaction_and_union_bounds', [paper/'phase21/verify_published_counts.py'])
        # Published aggregate reconciliation, explicitly not a raw-source replay.
        data = list(csv.DictReader((paper/'phase26/results/control_runtime_readiness.csv').open()))
        aggregates = {}
        for mode in sorted({r['mode'] for r in data}):
            rows = [r for r in data if r['mode'] == mode]
            totals = {k: sum(int(r[k]) for r in rows) for k in ['transactions','z19_ready','mad19_ready','ewma5_ready']}
            assert totals['transactions'] == 714951
            totals['kind'] = 'published_daily_aggregate_reconciliation_only'
            aggregates[mode] = totals
        assert aggregates['daily_reset']['z19_ready'] == 275250
        assert aggregates['daily_reset']['mad19_ready'] == 13816
        assert aggregates['daily_reset']['ewma5_ready'] == 711525
        audit['phase26_aggregates'] = aggregates
    audit['status'] = 'PASS'
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(audit, indent=2, sort_keys=True)+'\n')
    print('PASS: frozen joins, original causal replays, 252 independent cells, four exact tables, comparison aggregates')


if __name__ == '__main__':
    main()
