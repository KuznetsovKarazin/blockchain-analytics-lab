#!/usr/bin/env python3
"""Exercise rejection checks on disposable copies; never modify source evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

BASE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(folder):
    return {str(p.relative_to(folder)): digest(p)
            for p in sorted(folder.rglob('*')) if p.is_file()}


def save(path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, default=BASE / 'audit/INTEGRITY_TESTS.json')
    args = parser.parse_args()
    results = BASE / 'results'
    original = inventory(results)
    checks = []
    for test in ['coordinate_byte_change', 'projected_row_group_omission', 'case_day_omission']:
        with tempfile.TemporaryDirectory(prefix='census32_integrity_') as temp:
            copy = Path(temp) / 'results'
            shutil.copytree(results, copy)
            batch = copy / 'batch_0'
            census_path = batch / 'source_census.json'
            census = json.loads(census_path.read_text())
            if test == 'coordinate_byte_change':
                path = batch / census['case_results'][0]['days'][0]['selected_coordinates_path']
                path.write_bytes(path.read_bytes() + b'changed')
                expected = 'coordinatescompressedhash'
            elif test == 'projected_row_group_omission':
                source = census['source_days'][0]
                path = batch / source['source_manifest_path']
                proof = json.loads(path.read_text())
                proof['read_projections'].pop()
                save(path, proof)
                source['source_manifest_sha256'] = digest(path)
                save(census_path, census)
                expected = 'allrowgroupsprojected'
            else:
                census['case_results'][0]['days'].pop()
                save(census_path, census)
                expected = 'casewindow'
            command = [sys.executable, str(BASE / 'verify_census.py'), '--results', str(copy),
                       '--out', str(Path(temp) / 'audit')]
            result = subprocess.run(command, text=True, capture_output=True)
            assert result.returncode != 0 and 'ValueError: ' + expected in result.stderr, (test, result)
            checks.append({'mutation': test, 'status': 'PASS_REJECTED', 'expected_reason': expected,
                           'exit_code': result.returncode})
    assert original == inventory(results), 'Retained evidence changed during tests'
    report = {'schema': 'phase32_census_integrity_tests_v1', 'status': 'PASS',
              'checks': checks, 'retained_evidence_unchanged': True,
              'retained_file_count': len(original),
              'verifier_sha256': digest(BASE / 'verify_census.py'),
              'test_script_sha256': digest(Path(__file__)),
              'source_census_sha256': {f'batch_{b}': digest(results / f'batch_{b}/source_census.json')
                                       for b in range(4)}}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    save(args.out, report)
    print(json.dumps({'status': 'PASS', 'rejected_mutations': len(checks)}))


if __name__ == '__main__':
    main()
