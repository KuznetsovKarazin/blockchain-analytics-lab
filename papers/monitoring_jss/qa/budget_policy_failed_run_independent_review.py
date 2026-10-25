#!/usr/bin/env python3
"""Read-only byte-integrity audit; no production imports or policy re-execution.

Records current bytes and inode/mtime/ctime without assigning a causal actor.
Failed gzip streams are invalid even if some or all JSON lines can be recovered.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[3]


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def load(path): return json.loads(Path(path).read_text())


def stat(path):
    s = Path(path).stat()
    return {'device': s.st_dev, 'inode': s.st_ino, 'bytes': s.st_size,
            'mtime_ns': s.st_mtime_ns, 'ctime_ns': s.st_ctime_ns,
            'mtime_utc': datetime.fromtimestamp(s.st_mtime_ns / 10**9, timezone.utc).isoformat(),
            'ctime_utc': datetime.fromtimestamp(s.st_ctime_ns / 10**9, timezone.utc).isoformat(),
            'mode': s.st_mode, 'hard_links': s.st_nlink}


def bytes_check(path, expected=None, expected_bytes=None):
    d = {'path': str(path), 'expected_sha256': expected, 'expected_bytes': expected_bytes}
    try:
        d['stat_before'] = stat(path); d['actual_sha256'] = sha(path)
        d['sha256_matches'] = None if expected is None else d['actual_sha256'] == expected
        d['bytes_match'] = None if expected_bytes is None else d['stat_before']['bytes'] == expected_bytes
        d['stat_after'] = stat(path); d['stable_during_read'] = d['stat_before'] == d['stat_after']
        d['status'] = 'FAIL' if d['sha256_matches'] is False or d['bytes_match'] is False or not d['stable_during_read'] else 'PASS'
    except Exception as e:
        d['error'] = repr(e); d['status'] = 'FAIL'
    return d


def gzip_check(path, expected_rows=None, decision_lines=False):
    result = {'gzip_eof_crc': 'FAIL', 'json_parse': 'FAIL', 'expected_rows': expected_rows}
    count = 0; valid = 0; first = last = None; h = hashlib.sha256(); bad_json = []
    try:
        with gzip.open(path, 'rb') as f:
            if decision_lines:
                for line in f:
                    count += 1; h.update(line)
                    try:
                        row = json.loads(line); valid += 1
                        if first is None: first = row
                        last = row
                    except Exception as e:
                        bad_json.append({'line': count, 'error': repr(e), 'line_bytes': len(line)})
                result['json_parse'] = 'PASS' if not bad_json else 'FAIL'
            else:
                content = f.read(); h.update(content)
                obj = json.loads(content)
                result['json_parse'] = 'PASS'
                result['state_summary'] = {
                    k: (len(obj[k]) if k in ('seen', 'order_keys', 'alert_ids', 'window') else obj.get(k))
                    for k in ('schema_version', 'seen', 'order_keys', 'alert_ids', 'window', 'watermark', 'policy_clock_ns', 'last_emitted_time_ns', 'token_credit_units')
                }
        result['gzip_eof_crc'] = 'PASS'
    except Exception as e:
        result['error'] = repr(e)
        if decision_lines and not bad_json: result['json_parse'] = 'PASS_FOR_COMPLETE_PREFIX_LINES_ONLY'
    result['decompressed_bytes_sha256_scope'] = 'complete stream' if result['gzip_eof_crc'] == 'PASS' else 'only bytes successfully returned before error; never complete evidence'
    result['decompressed_bytes_sha256'] = h.hexdigest()
    if decision_lines:
        result.update({'lines_returned': count, 'valid_json_rows': valid, 'json_errors': bad_json,
                       'row_count_matches': count == expected_rows, 'first_complete_row': first, 'last_complete_row': last})
    result['status'] = 'PASS' if result['gzip_eof_crc'] == 'PASS' and result['json_parse'] == 'PASS' and (not decision_lines or count == expected_rows) else 'FAIL'
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run', default='papers/monitoring_jss/runs/budget_policy_20261025T124444_450736Z')
    ap.add_argument('--output', default='papers/monitoring_jss/qa/budget_policy_failed_run_independent_review.json')
    args = ap.parse_args(); run = (ROOT / args.run).resolve(); output = (ROOT / args.output).resolve()
    started = time.perf_counter()
    report = {'schema': 'budget_policy_run_independent_integrity_review_v1', 'run': str(run),
              'auditor': str(Path(__file__).relative_to(ROOT)), 'auditor_sha256': sha(__file__),
              'started_utc': datetime.now(timezone.utc).isoformat(), 'read_only': True,
              'production_imports': False, 'policy_reexecution': False, 'network_requests': 0,
              'causal_attribution': 'Not established. Bytes, recorded hashes and filesystem metadata are observations only.',
              'cells': [], 'frozen_files': [], 'tracked_sources_current': [], 'inputs': [], 'shared_headers': [], 'errors': []}
    m = load(run / 'run_manifest.json'); study = load(run / 'study_summary.json'); resolved = load(run / 'resolved_inputs.json'); inp = load(run / 'input_manifest.json')
    report['run_manifest'] = bytes_check(run / 'run_manifest.json')
    report['recorded_run_status'] = m.get('status'); report['recorded_run_error'] = m.get('error')
    report['study_summary'] = bytes_check(run / 'study_summary.json')
    for name, digest in m['frozen_file_sha256'].items():
        report['frozen_files'].append(bytes_check(run / name, digest))
    for name, digest in m['tracked_source_sha256'].items():
        report['tracked_sources_current'].append(bytes_check(Path(name), digest))
    input_expected = {(p['population_id'], i['day_utc']):i for p in inp['populations'] for i in p['inputs']}
    for pop, entries in sorted(resolved.items()):
        for entry in entries:
            p = Path(entry['path']); d = bytes_check(p, entry['sha256'], entry['bytes'])
            d.update({'population_id':pop, 'day':entry['day_utc'], 'expected_rows':entry['rows']})
            try:
                rows = 0
                with p.open() as f:
                    for line in f: json.loads(line); rows += 1
                d['valid_json_rows'] = rows
                manifest_entry = input_expected[(pop, entry['day_utc'])]
                d['matches_frozen_acquisition_manifest'] = all(entry[k] == manifest_entry[k] for k in ('sha256','bytes','rows','population_id','day_utc','complete','status'))
                if rows != entry['rows'] or not d['matches_frozen_acquisition_manifest']: d['status'] = 'FAIL'
            except Exception as e: d['status'] = 'FAIL'; d['parse_error'] = repr(e)
            report['inputs'].append(d)
    for day in inp['days']:
        path = ROOT / day['acquisition_manifest_path']; hd = day['headers_output']
        hpath = path.parent / hd['path']
        d = bytes_check(hpath, hd['sha256'], hd['bytes']); d['day'] = day['day_utc']
        d['day_manifest_current'] = bytes_check(path)
        try:
            d['day_manifest_equals_frozen_record'] = load(path) == {k:v for k,v in day.items() if k not in ('archive','acquisition_manifest_path')}
            if not d['day_manifest_equals_frozen_record']: d['status'] = 'FAIL'
        except Exception as e: d['status'] = 'FAIL';d['day_manifest_error'] = repr(e)
        report['shared_headers'].append(d)
    actual_cells = {p.name for p in (run / 'cells').iterdir() if p.is_dir()}
    declared_cells = {c['cell_id'] for c in study['cells']}
    if actual_cells != declared_cells or len(declared_cells) != 18:
        report['errors'].append({'cell_inventory':{'actual':sorted(actual_cells),'declared':sorted(declared_cells)}})
    for summary in study['cells']:
        cid = summary['cell_id']; folder = run / 'cells' / cid
        c = {'cell_id': cid, 'summary_file': bytes_check(folder/'summary.json'), 'artifacts': [], 'status': 'PASS'}
        try:
            c['cell_summary_equals_study_summary'] = load(folder/'summary.json') == summary
            if not c['cell_summary_equals_study_summary']: c['status'] = 'FAIL'
        except Exception as e: c['status'] = 'FAIL';c['summary_error'] = repr(e)
        if summary['decision_log']['sha256'] != summary['artifacts']['decisions.jsonl.gz'] or summary['decision_log']['rows'] != summary['records']:
            c['status'] = 'FAIL';c['summary_internal_mismatch'] = True
        for name, digest in summary['artifacts'].items():
            p = folder/name; d = bytes_check(p,digest)
            if p.name.endswith('.gz'):
                d['gzip_review'] = gzip_check(p, summary['records'] if name=='decisions.jsonl.gz' else None, name=='decisions.jsonl.gz')
                if d['gzip_review']['status'] != 'PASS': d['status']='FAIL'
            else:
                try:
                    parsed = load(p); d['json_parse'] = 'PASS';d['json_type'] = type(parsed).__name__
                    if isinstance(parsed,(dict,list)):d['json_top_level_length']=len(parsed)
                except Exception as e:d['json_parse']='FAIL';d['error']=repr(e);d['status']='FAIL'
            d['stat_after_all_checks'] = stat(p)
            d['stable_across_hash_and_decode'] = d.get('stat_before') == d['stat_after_all_checks']
            if not d['stable_across_hash_and_decode']:d['status']='FAIL'
            if d['status']!='PASS':c['status']='FAIL'
            c['artifacts'].append(d)
        report['cells'].append(c)
    failed_artifacts = [{'cell_id':c['cell_id'],'path':d['path'],'sha256_matches':d.get('sha256_matches'),'bytes':d.get('stat_before',{}).get('bytes'),
                         'gzip_status':d.get('gzip_review',{}).get('gzip_eof_crc'),'valid_json_rows':d.get('gzip_review',{}).get('valid_json_rows'),
                         'expected_rows':d.get('gzip_review',{}).get('expected_rows'),'error':d.get('gzip_review',{}).get('error',d.get('error'))}
                        for c in report['cells'] for d in c['artifacts'] if d['status']!='PASS']
    report['failed_artifacts'] = failed_artifacts
    groups = ('frozen_files','tracked_sources_current','inputs','shared_headers')
    report['totals'] = {g:{'checked':len(report[g]),'failed':sum(x['status']!='PASS' for x in report[g])} for g in groups}
    report['totals'].update({'cells':len(report['cells']),'failed_cells':sum(c['status']!='PASS' for c in report['cells']),
                             'cell_artifacts':sum(len(c['artifacts']) for c in report['cells']), 'failed_artifacts':len(failed_artifacts),
                             'gzip_streams':sum(d['path'].endswith('.gz') for c in report['cells'] for d in c['artifacts']),
                             'failed_gzip_streams':sum(d.get('gzip_review',{}).get('status')=='FAIL' for c in report['cells'] for d in c['artifacts'])})
    report['status'] = 'FAIL' if failed_artifacts or report['errors'] or any(x['status']!='PASS' for g in groups for x in report[g]) or any(c['status']!='PASS' for c in report['cells']) else 'PASS'
    report['evidence_eligibility'] = 'invalid_for_evidence_entire_run' if report['status']=='FAIL' or m.get('status')!='complete' else 'byte_integrity_passed_policy_semantics_not_evaluated'
    report['audit_execution'] = 'complete';report['finished_utc']=datetime.now(timezone.utc).isoformat();report['wall_seconds']=time.perf_counter()-started
    report['limitations'] = ['No causal actor or mechanism inferred from matching/mismatching hashes or file timestamps.',
                             'Filesystem metadata was observed after failure; no original inode/ctime snapshot was recorded before replay.',
                             'Readable decision prefixes in failed gzip files are diagnostic only and do not rehabilitate the run.',
                             'This audit does not recalculate policy semantics or use partial results for policy comparison.',
                             'Upstream full Parquet archives were independently validated in the acquisition audit; this failure audit rechecks replay inputs and shared headers.']
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'status':report['status'],'evidence_eligibility':report['evidence_eligibility'],'totals':report['totals'],'failed_artifacts':failed_artifacts,'output':str(output)},indent=2))
    return 1 if report['status']=='FAIL' else 0


if __name__=='__main__':raise SystemExit(main())
