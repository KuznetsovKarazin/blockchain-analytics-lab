#!/usr/bin/env python3
"""Independent offline seal and gzip audit of the unchanged technical retry.

Reuses only the independent QA byte checker, never production replay modules.
No raw or run writes, no policy execution, no extraction of the evidence archive.
"""
from __future__ import annotations
import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[3]
HELPER = Path(__file__).with_name('budget_policy_failed_run_independent_review.py')
SPEC = importlib.util.spec_from_file_location('independent_integrity_helper', HELPER)
qa = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qa)


def require(ok, message):
    if not ok: raise AssertionError(message)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run', default='papers/monitoring_jss/runs/budget_policy_20261025T125143_314640Z')
    ap.add_argument('--publication', default='data/raw/monitoring_jss/budget/budget_policy_20261025T125143_314640Z_sealed_publication.json')
    ap.add_argument('--output', default='papers/monitoring_jss/qa/budget_policy_retry_integrity_independent_review.json')
    args = ap.parse_args(); run = (ROOT / args.run).resolve(); publication = (ROOT / args.publication).resolve(); output = (ROOT / args.output).resolve()
    started = time.perf_counter()
    report = {'schema': 'budget_policy_retry_independent_integrity_review_v1', 'status': 'RUNNING',
              'auditor': str(Path(__file__).relative_to(ROOT)), 'auditor_sha256': qa.sha(__file__),
              'independent_helper': str(HELPER.relative_to(ROOT)), 'independent_helper_sha256': qa.sha(HELPER),
              'started_utc': datetime.now(timezone.utc).isoformat(), 'run': str(run),
              'production_imports': False, 'policy_reexecution': False, 'raw_or_run_writes': False,
              'network_requests': 0, 'archive_extractions': 0, 'failures': []}
    try:
        pub = qa.load(publication); archive = Path(pub['path'])
        require(Path(pub['exported_run']) == run and pub['status'] == 'sealed_verified_and_exported', 'publication identity/status')
        archive_review = qa.bytes_check(archive, pub['sha256'], pub['bytes'])
        require(archive_review['status'] == 'PASS', 'whole archive SHA/bytes')
        report['publication'] = qa.bytes_check(publication)
        report['archive'] = archive_review
        m = qa.load(run/'run_manifest.json'); seal_exec = qa.load(run/'sealed_execution.json')
        isolated_run = Path(seal_exec['path_resolution']['runtime_root']) / 'papers/monitoring_jss/runs' / run.name
        report['isolated_run'] = str(isolated_run)
        require(m['status'] == 'complete' and m['frozen_sources_config_inputs_unchanged'] is True, 'complete unchanged computation')
        require(seal_exec['policy_or_parameter_changes'] is False and seal_exec['labels_joined'] is False, 'technical retry scope')
        require(seal_exec['wrapper_sha256'] == pub['wrapper_sha256'] == qa.sha(run/'provenance/seal_budget_policy_retry.py'), 'wrapper frozen SHA')
        require(qa.sha(run/'study_summary.json') == pub['study_summary_sha256'], 'published study summary')
        prior = ROOT / 'papers/monitoring_jss/runs' / seal_exec['failed_run_id']
        old_manifest = qa.load(prior/'run_manifest.json')
        require(m['frozen_file_sha256'] == old_manifest['frozen_file_sha256'], 'retry changed frozen code/config/inputs')
        report['unchanged_vs_failed_run'] = {'run':str(prior), 'identical_frozen_file_sha256':m['frozen_file_sha256']}
        report['members'] = []
        with zipfile.ZipFile(archive) as z:
            names = z.namelist(); require(len(names) == len(set(names)) == pub['members'], 'archive member count/uniqueness')
            manifest_bytes = z.read('sealed_member_manifest.json')
            sealed = json.loads(manifest_bytes)
            require(set(names) == set(sealed['members']) | {'sealed_member_manifest.json'}, 'manifest exact inventory with explicit self-exclusion')
            require(manifest_bytes == (run/'sealed_member_manifest.json').read_bytes(), 'exported seal manifest bytes')
            require(manifest_bytes == (isolated_run/'sealed_member_manifest.json').read_bytes(), 'isolated seal manifest bytes')
            for name in names:
                require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'unsafe member name')
                h=hashlib.sha256(); size=0
                with z.open(name) as f:
                    for b in iter(lambda:f.read(1024*1024), b''):
                        h.update(b);size+=len(b)
                actual={'sha256':h.hexdigest(),'bytes':size}
                if name!='sealed_member_manifest.json':require(actual==sealed['members'][name], 'sealed member SHA/bytes: '+name)
                loose=qa.bytes_check(run/name,actual['sha256'],size)
                original=qa.bytes_check(isolated_run/name,actual['sha256'],size)
                require(loose['status']=='PASS' and original['status']=='PASS','sealed/isolated/exported mismatch: '+name)
                report['members'].append({'path':name,**actual,'crc_eof':'PASS','exported':loose,'isolated':original})
        report['all_archive_crc_member_hash_and_both_loose_copies_match']=True
        actual_loose={str(p.relative_to(run)) for p in run.rglob('*') if p.is_file()}
        report['exported_extra_files']=sorted(actual_loose-set(names))
        # Result-artifact hashes in the completed run manifest are additional to
        # the per-cell summaries checked by the independent helper.
        results=m['result_artifact_sha256']
        report['result_manifest_hash_checks']=[qa.bytes_check(run/name,digest) for name,digest in results.items()]
        require(all(x['status']=='PASS' for x in report['result_manifest_hash_checks']), 'result manifest SHA')
        report['retry_provenance_source_checks']=[qa.bytes_check(Path(name),digest) for name,digest in seal_exec['source_hashes'].items()]
        require(all(x['status']=='PASS' for x in report['retry_provenance_source_checks']), 'retry provenance hashes')
        with tempfile.TemporaryDirectory(prefix='budget-retry-qa-report-') as tmp:
            temp_report=Path(tmp)/'loose_integrity.json'
            original_argv=sys.argv
            try:
                sys.argv=[str(HELPER),'--run',str(run),'--output',str(temp_report)]
                with contextlib.redirect_stdout(io.StringIO()): result=qa.main()
            finally:sys.argv=original_argv
            integrity=qa.load(temp_report)
        report['loose_integrity']=integrity
        require(result==0 and integrity['status']=='PASS', 'independent artifact/gzip/input checks')
        require(integrity['totals']['cells']==18 and integrity['totals']['cell_artifacts']==72 and integrity['totals']['gzip_streams']==36,'required cell/artifact inventory')
        summaries={s['cell_id']:s for s in qa.load(run/'study_summary.json')['cells']}
        rows=0; state_checks=[]
        for cell in integrity['cells']:
            summary=summaries[cell['cell_id']]
            dec=next(x['gzip_review'] for x in cell['artifacts'] if Path(x['path']).name=='decisions.jsonl.gz')
            state=next(x['gzip_review']['state_summary'] for x in cell['artifacts'] if Path(x['path']).name=='final_state.json.gz')
            rows+=dec['valid_json_rows']
            require(state['seen']==state['order_keys']==summary['records'], 'finalstate exact ledger counts')
            require(state['alert_ids']==summary['notifications']==summary['unique_alert_ids'], 'finalstate alert count')
            require(state['window']==summary['window_entries_at_end'], 'finalstate rolling count')
            state_checks.append({'cell_id':cell['cell_id'],'records':summary['records'],'seen':state['seen'],'order_keys':state['order_keys'],
                                 'alert_ids':state['alert_ids'],'window_entries':state['window'],'status':'PASS'})
        require(rows==435240,'all435240 decision rows')
        require(integrity['totals']['inputs']=={'checked':60,'failed':0} and integrity['totals']['shared_headers']=={'checked':30,'failed':0},'complete frozen inputs')
        require(qa.sha(archive)==pub['sha256'],'archive remained unchanged after full audit')
        report['finalstate_count_checks']=state_checks
        report['totals']={'archive_members':len(report['members']),'archive_bytes':pub['bytes'],'sealed_hashed_members':len(sealed['members']),
                          'cells':18,'cell_artifacts':72,'gzip_streams':36,'decision_rows':rows,'final_states':18,'selected_inputs':60,'shared_headers':30,
                          'frozen_files':len(m['frozen_file_sha256']),'result_manifest_hashes':len(results)}
        report['status']='PASS'
        report['evidence_eligibility']='byte_integrity_passed; separate independent policy-semantic oracle required'
    except Exception as e:
        report['status']='FAIL';report['failures'].append(repr(e));report['evidence_eligibility']='not_accepted'
    report['finished_utc']=datetime.now(timezone.utc).isoformat();report['wall_seconds']=time.perf_counter()-started
    report['limitations']=['Technical preservation retry with unchanged frozen computation; original failed run remains invalid.',
                          'Successful sealed retry does not establish the cause or causal actor of the original corruption.',
                          'CRC/SHA and full JSON counts establish artifact integrity, not policy correctness or attack detection effectiveness.',
                          'Runtime paths and source references are retained for observed provenance; independent replay inputs must be relocated explicitly if the workspace changes.']
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'status':report['status'],'totals':report.get('totals'),'failures':report['failures'],'output':str(output)},indent=2))
    return 0 if report['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
