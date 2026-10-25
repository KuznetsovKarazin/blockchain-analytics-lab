"""Compare frozen scientific inputs/jobs while preserving both measured series."""
from pathlib import Path
import argparse
from datetime import datetime,timezone
import hashlib
import json
import zipfile

ROOT=Path(__file__).resolve().parents[3]

def sha(p):
    with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def audit(first,repeat,first_review,output):
    expected_first='85935b37bce6f436f934922afd25ec5f2b2f2ef7102cf2d0de45bab2d5a38dcf'
    expected_repeat='83a67a539f554b33c89a7947044b5eb0eb152e5b6e7ec8054e6c592a5fcc4d10'
    expected_review='d18993114b8f4e9e7545ed539939fbd5f94d7111d08598c5a05951c5fa829fc1'
    assert sha(first)==expected_first and sha(repeat)==expected_repeat
    assert sha(first_review)==expected_review
    with zipfile.ZipFile(first) as a,zipfile.ZipFile(repeat) as b:
        fa=json.loads(a.read('design_freeze.json'));fb=json.loads(b.read('design_freeze.json'))
        assert fa['run_id']!=fb['run_id'] and fa['stage']!=fb['stage']
        assert fa['source_hashes']==fb['source_hashes']
        assert fa['config_sha256']==fb['config_sha256']
        assert fa['actual_cpu_affinity']==fb['actual_cpu_affinity']
        assert fa['jobs']==fb['jobs'] and len(fa['jobs'])==54
        for name,h in fa['source_hashes'].items():
            x=a.read('source_snapshot/'+name);y=b.read('source_snapshot/'+name)
            assert x==y and hashlib.sha256(x).hexdigest()==h
        for job in fa['jobs']:
            x=a.read(job['job_path']);y=b.read(job['job_path'])
            assert x==y and hashlib.sha256(x).hexdigest()==job['job_sha256']
        ea=json.loads(a.read('execution_manifest.json'));eb=json.loads(b.read('execution_manifest.json'))
        assert ea['status']==eb['status']=='complete'
        assert [r['job_id'] for r in ea['jobs']]==[r['job_id'] for r in eb['jobs']]
        for j1,j2 in zip(ea['jobs'],eb['jobs']):
            r1=json.loads(a.read(j1['output_path']+'/summary.json'));r2=json.loads(b.read(j2['output_path']+'/summary.json'))
            for key in ('records','source_sha256','job_source_sha256','decision_stream_sha256','final_state_sha256',
                        'canonical_state_bytes','seen_entries','order_key_entries','rolling_window_entries','notification_ids','policy_config'):
                assert r1[key]==r2[key],(j1['job_id'],key)
        result={'status':'PASS','scope':'Same scientific source/config/input/job order and semantic outputs; new timing measurements',
            'first_run':fa['run_id'],'repeat_run':fb['run_id'],'first_archive_sha256':expected_first,
            'repeat_archive_sha256':expected_repeat,'first_independent_review_sha256_unchanged':expected_review,
            'source_snapshot_files_identical':len(fa['source_hashes']),'job_files_identical':54,'execution_order_identical':True,
            'all_semantic_decision_and_state_hashes_identical':True,'cpu_affinity_identical':fa['actual_cpu_affinity'],
            'first_run_retained_valid_descriptive_with_known_concurrency':True,'performance_based_exclusion':False,
            'local_source_commits':[fa['local_source_commit'],fb['local_source_commit']],
            'archive_member_counts':[len(a.infolist()),len(b.infolist())],
            'completed_utc':datetime.now(timezone.utc).isoformat(),'review_source_sha256':sha(__file__)}
    with Path(output).open('x') as f:json.dump(result,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps(result))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--first',type=Path,required=True);p.add_argument('--repeat',type=Path,required=True)
    p.add_argument('--first-review',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();audit(a.first,a.repeat,a.first_review,a.output)
