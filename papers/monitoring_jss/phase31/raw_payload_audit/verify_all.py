#!/usr/bin/env python3
"""Offline complete125 aggregation; optional negative integrity tests on copies."""
import argparse,gzip,hashlib,json,shutil,stat,subprocess,sys,tempfile,zipfile
from pathlib import Path, PurePosixPath
BASE=Path(__file__).resolve().parent
CASES={'cohort28_07':44,'cohort28_11':43,'cohort28_14':38}
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def load(path):return json.loads(path.read_bytes())
def write(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def command(case,path):return [sys.executable,str(BASE/'collect_and_verify.py'),'--case',case,'--out',str(path),'--verify-only']
def extract_archive(archive,destination):
 with zipfile.ZipFile(archive) as z:
  seen=set();total=0
  for info in z.infolist():
   name=PurePosixPath(info.filename)
   if name.is_absolute() or '..' in name.parts or '\\' in info.filename or str(name) in seen or not name.parts or name.parts[0]!='data':
    raise ValueError('unsafe or duplicate archive member')
   if stat.S_ISLNK(info.external_attr>>16):raise ValueError('archive symlink not accepted')
   seen.add(str(name));total+=info.file_size
   if info.file_size>20000000 or total>500000000:raise ValueError('archive size bound')
  for info in z.infolist():
   path=destination/str(PurePosixPath(info.filename))
   if info.is_dir():path.mkdir(parents=True,exist_ok=True);continue
   path.parent.mkdir(parents=True,exist_ok=True)
   with z.open(info) as source,path.open('wb') as target:shutil.copyfileobj(source,target)

def main():
 p=argparse.ArgumentParser();p.add_argument('--data',type=Path,default=BASE/'data');p.add_argument('--out',type=Path,default=BASE/'FULL_RAW_OBSERVATION_AUDIT.json');p.add_argument('--integrity-tests',action='store_true');p.add_argument('--archive',type=Path);a=p.parse_args()
 archive=a.archive or (BASE/'raw_observations.zip' if not a.data.exists() else None)
 temporary=None
 if archive is not None:
  temporary=tempfile.TemporaryDirectory(prefix='article2-raw-archive-');extract_archive(archive,Path(temporary.name));a.data=Path(temporary.name)/'data'
 results=[];failures=[];negative=[]
 for case,n in CASES.items():
  path=a.data/case;run=subprocess.run(command(case,path),capture_output=True,text=True)
  if run.returncode!=0:
   failures.append({'case':case,'returncode':run.returncode,'stderr':run.stderr[-2000:],'stdout':run.stdout[-2000:]});continue
  r=load(path/'offline_verification.json')
  if r['status']!='COMPLETE' or r['verified_transactions']!=n or r['expected_transactions']!=n or r['case_scope']!=[case]:
   failures.append({'case':case,'reason':'unexpected complete-case shape'});continue
  results.append({'case':case,'verified_transactions':n,'all_emitter_logs':r['all_emitter_logs'],
                  'http_response_count':r['response_count'],'http_response_bytes':r['response_bytes'],
                  'http_receipt_chain_head':r['response_chain_head'],'offline_verification_sha256':sha(path/'offline_verification.json'),
                  'all_historical_payload_digests_match':all(x['historical_payload_digest_match'] for x in r['transaction_verification']),
                  'all_frozen_features_match':all(x['all_frozen_feature_fields_match'] for x in r['transaction_verification']),
                  'all_independent_counts_and_flows_match':all(x['independent_event_counts_and_flows_match'] for x in r['transaction_verification'])})
 if a.integrity_tests and not failures:
  case='cohort28_07'
  for kind in ('response_body_changed','normalized_event_changed','success_metadata_changed'):
   with tempfile.TemporaryDirectory(prefix='article2-negative-integrity-') as tmp:
    target=Path(tmp)/case;shutil.copytree(a.data/case,target)
    if kind=='response_body_changed':
     path=sorted((target/'responses').glob('*.gz'))[0]
     with gzip.open(path,'rb') as f:body=f.read()
     with gzip.open(path,'wb') as f:f.write(body+b' ')
    else:
     path=sorted((target/'bundles'/case).glob('*.gz'))[0]
     with gzip.open(path,'rt') as f:bundle=json.load(f)
     if kind=='normalized_event_changed':bundle['normalized_events'][0]['data']+='00'
     else:bundle['transaction_metadata']['status']='error'
     with gzip.open(path,'wt') as f:json.dump(bundle,f)
    run=subprocess.run(command(case,target),capture_output=True,text=True)
    negative.append({'mutation':kind,'rejected':run.returncode!=0,'returncode':run.returncode})
    if run.returncode==0:failures.append({'integrity_test':kind,'reason':'corrupted evidence accepted'})
 status='PASS' if not failures and len(results)==3 else 'FAIL'
 report={'schema':'article2_phase31_full_raw_observation_audit_v1','status':status,'cases':results,
         'verified_transactions':sum(x['verified_transactions'] for x in results),
         'all_emitter_logs':sum(x['all_emitter_logs'] for x in results),
         'failures':failures,'negative_integrity_tests':negative,'network_requests_during_verification':0,
         'collector_sha256':sha(BASE/'collect_and_verify.py'),'verifier_sha256':sha(Path(__file__)),
         'data_archive_sha256':sha(archive) if archive else None,'archive_extracted_to_fresh_temporary_directory':archive is not None,
         'source_tier':'AWS-selected identities/counts plus retained Blockscout response bytes, full logs and success metadata',
         'original_AWS_topics_data_reacquired':False,'receipt_root_authenticated':False,'attack_reference_inventory_closed':False}
 write(a.out,report);print(json.dumps(report,sort_keys=True))
 if temporary is not None:temporary.cleanup()
 if status!='PASS':raise SystemExit(1)
if __name__=='__main__':main()
