#!/usr/bin/env python3
"""Freeze catalogue-completion nominations before new traffic acquisition."""
import hashlib,json
from pathlib import Path
from datetime import datetime,timezone
BASE=Path(__file__).resolve().parent
PAPER=BASE.parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,x):p.write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
def main():
 if any((BASE/n).exists() for n in ['CANDIDATE_FRAME.json','FORK_WINDOWS.json','CATALOGUE_COVERAGE.json']):
  raise SystemExit('Frozen frame already exists; refusing to overwrite post-acquisition provenance.')
 mapping=json.loads((BASE/'metadata/SOURCE_MAPPING.json').read_text())
 meta=json.loads((BASE/'metadata/METADATA_AUDIT.json').read_text())
 assert meta['status']=='COMPLETE' and meta['complete_fork_blocks']==7 and meta['complete_contract_creations']==6
 old=json.loads((PAPER/'phase28/CANDIDATE_FRAME.json').read_text())
 catalogue=json.loads((PAPER/'phase31/cohort_audit/CATALOGUE_DISPOSITION.json').read_text())
 rows=mapping['rows'];omitted={x['source_path']:x for x in catalogue['rows'] if x['disposition']=='ETHEREUM_NOT_NOMINATED_REASON_UNDOCUMENTED'}
 assert set(omitted)=={x['source_path'] for x in rows}
 cases=[];pairs={}
 for r in rows:
  assert r['source_sha256']==omitted[r['source_path']]['source_sha256']
  key=(r['core_address'],r['fork_block'])
  if key not in pairs:
   c={'id':f'cohort32_{len(cases)+1:02}','family':r['family'],'core_address':r['core_address'],'core_role_nomination':r['core_role'],'poC_fork_block':r['fork_block'],'source_status':'SOURCE_REPRODUCTION_ONLY_NOT_INCIDENT_ADMITTED','source_files':[],'nomination_reason':r['reason_and_limits']}
   cases.append(c);pairs[key]=c
  pairs[key]['source_files'].append({'source_path':r['source_path'],'source_sha256':r['source_sha256'],'git_blob_sha1':r['git_blob_sha1']})
 assert len(cases)==7 and len({x['core_address'] for x in cases})==6
 frame={'schema':'article2_phase32_catalogue_completion_frame_v1','frozen_utc':datetime.now(timezone.utc).isoformat(),'baseline_release':'article2-jss-v7-2026-10-29','baseline_commit':'aab963c5c5aa60adb7af5f04bc86601f92c67b87','catalogue_commit':mapping['source_commit'],'directory_frame':[f'src/test/2022-{m:02}' for m in range(3,10)],'inclusion_rule':'Every Ethereum-mainnet PoC source file in the pinned directory frame is accounted for. Four original-family files remain in the primary study; all other files map to an extension nomination. The eight previously omitted files receive source-designated or directly targeted operational components before their traffic is measured. Exact core/fork duplicates collapse; distinct fork windows are retained.','historical_status':'This completes the catalogue prospectively after review; it does not retroactively make the original sixteen convenience nominations exhaustive.','unit':'Unique nominated core-address/fork-block window, not independent incident. Primary aggregate deduplicates repeated (core_address, UTC day).','window_rule':'30 whole UTC dates ending inclusively on the indexed PoC fork-block date; not strictly pre-attack histories.','old_frame_sha256':sha(PAPER/'phase28/CANDIDATE_FRAME.json'),'mapping_sha256':sha(BASE/'metadata/SOURCE_MAPPING.json'),'metadata_audit_sha256':sha(BASE/'metadata/METADATA_AUDIT.json'),'traffic_acquired_before_freeze':False,'detector_scores_computed':False,'cases':cases,'batches':[[cases[0]['id'],cases[1]['id']],[cases[2]['id'],cases[3]['id']],[cases[4]['id'],cases[5]['id']],[cases[6]['id']]]}
 write(BASE/'CANDIDATE_FRAME.json',frame)
 block={x['fork_block']:x for x in meta['fork_blocks']}
 windows={'schema':'article2_phase32_catalogue_completion_windows_v1','frame_sha256':sha(BASE/'CANDIDATE_FRAME.json'),'complete':7,'source_tier':meta['source_tier'],'results':[{'id':c['id'],'core_address':c['core_address'],**block[c['poC_fork_block']]} for c in cases]}
 write(BASE/'FORK_WINDOWS.json',windows)
 source_to_case={f['source_path']:c['id'] for c in cases for f in c['source_files']}
 ledger=[]
 for r in catalogue['rows']:
  x={k:r[k] for k in ['source_path','source_sha256','git_blob_sha1','fork_rpc_alias']}
  if r['source_path'] in source_to_case:x.update(disposition='NEW_EXTENSION_NOMINATION',case_id=source_to_case[r['source_path']])
  elif r['disposition']=='PHASE28_NOMINATED':x.update(disposition='ORIGINAL_EXTENSION_NOMINATION',case_id=r['phase28_id'])
  elif r['disposition']=='INITIAL_FOUR_FAMILY_SOURCE':x.update(disposition='PRIMARY_STUDY_SOURCE',case_id=r['family'])
  else:assert r['fork_rpc_alias']!='mainnet';x.update(disposition='OTHER_CHAIN_EXCLUDED',case_id=None)
  ledger.append(x)
 counts={k:sum(x['disposition']==k for x in ledger) for k in ['PRIMARY_STUDY_SOURCE','ORIGINAL_EXTENSION_NOMINATION','NEW_EXTENSION_NOMINATION','OTHER_CHAIN_EXCLUDED']}
 assert list(counts.values())==[4,16,8,39]
 write(BASE/'CATALOGUE_COVERAGE.json',{'schema':'phase32_catalogue_coverage_v1','catalogue_files':67,'ethereum_files':28,'extension_source_files':24,'extension_unique_windows':23,'extension_unique_core_addresses':22,'counts':counts,'rows':ledger,'original_catalogue_sha256':sha(PAPER/'phase31/cohort_audit/CATALOGUE_DISPOSITION.json'),'new_frame_sha256':sha(BASE/'CANDIDATE_FRAME.json')})
 print('FROZEN: 8 formerly omitted source files, 7 new windows, 6 new cores; all 28 Ethereum files accounted for')
if __name__=='__main__':main()
