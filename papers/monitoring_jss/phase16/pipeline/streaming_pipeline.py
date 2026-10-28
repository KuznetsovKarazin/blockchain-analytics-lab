"""Arrow-projected fixed-core preparation; no labels or detector scoring.
Full log identity/address and transaction metadata columns are validated. Only
selected payload rows become Python dictionaries. Independent audit is required.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
PAPER = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PAPER / 'phase15' / 'adapter'))
sys.path.insert(0, str(PAPER / 'phase15' / 'driver'))
from retained_observation_core import normalize_log, observe, validate_transaction, LOG_FIELDS, TX_FIELDS
import fixed_address_replay as driver
DAY_NS = 86_400_000_000_000
LOG_ID_COLUMNS = ['address','transaction_index','log_index','transaction_hash','block_number','block_hash','block_timestamp']
LOG_COLUMNS = ['address','topics','data','transaction_index','log_index','transaction_hash','block_number','block_hash','block_timestamp']
TX_COLUMNS = ['hash','transaction_index','block_hash','block_number','block_timestamp','receipt_status']
BLOCK_COLUMNS = ['number','hash','parent_hash','timestamp','transaction_count']
DEPENDENCIES = {
 'phase15/adapter/retained_observation_core.py':'63119a14c1f3fb5a2cf74f24f918181679611633e6e75df63b5dc6b7180ef662',
 'transfer_observation.py':'eb905fdbdc44033424066e4baebbbc1f6724bd68bd9e0573676f39e4908f429c',
 'phase15/driver/fixed_address_replay.py':'591a8e09cd1920496ad0acc8fb13a1f4c62a0a224b3d8925ec364fff91ed293d'}
def need(v,m):
 if not v: raise ValueError(m)
def canonical(v): return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def digest(v): return hashlib.sha256(canonical(v)).hexdigest()
def file_sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def put(p,v):
 Path(p).write_bytes(canonical(v)+b'\n');return file_sha(p)
def check_dependencies():
 for p,h in DEPENDENCIES.items():need(file_sha(PAPER/p)==h,'frozen dependency changed: '+p)
def day_start(d):
 need(type(d)is str and date.fromisoformat(d).isoformat()==d,'invalid UTC day')
 return (date.fromisoformat(d)-date(1970,1,1)).days*DAY_NS
def days_between(a,b):return [(date.fromisoformat(a)+timedelta(days=i)).isoformat() for i in range((date.fromisoformat(b)-date.fromisoformat(a)).days)]
def array_ok(a,pc):return a.null_count==0 and (len(a)==0 or pc.all(a).as_py() is True)
def normalize_table(t,kind,pa,pc):
 cols={'logs':LOG_ID_COLUMNS,'transactions':TX_COLUMNS,'blocks':BLOCK_COLUMNS}[kind]
 need(set(cols)<=set(t.column_names),'missing source projection')
 rename={'blocks':{'number':'block_number','hash':'block_hash','timestamp':'event_time_ns'},'transactions':{'hash':'transaction_hash','block_timestamp':'event_time_ns','receipt_status':'dataset_execution_status'},'logs':{'block_timestamp':'event_time_ns'}}[kind]
 out={}
 for k in cols:
  a=t[k];dest=rename.get(k,k);need(a.null_count==0,'null required source column: '+k)
  if dest=='event_time_ns':
   need(pa.types.is_timestamp(a.type) and a.type.unit in ('s','ms','us','ns') and a.type.tz in (None,'UTC'),'invalid timestamp type')
   a=pc.cast(pc.cast(a,pa.timestamp('ns',tz=a.type.tz)),pa.int64())
  elif dest in ('block_number','transaction_index','log_index','transaction_count','dataset_execution_status'):
   need(pa.types.is_int64(a.type),'invalid integer type: '+k);need(array_ok(pc.greater_equal(a,0),pc),'negative integer: '+k)
  else:
   need(pa.types.is_string(a.type),'invalid identity type: '+k);n=40 if dest=='address' else 64
   need(array_ok(pc.match_substring_regex(a,'^0x[0-9a-fA-F]{'+str(n)+'}$'),pc),'malformed identity: '+k);a=pc.utf8_lower(a)
  out[dest]=a
 return pa.table(out)
def check_headers(t,d,pa,pc,np):
 h=normalize_table(t,'blocks',pa,pc);h=h.take(pc.sort_indices(h,sort_keys=[('block_number','ascending')]))
 need(len(h)>0,'missing daily headers');b=h['block_number'].to_numpy();ts=h['event_time_ns'].to_numpy()
 need(bool(np.all(np.diff(b)==1)) and bool(np.all(np.diff(ts)>0)),'header gap/timestamp order')
 need(pc.count_distinct(h['block_hash']).as_py()==len(h),'duplicate header hash')
 need(int(ts[0])>=day_start(d) and int(ts[-1])<day_start(d)+DAY_NS,'header outside UTC day')
 need(array_ok(pc.equal(h['parent_hash'].slice(1),h['block_hash'].slice(0,len(h)-1)),pc),'broken header parent link')
 return h
def check_header_pair(l,r):need(r['block_number']==l['block_number']+1 and r['parent_hash']==l['block_hash'] and r['event_time_ns']>l['event_time_ns'],'cross-day header link')
def check_transactions(t,h,d,pa,pc,np):
 tx=normalize_table(t,'transactions',pa,pc)
 need(array_ok(pc.is_in(tx['dataset_execution_status'],value_set=pa.array([0,1],type=pa.int64())),pc),'unknown transaction status')
 need(pc.count_distinct(tx['transaction_hash']).as_py()==len(tx),'duplicate transaction hash')
 pos=pc.index_in(tx['block_number'],value_set=h['block_number']);need(pos.null_count==0,'transaction header missing')
 for k in ('block_hash','event_time_ns'):need(array_ok(pc.equal(tx[k],pc.take(h[k],pos)),pc),'transaction/header mismatch')
 need(array_ok(pc.less(tx['transaction_index'],pc.take(h['transaction_count'],pos)),pc),'transaction index outside header')
 b=tx['block_number'].to_numpy();ix=tx['transaction_index'].to_numpy();order=np.lexsort((ix,b))
 if len(order)>1:need(not bool(np.any((b[order[1:]]==b[order[:-1]])&(ix[order[1:]]==ix[order[:-1]]))),'duplicate transaction position')
 counts=np.bincount(pos.to_numpy(),minlength=len(h));need(bool(np.array_equal(counts,h['transaction_count'].to_numpy())),'transaction/header counts differ')
 return tx
def check_log_identities(t,h,tx,d,pa,pc,np):
 logs=normalize_table(t,'logs',pa,pc);pos=pc.index_in(logs['transaction_hash'],value_set=tx['transaction_hash']);need(pos.null_count==0,'log transaction missing')
 for k in ('block_number','transaction_index','block_hash','event_time_ns'):need(array_ok(pc.equal(logs[k],pc.take(tx[k],pos)),pc),'log/transaction mismatch')
 need(array_ok(pc.equal(pc.take(tx['dataset_execution_status'],pos),1),pc),'failed transaction with logs')
 b,t,li=(logs[k].to_numpy() for k in ('block_number','transaction_index','log_index'));order=np.lexsort((li,t,b))
 if len(order)>1:
  prev,curr=order[:-1],order[1:];sb=b[curr]==b[prev];st=sb&(t[curr]==t[prev])
  need(bool(np.all(li[curr][sb]>li[prev][sb])),'duplicate/reversed block log position')
  need(bool(np.all(li[curr][st]==li[prev][st]+1)),'gapped source transaction logs')
 return logs
def projection(readers,cols,pa):
 tables,groups=[],[]
 for r in readers:
  count=0
  if r.metadata.num_row_groups==0:
   need(r.metadata.num_rows==0,'zero groups with nonzero rows');tables.append(pa.Table.from_batches([],schema=pa.schema([r.schema.field(k) for k in cols])))
  for rg,t in r.iter_row_groups(cols):
   need(len(t)==r.metadata.row_group(rg).num_rows,'row-group decoded count differs');tables.append(t);count+=len(t)
   groups.append({'source_key':r.source['key'],'row_group':rg,'rows':len(t),'columns':list(cols)})
  need(count==r.metadata.num_rows,'full projection row count differs')
 need(tables,'missing projection');return pa.concat_tables(tables),groups
def selected_payload(readers,col,values,pa,pc,max_rows=None):
 rows,groups=[],[];vs=pa.array(sorted(values),type=pa.string())
 for r in readers:
  for rg,scan in r.iter_row_groups([col]):
   need(scan[col].null_count==0,'null predicate scan');mask=pc.is_in(pc.utf8_lower(scan[col]),value_set=vs);n=pc.sum(pc.cast(mask,pa.int64())).as_py() or 0
   groups.append({'source_key':r.source['key'],'row_group':rg,'rows_scanned':len(scan),'matched_rows':n,'predicate':col})
   if n:
    need(max_rows is None or len(rows)+n<=max_rows,'selected payload row cap before materialization')
    full=r.read_row_group(rg,LOG_COLUMNS);need(len(full)==len(scan),'payload/scan row counts differ')
    need(array_ok(pc.equal(pc.utf8_lower(full[col]),pc.utf8_lower(scan[col])),pc),'payload/scan predicate differs')
    ids=normalize_table(full,'logs',pa,pc).filter(mask).to_pylist();raw=full.select(['topics','data']).filter(mask).to_pylist()
    for identity,payload in zip(ids,raw):rows.append(normalize_log({**identity,**payload},identity['event_time_ns']))
 rows.sort(key=lambda x:(x['block_number'],x['transaction_index'],x['log_index']));return rows,groups
def selected_records(core,addresses):
 groups=defaultdict(list)
 for row in core:
  if row['address'] in addresses:groups[row['transaction_hash']].append(row)
 selected=[]
 for rows in groups.values():selected.append({'chain_id':1,**{k:rows[0][k] for k in TX_FIELDS if k!='chain_id'},'archived_core_log_count':len(rows),'archived_core_payload_sha256':digest(rows)})
 return sorted(selected,key=lambda x:(x['block_number'],x['transaction_index']))
def prepare_day(day,readers,headers,predecessor,successor,configs,output,pa,pc,np,limits):
 need(not output.exists(),'day output already exists');output.mkdir(parents=True)
 check_header_pair(predecessor,headers.slice(0,1).to_pylist()[0]);check_header_pair(headers.slice(len(headers)-1,1).to_pylist()[0],successor)
 need(predecessor['event_time_ns']<day_start(day) and successor['event_time_ns']>=day_start(day)+DAY_NS,'wrong UTC boundary anchors')
 need(sum(r.metadata.num_rows for r in readers['transactions'])<=limits['max_transaction_rows_per_day'],'transaction metadata row cap')
 need(sum(r.metadata.num_rows for r in readers['logs'])<=limits['max_log_rows_per_day'],'log metadata row cap')
 raw,txgroups=projection(readers['transactions'],TX_COLUMNS,pa);need(len(raw)<=limits['max_transaction_rows_per_day'],'transaction row cap')
 tx=check_transactions(raw,headers,day,pa,pc,np);del raw
 raw,loggroups=projection(readers['logs'],LOG_ID_COLUMNS,pa);need(len(raw)<=limits['max_log_rows_per_day'],'log row cap')
 logs=check_log_identities(raw,headers,tx,day,pa,pc,np);del raw
 addresses=sorted({a for cfg in configs.values() for a in cfg['population_addresses']})
 cores,coregroups=selected_payload(readers['logs'],'address',addresses,pa,pc,limits['max_selected_logs_per_day'])
 expected=logs.filter(pc.is_in(logs['address'],value_set=pa.array(addresses)));keys=list(logs.column_names)
 expected_ids=sorted(expected.to_pylist(),key=lambda x:(x['block_number'],x['transaction_index'],x['log_index']))
 need(canonical([{k:r[k] for k in keys} for r in cores])==canonical(expected_ids),'full address scan/core payload membership differs')
 choices={case:selected_records(cores,cfg['population_addresses']) for case,cfg in configs.items()}
 need(all(len(rows)<=limits['max_selected_transactions_per_case_day'] for rows in choices.values()),'selected transaction cap')
 seal={'schema_version':'phase16_core_selection_day_v1','day_utc':day,'rule':'at_least_one_core_emitter_log_no_topic_filter','cases':choices,'core_payload_sha256':digest(cores),'sealed_before_expansion_or_transfer_decode':True}
 seal_sha=put(output/'core_selection.json',seal)
 selected_hashes={r['transaction_hash'] for rows in choices.values() for r in rows};vs=pa.array(sorted(selected_hashes),type=pa.string())
 expanded,expandgroups=selected_payload(readers['logs'],'transaction_hash',selected_hashes,pa,pc,limits['max_selected_logs_per_day'])
 need(len(expanded)<=limits['max_selected_logs_per_day'],'selected log cap')
 expected=logs.filter(pc.is_in(logs['transaction_hash'],value_set=vs))
 expected_ids=sorted(expected.to_pylist(),key=lambda x:(x['block_number'],x['transaction_index'],x['log_index']))
 need(canonical([{k:r[k] for k in keys} for r in expanded])==canonical(expected_ids),'full hash scan/expanded membership differs')
 chosen=tx.filter(pc.is_in(tx['transaction_hash'],value_set=vs)).to_pylist();txmap={r['transaction_hash']:{'chain_id':1,**r} for r in chosen}
 hmap={r['block_number']:r for r in headers.to_pylist()};logmap=defaultdict(list)
 for row in expanded:logmap[row['transaction_hash']].append(row)
 cases={}
 for case,cfg in configs.items():
  bundles=[]
  for member in choices[case]:
   group=logmap[member['transaction_hash']];core=[r for r in group if r['address'] in cfg['population_addresses']]
   identity=validate_transaction(member,txmap[member['transaction_hash']],group,hmap[member['block_number']],core,cfg['population_addresses'])
   bundles.append({'transaction':identity,'dataset_execution_status':1,'archived_core_log_count':len(core),'logs':group})
  cases[case]={'population_addresses':cfg['population_addresses'],'selected_transactions':choices[case],'bundles':bundles}
 scan={'schema_version':'phase16_full_projection_scan_v1','day_utc':day,'all_log_identity_rows':len(logs),'all_transaction_rows':len(tx),'log_identity_row_groups':loggroups,'transaction_row_groups':txgroups,'all_address_row_groups':coregroups,'all_log_hash_row_groups':expandgroups,'full_log_identity_and_transaction_consistency_checked':True,'nonselected_topics_and_data_validated':False,'scope':'All source identity/address/hash rows scanned; topics/data validated only for selected transaction logs. Not the Phase15 full normalized-row interface.'}
 scan_sha=put(output/'scan.json',scan);header_sha=put(output/'headers.json',{'day_utc':day,'headers':headers.to_pylist(),'predecessor':predecessor,'successor':successor})
 source_manifest={'day_utc':day,'prepared_cases_sha256':digest(cases),'tables':{name:[r.manifest() for r in rs] for name,rs in readers.items()}};source_sha=put(output/'source_parts.json',source_manifest)
 prepared={'schema_version':'phase16_prepared_day_v1','status':'PRODUCER_CHECKED_AWAITING_INDEPENDENT_SOURCE_AUDIT','day_utc':day,'core_selection_file_sha256':seal_sha,'address_scan_manifest_sha256':scan_sha,'header_chain_sha256':header_sha,'partition_manifest_sha256':source_sha,'cases':cases,'transfer_decoding_performed':False,'labels_used':False}
 put(output/'prepared.json',prepared);need(file_sha(output/'core_selection.json')==seal_sha,'core selection changed during expansion');return prepared

def selection_for_case(config,config_sha,prepared):
 need([x['day_utc'] for x in prepared]==driver.expected_days(config),'missing or unordered case preparation days')
 return {'schema_version':'fixed_address_transaction_selection_v1','status':'SEALED_BEFORE_SCORING','config_sha256':config_sha,'rule':'at_least_one_core_emitter_log_no_topic_filter','days':[{'day_utc':x['day_utc'],'transactions':x['cases'][config['case_id']]['selected_transactions']} for x in prepared]}

def assemble_case(config_path,config,prepared_paths,audit_path,expected_audit_sha256,output):
 check_dependencies();driver.validate_config(config);need(not output.exists(),'case output already exists')
 config_sha=file_sha(config_path);prepared=[json.loads(Path(p).read_bytes()) for p in prepared_paths]
 selection=selection_for_case(config,config_sha,prepared);raw=canonical(selection)+b'\n';selection_sha=hashlib.sha256(raw).hexdigest()
 need(file_sha(audit_path)==expected_audit_sha256,'independent audit digest differs');audit=json.loads(Path(audit_path).read_bytes())
 need(audit['schema_version']=='fixed_address_source_audit_v1' and audit['status']=='PASS' and audit['config_sha256']==config_sha and audit['selection_manifest_sha256']==selection_sha,'audit does not bind config/selection')
 need(audit['cross_day_header_links_checked'] is True and audit['endpoint_anchors_checked'] is True,'header audit missing')
 need([x['day_utc'] for x in audit['days']]==driver.expected_days(config),'incomplete audit days')
 for path,prep,checked in zip(prepared_paths,prepared,audit['days']):
  folder=Path(path).parent
  for name,key in (('source_parts.json','partition_manifest_sha256'),('headers.json','header_chain_sha256'),('scan.json','address_scan_manifest_sha256')):
   need(file_sha(folder/name)==prep[key],'audited preparation sidecar changed')
  parts=json.loads((folder/'source_parts.json').read_bytes())
  need(parts['prepared_cases_sha256']==digest(prep['cases']),'audited prepared bundles changed')
  need(file_sha(folder/'core_selection.json')==prep['core_selection_file_sha256'],'core selection seal changed')
  for k in driver.COVERAGE_HASHES:need(prep[k]==checked[k],'audit/preparation source differs')
  need(checked['status']=='COVERED' and all(checked[k] is True for k in driver.COVERAGE_CHECKS),'audit coverage incomplete')
 output.mkdir(parents=True);(output/'selection.json').write_bytes(raw);(output/'source_audit.json').write_bytes(Path(audit_path).read_bytes())
 manifest={'schema_version':'fixed_address_observation_manifest_v1','status':'COMPLETE','config_sha256':config_sha,**{k:config[k] for k in ('case_id','chain_id','population_addresses','source_scope','source_tier')},'selection':{'path':'selection.json','sha256':selection_sha},'source_audit':{'path':'source_audit.json','sha256':expected_audit_sha256},'days':[]}
 for prep in prepared:
  case=prep['cases'][config['case_id']];need(case['population_addresses']==config['population_addresses'],'prepared core differs')
  rows=[observe(x['transaction'],x['logs'],config['population_addresses'],x['archived_core_log_count'],expected_audit_sha256,selection_sha,dataset_execution_status=x['dataset_execution_status']) for x in case['bundles']]
  dest=output/(prep['day_utc']+'.jsonl');dest.write_bytes(b''.join(canonical(x)+b'\n' for x in rows))
  manifest['days'].append({'day_utc':prep['day_utc'],'coverage_status':'COVERED','observation_file':{'path':dest.name,'sha256':file_sha(dest)},'bytes':dest.stat().st_size,'transaction_count':len(rows),'core_log_count':sum(x['archived_core_log_count'] for x in rows),'observation_sha256':[digest(x) for x in rows]})
 sha=put(output/'manifest.json',manifest);driver.load_inputs(config,output/'manifest.json',expected_manifest_sha256=sha,expected_config_sha256=config_sha)
 return {'status':'COMPLETE_OBSERVATIONS_NOT_SCORED','manifest_sha256':sha,'case_id':config['case_id']}
def read_binding(binding,repo):
 need(type(binding)is dict and set(binding)=={'path','sha256'},'invalid file binding')
 p=Path(binding['path']);need(not p.is_absolute() and '..' not in p.parts,'binding must be repository-relative')
 p=repo/p;need(file_sha(p)==binding['sha256'],'bound file changed');return p,json.loads(p.read_bytes())
def validate_execution_gate(freeze,acceptance_dir,repo,expected_plan_sha):
 _,gate=read_binding(freeze['gate_bindings']['source_plan'],acceptance_dir)
 need(gate['schema_version']=='article2_phase16_bound_source_execution_gate_v1' and gate['status']=='ROOT_ACCEPTED_AS_PART_OF_DECLARED_MEASUREMENT','invalid execution gate')
 _,accepted_plan=read_binding(gate['source_plan'],acceptance_dir)
 need(gate['source_plan']['sha256']==expected_plan_sha,'acceptance source plan differs')
 read_binding(gate['measurement_protocol'],acceptance_dir)
 bindings=gate['execution_source_bindings'];need(bindings and len({x['path'] for x in bindings})==len(bindings),'missing/duplicate execution bindings')
 for bind in bindings:
  need(type(bind)is dict and set(bind)=={'path','sha256'},'invalid execution binding')
  p=Path(bind['path']);need(not p.is_absolute() and '..' not in p.parts,'execution path must be repository-relative')
  need(file_sha(repo/p)==bind['sha256'],'execution source changed after acceptance: '+str(p))
 required={str(Path(__file__).resolve().relative_to(repo.resolve())),str((PAPER/'phase16'/'collector'/'range_collector.py').relative_to(repo.resolve()))}
 need(required<=set(x['path'] for x in bindings),'pipeline/collector execution binding absent')
 return accepted_plan
def validate_reuse(reuse,expectations,sources,repo):
 need(type(reuse)is dict and type(expectations)is dict,'invalid reuse mapping')
 known={s['key']:s for s in sources};need(set(reuse)<=set(expectations)<=set(known),'reuse lacks frozen source expectation')
 for key,expected in expectations.items():
  need(set(expected)=={'sha256','size_bytes','etag_opaque','acquisition_receipt'},'invalid frozen reuse expectation')
  need(type(expected['sha256'])is str and len(expected['sha256'])==64 and all(x in '0123456789abcdef' for x in expected['sha256']),'invalid frozen reuse digest')
  need(all(expected[k]==known[key][k] for k in ('size_bytes','etag_opaque')),'frozen reuse identity differs from source inventory')
  _,receipt=read_binding(expected['acquisition_receipt'],repo)
  need(receipt['source_key']==key and all(receipt[k]==expected[k] for k in ('sha256','size_bytes','etag_opaque')),'acquisition receipt differs from frozen reuse expectation')
  if key in reuse:
   value=reuse[key];need(set(value)=={'path','sha256','source_key','size_bytes','etag_opaque'},'runtime reuse fields differ')
   need(value['source_key']==key and all(value[k]==expected[k] for k in ('sha256','size_bytes','etag_opaque')),'runtime reuse differs from frozen expectation')
 return reuse
def validate_reuse_expectations_binding(expectations,retained,repo):
 need(retained['schema_version']=='phase16_retained_original_source_reuse_expectations_v1','wrong retained reuse schema')
 rows=retained['objects'];known={x['source_key']:x for x in rows}
 need(len(known)==len(rows) and set(expectations)<=set(known),'reuse source differs from retained expectations')
 for key,value in expectations.items():
  original=known[key]
  need(value['sha256']==original['expected_whole_object_sha256'] and all(value[k]==original[k] for k in ('size_bytes','etag_opaque')),'reuse whole-object expectation changed')
  _,receipt=read_binding(value['acquisition_receipt'],repo)
  need(all(receipt[k]==original[k] for k in ('expected_archive_sha256','expected_original_member_name')),'reuse archive/member expectation changed')
def collect(args):
 check_dependencies();need(file_sha(args.plan)==args.expected_plan_sha256,'plan freeze differs');plan=json.loads(args.plan.read_bytes())
 need(plan['schema_version']=='article2_phase16_streaming_pipeline_plan_v1','wrong pipeline plan')
 need(plan['pipeline_sha256']==file_sha(__file__),'pipeline code changed after freeze')
 collector_path=PAPER/'phase16'/'collector'/'range_collector.py';need(plan['collector_sha256']==file_sha(collector_path),'collector code changed after freeze')
 need(file_sha(args.wheel)==plan['pyarrow_wheel_sha256'],'dependency wheel changed')
 sys.path.insert(0,str(args.dependencies.resolve()));import pyarrow as pa;import pyarrow.compute as pc;import pyarrow.parquet as pq;import numpy as np
 need(np.__version__==plan['numpy_version']=='2.3.5','NumPy runtime differs')
 need(pa.__version__==plan['pyarrow_version']=='26.0.0' and Path(pa.__file__).resolve().is_relative_to(args.dependencies.resolve()),'parser version/origin differs')
 sys.path.insert(0,str(collector_path.parent));from range_collector import RangeSession,SourceReader
 _,inventory=read_binding(plan['source_union'],args.repo)
 _,anchor_evidence=read_binding(plan['header_anchor_evidence_binding'],args.repo)
 anchored={x['block_number']:x['block_hash'] for x in anchor_evidence['checkpoint_observations']}
 need({x['block_number'] for x in plan['accepted_header_anchors']}=={14233162,14426367},'retained LiFi anchor population differs')
 need(all(anchored.get(x['block_number'])==x['block_hash'] for x in plan['accepted_header_anchors']),'anchor differs from retained independent evidence')
 need(plan['inventory_binding']==plan['source_union'],'inventory bindings differ')
 _,retained_reuse=read_binding(plan['reuse_expectations_binding'],args.repo)
 validate_reuse_expectations_binding(plan.get('whole_object_reuse_expectations',{}),retained_reuse,args.repo)
 configs,config_paths,config_shas={},{},{}
 acceptances=json.loads(args.acceptances.read_bytes())
 for bind in plan['case_configs']:
  path,cfg=read_binding(bind,args.repo);driver.validate_config(cfg);case=cfg['case_id'];need(case not in configs,'duplicate case config')
  acceptance=acceptances[case];freeze=driver.validate_freeze(acceptance['path'],path,expected_freeze_sha256=acceptance['sha256'])
  validate_execution_gate(freeze,Path(acceptance['path']).parent,args.repo,args.expected_plan_sha256)
  configs[case]=cfg;config_paths[case]=path;config_shas[case]=bind['sha256']
 need(set(acceptances)==set(configs) and len(configs)==2,'acceptance case population differs')
 study=days_between(plan['study_start'],plan['study_end_exclusive']);need(len(study)==37,'study union must retain37days')
 need(set(study)==set(d for cfg in configs.values() for d in driver.expected_days(cfg)),'case window union differs')
 need(inventory['study_window_utc']==[plan['study_start']+'T00:00:00Z',plan['study_end_exclusive']+'T00:00:00Z'],'source union window differs')
 source_list=inventory['objects'];need(len(source_list)==113 and len({x['key'] for x in source_list})==113,'transport population differs')
 reuse=json.loads(args.reuse_map.read_bytes()) if args.reuse_map else {}
 validate_reuse(reuse,plan.get('whole_object_reuse_expectations',{}),source_list,args.repo)
 need(not args.output.exists(),'output already exists');args.output.mkdir(parents=True)
 put(args.output/'frozen_plan.json',plan);put(args.output/'runtime_acceptances.json',acceptances)
 session=RangeSession(plan['collector'],args.output/'transport');readers={};headers={};all_prepared=[];sourcepaths={}
 try:
  byday=defaultdict(lambda:defaultdict(list))
  for source in source_list:byday[source['day_utc']][source['table']].append(source)
  alldays=days_between((date.fromisoformat(study[0])-timedelta(days=1)).isoformat(),(date.fromisoformat(study[-1])+timedelta(days=2)).isoformat())
  need(sorted(byday)==alldays,'source day coverage differs')
  def open_reader(source):
   key=source['key']
   if key not in readers:
    r=SourceReader(source,session,args.output/'cache',pa,pq,reuse=reuse.get(key));r.open();readers[key]=r;sourcepaths[key]=str(r.path.resolve())
    put(args.output/'runtime_source_paths.json',sourcepaths)
   return readers[key]
  # Complete header timeline, including the two explicitly separate boundary days.
  for day in alldays:
   rs=[open_reader(s) for s in byday[day]['blocks']];raw,_=projection(rs,BLOCK_COLUMNS,pa);headers[day]=check_headers(raw,day,pa,pc,np)
  for left,right in zip(alldays,alldays[1:]):check_header_pair(headers[left].slice(len(headers[left])-1,1).to_pylist()[0],headers[right].slice(0,1).to_pylist()[0])
  for anchor in plan['accepted_header_anchors']:
   matches=[]
   for h in headers.values():matches.extend(h.filter(pc.equal(h['block_number'],anchor['block_number'])).to_pylist())
   need(len(matches)==1 and all(matches[0][k]==v for k,v in anchor.items()),'retained independent header anchor differs')
  put(args.output/'header_timeline.json',{'days':[{'day_utc':d,'first':headers[d].slice(0,1).to_pylist()[0],'last':headers[d].slice(len(headers[d])-1,1).to_pylist()[0],'count':len(headers[d]),'canonical_headers_sha256':digest(headers[d].to_pylist())} for d in alldays],'accepted_header_anchors':plan['accepted_header_anchors']})
  for day in study:
   active={k:v for k,v in configs.items() if day in driver.expected_days(v)}
   need(set(byday[day])=={'blocks','logs','transactions'},'missing source table')
   rs={table:[open_reader(s) for s in byday[day][table]] for table in ('blocks','logs','transactions')}
   previous=(date.fromisoformat(day)-timedelta(days=1)).isoformat();following=(date.fromisoformat(day)+timedelta(days=1)).isoformat()
   prepared=prepare_day(day,rs,headers[day],headers[previous].slice(len(headers[previous])-1,1).to_pylist()[0],headers[following].slice(0,1).to_pylist()[0],active,args.output/'days'/day,pa,pc,np,plan['limits']);all_prepared.append(prepared)
   put(args.output/'progress.json',{'status':'IN_PROGRESS_NO_SCORING','completed_days':[x['day_utc'] for x in all_prepared],'last_completed_day':day})
   print(json.dumps({'completed_day':day,'cases':{k:len(v['selected_transactions']) for k,v in prepared['cases'].items()} }),flush=True)
  selections={}
  for case,cfg in configs.items():
   chosen=[p for p in all_prepared if p['day_utc'] in driver.expected_days(cfg)];folder=args.output/'cases'/case;folder.mkdir(parents=True)
   selected=selection_for_case(cfg,config_shas[case],chosen);sha=put(folder/'selection.json',selected)
   selections[case]={'path':str((folder/'selection.json').relative_to(args.output)),'sha256':sha,'config_sha256':config_shas[case],'days':30,'transactions':sum(len(x['transactions']) for x in selected['days'])}
  put(args.output/'transport_sources.json',{'sources':[r.manifest() for r in readers.values()]})
  session.close('COMPLETE')
  for bind in plan['case_configs']:read_binding(bind,args.repo)
  need(file_sha(args.plan)==args.expected_plan_sha256,'plan changed during collection')
  result={'schema_version':'phase16_collection_result_v1','status':'COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT','plan_sha256':args.expected_plan_sha256,'study_days':37,'transport_sources':len(readers),'selection_manifests':selections,'prepared_days':[{'path':str((args.output/'days'/d/'prepared.json').relative_to(args.output)),'sha256':file_sha(args.output/'days'/d/'prepared.json')} for d in study],'transfer_decoding_performed':False,'detector_scoring_performed':False,'labels_used':False,'pyarrow_version':pa.__version__,'numpy_version':np.__version__}
  put(args.output/'collection_result.json',result);print(json.dumps({'status':result['status'],'cases':selections}),flush=True);return result
 except Exception as exc:
  session.close('FAILED')
  put(args.output/'failure.json',{'status':'FAILED_NOT_ACCEPTED','error_type':type(exc).__name__,'error':str(exc),'completed_days':[x['day_utc'] for x in all_prepared],'transfer_decoding_performed':False,'detector_scoring_performed':False})
  raise

def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__);subs=parser.add_subparsers(dest='command',required=True)
 collectp=subs.add_parser('collect')
 for k in ('plan','repo','dependencies','wheel','acceptances','output'):collectp.add_argument('--'+k,type=Path,required=True)
 collectp.add_argument('--expected-plan-sha256',required=True);collectp.add_argument('--reuse-map',type=Path)
 assemblep=subs.add_parser('assemble')
 for k in ('config','collection','audit','output'):assemblep.add_argument('--'+k,type=Path,required=True)
 assemblep.add_argument('--expected-audit-sha256',required=True)
 args=parser.parse_args(argv)
 if args.command=='collect':return collect(args)
 cfg=json.loads(args.config.read_bytes());paths=[args.collection/'days'/d/'prepared.json' for d in driver.expected_days(cfg)]
 result=assemble_case(args.config,cfg,paths,args.audit,args.expected_audit_sha256,args.output);print(json.dumps(result));return result
if __name__=='__main__':main()
