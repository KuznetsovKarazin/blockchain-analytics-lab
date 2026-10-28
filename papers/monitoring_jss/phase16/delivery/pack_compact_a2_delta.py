"""Candidate compact A2 delta preservation. No live-A2 reads or upload in tests.

Only new successful response blobs and small artifacts are archived. Parent
ranges and original whole objects remain explicit hash-bound dependencies.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

PAPER = Path(__file__).resolve().parents[2]
REPO = PAPER.parents[1]
HELPER = Path(__file__).with_name('pack_closed_a1_forensics.py')
HELPER_SHA256 = '16d2c759ba7876f2d6357c279c85941f5bb52d40f9b2d8cec5b2dbffc82ddbd3'
if hashlib.sha256(HELPER.read_bytes()).hexdigest() != HELPER_SHA256:
    raise ValueError('forensic ZIP helper changed')
_spec = importlib.util.spec_from_file_location('phase16_verified_forensic_zip_helpers', HELPER)
z = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(z)
need, canonical, file_sha, snapshot = z.need, z.canonical, z.file_sha, z.snapshot
MAX_PACK = z.MAX_PACK
RUNTIME_ROOT = Path('/tmp/article2_phase16_runtime_159bf77d8682')
SOURCE_FIELDS = ('table', 'day_utc', 'key', 'size_bytes', 'etag_opaque', 'url')


def digest(value): return hashlib.sha256(canonical(value)).hexdigest()
def read(path): return json.loads(Path(path).read_bytes())
def bound(binding, parent=None):
    need(set(binding) == {'path','sha256'}, 'binding fields differ')
    p = Path(binding['path'])
    if not p.is_absolute():
        need(parent is not None, 'relative binding without base'); p = Path(parent) / p
    need(p.is_file() and file_sha(p) == binding['sha256'], 'bound file digest differs')
    return p

def relative(root, value):
    safe = z.safe_member(value); p = Path(root).joinpath(*safe.parts)
    need(p.resolve().is_relative_to(Path(root).resolve()), 'path escapes capture')
    return p

def identity(source):
    need(set(source) == set(SOURCE_FIELDS), 'source identity fields differ')
    return {key: source[key] for key in SOURCE_FIELDS}


def retain_expected(expected, path, sha256, *, verify=True):
    """Keep the authoritative digest, never replace it with a later file hash."""
    path = Path(path).resolve(); key = str(path)
    need(type(sha256) is str and len(sha256) == 64
         and all(c in '0123456789abcdef' for c in sha256), 'invalid artifact digest')
    need(key not in expected or expected[key] == sha256, 'conflicting artifact bindings')
    if verify: need(path.is_file() and file_sha(path) == sha256, 'bound artifact missing or changed')
    expected[key] = sha256
    return path


def require_frozen_reuse_digest(sources, original_plan):
    need(sources['reuse_expectations']['sha256'] == original_plan['reuse_expectations_binding']['sha256'],
         'reuse member map differs from frozen original plan')


def dependencies(a1_index, catalog, upload_receipt, original_archives, reuse_expectations, original_plan):
    """Normalize already supplied durable metadata without opening source bodies."""
    need(a1_index['status'] == 'COMPLETE_FORENSIC_PRESERVATION_NOT_SOURCE_AUDIT', 'A1 preservation incomplete')
    need(catalog['schema_version'] == 'article2_phase16_durable_a1_forensic_catalog_v1'
         and catalog['status'] == 'ALL_43_LIBRARY_SAVES_CONFIRMED', 'A1 durable catalog incomplete')
    entries = catalog['entries']; uploads = upload_receipt['results']
    need(len(entries) == len(uploads) == 43, 'A1 durable object count differs')
    by_name = {x['file_name']: x for x in entries}; saved = {x['file_name']: x for x in uploads}
    need(len(by_name) == len(saved) == 43 and set(by_name) == set(saved), 'A1 delivery names duplicate or differ')
    for name, item in by_name.items():
        need(saved[name]['status'] == 'succeeded' and saved[name]['library_file_id'] == item['library_file_id']
             and saved[name]['file_id'] == item['file_id'] and item['library_file_id'], 'A1 Library confirmation differs')
    need(len(a1_index['packs']) == 42, 'A1 ZIP population differs')
    for pack in a1_index['packs']:
        item = by_name[pack['path']]
        need(item['sha256'] == pack['sha256'] and item['bytes'] == pack['bytes'], 'A1 durable ZIP identity differs')
    originals = {x['sha256']: x for x in original_archives}
    need(len(originals) == len(original_archives) == 9 and all(x['library_file_id'] for x in originals.values()), 'original archive provenance incomplete')
    whole = {}
    expected = original_plan['whole_object_reuse_expectations']
    rows = reuse_expectations['objects']; need(len(rows) == len(expected) == 18, 'whole original population differs')
    need({x['expected_archive_sha256'] for x in rows} == set(originals), 'whole original archive set differs')
    for row in rows:
        key = row['source_key']; assertion = expected[key]; archive = originals[row['expected_archive_sha256']]
        need(assertion['sha256'] == row['expected_whole_object_sha256']
             and assertion['size_bytes'] == row['size_bytes'] and assertion['etag_opaque'] == row['etag_opaque'], 'whole original binding differs')
        need(key not in whole, 'duplicate whole source')
        whole[key] = {'size_bytes':row['size_bytes'], 'etag_opaque':row['etag_opaque'], 'sha256':row['expected_whole_object_sha256'],
                      'archive_sha256':row['expected_archive_sha256'], 'archive_bytes':archive['bytes'],
                      'archive_library_file_id':archive['library_file_id'], 'member_name':row['expected_original_member_name']}
    return {'a1_durable_objects':[{k:x[k] for k in ('file_name','bytes','sha256','library_file_id','file_id')} for x in entries],
            'whole_object_origins':whole,
            'original_archive_objects':[{k:x[k] for k in ('sha256','bytes','library_file_id')} for x in original_archives]}


def make_dependencies(args):
    sources = {name:{'path':str(getattr(args,name).resolve()), 'sha256':file_sha(getattr(args,name))}
               for name in ('a1_index','catalog','upload_receipt','original_archives','reuse_expectations','original_plan')}
    values = {name:read(binding['path']) for name,binding in sources.items()}
    require_frozen_reuse_digest(sources, values['original_plan'])
    need(values['catalog']['forensic_index_sha256'] == sources['a1_index']['sha256'], 'durable catalog points to another A1 index')
    normalized = dependencies(**values)
    result = {'schema_version':'phase16_compact_a2_delta_dependencies_v1', 'status':'EXACT_EXISTING_DURABLE_DEPENDENCIES',
              'a1_index_sha256':sources['a1_index']['sha256'], 'raw_metadata_bindings':sources,
              'a1_catalog_library_file_id':args.catalog_library_file_id, **normalized,
              'body_bytes_read':0, 'new_uploads':0}
    need(not args.output.exists(), 'fresh dependency output required'); args.output.parent.mkdir(parents=True,exist_ok=True)
    z.write_json(args.output,result); return result


def a1_members(index):
    result = {}
    for pack in index['packs']:
        for record in pack['members']:
            need(record['member'] not in result, 'duplicate A1 member')
            need(record['sha256_before'] == record['sha256_after'] == record['zip_roundtrip_sha256'], 'A1 member was not verified')
            result[record['member']] = (pack,record)
    return result


def recipe_catalog(session, inherited, new_requests, wrappers, descriptors, locations, a1_index, whole_origins):
    """Pure exact partition/interval/path checks; no source bodies are read."""
    count = session['inherited_request_count']; parent = session['parent_attempt_id']; current = session['attempt_id']
    need(count == len(inherited) and [r['ordinal'] for r in inherited] == list(range(1,count+1)), 'parent receipt population differs')
    need(all(r['transport_ok'] is True for r in inherited[:-1]) and inherited[-1]['transport_ok'] is False,
         'parent accepted/pending partition differs')
    need([r['ordinal'] for r in new_requests] == list(range(count+1,count+1+len(new_requests)))
         and len(new_requests) == session['new_request_count'] and all(r['transport_ok'] is True for r in new_requests), 'new receipt population differs')
    expected = {(parent,r['ordinal']):r for r in inherited[:-1]}
    expected.update({(current,r['ordinal']):r for r in new_requests})
    need(len(wrappers) == len(expected), 'accepted wrapper count differs')
    observed = {}; blobs = {}; by_source = defaultdict(list); source_values = {}
    for w in wrappers:
        origin = (w['origin_attempt_id'],w['origin_ordinal']); r = w['receipt']; blob = w['blob']
        need(origin in expected and origin not in observed and canonical(r) == canonical(expected[origin]), 'missing/duplicate/tampered accepted receipt')
        need(r['transport_ok'] is True and r['response_bytes'] == r['length'] and r['length'] > 0, 'unaccepted body')
        source = identity(r['source']); sid = digest(source); key = source['key']; bodysha = r['response_sha256']
        expected_path = f"storage/{sid}/blobs/{origin[0]}-{origin[1]:06d}-{bodysha}.bin"
        need(blob == {'path':expected_path,'size_bytes':r['length'],'sha256':bodysha}, 'blob origin/path/size/hash differs')
        need(expected_path not in blobs, 'duplicate physical blob')
        if origin[0] == current: need(r['blob'] == blob, 'new request blob differs')
        item = {'path':expected_path,'sha256':bodysha,'size_bytes':r['length'],'origin_ordinal':origin[1],
                'origin_attempt_id':origin[0],'source_key':key,'source_id':sid,'start':r['start'],
                'length':r['length'],'receipt_sha256':digest(r)}
        need(type(r['start']) is int and r['start'] >= 0 and r['start']+r['length'] <= source['size_bytes'], 'body interval outside source')
        observed[origin] = item; blobs[expected_path] = item; by_source[key].append(item); source_values[key] = source
    need(set(observed) == set(expected), 'accepted wrapper omitted')
    members = a1_members(a1_index); recipes = []; new_blobs = []
    for origin,item in sorted(observed.items(),key=lambda x:x[0][1]):
        if origin[0] == current: new_blobs.append(item); continue
        member = f"attempt1/cache/{item['source_id']}/source.parquet"; pack,record = members[member]
        need(record['source_identity'] == source_values[item['source_key']]
             and record['logical_bytes'] == record['source_identity']['size_bytes'], 'A1 cache identity differs')
        recipes.append({'target_path':item['path'], **{k:v for k,v in item.items() if k not in ('path','size_bytes')},
            'a1_member':member, 'a1_archive':{'path':pack['path'],'sha256':pack['sha256']},
            'a1_artifact_sha256':record['sha256_before'],'a1_artifact_logical_bytes':record['logical_bytes']})
    need(set(locations) == set(by_source) | set(whole_origins) and not set(by_source) & set(whole_origins), 'range/whole source partition differs')
    normalized_locations = {}
    for key,location in locations.items():
        need(set(location) == {'path','storage_kind'}, 'typed location fields differ')
        if key in whole_origins:
            need(location['storage_kind'] == 'verified_whole_object' and key not in descriptors, 'whole source descriptor unexpected')
            normalized_locations[key] = {'storage_kind':'verified_whole_object','original_path':location['path'],
                                         'whole_object_sha256':whole_origins[key]['sha256']}
            continue
        need(location['storage_kind'] == 'compact_descriptor' and key in descriptors, 'compact descriptor missing')
        descriptor = descriptors[key]; source = source_values[key]; sid = digest(source)
        need(descriptor['schema_version'] == 'article2_phase16_compact_source_v1'
             and descriptor['storage_kind'] == 'compact_descriptor' and descriptor['source'] == source
             and descriptor['source_id'] == sid and descriptor['logical_size_bytes'] == source['size_bytes']
             and descriptor['attempt_id'] == current and descriptor['parent_attempt_id'] == parent, 'descriptor identity differs')
        expected_segments=[];end=0
        for item in sorted(by_source[key],key=lambda x:x['start']):
            need(item['start'] >= end,'accepted source intervals overlap');end=item['start']+item['length']
            expected_segments.append({'start':item['start'],'length':item['length'],
                'blob_path':str(Path(item['path']).relative_to(Path('storage')/sid)),
                'blob_sha256':item['sha256'],'origin_attempt_id':item['origin_attempt_id'],
                'origin_ordinal':item['origin_ordinal'],'receipt_sha256':item['receipt_sha256']})
        need(descriptor['segments'] == expected_segments, 'descriptor missing/extra/tampered interval')
        normalized_locations[key]={'storage_kind':'compact_descriptor','original_path':location['path'],
                                   'descriptor_relative_path':f'storage/{sid}/source_storage.json'}
    return {'inherited_recipes':recipes,'new_blob_entries':new_blobs,'source_locations':normalized_locations,
            'all_blob_paths':set(blobs),'accepted_parent_body_bytes':sum(x['length'] for x in recipes),
            'new_body_bytes':sum(x['size_bytes'] for x in new_blobs),'parent_pending_ordinal':count}


def load_ready(root, proof_path, expected_proof_sha):
    """Read only sealed metadata until all acquisition/audit/final-snapshot gates pass."""
    need(file_sha(proof_path)==expected_proof_sha,'delivery proof digest differs');proof=read(proof_path)
    expected_artifacts={};retain_expected(expected_artifacts,proof_path,expected_proof_sha)
    need(proof['schema_version']=='phase16_compact_a2_delta_ready_inputs_v1','delivery proof schema')
    base=Path(proof_path).parent
    protocol_path=bound(proof['protocol_code'],base)
    retain_expected(expected_artifacts,protocol_path,proof['protocol_code']['sha256'])
    need(protocol_path.resolve()==(PAPER/'phase16/storage_recovery/protocol.py').resolve(),'only frozen storage protocol is allowed')
    spec=importlib.util.spec_from_file_location('phase16_delta_storage_gate',protocol_path);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    amendment=bound(proof['amendment'],base)
    retain_expected(expected_artifacts,amendment,proof['amendment']['sha256'])
    ctx=helper.validate_recovered_source_ready(amendment,proof['amendment']['sha256'],transport_audit=proof['transport_audit'],
        source_review=proof['source_review'],multiattempt_ledger=proof['multiattempt_ledger'],binding_parent=base)
    plan_path=retain_expected(expected_artifacts,ctx['plan_path'],ctx['plan_sha256'])
    need(Path(root).resolve()==Path(ctx['recovery_output_root']).resolve(),'collection differs from audited recovery root')
    paths={name:bound(proof[name],base) for name in ('transport_audit','source_review','multiattempt_ledger','assembly_result','dependencies','final_snapshot')}
    for name,path in paths.items():retain_expected(expected_artifacts,path,proof[name]['sha256'])
    transport,source=read(paths['transport_audit']),read(paths['source_review'])
    result=read(Path(root)/'collection_result.json');result_sha=file_sha(Path(root)/'collection_result.json')
    need(result_sha==transport['collection_result_sha256']==source['collection_result_sha256'],'audited collection bytes differ')
    retain_expected(expected_artifacts,Path(root)/'collection_result.json',transport['collection_result_sha256'])
    need(result['status']=='COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT'
         and result['plan_sha256']==ctx['plan_sha256'] and result['storage_recovery_amendment_sha256']==proof['amendment']['sha256'], 'collection lineage differs')
    need(not (Path(root)/'failure.json').exists(),'completed capture has failure artifact')
    session=read(Path(root)/'transport/session.json')
    need(session['status']=='COMPLETE' and file_sha(Path(root)/'transport/session.json')==transport['session_sha256'],'session not complete or changed')
    retain_expected(expected_artifacts,Path(root)/'transport/session.json',transport['session_sha256'])
    assembly=read(paths['assembly_result'])
    need(assembly['schema_version']=='phase16_storage_recovery_observation_assembly_v1'
         and assembly['status']=='COMPLETE_OBSERVATIONS_AWAITING_CURRENT_PRE_REPLAY_AUTHORIZATION'
         and assembly['collection_result_sha256']==result_sha
         and assembly['source_review_sha256']==proof['source_review']['sha256']
         and assembly['transport_audit_sha256']==proof['transport_audit']['sha256']
         and assembly['multiattempt_ledger_sha256']==proof['multiattempt_ledger']['sha256']
         and assembly['storage_recovery_amendment_sha256']==proof['amendment']['sha256'], 'observations not complete or audit lineage differs')
    cases={'lifi_20220320','revest_20220327'}
    need(set(assembly['input_manifests'])==cases,'both complete observation cases required')
    case_audit_paths=[]
    for binding in source['case_audits'].values():
        path=bound(binding,paths['source_review'].parent);case_audit_paths.append(path)
        retain_expected(expected_artifacts,path,binding['sha256'])
    for case,binding in assembly['input_manifests'].items():
        path=bound(binding,paths['assembly_result'].parent);need(path.resolve().is_relative_to(Path(root).resolve()),'input manifest outside capture')
        manifest=read(path);need(manifest['status']=='COMPLETE' and len(manifest['days'])==30
             and manifest['source_audit']['sha256']==source['case_audits'][case]['sha256'],'observation source binding differs')
        retain_expected(expected_artifacts,path,binding['sha256'])
        for name in ('selection','source_audit'):
            linked=bound(manifest[name],path.parent)
            retain_expected(expected_artifacts,linked,manifest[name]['sha256'])
        for day in manifest['days']:
            item=day['observation_file'];target=relative(path.parent,item['path'])
            need(target.is_file() and target.stat().st_size==day['bytes'] and day['coverage_status']=='COVERED','observation file missing/size differs')
            retain_expected(expected_artifacts,target,item['sha256'],verify=False)
    final=read(paths['final_snapshot'])
    need(final['schema_version']=='phase16_final_delivery_snapshot_v1' and final['status']=='CLOSED_FINAL_DELIVERY_SNAPSHOT'
         and final['all_scientific_processes_stopped'] is True and final['no_additional_A2_files_expected'] is True
         and set(final['case_ids'])==cases and final['artifact_bindings'],'final scientific snapshot is not explicitly closed')
    final_artifacts=[]
    for binding in final['artifact_bindings']:
        path=bound(binding,paths['final_snapshot'].parent);final_artifacts.append(path);retain_expected(expected_artifacts,path,binding['sha256'])
    deps=read(paths['dependencies']);need(deps['schema_version']=='phase16_compact_a2_delta_dependencies_v1'
         and deps['status']=='EXACT_EXISTING_DURABLE_DEPENDENCIES','durable dependencies absent')
    raw={name:bound(binding,paths['dependencies'].parent) for name,binding in deps['raw_metadata_bindings'].items()}
    for name,path in raw.items():retain_expected(expected_artifacts,path,deps['raw_metadata_bindings'][name]['sha256'])
    require_frozen_reuse_digest(deps['raw_metadata_bindings'],ctx['original_plan'])
    need(file_sha(raw['a1_index'])==deps['a1_index_sha256'],'A1 index dependency differs')
    recomputed=dependencies(**{name:read(path) for name,path in raw.items()})
    need(all(deps[k]==v for k,v in recomputed.items()),'normalized durable origins changed')
    need(read(raw['catalog'])['forensic_index_sha256']==deps['a1_index_sha256'],'catalog/index mismatch')
    need(canonical(read(raw['original_plan']))==canonical(ctx['original_plan']),'durable whole origins refer to another original plan')
    external=[Path(proof_path).resolve(),amendment,protocol_path,plan_path,*paths.values(),*raw.values(),*final_artifacts,*case_audit_paths]
    return {'proof':proof,'proof_sha256':expected_proof_sha,'context':ctx,'transport':transport,'source':source,
            'result':result,'session':session,'dependencies':deps,'a1_index':read(raw['a1_index']),
            'external':list(dict.fromkeys(p.resolve() for p in external)), 'expected_artifacts':expected_artifacts,
            'final_snapshot_sha256':proof['final_snapshot']['sha256']}


def prepare_catalog(root, ready):
    root=Path(root).resolve();transport=ready['transport'];result=ready['result'];deps=ready['dependencies']
    for name,key in [('transport_sources.json','transport_sources_sha256'),('runtime_source_storage.json','runtime_source_storage_sha256'),
                     ('transport/requests.json','requests_sha256'),('transport/inherited_requests.json','inherited_requests_sha256'),
                     ('transport/accepted_range_evidence.json','accepted_range_evidence_sha256')]:
        retain_expected(ready['expected_artifacts'],root/name,transport[key])
    retain_expected(ready['expected_artifacts'],root/'prior_completed_day_comparisons.json',result['prior_completed_day_comparisons_sha256'])
    need(len(result['prepared_days'])==37 and len(result['selection_manifests'])==2,'prepared artifact population differs')
    for binding in result['selection_manifests'].values():
        retain_expected(ready['expected_artifacts'],relative(root,binding['path']),binding['sha256'])
    for binding in result['prepared_days']:
        path=relative(root,binding['path']);retain_expected(ready['expected_artifacts'],path,binding['sha256'])
        prepared=read(path)
        for name,key in [('core_selection.json','core_selection_file_sha256'),('scan.json','address_scan_manifest_sha256'),
                         ('headers.json','header_chain_sha256'),('source_parts.json','partition_manifest_sha256')]:
            retain_expected(ready['expected_artifacts'],path.parent/name,prepared[key])
    locations=read(root/'runtime_source_storage.json');manifests=read(root/'transport_sources.json')['sources']
    need(len(locations)==len(manifests)==113,'source population differs')
    inherited=read(root/'transport/inherited_requests.json');new_requests=read(root/'transport/requests.json')
    accepted=read(root/'transport/accepted_range_evidence.json');need(accepted['schema_version']=='article2_phase16_compact_accepted_ranges_v1','accepted range schema')
    a1=ready['a1_index'];need(a1['capture_facts']['request_count']==730 and a1['capture_facts']['successful_receipt_count']==729,'A1 canonical receipt population differs')
    a1map=a1_members(a1);need(file_sha(root/'transport/inherited_requests.json')==a1map['attempt1/transport/requests.json'][1]['sha256_before'],'A1 preserved receipt ledger differs')
    descriptors={}
    for key,location in locations.items():
        if location['storage_kind']=='compact_descriptor':
            path=Path(location['path']);need(path.resolve().is_relative_to(root),'descriptor outside capture');descriptors[key]=read(path)
    catalog=recipe_catalog(ready['session'],inherited,new_requests,accepted['ranges'],descriptors,locations,a1,deps['whole_object_origins'])
    need(catalog['parent_pending_ordinal']==730 and len(catalog['inherited_recipes'])==729,'parent/pending split differs')
    descriptor_manifest={m['source']['key']:m for m in manifests}
    for key,descriptor in descriptors.items():
        path=root/catalog['source_locations'][key]['descriptor_relative_path']
        need(path.resolve()==Path(locations[key]['path']).resolve() and file_sha(path)==descriptor_manifest[key]['descriptor_sha256'],'descriptor path/hash differs')
        retain_expected(ready['expected_artifacts'],path,descriptor_manifest[key]['descriptor_sha256'])
    return catalog


def artifact_entries(root,catalog,ready,metadata_limit=128*1024*1024):
    root=Path(root).resolve();all_blobs=catalog['all_blob_paths'];new={x['path']:x for x in catalog['new_blob_entries']}
    seen_blobs=set();entries=[];metadata_members=[];census=[]
    whole_paths={Path(x['original_path']).resolve() for x in catalog.get('source_locations',{}).values()
                 if x['storage_kind']=='verified_whole_object'}
    forbidden_suffixes={'.parquet','.zip','.gz','.bz2','.xz','.tar','.tgz','.zst','.7z'}
    def small_artifact(path):
        bound_jsonl_gzip=path.name.lower().endswith('.jsonl.gz') and str(path.resolve()) in ready['expected_artifacts']
        need(path.resolve() not in whole_paths and (path.suffix.lower() not in forbidden_suffixes or bound_jsonl_gzip),
             'source/archive payload cannot be a small metadata artifact')
    for path in sorted(root.rglob('*')):
        if not path.is_file():continue
        need(path.resolve().is_relative_to(root),'snapshot artifact leaves A2 root')
        rel=path.relative_to(root).as_posix();stat=snapshot(path);census.append(rel)
        if rel in all_blobs:
            seen_blobs.add(rel);need(not stat['mode']&0o222,'accepted response blob is writable')
            if rel not in new:continue  # No inherited body read or duplicate archive payload.
            blob=new[rel];need(stat['logical_bytes']==blob['size_bytes'],'new body size differs')
            entries.append({'path':path,'member':'attempt2/'+rel,'before_stat':stat,
                'artifact_kind':'accepted_new_response_blob','expected_sha256':blob['sha256'],
                'origin_ordinal':blob['origin_ordinal'],'origin_attempt_id':blob['origin_attempt_id']})
        else:
            need(path.suffix!='.bin' and not rel.endswith(('.writing','.partial')),'orphan/unfinished blob or artifact')
            small_artifact(path)
            need(stat['logical_bytes']<=metadata_limit,'small-artifact size cap exceeded; never silently skip')
            expected=ready['expected_artifacts'].get(str(path.resolve()))
            entry={'path':path,'member':'attempt2/'+rel,'before_stat':stat,'artifact_kind':'exact_final_metadata_or_observation'}
            if expected is not None:entry['expected_sha256']=expected
            entries.append(entry);metadata_members.append(rel)
    need(seen_blobs==all_blobs,'missing/orphan accepted blob population')
    for i,path in enumerate([p for p in ready['external'] if not p.is_relative_to(root)],1):
        small_artifact(path);stat=snapshot(path);need(stat['logical_bytes']<=metadata_limit,'external artifact too large')
        expected=ready['expected_artifacts'].get(str(path.resolve()))
        need(expected is not None,'external artifact lacks gate-time digest')
        entries.append({'path':path,'member':f'delivery_control/{i:03d}_{path.name}','before_stat':stat,
                        'artifact_kind':'explicit_bound_delivery_proof_or_final_scientific_report','expected_sha256':expected,
                        'original_external_path':str(path.resolve())})
    need(len({x['member'] for x in entries})==len(entries),'duplicate delta member')
    archived_paths={str(x['path'].resolve()) for x in entries}
    need(set(ready['expected_artifacts'])<=archived_paths,'gate-bound artifact missing from final inventory')
    return entries,metadata_members,census


def group_entries(entries,maximum):
    groups=[];limit=maximum-max(8192,maximum//100)
    for category in ('accepted_new_response_blob','metadata'):
        chosen=[x for x in entries if (x['artifact_kind']=='accepted_new_response_blob')==(category=='accepted_new_response_blob')]
        group=[];size=0;ordinal=1
        for entry in chosen:
            length=entry['before_stat']['logical_bytes'];need(length<=limit,'delta member exceeds ZIP planning cap')
            if group and size+length>limit:
                groups.append((f'a2_delta_{category}_{ordinal:03d}.zip',group));group=[];size=0;ordinal+=1
            group.append(entry);size+=length
        if group:groups.append((f'a2_delta_{category}_{ordinal:03d}.zip',group))
    return groups


def pack_delta(args):
    root=args.collection.resolve();output=args.output.resolve()
    need(not output.exists() and not output.is_relative_to(root),'fresh delta output outside A2 required')
    ready=load_ready(root,args.proofs,args.expected_proofs_sha256)
    need(output.is_relative_to(RUNTIME_ROOT) and not output.is_relative_to(Path(ready['context']['parent_root']).resolve()),
         'delta bulk output must stay in external runtime and outside immutable A1')
    catalog=prepare_catalog(root,ready);entries,metadata,census=artifact_entries(root,catalog,ready)
    groups=group_entries(entries,MAX_PACK);output.mkdir(parents=True);packs=[]
    try:
        for name,items in groups:
            packed=z.pack_one(output,name,items,MAX_PACK)
            for record in packed['members']:
                if 'expected_sha256' in record:need(record['sha256_before']==record['expected_sha256'],'archived bytes do not match bound receipt/report')
            packs.append(packed)
            z.write_json(output/'delta_progress.json',{'status':'IN_PROGRESS_NOT_DELIVERED','completed_packs':len(packs),'planned_packs':len(groups)})
            print(json.dumps({'verified_delta_pack':name,'bytes':packed['bytes'],'completed':len(packs),'total':len(groups)}),flush=True)
        need(sorted(p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file())==census,'A2 file inventory changed during final snapshot')
        for item in entries:need(z.same_snapshot(item['before_stat'],snapshot(item['path'])),'final artifact changed during packing')
        need(file_sha(args.proofs)==args.expected_proofs_sha256,'delivery proof changed')
        immutable_catalog={k:v for k,v in catalog.items() if k!='all_blob_paths'}
        deps={k:v for k,v in ready['dependencies'].items() if k!='raw_metadata_bindings'}
        index={'schema_version':'phase16_compact_a2_delta_index_v1','status':'COMPLETE_DELTA_PRESERVATION_NOT_NEW_SOURCE_AUDIT',
            'created_utc':z.stamp(),'packer_sha256':file_sha(__file__),'zip_helper_sha256':HELPER_SHA256,
            'original_runtime_root':str(root),'dependencies':deps,**immutable_catalog,
            'delivery_proof_sha256':args.expected_proofs_sha256,'final_snapshot_sha256':ready['final_snapshot_sha256'],
            'plan_sha256':ready['context']['plan_sha256'],'storage_recovery_amendment_sha256':ready['proof']['amendment']['sha256'],
            'collection_result_sha256':ready['transport']['collection_result_sha256'],
            'transport_audit_sha256':ready['proof']['transport_audit']['sha256'],'source_review_sha256':ready['proof']['source_review']['sha256'],
            'assembly_result_sha256':ready['proof']['assembly_result']['sha256'],
            'packs':packs,'archive_count':len(packs),'archive_bytes_total':sum(x['bytes'] for x in packs),
            'metadata_members':metadata,'metadata_and_external_artifact_count':sum(x['artifact_kind']!='accepted_new_response_blob' for x in entries),
            'inherited_body_bytes_duplicated':0,'whole_original_object_body_bytes_duplicated':0,
            'pending_parent_bytes_accepted':False,'new_source_rows_decoded':False,'new_scores_computed':False,
            'historical_audits_preserved_not_repeated':True,
            'restore_note':'Reconstruct inherited blobs only from verified A1 artifact intervals; preserve original JSON verbatim and emit a separate relocation map.'}
        z.write_json(output/'a2_delta_index.json',index)
        z.write_json(output/'delta_progress.json',{'status':index['status'],'index_sha256':file_sha(output/'a2_delta_index.json'),'archive_count':len(packs)})
        print(json.dumps({'status':index['status'],'index_sha256':file_sha(output/'a2_delta_index.json'),'archive_count':len(packs),'archive_bytes_total':index['archive_bytes_total']}),flush=True)
        return index
    except Exception as exc:
        z.write_json(output/'delta_failure.json',{'status':'INCOMPLETE_DELTA_NOT_VERIFIED','error_type':type(exc).__name__,'error':str(exc),'completed_pack_count':len(packs)})
        raise


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    deps=sub.add_parser('dependencies')
    for name in ('a1-index','catalog','upload-receipt','original-archives','reuse-expectations','original-plan','output'):deps.add_argument('--'+name,type=Path,required=True)
    deps.add_argument('--catalog-library-file-id',required=True)
    packing=sub.add_parser('pack')
    for name in ('collection','proofs','output'):packing.add_argument('--'+name,type=Path,required=True)
    packing.add_argument('--expected-proofs-sha256',required=True)
    args=parser.parse_args(argv)
    return make_dependencies(args) if args.command=='dependencies' else pack_delta(args)


if __name__=='__main__':main()
