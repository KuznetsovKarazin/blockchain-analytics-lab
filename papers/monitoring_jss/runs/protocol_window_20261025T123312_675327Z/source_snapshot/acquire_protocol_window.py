"""Collect frozen daily Ethereum populations with complete raw-object evidence.

No detection or label use. A single complete address scan serves all emitters.
Daily archives are committed only after every member passes SHA-256 and CRC.
Only reproducible loose Parquet copies may then be removed; archives are retained.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import sys
import threading
import time
import urllib.request
import zipfile

from acquire_protocol_logs import ADDRESS, BASE, HEX32, sha256, validate_logs

ROOT=Path(__file__).resolve().parents[2]
PAPER=Path(__file__).resolve().parent
SAFE=re.compile(r'[a-zA-Z0-9_-]+\Z')

def atomic_json(path,value):
    path=Path(path); temp=path.with_name(path.name+'.partial')
    with temp.open('w') as f:
        json.dump(value,f,sort_keys=True,indent=2,allow_nan=False);f.write('\n');f.flush();os.fsync(f.fileno())
    temp.replace(path)
    fd=os.open(path.parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

def ensure_space(path,need,min_free_bytes):
    if shutil.disk_usage(Path(path).parent).free < need+min_free_bytes:
        raise RuntimeError('insufficient free disk; no archive or prior evidence is deleted')

def identity(source):
    return {k:source.get(k) for k in ('url','size','etag','version_id')}

def download_object(source,path,*,max_bytes,min_free_bytes,opener=None):
    """One pinned GET. A failed attempt can resume safely by restarting this object."""
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    receipt_path=path.with_suffix(path.suffix+'.receipt.json')
    if source['size']<0 or source['size']>max_bytes:raise ValueError('source exceeds frozen byte cap')
    if path.exists():
        if not receipt_path.exists():raise RuntimeError('unreceipted completed object; preserve and investigate')
        saved=json.loads(receipt_path.read_text())
        if identity(saved['source'])!=identity(source) or path.stat().st_size!=source['size'] or sha256(path)!=saved['sha256']:
            raise RuntimeError('cached object identity or SHA mismatch')
        return {**saved,'reused':True,'network_bytes_this_attempt':0}
    ensure_space(path,source['size'],min_free_bytes)
    request=urllib.request.Request(source['url'],headers={'If-Match':source['etag']})
    started=time.perf_counter();count=0;digest=hashlib.sha256();partial=path.with_suffix(path.suffix+'.partial')
    open_url=opener or urllib.request.urlopen
    try:
        with open_url(request,timeout=120) as response:
            if response.status!=200:raise RuntimeError('full-object GET must return HTTP 200')
            if response.headers.get('ETag')!=source['etag']:raise RuntimeError('remote ETag changed')
            if int(response.headers.get('Content-Length','-1'))!=source['size']:raise RuntimeError('incorrect Content-Length')
            version=response.headers.get('x-amz-version-id')
            if source.get('version_id') is not None and version!=source['version_id']:raise RuntimeError('source version changed')
            with partial.open('wb') as out:
                while block:=response.read(1024*1024):
                    count+=len(block)
                    if count>source['size']:raise RuntimeError('excess object bytes')
                    ensure_space(path,len(block),min_free_bytes)
                    out.write(block);digest.update(block)
                out.flush();os.fsync(out.fileno())
        if count!=source['size']:raise RuntimeError('truncated object')
        receipt={'source':identity(source),'sha256':digest.hexdigest(),'bytes':count,'network_bytes_this_attempt':count,
                 'elapsed_seconds':time.perf_counter()-started,'acquired_utc':datetime.now(timezone.utc).isoformat(),
                 'reused':False,'hash_scope':'whole source object'}
        # Receipt first: a crash before rename leaves only a restartable .partial.
        atomic_json(receipt_path,receipt);partial.replace(path)
        return receipt
    except Exception as exc:
        failure_name=path.name+'.failed_attempt_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')+'.json'
        atomic_json(path.with_name(failure_name),{'source':identity(source),'bytes_received':count,
                    'error':f'{type(exc).__name__}: {exc}','finished_utc':datetime.now(timezone.utc).isoformat()})
        raise

def validate_headers(headers,day):
    if not headers:raise ValueError('empty full-day header partition')
    if headers!=sorted(headers,key=lambda r:r['block_number']):raise ValueError('headers not sorted')
    for field in ('block_number','block_hash'):
        if len({r[field] for r in headers})!=len(headers):raise ValueError('duplicate header identity')
    for r in headers:
        if not HEX32.fullmatch(r['block_hash']) or not HEX32.fullmatch(r['parent_hash']):raise ValueError('invalid header hash')
        for field in ('block_number','event_time_ns','transaction_count'):
            if isinstance(r[field],bool) or not isinstance(r[field],int) or r[field]<0:raise ValueError('invalid header integer')
        if datetime.fromtimestamp(r['event_time_ns']//10**9,timezone.utc).date().isoformat()!=day:raise ValueError('header outside day')
    if any(b['block_number']!=a['block_number']+1 or b['parent_hash']!=a['block_hash'] or b['event_time_ns']<=a['event_time_ns'] for a,b in zip(headers,headers[1:])):
        raise ValueError('header continuity, parent link or timestamp failure')
    return {'full_header_count':len(headers),'parent_links_checked':len(headers)-1,'first_header':headers[0],'last_header':headers[-1],
            'header_checks':'nonempty, unique number/hash, strict integer and hash syntax, UTC day, consecutive numbers, parent links and increasing time'}

def validate_cross_day(days):
    if not days:raise ValueError('no completed days')
    for a,b in zip(days,days[1:]):
        if date.fromisoformat(b['day_utc'])!=date.fromisoformat(a['day_utc'])+timedelta(days=1):raise ValueError('nonconsecutive UTC days')
        x,y=a['last_header'],b['first_header']
        if y['block_number']!=x['block_number']+1 or y['parent_hash']!=x['block_hash'] or y['event_time_ns']<=x['event_time_ns']:
            raise ValueError('cross-day chain linkage failure')
    return {'consecutive_day_count':len(days),'cross_day_parent_links_checked':len(days)-1,'status':'complete'}

def write_jsonl(path,rows):
    path=Path(path);temp=path.with_name(path.name+'.partial')
    with temp.open('w') as f:
        for row in rows:f.write(json.dumps(row,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n')
        f.flush();os.fsync(f.fileno())
    temp.replace(path)
    return {'path':path.name,'sha256':sha256(path),'bytes':path.stat().st_size,'rows':len(rows),'complete':True}

def select_day(logs_path,headers_path,populations,day,output_dir):
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.parquet as pq
    out=Path(output_dir);out.mkdir(parents=True,exist_ok=True)
    header_table=pq.read_table(headers_path,columns=['number','hash','parent_hash','timestamp','transaction_count'],use_threads=False)
    scale={'s':10**9,'ms':10**6,'us':10**3,'ns':1}[header_table['timestamp'].type.unit]
    stamps=pc.cast(header_table['timestamp'],pa.int64()).to_pylist()
    headers=sorted([{'block_number':int(r['number']),'block_hash':r['hash'].lower(),'parent_hash':r['parent_hash'].lower(),
                    'event_time_ns':int(t)*scale,'transaction_count':int(r['transaction_count'])} for r,t in zip(header_table.to_pylist(),stamps)],key=lambda r:r['block_number'])
    header_checks=validate_headers(headers,day);block_map={r['block_number']:r for r in headers}
    addresses={address for p in populations for address in p['addresses']}
    parquet=pq.ParquetFile(logs_path)
    required=['address','topics','data','transaction_index','log_index','transaction_hash','block_number','block_hash','block_timestamp']
    if any(name not in parquet.schema_arrow.names for name in required):raise ValueError('required log source column missing')
    payload_columns=required+(['removed'] if 'removed' in parquet.schema_arrow.names else [])
    rows=[];groups=[];scanned=0
    for group in range(parquet.num_row_groups):
        column=parquet.read_row_group(group,columns=['address'],use_threads=False)['address']
        if column.null_count:raise ValueError('null source address prevents complete membership classification')
        if len(column)!=parquet.metadata.row_group(group).num_rows:raise ValueError('address scan count mismatch')
        indices=pc.indices_nonzero(pc.is_in(pc.utf8_lower(column),value_set=pa.array(sorted(addresses)))).to_pylist()
        groups.append({'row_group':group,'source_row_start':scanned,'address_rows_scanned':len(column),'matching_rows':len(indices),'address_null_rows':column.null_count})
        if indices:
            selected={}
            for name in payload_columns:
                values=parquet.read_row_group(group,columns=[name],use_threads=False)[name].take(pa.array(indices,type=pa.int64()))
                if name=='block_timestamp':
                    scale={'s':10**9,'ms':10**6,'us':10**3,'ns':1}[values.type.unit]
                    selected['event_time_ns']=[int(v)*scale for v in pc.cast(values,pa.int64()).to_pylist()]
                else:selected[name]=values.to_pylist()
            for offset,ordinal in enumerate(indices):
                row={name:values[offset] for name,values in selected.items()}
                for name in ('address','block_hash','transaction_hash','data'):row[name]=row[name].lower()
                row['topics']=[topic.lower() for topic in row['topics']]
                if 'removed' in row:
                    if row['removed'] is not None and type(row['removed']) is not bool:raise ValueError('removed must be boolean or null')
                    if row['removed'] is True:raise ValueError('removed=true is outside canonical historical population')
                row.update(chain_id=1,source_row_group=group,source_row_index=ordinal,source_global_row_index=scanned+ordinal,
                           observed_time=None,label_available_time=None)
                rows.append(row)
        scanned+=len(column)
    if scanned!=parquet.metadata.num_rows or len(rows)!=sum(g['matching_rows'] for g in groups):raise ValueError('incomplete scan or lost matches')
    validate_logs(rows,addresses,day,block_map)
    rows.sort(key=lambda r:(r['block_number'],r['transaction_index'],r['log_index']))
    outputs=[]
    for population in populations:
        selected=[r for r in rows if r['address'] in population['addresses']]
        outputs.append({'population_id':population['population_id'],**write_jsonl(out/(population['population_id']+'_logs.jsonl'),selected)})
    return {'status':'complete','day_utc':day,'source_log_schema':str(parquet.schema_arrow),'complete_address_rows_scanned':scanned,
            'row_groups':groups,'union_selected_logs':len(rows),'no_matched_rows_lost':True,'population_outputs':outputs,
            'headers_output':write_jsonl(out/'headers.jsonl',headers),**header_checks,
            'source_missing_removed':'removed' not in parquet.schema_arrow.names,
            'removed_status':'unknown; source field absent' if 'removed' not in parquet.schema_arrow.names else 'source bool/null preserved; removed=true rejected',
            'receipt_status':None,'historical_observed_time':None,'historical_label_available_time':None,
            'completeness_scope':'all matched emitter logs in the listed source partitions; not independently all chain receipts'}

def verify_seal(archive_path):
    archive_path=Path(archive_path)
    with zipfile.ZipFile(archive_path) as z:
        names=z.namelist()
        if len(names)!=len(set(names)):raise ValueError('duplicate archive names')
        manifest=json.loads(z.read('ARCHIVE_MANIFEST.json'))
        expected={r['path'] for r in manifest['files']}|{'ARCHIVE_MANIFEST.json'}
        if set(names)!=expected:raise ValueError('archive inventory mismatch')
        for item in manifest['files']:
            digest=hashlib.sha256();size=0
            with z.open(item['path']) as f:
                while block:=f.read(1024*1024):digest.update(block);size+=len(block)
            if size!=item['bytes'] or digest.hexdigest()!=item['sha256']:raise ValueError('archive member SHA/size mismatch')
    return {'path':str(archive_path),'sha256':sha256(archive_path),'bytes':archive_path.stat().st_size,
            'members':len(names),'all_member_sha256_and_crc_verified':True,'status':'sealed'}

def seal_day(day_dir,archive_path,extra_files):
    day_dir=Path(day_dir);archive_path=Path(archive_path);archive_path.parent.mkdir(parents=True,exist_ok=True)
    if archive_path.exists():raise FileExistsError('sealed archive exists; verify and resume explicitly, never overwrite')
    members={str(p.relative_to(day_dir)):p for p in day_dir.rglob('*') if p.is_file() and not p.name.endswith('.partial') and '__pycache__' not in p.parts}
    for name,path in extra_files.items():
        if name in members:raise ValueError('archive name collision')
        members[name]=Path(path)
    if any(p.is_symlink() for p in members.values()):raise ValueError('symlink cannot be sealed')
    files=[{'path':name,'bytes':p.stat().st_size,'sha256':sha256(p)} for name,p in sorted(members.items())]
    manifest={'schema':'protocol_window_day_seal_v1','created_utc':datetime.now(timezone.utc).isoformat(),'files':files,
              'whole_source_objects':True,'private_evidence_only':True,'raw_redistribution_authorization':False}
    temp=archive_path.with_suffix(archive_path.suffix+'.partial')
    with zipfile.ZipFile(temp,'w',compression=zipfile.ZIP_STORED,allowZip64=True) as z:
        z.writestr('ARCHIVE_MANIFEST.json',json.dumps(manifest,sort_keys=True,indent=2)+'\n')
        for item in files:
            p=members[item['path']]
            if p.stat().st_size!=item['bytes'] or sha256(p)!=item['sha256']:raise RuntimeError('source changed while sealing')
            z.write(p,item['path'])
    verify_seal(temp)
    with temp.open('rb') as f:os.fsync(f.fileno())
    temp.replace(archive_path)
    fd=os.open(archive_path.parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)
    return verify_seal(archive_path)

def load_config(path,expected_sha):
    path=Path(path).resolve()
    if sha256(path)!=expected_sha:raise ValueError('configuration hash differs from explicit frozen hash')
    config=json.loads(path.read_text())
    if config.get('study_design_freeze_path'):
        if sha256(ROOT/config['study_design_freeze_path'])!=config['study_design_freeze_sha256']:
            raise ValueError('study design freeze hash mismatch')
    inventory_path=(ROOT/config['inventory_path']).resolve()
    if sha256(inventory_path)!=config['inventory_sha256']:raise ValueError('inventory hash mismatch')
    inventory=json.loads(inventory_path.read_text())
    start=datetime.fromisoformat(config['start_utc'].replace('Z','+00:00'));end=datetime.fromisoformat(config['end_utc_exclusive'].replace('Z','+00:00'))
    if start.utcoffset()!=timedelta(0) or end.utcoffset()!=timedelta(0) or start.time().isoformat()!='00:00:00' or end.time().isoformat()!='00:00:00':raise ValueError('UTC midnight boundaries required')
    expected=[(start+timedelta(days=i)).date().isoformat() for i in range((end-start).days)]
    if not expected or [d['day'] for d in inventory['days']]!=expected:raise ValueError('inventory is not the frozen complete consecutive window')
    addresses=[];ids=[]
    for p in config['populations']:
        if not SAFE.fullmatch(p['population_id']) or p['chain_id']!=1 or not p.get('address_source'):raise ValueError('invalid population identity/provenance')
        if not p['addresses'] or any(not ADDRESS.fullmatch(a) for a in p['addresses']):raise ValueError('invalid or non-normalized emitter')
        ids.append(p['population_id']);addresses.extend(p['addresses'])
    if len(set(ids))!=len(ids) or len(set(addresses))!=len(addresses):raise ValueError('population IDs/addresses must be unique and disjoint')
    if config['download_workers'] not in range(1,5) or config['decode_workers'] not in range(1,3):raise ValueError('unsupported worker bound')
    if config['min_free_bytes']<1_500_000_000:raise ValueError('minimum free disk must be at least 1.5 GB')
    if config['max_object_bytes']>500_000_000:raise ValueError('object cap exceeds reviewed 500 MB bound')
    for d in inventory['days']:
        for table in ('logs','blocks'):
            s=d[table]
            if not s['key'].startswith(f"v1.0/eth/{table}/date={d['day']}/") or not s['key'].endswith('.parquet') or not s['etag'] or s['size']>config['max_object_bytes']:
                raise ValueError('invalid frozen source object')
    for name,expected_hash in config['source_hashes'].items():
        if sha256(PAPER/name)!=expected_hash:raise ValueError('source code changed since freeze')
    if set(config['source_hashes'])!={'acquire_protocol_window.py','acquire_protocol_logs.py'}:raise ValueError('both source hashes must be frozen')
    import pyarrow as pa
    if pa.__version__!=config['pyarrow_version']:raise ValueError('PyArrow version differs from freeze')
    return config,inventory,inventory_path

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True);parser.add_argument('--config-sha256',required=True)
    parser.add_argument('--run-id');parser.add_argument('--resume',action='store_true');parser.add_argument('--check-config',action='store_true')
    args=parser.parse_args();config,inventory,inventory_path=load_config(args.config,args.config_sha256)
    if args.check_config:
        print(json.dumps({'status':'configuration_valid','days':len(inventory['days']),'payload_requests':0}));return
    run_id=args.run_id or datetime.now(timezone.utc).strftime('protocol_window_%Y%m%dT%H%M%S_%fZ')
    attempt_wall_start=time.perf_counter();attempt_cpu_start=time.process_time()
    if not SAFE.fullmatch(run_id):raise ValueError('invalid run ID')
    run=PAPER/'runs'/run_id;raw=ROOT/'data/raw/monitoring_jss/windows'/run_id
    if args.resume:
        prior=json.loads((run/'manifest.json').read_text())
        if prior['config_sha256']!=args.config_sha256:raise ValueError('resume config differs')
    else:
        run.mkdir(parents=True,exist_ok=False);raw.mkdir(parents=True,exist_ok=False)
        shutil.copy2(args.config,run/'config.json');shutil.copy2(inventory_path,run/'inventory.json')
        (run/'source_snapshot').mkdir()
        for name in config['source_hashes']:shutil.copy2(PAPER/name,run/'source_snapshot'/name)
    (raw/'archives').mkdir(exist_ok=True)
    if sha256(run/'config.json')!=args.config_sha256 or sha256(run/'inventory.json')!=config['inventory_sha256']:
        raise ValueError('frozen run snapshot changed')
    for name,expected in config['source_hashes'].items():
        if sha256(run/'source_snapshot'/name)!=expected:raise ValueError('frozen source snapshot changed')
    frozen={'config.json':run/'config.json','inventory.json':run/'inventory.json',
            **{'source_snapshot/'+n:run/'source_snapshot'/n for n in config['source_hashes']}}
    state={'schema':'protocol_window_acquisition_v1','run_id':run_id,'status':'running','command':[sys.executable,*sys.argv],
           'config_sha256':args.config_sha256,'start_utc':config['start_utc'],'end_utc_exclusive':config['end_utc_exclusive'],
           'source_hashes':config['source_hashes'],'days':[],'populations':[],'no_attack_outcome_evaluation':True,
           'started_utc':datetime.now(timezone.utc).isoformat(),'raw_storage':str(raw.relative_to(ROOT)),
           'environment':{'python':sys.version,'pyarrow':config['pyarrow_version'],'os_cpu_count':os.cpu_count(),
                          'download_workers':config['download_workers'],'decode_workers':config['decode_workers'],
                          'start_free_disk_bytes':shutil.disk_usage(raw).free,'min_free_bytes':config['min_free_bytes']}}
    atomic_json(run/'manifest.json',state)
    decoder=threading.Semaphore(config['decode_workers']);stop=threading.Event()
    def collect(d):
        if stop.is_set():raise RuntimeError('window stopped after prior failure')
        day=d['day'];folder=raw/day;folder.mkdir(exist_ok=True);archive=raw/'archives'/(day+'.zip')
        if archive.exists():
            receipt=verify_seal(archive)
            with zipfile.ZipFile(archive) as z:
                result=json.loads(z.read('day_manifest.json'))
                if result['config_sha256']!=args.config_sha256:raise ValueError('sealed day config mismatch')
                manifest_path=folder/'day_manifest.json'
                if not manifest_path.exists():manifest_path.write_bytes(z.read('day_manifest.json'))
                elif manifest_path.read_bytes()!=z.read('day_manifest.json'):raise ValueError('retained day manifest changed')
                for record in result['population_outputs']+[result['headers_output']]:
                    p=folder/record['path']
                    if not p.exists():p.write_bytes(z.read(record['path']))
                    if sha256(p)!=record['sha256']:raise ValueError('retained selected file changed')
            return {**result,'archive':receipt,'acquisition_manifest_path':str((folder/'day_manifest.json').relative_to(ROOT))}
        receipts={}
        for table,filename in [('logs','logs.parquet'),('blocks','headers.parquet')]:
            if stop.is_set():raise RuntimeError('window stopped before next source')
            source={'url':BASE+d[table]['key'],'size':d[table]['size'],'etag':d[table]['etag'],'version_id':None}
            receipts[table]=download_object(source,folder/filename,max_bytes=config['max_object_bytes'],min_free_bytes=config['min_free_bytes'])
        with decoder:
            if stop.is_set():raise RuntimeError('window stopped before decoding')
            result=select_day(folder/'logs.parquet',folder/'headers.parquet',config['populations'],day,folder)
            import gc
            import pyarrow as pa
            gc.collect();pa.default_memory_pool().release_unused()
            result.update(config_sha256=args.config_sha256,source_objects=receipts,source_hashes=config['source_hashes'])
            atomic_json(folder/'day_manifest.json',result)
            ensure_space(archive,sum(p.stat().st_size for p in folder.iterdir() if p.is_file()),config['min_free_bytes'])
            receipt=seal_day(folder,archive,frozen)
            atomic_json(folder/'seal_receipt.json',receipt)
            if config['remove_loose_parquet_after_verified_seal']:
                for name in ('logs.parquet','headers.parquet'):(folder/name).unlink()
        return {**result,'archive':receipt,'acquisition_manifest_path':str((folder/'day_manifest.json').relative_to(ROOT))}
    error=None
    with ThreadPoolExecutor(max_workers=config['download_workers']) as pool:
        jobs={pool.submit(collect,d):d['day'] for d in inventory['days']}
        for future in as_completed(jobs):
            try:
                day=future.result();state['days'].append(day);state['days'].sort(key=lambda d:d['day_utc'])
                atomic_json(run/'manifest.json',state)
                print(json.dumps({'stage':'day_sealed','day':day['day_utc'],'archive_bytes':day['archive']['bytes'],
                                  'population_rows':{r['population_id']:r['rows'] for r in day['population_outputs']}}),flush=True)
            except Exception as exc:
                stop.set();error=error or exc
                for f in jobs:f.cancel()
    if error is not None:
        state.update(status='incomplete_resumable',error=f'{type(error).__name__}: {error}')
        atomic_json(run/'manifest.json',state);raise error
    try:
        state['cross_day_checks']=validate_cross_day(state['days'])
        if len(state['days'])!=len(inventory['days']):raise RuntimeError('missing day result')
        for p in config['populations']:
            inputs=[]
            for day in state['days']:
                record=next(r for r in day['population_outputs'] if r['population_id']==p['population_id'])
                inputs.append({**record,'path':str((raw/day['day_utc']/record['path']).relative_to(ROOT)),
                               'day_utc':day['day_utc'],'acquisition_manifest_path':day['acquisition_manifest_path'],
                               'shared_headers_path':str((raw/day['day_utc']/'headers.jsonl').relative_to(ROOT)),'status':'complete'})
            state['populations'].append({**p,'address':p['addresses'][0] if len(p['addresses'])==1 else None,
                                        'start_utc':config['start_utc'],'end_utc_exclusive':config['end_utc_exclusive'],'inputs':inputs})
        for name,expected in config['source_hashes'].items():
            if sha256(PAPER/name)!=expected:raise RuntimeError('live source mutated during collection')
        state.update(status='complete',finished_utc=datetime.now(timezone.utc).isoformat(),
                     attempt_wall_seconds=time.perf_counter()-attempt_wall_start,
                     attempt_process_cpu_seconds=time.process_time()-attempt_cpu_start,
                     peak_process_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
                     timing_scope='current process attempt, including downloading, decoding, hash verification and sealing; resumed attempts reported separately')
        atomic_json(run/'manifest.json',state)
    except Exception as exc:
        state.update(status='incomplete_resumable',error=f'{type(exc).__name__}: {exc}')
        atomic_json(run/'manifest.json',state);raise
    print(json.dumps({'status':'complete','manifest':str(run/'manifest.json'),'days':len(state['days'])}),flush=True)

if __name__=='__main__':main()
