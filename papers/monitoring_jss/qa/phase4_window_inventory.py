"""Metadata-only AWS partition inventory; never downloads Parquet payloads."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import statistics
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[3]
PAPER=ROOT/'papers/monitoring_jss'
BASE='https://aws-public-blockchain.s3.us-east-2.amazonaws.com/'
NS={'s':'http://s3.amazonaws.com/doc/2006-03-01/'}

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def list_month(month,table,out):
    prefix=f'v1.0/eth/{table}/date={month}-'
    token=None;pages=[];objects=[]
    while True:
        params={'list-type':'2','prefix':prefix,'max-keys':'1000'}
        if token is not None:params['continuation-token']=token
        url=BASE+'?'+urllib.parse.urlencode(params)
        started=time.perf_counter()
        with urllib.request.urlopen(url,timeout=90) as response:
            assert response.status==200
            content=response.read()
        tree=ET.fromstring(content)
        filename=f'{table}_{month}_page{len(pages)+1}.xml'
        path=out/filename;path.write_bytes(content)
        truncated=tree.findtext('s:IsTruncated',namespaces=NS)
        assert truncated in {'true','false'}
        pages.append({'url':url,'retrieved_utc':datetime.now(timezone.utc).isoformat(),'snapshot':filename,
                      'bytes':len(content),'sha256':hashlib.sha256(content).hexdigest(),
                      'is_truncated':truncated=='true','elapsed_seconds':time.perf_counter()-started})
        for item in tree.findall('s:Contents',NS):
            objects.append({'key':item.findtext('s:Key',namespaces=NS),'size':int(item.findtext('s:Size',namespaces=NS)),
                            'etag':item.findtext('s:ETag',namespaces=NS),'last_modified':item.findtext('s:LastModified',namespaces=NS)})
        if truncated=='false':break
        token=tree.findtext('s:NextContinuationToken',namespaces=NS)
        assert token
    assert len({o['key'] for o in objects})==len(objects)
    return {'month':month,'table':table,'prefix':prefix,'all_pages_complete':True,'pages':pages,'objects':objects}

def main():
    run_id=datetime.now(timezone.utc).strftime('phase4_feasibility_%Y%m%dT%H%M%S_%fZ')
    out=PAPER/'qa'/run_id;out.mkdir(exist_ok=False)
    started=datetime.now(timezone.utc).isoformat()
    jobs=[(m,t) for m in ['2023-03','2022-04'] for t in ['logs','blocks']]
    with ThreadPoolExecutor(max_workers=4) as pool:
        listings=list(pool.map(lambda job:list_month(*job,out),jobs))
    measured=[]
    for path in sorted((PAPER/'runs').glob('protocol_logs_*/acquisition_manifest.json')):
        m=json.loads(path.read_text())
        if m.get('status')!='complete':continue
        seconds=(datetime.fromisoformat(m['finished_utc'])-datetime.fromisoformat(m['started_utc'])).total_seconds()
        ranges=m['logs_range_acquisition'];headers=m['header_acquisition']
        measured.append({'manifest':str(path.relative_to(ROOT)),'manifest_sha256':sha(path),'day':m['scope']['day_utc'],
              'wall_acquisition_seconds':seconds,'projection_transfer_ratio':m['projection_transfer_ratio'],
              'cached_range_bytes':ranges['total_cached_range_bytes'],'header_bytes':headers['bytes'],
              'peak_rss_bytes':m['peak_rss_bytes'],'row_groups':m['source_log_row_groups'],
              'payload_groups':sum(r['payload_acquired'] for r in m['row_groups']),
              'range_transfer_elapsed_seconds':sum(r['elapsed_seconds'] for r in ranges['ranges'].values()),
              'actual_cpu_seconds':None,'cpu_note':'Prior manifests measure wall acquisition and RSS, not process CPU seconds.'})
    ratios=[m['projection_transfer_ratio'] for m in measured]
    rates=[m['wall_acquisition_seconds']/(m['cached_range_bytes']+m['header_bytes']) for m in measured]
    windows=[]
    for protocol,month in [('Euler','2023-03'),('Beanstalk','2022-04')]:
        days=[]
        for daynum in range(1,31):
            day=f'{month}-{daynum:02d}';row={'day':day}
            for table in ['logs','blocks']:
                listing=next(x for x in listings if x['month']==month and x['table']==table)
                matches=[o for o in listing['objects'] if o['key'].startswith(f'v1.0/eth/{table}/date={day}/') and o['key'].endswith('.parquet')]
                row[table]=matches
                row[table+'_object_count']=len(matches)
                row[table+'_bytes']=sum(o['size'] for o in matches)
            days.append(row)
        logbytes=sum(d['logs_bytes'] for d in days);headerbytes=sum(d['blocks_bytes'] for d in days)
        estimate=logbytes*statistics.mean(ratios)+headerbytes
        high=logbytes+headerbytes
        windows.append({'protocol':protocol,'start_day':month+'-01','end_day_inclusive':month+'-30','days':days,
            'expected_days':30,'complete_inventory_days':sum(bool(d['logs']) and bool(d['blocks']) for d in days),
            'all_days_exactly_one_log_and_one_header_object':all(d['logs_object_count']==d['blocks_object_count']==1 for d in days),
            'logs_total_bytes':logbytes,'headers_total_bytes':headerbytes,'full_object_bytes_total':high,
            'logs_day_min_bytes':min(d['logs_bytes'] for d in days),'logs_day_max_bytes':max(d['logs_bytes'] for d in days),
            'logs_days_over_current_500MB_cap':[d['day'] for d in days if d['logs_bytes']>500_000_000],
            'estimated_projection_bytes_using_measured_euler_ratio':round(estimate),
            'projection_estimate_limit':'Extrapolation from two Euler days. Match distribution for remaining days/Beanstalk is unknown until a complete address scan; not a measured coverage claim.',
            'estimated_sequential_wall_seconds_range':[round(estimate*min(rates)),round(high*max(rates))],
            'raw_archives_stored_bytes_approx_range':[round(estimate),high],
            'whole_source_projection_sha256_claim':False})
    disk=shutil.disk_usage(ROOT)
    result={'schema':'phase4_metadata_only_window_feasibility_v1','run_id':run_id,'started_utc':started,
            'finished_utc':datetime.now(timezone.utc).isoformat(),'command':[sys.executable,*sys.argv],
            'script_sha256':sha(__file__),'payload_requests':0,'attack_outcomes_evaluated':False,
            'inventory_semantics':'AWS object discoverability and listed identities only; neither row completeness nor chain receipt completeness established by listing.',
            'source_metadata_pages':listings,'measured_prior_acquisitions':measured,'windows':windows,
            'disk_at_inventory':{'total_bytes':disk.total,'used_bytes':disk.used,'free_bytes':disk.free},
            'same_day_multi_address_reuse':{'supported_in_principle':True,'existing_cli':'repeat --address; complete single address-column scan uses membership in the address union',
              'cache_identity':['url','size','etag','version_id'],'scope':'A single Ethereum source day can serve multiple emitters with separate population projections. These two target windows do not overlap in date, so they share no raw daily bytes.',
              'restriction':'Do not reuse a selected single-emitter JSONL as complete input for another emitter; rescan the complete address column and project all matches for the new frozen union.'},
            'decision':'Metadata inventory only. Protocol, population, byte caps and durable checkpoint policy require root freeze before any payload collection.'}
    (out/'feasibility_inventory.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'directory':str(out),'disk_free_bytes':disk.free,'windows':[{k:w[k] for k in ['protocol','complete_inventory_days','logs_total_bytes','headers_total_bytes','full_object_bytes_total','logs_day_max_bytes','logs_days_over_current_500MB_cap','estimated_projection_bytes_using_measured_euler_ratio','estimated_sequential_wall_seconds_range']} for w in windows]},indent=2))

if __name__=='__main__':main()
