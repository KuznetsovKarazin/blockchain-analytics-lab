#!/usr/bin/env python3
"""Reconstruct a fixed Revest window from six retained monthly XML listings.

Offline only. This program has no network or Parquet dependencies. It binds
the original listing bytes and reports source metadata, not readable chain rows.
"""
import argparse
from datetime import date, timedelta
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET


N = '{http://s3.amazonaws.com/doc/2006-03-01/}'
ROOT_PATH = 'papers/monitoring_jss/'
EXPECTED = [
    ('repo', 'qa/phase4_common_window_feasibility_20261025T122103_763107Z/logs_2022-03_page1.xml', 'a4fa3ab3ca8f30a6a881306ca858a5ae4eee1105b57c94ad7804443874b8d000', 'logs', '2022-03'),
    ('repo', 'qa/phase4_common_window_feasibility_20261025T122103_763107Z/blocks_2022-03_page1.xml', '28d13f4044f74d245a4de952ad3fb77eea9972e0bd82c6b70482fec34f319a50', 'blocks', '2022-03'),
    ('capture', '001_prefix0_page1_response.xml', '67a80f0bf7cb80a1ad6a8145066f19a345a613fc69dd8a416273283dc0953590', 'logs', '2022-02'),
    ('capture', '002_prefix1_page1_response.xml', 'c7391fb6aa9689d1207e3a41258a46172b6db315b6324f7a8e8f00b49278d159', 'blocks', '2022-02'),
    ('capture', '003_prefix2_page1_response.xml', 'ee134897927838d80e8e623f1d8a154cb0a017988e88e8af2dfc35725a6817f3', 'transactions', '2022-02'),
    ('capture', '004_prefix3_page1_response.xml', '87d8e89b52531d6d33dfee29909056e73598099b1e5b8a5cf632c8f4674a547b', 'transactions', '2022-03'),
]


def need(value, message):
    if not value:
        raise ValueError(message)


def parse(raw, table, month):
    root = ET.fromstring(raw)
    need(root.tag == N+'ListBucketResult', 'Unexpected XML root')
    def one(name):
        values=root.findall(N+name)
        need(len(values)==1 and values[0].text is not None, 'Missing/duplicate '+name)
        return values[0].text
    prefix=f'v1.0/eth/{table}/date={month}-'
    need(one('Name')=='aws-public-blockchain', 'Bucket mismatch')
    need(one('Prefix')==prefix, 'Prefix mismatch')
    need(one('IsTruncated')=='false', 'Unfinished listing')
    need(not root.findall(N+'NextContinuationToken'), 'Unexpected continuation')
    entries=root.findall(N+'Contents')
    need(int(one('KeyCount'))==len(entries)<1000, 'Key count/saturation')
    values=[]; seen=set()
    for entry in entries:
        def field(name):
            nodes=entry.findall(N+name)
            need(len(nodes)==1 and nodes[0].text is not None, 'Object missing/duplicate '+name)
            return nodes[0].text
        key=field('Key')
        match=re.fullmatch(r'v1\.0/eth/'+table+r'/date=(\d{4}-\d{2}-\d{2})/[^/]+\.parquet', key)
        need(match is not None and key.startswith(prefix), 'Unexpected object key')
        day=match.group(1)
        need(date.fromisoformat(day).isoformat()==day and key not in seen, 'Invalid date/duplicate key')
        size_text=field('Size')
        need(re.fullmatch('[1-9][0-9]*',size_text) is not None, 'Invalid size')
        seen.add(key)
        values.append({'day_utc':day,'table':table,'key':key,'size_bytes':int(size_text),'etag_opaque':field('ETag'),'last_modified_metadata':field('LastModified'),'storage_class_metadata':field('StorageClass')})
    return values


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--repo',type=Path,required=True)
    parser.add_argument('--phase14-capture',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    all_objects=[]; bindings=[]
    for location, rel, digest, table, month in EXPECTED:
        p=(args.repo/ROOT_PATH/rel) if location=='repo' else args.phase14_capture/rel
        raw=p.read_bytes()
        need(hashlib.sha256(raw).hexdigest()==digest, 'Listing hash mismatch: '+rel)
        objects=parse(raw,table,month)
        artifact_id=('retained_phase4/' if location=='repo' else 'retained_phase14/')+p.name
        bindings.append({'artifact_id':artifact_id,'sha256':digest,'bytes':len(raw),'prefix':f'v1.0/eth/{table}/date={month}-','listed_objects':len(objects),'terminal_page':True,'original_origin':'Phase4' if location=='repo' else 'Phase14','new_requests':0})
        for item in objects:
            all_objects.append({**item,'source_listing_id':artifact_id,'source_listing_sha256':digest})
    need(len({x['key'] for x in all_objects})==len(all_objects), 'Duplicate key across listings')
    days=[(date(2022,2,26)+timedelta(days=n)).isoformat() for n in range(30)]
    cells=[]
    for day in days:
        for table in ['blocks','logs','transactions']:
            selected=sorted((x for x in all_objects if x['day_utc']==day and x['table']==table),key=lambda x:x['key'])
            cells.append({'day_utc':day,'table':table,'listing_complete':True,'status':'LISTED_NONEMPTY' if selected else 'LISTED_EMPTY','objects':selected,'declared_object_bytes':sum(x['size_bytes'] for x in selected),'parquet_readability_verified':False,'object_content_sha256_verified':False})
    selected=[o for c in cells for o in c['objects']]
    # Prior Phase6 independently selected the same 30 dates for logs and blocks.
    p6=args.repo/ROOT_PATH/'incidents/source_availability_phase6/run_20261025T145900Z/availability.json'
    p6raw=p6.read_bytes()
    need(hashlib.sha256(p6raw).hexdigest()=='7957fd0c2f6ddd868dcca80ae71e2984429da94e5bc186440797a5a35f5c2f20','Phase6 metadata hash mismatch')
    prior=json.loads(p6raw)
    p14=args.phase14_capture/'summary.json'; p14raw=p14.read_bytes()
    need(hashlib.sha256(p14raw).hexdigest()=='8b85676f2dbe50ff5e6f4d66d98cd9510017b906a3ba8249496624566ab4d26b','Phase14 summary hash mismatch')
    previous=json.loads(p14raw)
    prior_by_key={o['key']:o for p in prior['partitions'] for o in p['objects']}
    comparisons=[]
    for item in selected:
        if item['key'] in prior_by_key:
            before=prior_by_key[item['key']]
            need(item['size_bytes']==before['size_bytes'] and item['etag_opaque']==before['etag_opaque'],'Phase6 source identity mismatch')
            comparisons.append(item['key'])
    lifi_by_key={o['key']:o for c in previous['day_table_cells'] for o in c['objects']}
    overlap=[o for o in selected if o['key'] in lifi_by_key]
    for item in overlap:
        before=lifi_by_key[item['key']]
        need(item['size_bytes']==before['size_bytes'] and item['etag_opaque']==before['etag_opaque'],'Phase14 overlap identity mismatch')
    union={**lifi_by_key,**{o['key']:o for o in selected}}
    result={'schema_version':'article2_phase15_revest_retained_source_inventory_v1','status':'COMPLETE_RETAINED_LISTING_METADATA_ONLY','case_name':'Revest Finance','catalogue_line':70,'chain_id':1,'window_utc':['2022-02-26T00:00:00Z','2022-03-28T00:00:00Z'],'window_days':30,'endpoint':'https://aws-public-blockchain.s3.us-east-2.amazonaws.com/','source_bindings':bindings,'retained_summary_bindings':[{'artifact_id':'retained_phase6/availability.json','sha256':hashlib.sha256(p6raw).hexdigest()},{'artifact_id':'retained_phase14/measurement_inventory_summary.json','sha256':hashlib.sha256(p14raw).hexdigest()}],'cells':cells,'day_table_cells':len(cells),'nonempty_cells':sum(c['status']=='LISTED_NONEMPTY' for c in cells),'empty_cells':sum(c['status']=='LISTED_EMPTY' for c in cells),'listed_objects':len(selected),'declared_object_bytes':sum(x['size_bytes'] for x in selected),'by_table':{table:{'objects':sum(x['table']==table for x in selected),'declared_object_bytes':sum(x['size_bytes'] for x in selected if x['table']==table)} for table in ['blocks','logs','transactions']},'phase6_overlapping_identities_equal':True,'phase6_compared_objects':len(comparisons),'lifi_overlap':{'shared_days':len({x['day_utc'] for x in overlap}),'shared_object_identities':len(overlap),'shared_declared_object_bytes':sum(x['size_bytes'] for x in overlap),'identities_equal':True},'lifi_revest_union':{'window_utc':['2022-02-19T00:00:00Z','2022-03-28T00:00:00Z'],'days':37,'listed_objects':len(union),'declared_object_bytes':sum(x['size_bytes'] for x in union.values()),'new_revest_only_objects':len(selected)-len(overlap),'new_revest_only_declared_bytes':sum(x['size_bytes'] for x in selected if x['key'] not in lifi_by_key),'meaning':'Shared listed objects can be acquired once and separately projected by fixed per-case rules; overlap is not duplicate independent evidence.'},'new_http_requests':0,'new_response_bytes':0,'new_object_payload_bytes':0,'new_data_rows_read':0,'new_detector_scores':0,'new_label_joins':0,'scientific_admissions':0,'limits':['Metadata is reused at its original capture times, not refreshed.','Opaque ETag values are not content SHA256; any later range/full acquisition must validate If-Match and exact bytes.','Nonempty listed partitions do not establish all required columns, readability, chain/source completeness or selected-log/status/header consistency.','Totals are declared whole-object metadata sizes, not downloaded bytes, selected-column costs or measured performance.','The Phase14 first-day footer is19February, outside this Revest window, and supplies no Revest-specific footer result.','No case or measurement is admitted by this inventory.']}
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k in ['status','day_table_cells','nonempty_cells','listed_objects','declared_object_bytes','by_table','phase6_compared_objects','lifi_overlap','lifi_revest_union']},indent=2))


if __name__=='__main__':
    main()
