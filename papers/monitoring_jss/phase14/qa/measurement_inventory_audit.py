#!/usr/bin/env python3
"""Independent reconstruction of retained S3 listing evidence; no producer imports."""
import argparse
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import urllib.parse
import xml.etree.ElementTree as ET

PHASE=Path(__file__).resolve().parents[1]
PAPER=PHASE.parent
BASE='https://aws-public-blockchain.s3.us-east-2.amazonaws.com/'
NS='{http://s3.amazonaws.com/doc/2006-03-01/}'
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def read(path):
    def pairs(items):
        result={}
        for key,value in items:
            assert key not in result
            result[key]=value
        return result
    return json.loads(Path(path).read_bytes(),object_pairs_hook=pairs)
def digest(path):
    return sha(Path(path).read_bytes())
def timestamp(value):
    return datetime.fromisoformat(value.replace('Z','+00:00'))
def listing(raw,prefix,token):
    root=ET.fromstring(raw);assert root.tag==NS+'ListBucketResult'
    def one(name):
        found=root.findall(NS+name);assert len(found)<=1
        return found[0].text if found else None
    assert one('Name')=='aws-public-blockchain' and one('Prefix')==prefix
    assert one('ContinuationToken')==token and not root.findall(NS+'CommonPrefixes')
    truncated=one('IsTruncated');assert truncated in ('true','false')
    next_token=one('NextContinuationToken')
    assert (truncated=='true' and next_token) or (truncated=='false' and next_token is None)
    out=[];keys=set()
    for node in root.findall(NS+'Contents'):
        def field(name):
            found=node.findall(NS+name);assert len(found)<=1
            return found[0].text if found else None
        key,size,etag=field('Key'),field('Size'),field('ETag')
        assert key and key.startswith(prefix) and key not in keys
        assert size and size.isdigit() and etag is not None
        match=re.fullmatch(r'v1\.0/eth/(blocks|logs|transactions)/date=(\d{4}-\d{2}-\d{2})/[^/]+\.parquet',key)
        assert match and date.fromisoformat(match.group(2)).isoformat()==match.group(2)
        keys.add(key);out.append({'key':key,'size_bytes':int(size),'etag_opaque':etag,
            'last_modified_metadata':field('LastModified'),'storage_class_metadata':field('StorageClass')})
    assert one('KeyCount') is not None and int(one('KeyCount'))==len(out)<=1000
    return out,truncated=='true',next_token

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--attempt',type=Path,required=True)
    parser.add_argument('--root-freeze',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=PHASE/'qa/measurement_inventory_actual_review.json')
    args=parser.parse_args();assert not args.output.exists()
    folder=args.attempt;plan=read(folder/'frozen_plan.json');summary=read(folder/'summary.json')
    freeze=read(args.root_freeze);acceptance=read(folder/'acceptance.json');ledger=read(folder/'requests.json')
    runner=PHASE/'measurement_design/list_measurement_sources.py'
    bindings={row['path']:row['sha256'] for row in freeze['bindings']}
    assert len(bindings)==len(freeze['bindings'])==3 and freeze['status']=='ACCEPTED_BEFORE_FIRST_REQUEST'
    assert all(digest(PAPER/path)==value for path,value in bindings.items())
    assert digest(folder/'frozen_plan.json')==summary['plan_sha256']==bindings['phase14/measurement_design/measurement_metadata_plan.json']==acceptance['plan_sha256']
    assert digest(runner)==digest(folder/'runner_source.py')==summary['runner_sha256']==bindings['phase14/measurement_design/list_measurement_sources.py']==acceptance['runner_sha256']
    frozen_time=freeze.get('accepted_utc',freeze.get('accepted_at_utc'))
    assert frozen_time and timestamp(frozen_time)<timestamp(acceptance['started_utc'])
    assert plan['endpoint']==BASE
    assert plan['days_utc']==[(date(2022,2,19)+timedelta(days=i)).isoformat() for i in range(30)]
    assert digest(PAPER/plan['parser_binding']['path'])==plan['parser_binding']['sha256']
    assert digest(PAPER/plan['phase6_comparison']['path'])==plan['phase6_comparison']['sha256']
    inventories={};reuse=[]
    for row in plan['reused_listings']:
        path=PAPER/row['path'];raw=path.read_bytes();assert sha(raw)==row['sha256']
        objects,truncated,token=listing(raw,row['prefix'],None);assert not truncated and token is None
        inventories[row['prefix']]={'prefix':row['prefix'],'objects':objects,'listing_complete':True,
            'origin':'retained_phase4_month_listing','new_requests':0}
        reuse.append({**row,'bytes':len(raw),'objects':len(objects),'new_requests':0})
    assert summary['reused_listings']==reuse and len(reuse)==2
    assert len(ledger)<=8
    prefix_index=0;page=1;token=None;tokens=set();total=0;request_results=[]
    for ordinal,record in enumerate(ledger,1):
        assert record['ordinal']==ordinal and prefix_index<len(plan['new_prefixes'])
        assert timestamp(acceptance['started_utc'])<=timestamp(record['started_utc'])<=timestamp(record['completed_utc'])
        if ordinal>1:assert timestamp(ledger[ordinal-2]['completed_utc'])<=timestamp(record['started_utc'])
        prefix=plan['new_prefixes'][prefix_index]
        if page==1:
            assert prefix not in inventories
            inventories[prefix]={'prefix':prefix,'objects':[],'listing_complete':False,
                'origin':'fresh_phase14_metadata','new_requests':0}
        value=inventories[prefix];value['new_requests']+=1
        for side in ('request','response'):
            name=record[side+'_file'];assert Path(name).name==name
            assert digest(folder/name)==record[side+'_sha256']
        request=read(folder/record['request_file']);raw=(folder/record['response_file']).read_bytes()
        assert request=={'url':request['url'],'method':'GET','kind':'S3_ListObjectsV2_metadata',
                         'prefix':prefix,'page':page,'continuation_token':token}
        parsed=urllib.parse.urlsplit(request['url']);assert parsed.scheme+'://'+parsed.netloc+parsed.path==BASE
        query={'list-type':['2'],'prefix':[prefix],'max-keys':['1000']}
        if token is not None:query['continuation-token']=[token]
        assert urllib.parse.parse_qs(parsed.query,strict_parsing=True)==query
        assert len(raw)==record['response_bytes']<=1048576;total+=len(raw);assert total<=8388608
        request_results.append({'ordinal':ordinal,'prefix':prefix,'page':page,'response_bytes':len(raw),
            'response_sha256':sha(raw),'body_complete':record['body_complete']})
        if not record['body_complete']:
            assert ordinal==len(ledger) and summary['failure']
            break
        assert record['http_status']==200 and record['body_at_cap_eof_unproved'] is False and len(raw)<1048576
        objects,truncated,next_token=listing(raw,prefix,token)
        assert len(objects)==record['parsed_object_count'] and truncated==record['is_truncated']
        existing={x['key'] for x in value['objects']};assert not existing.intersection(x['key'] for x in objects)
        assert next_token is None or next_token not in tokens
        value['objects'].extend(objects);value['listing_complete']=not truncated
        if truncated:
            tokens.add(next_token);token=next_token;page+=1
            if page>2:assert ordinal==len(ledger) and summary['failure']
        else:
            prefix_index+=1;page=1;token=None;tokens=set()
    fresh=[x for x in inventories.values() if x['origin']=='fresh_phase14_metadata']
    assert summary['new_listings']==fresh
    cells=[];outside=0
    for value in inventories.values():
        outside+=sum(item['key'].split('/')[3].removeprefix('date=') not in plan['days_utc'] for item in value['objects'])
    for day in plan['days_utc']:
        for table in ('blocks','logs','transactions'):
            prefix=f'v1.0/eth/{table}/date={day[:7]}-';value=inventories.get(prefix)
            complete=bool(value and value['listing_complete'])
            objects=[] if value is None else [{**item,'url':BASE+item['key'],'listing_prefix':prefix,
                'listing_origin':value['origin']} for item in value['objects'] if item['key'].startswith(f'v1.0/eth/{table}/date={day}/')]
            objects.sort(key=lambda x:x['key']);assert len(objects)<=4 and all(x['size_bytes']>0 for x in objects)
            cells.append({'day_utc':day,'table':table,'listing_complete':complete,
                'status':'LISTED_NONEMPTY' if complete and objects else 'LISTED_EMPTY' if complete else 'UNAVAILABLE_OR_INCOMPLETE_LISTING',
                'objects':objects,'object_bytes_metadata':sum(x['size_bytes'] for x in objects),
                'object_content_sha256_verified':False,'parquet_readability_verified':False})
    assert summary['day_table_cells']==cells and len(cells)==90
    expected={'new_metadata_requests':len(ledger),'new_metadata_response_bytes':total,'selected_day_table_cell_count':90,
        'listed_nonempty_cells':sum(x['status']=='LISTED_NONEMPTY' for x in cells),
        'listed_empty_cells':sum(x['status']=='LISTED_EMPTY' for x in cells),
        'unavailable_or_incomplete_cells':sum(x['status']=='UNAVAILABLE_OR_INCOMPLETE_LISTING' for x in cells),
        'selected_object_count':sum(len(x['objects']) for x in cells),
        'selected_object_total_bytes_metadata':sum(x['object_bytes_metadata'] for x in cells),
        'out_of_window_month_listing_object_count':outside}
    assert all(summary[k]==v for k,v in expected.items())
    completed=prefix_index==4 and all(x['listing_complete'] for x in cells)
    assert summary['status']==('COMPLETE_LISTING_METADATA_ONLY' if completed and summary['failure'] is None else 'UNAVAILABLE_OR_PARTIAL_LISTING_METADATA_ONLY')
    old={(x['day_utc'],x['table']):x for x in read(PAPER/plan['phase6_comparison']['path'])['partitions']}
    comparisons=[]
    for cell in cells:
        earlier=old.get((cell['day_utc'],cell['table']))
        if earlier is not None:
            identity=lambda x:(x['key'],x['size_bytes'],x['etag_opaque'])
            comparisons.append({'day_utc':cell['day_utc'],'table':cell['table'],'identities_equal':cell['listing_complete'] and
                sorted(map(identity,cell['objects']))==sorted(map(identity,earlier['objects']))})
    assert summary['phase6_overlapping_identity_comparisons']==comparisons
    assert all(summary[k]==0 for k in ('new_parquet_object_requests','new_chain_row_observations','detector_scores','scientific_admissions'))
    assert summary['fixed_address_scope_adoption_performed_by_this_program'] is False
    result={'schema':'article2_phase14_measurement_inventory_actual_review_v1','status':'PASS_INDEPENDENT_METADATA_INVENTORY_AUDIT',
        'audited_utc':datetime.now(timezone.utc).isoformat(),'auditor_sha256':digest(Path(__file__)),
        'root_freeze_sha256':digest(args.root_freeze),'plan_sha256':digest(folder/'frozen_plan.json'),
        'runner_sha256':digest(runner),'summary_sha256':digest(folder/'summary.json'),'requests_sha256':digest(folder/'requests.json'),
        'requests':request_results,'reused_listing_count':len(reuse),'reconstructed_totals':expected,
        'phase6_identity_comparison_count':len(comparisons),'phase6_identity_mismatch_count':sum(not x['identities_equal'] for x in comparisons),
        'all_90_cells_exactly_reconstructed':True,'request_and_response_bytes_hash_verified':True,
        'metadata_only':True,'payload_readability_proved':False,'source_completeness_proved':False,
        'new_network_requests_by_audit':0,'producer_modules_imported':0,'old_suites_rerun':0,'detector_scores':0,'scientific_admissions':0,
        'auditor_invocations':2,'successful_full_actual_audits':1,
        'initial_invocation_note':'Initial invocation stopped before request-byte auditing because root freeze stores hashes in bindings[]; auditor was aligned to that exact schema before the successful full audit.'}
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':
    main()
