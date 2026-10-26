#!/usr/bin/env python3
"""Independently bind retained HTTP ranges and reconstruct footer-only metadata."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode=True
PHASE=Path(__file__).resolve().parents[1]
PAPER=PHASE.parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(path):return sha(Path(path).read_bytes())
def read(path):
    def pairs(items):
        result={}
        for key,value in items:
            assert key not in result
            result[key]=value
        return result
    return json.loads(Path(path).read_bytes(),object_pairs_hook=pairs)
def when(value):return datetime.fromisoformat(value.replace('Z','+00:00'))
def metadata_description(source,footer,trailer,plan,pa,pq):
    assert len(trailer)==8 and trailer[4:]==b'PAR1' and int.from_bytes(trailer[:4],'little')==len(footer)
    metadata=pq.read_metadata(pa.BufferReader(b'PAR1'+footer+trailer))
    schema=metadata.schema.to_arrow_schema();caps=plan['caps']
    assert 0<metadata.num_row_groups<=caps['max_row_groups'] and 0<metadata.num_rows<=caps['max_rows']
    assert 0<len(schema.names)<=caps['max_top_level_columns'] and len(schema.names)==len(set(schema.names))
    required=set(plan['required_columns'][source['table']]);assert required<=set(schema.names)
    timestamp='timestamp' if source['table']=='blocks' else 'block_timestamp'
    assert pa.types.is_timestamp(schema.field(timestamp).type) and schema.field(timestamp).type.unit in ('s','ms','us','ns')
    if source['table']=='transactions':assert schema.field('receipt_status').type==pa.int64()
    chunks=[];groups=[];first_footer=source['size_bytes']-len(footer)-8
    for group_index in range(metadata.num_row_groups):
        group=metadata.row_group(group_index)
        assert 0<=group.num_rows and group.num_columns<=caps['max_leaf_columns']
        groups.append({'row_group':group_index,'rows':group.num_rows,'leaf_columns':group.num_columns})
        found=set()
        for column_index in range(group.num_columns):
            column=group.column(column_index);top=column.path_in_schema.partition('.')[0]
            if top not in required:continue
            assert column.file_path in (None,'')
            offsets=[x for x in (column.dictionary_page_offset,column.data_page_offset) if type(x)is int and x>=4]
            assert offsets and column.total_compressed_size>0
            begin=min(offsets);end=begin+column.total_compressed_size;assert end<=first_footer
            chunks.append({'row_group':group_index,'column':top,'leaf_path':column.path_in_schema,
                'physical_type':column.physical_type,'compression':column.compression,'start':begin,
                'end_exclusive':end,'compressed_bytes':column.total_compressed_size,
                'dictionary_page_offset':column.dictionary_page_offset,'data_page_offset':column.data_page_offset})
            found.add(top)
        assert found==required
    assert sum(x['rows'] for x in groups)==metadata.num_rows
    scenarios=[]
    for name,names in plan['projection_scenarios'][source['table']].items():
        selected=[x for x in chunks if x['column'] in names]
        spans=[]
        for begin,end in sorted((x['start'],x['end_exclusive']) for x in selected):
            assert begin>=4 and end>begin and (not spans or begin>=spans[-1][1])
            if spans and begin==spans[-1][1]:spans[-1][1]=end
            else:spans.append([begin,end])
        ranges=[{'start':a,'end_exclusive':b,'bytes':b-a} for a,b in spans]
        scenarios.append({'name':name,'columns':names,'column_chunks':len(selected),'merged_ranges':ranges,
            'range_request_count':len(ranges),'compressed_payload_bytes':sum(x['bytes'] for x in ranges),
            'rows_read_or_decoded':0,'meaning':'Exact footer-derived full selected-column span cost; no predicate result or payload acquired.'})
    return {'table':source['table'],'day_utc':source['day_utc'],'key':source['key'],
        'source_size_bytes':source['size_bytes'],'source_etag_opaque':source['etag_opaque'],
        'footer_bytes':len(footer),'footer_sha256':sha(footer),'trailer_sha256':sha(trailer),
        'schema':[{'name':f.name,'type':str(f.type),'nullable':f.nullable} for f in schema],
        'row_count_metadata':metadata.num_rows,'row_group_count':metadata.num_row_groups,'row_groups':groups,
        'selected_column_chunks':chunks,'projection_scenarios':scenarios,'statistics_values_exported':False,
        'row_data_read_or_decoded':False,'whole_source_sha256_verified':False,
        'local_decoder_envelope':'synthetic PAR1 + exact retained footer + exact retained trailer'}
def main():
    p=argparse.ArgumentParser()
    p.add_argument('--attempt',type=Path,required=True);p.add_argument('--root-freeze',type=Path,required=True)
    p.add_argument('--output',type=Path,default=PHASE/'qa/measurement_footer_actual_review.json')
    a=p.parse_args();assert not a.output.exists()
    folder=a.attempt;plan=read(folder/'frozen_plan.json');summary=read(folder/'summary.json')
    freeze=read(a.root_freeze);acceptance=read(folder/'acceptance.json');records=read(folder/'requests.json')
    bindings={x['path']:x['sha256'] for x in freeze['bindings']};assert len(bindings)==len(freeze['bindings'])
    assert all(digest(PAPER/path)==value for path,value in bindings.items())
    assert when(freeze['accepted_utc'])<when(acceptance['started_utc'])
    assert digest(folder/'frozen_plan.json')==summary['plan_sha256']==acceptance['plan_sha256']==bindings['phase14/measurement_design/first_day_footer_plan.json']
    assert digest(folder/'runner_source.py')==summary['runner_sha256']==acceptance['runner_sha256']==bindings['phase14/measurement_design/probe_parquet_footers.py']
    setup_path=PAPER/plan['dependency']['setup_receipt_path'];assert digest(setup_path)==plan['dependency']['setup_receipt_sha256']
    site=Path(read(setup_path)['site_directory']);wheel=site.parent/'wheels'/plan['dependency']['wheel_filename']
    assert digest(wheel)==plan['dependency']['wheel_sha256']==acceptance['dependency_wheel_sha256']
    sys.path.insert(0,str(site))
    import pyarrow as pa
    import pyarrow.parquet as pq
    assert pa.__version__==plan['dependency']['version']==acceptance['pyarrow_version']
    assert Path(pa.__file__).resolve().is_relative_to(site.resolve())
    assert len(records)<=6 and plan['day_utc']=='2022-02-19'
    cursor=0;total=0;descriptions=[];request_review=[];stopped=False
    for source in plan['sources']:
        payloads={};length=8;start=source['size_bytes']-8
        for kind in ('trailer','footer'):
            if cursor==len(records):stopped=True;break
            row=records[cursor];cursor+=1
            assert row['ordinal']==cursor and row['table']==source['table'] and row['kind']==kind
            assert when(acceptance['started_utc'])<=when(row['started_utc'])<=when(row['completed_utc'])
            if cursor>1:assert when(records[cursor-2]['completed_utc'])<=when(row['started_utc'])
            for side in ('request','response'):
                name=row[side+'_file'];assert Path(name).name==name and digest(folder/name)==row[side+'_sha256']
            request=read(folder/row['request_file']);raw=(folder/row['response_file']).read_bytes()
            assert request=={'method':'GET','url':source['url'],'headers':{
                'Range':f'bytes={start}-{start+length-1}','If-Match':source['etag_opaque'],
                'User-Agent':'Article2-footer-metadata/1','Accept':'application/octet-stream'},
                'kind':kind,'start':start,'length':length,'source_size_bytes':source['size_bytes']}
            assert len(raw)==row['response_bytes']<=length;total+=len(raw)
            request_review.append({'ordinal':cursor,'table':source['table'],'kind':kind,'range_start':start,
                'requested_bytes':length,'retained_bytes':len(raw),'response_sha256':sha(raw),'transport_ok':row['transport_ok']})
            if not row['transport_ok']:
                assert cursor==len(records) and summary['status']=='UNAVAILABLE_OR_PARTIAL_FIRST_DAY_FOOTER_METADATA'
                stopped=True;break
            assert row['http_status']==206 and row['etag']==source['etag_opaque']
            assert row['content_range']==f'bytes {start}-{start+length-1}/{source["size_bytes"]}'
            assert int(row['content_length'])==length==len(raw)
            payloads[kind]=raw
            if kind=='trailer':
                assert len(raw)==8 and raw[4:]==b'PAR1'
                length=int.from_bytes(raw[:4],'little');assert 0<length<=plan['caps']['max_footer_bytes'] and length+12<=source['size_bytes']
                start=source['size_bytes']-8-length
        if stopped:break
        descriptions.append(metadata_description(source,payloads['footer'],payloads['trailer'],plan,pa,pq))
    assert cursor==len(records) and total==summary['retained_response_bytes']<=plan['caps']['total_response_bytes']
    assert summary['new_range_requests']==len(records) and summary['sources']==descriptions
    assert summary['fully_described_sources']==len(descriptions)
    if not stopped:assert len(descriptions)==3 and summary['status']=='COMPLETE_FIRST_DAY_SCHEMA_AND_PROJECTION_METADATA_ONLY'
    assert all(summary[x] is False for x in ('row_data_read_or_decoded','whole_source_hashes_verified','full_window_cost_established'))
    assert all(summary[x]==0 for x in ('new_package_downloads_or_installs','detector_scores','scientific_admissions'))
    result={'schema':'article2_phase14_measurement_footer_actual_review_v1','status':'PASS_INDEPENDENT_RETAINED_FOOTER_AUDIT',
        'audited_utc':datetime.now(timezone.utc).isoformat(),'auditor_sha256':digest(Path(__file__)),
        'root_freeze_sha256':digest(a.root_freeze),'plan_sha256':digest(folder/'frozen_plan.json'),
        'summary_sha256':digest(folder/'summary.json'),'requests_sha256':digest(folder/'requests.json'),
        'dependency_wheel_sha256':digest(wheel),'pyarrow_version':pa.__version__,'requests':request_review,
        'new_range_requests':len(records),'retained_response_bytes':total,'described_sources':len(descriptions),
        'source_summaries':[{'table':x['table'],'footer_bytes':x['footer_bytes'],'row_count_metadata':x['row_count_metadata'],
            'row_group_count':x['row_group_count'],'projection_scenarios':x['projection_scenarios']} for x in descriptions],
        'all_source_descriptions_exactly_reconstructed':True,'producer_modules_imported':0,'row_pages_decoded':0,
        'new_network_requests_by_audit':0,'new_packages_downloaded_or_installed':0,'old_suites_rerun':0,
        'limitations':['Independent reconstruction uses the same pinned PyArrow decoder, not parser diversity.',
            'Synthetic leading magic does not verify source header; whole files and whole-window costs remain unobserved.',
            'Raw metadata statistics are not exported or used for target selection; no core activity or labels were computed.']}
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
