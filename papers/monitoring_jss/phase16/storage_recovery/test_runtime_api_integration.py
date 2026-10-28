"""Real compact collector/pipeline API integration over 113 invented sources.

Only the HTTP opener is a local byte oracle. No real acquisition or acceptance
is simulated as scientific evidence; the test bypasses the separate gate.
"""
import argparse
from datetime import date
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent


def run(dependencies):
    sys.path.insert(0,dependencies)
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.parquet as pq
    import numpy as np
    import compact_collector as collector
    import test_compact_collector as helper
    spec=importlib.util.spec_from_file_location('storage_pipeline_api_integration',HERE/'pipeline.py')
    pipeline=importlib.util.module_from_spec(spec);spec.loader.exec_module(pipeline)
    p=pipeline.original_pipeline()
    sys.path.insert(0,str(HERE.parent/'qa'))
    import streaming_fault_checks as tables
    import audit_prepared_sources as audit
    from independent_compact_reader import IndependentCompactSource
    configs={};config_shas={}
    for short in ('lifi','revest'):
        path=HERE.parent/'protocol/configs'/f'{short}.json';cfg=pipeline.read_json(path)
        configs[cfg['case_id']]=cfg;config_shas[cfg['case_id']]=p.file_sha(path)
    study=p.days_between('2022-02-19','2022-03-28')
    all_days=p.days_between('2022-02-18','2022-03-29')
    sources=[];oracle={};generated={};headers={}
    hx=lambda n:'0x'+format(n,'064x')
    for index,day in enumerate(all_days):
        stamp=(date.fromisoformat(day)-date(1970,1,1)).days*86_400_000_000_000+1
        active={key:cfg for key,cfg in configs.items() if day in p.driver.expected_days(cfg)}
        block={'block_number':100+index,'block_hash':hx(100+index),'parent_hash':hx(99+index),
               'event_time_ns':stamp,'transaction_count':1 if active else 0}
        headers[day]=block
        kinds={'blocks':[block]}
        if active:
            tx={'chain_id':1,'block_number':100+index,'block_hash':hx(100+index),
                'transaction_hash':hx(1000+index),'transaction_index':0,'event_time_ns':stamp,'dataset_execution_status':1}
            logs=[]
            for number,cfg in enumerate(active.values()):
                logs.append({k:v for k,v in tx.items() if k!='dataset_execution_status'} |
                    {'address':cfg['population_addresses'][0],'topics':[],'data':'0x','log_index':number})
            kinds.update(transactions=[tx],logs=logs)
        for kind,rows in kinds.items():
            raw=tables.arrow_table(rows,kind,pa);out=pa.BufferOutputStream();pq.write_table(raw,out,row_group_size=1)
            data=out.getvalue().to_pybytes();key=f'v1.0/eth/{kind}/date={day}/part-invented.parquet'
            source={'table':kind,'day_utc':day,'key':key,'size_bytes':len(data),'etag_opaque':'"invented-fixed"',
                    'url':collector.base.ENDPOINT+key}
            sources.append(source);oracle[key]=data;generated[key]=raw
    chosen=next(s for s in sources if s['table']=='logs' and s['day_utc']==study[0])
    data=oracle[chosen['key']];size=len(data);footer=int.from_bytes(data[-8:-4],'little')
    metadata=pq.ParquetFile(pa.BufferReader(data)).metadata;col=metadata.row_group(0).column(0)
    offset=min(x for x in (col.dictionary_page_offset,col.data_page_offset) if type(x)is int and x>=4)
    fixture=helper.CompactTests();fixture.setUp()
    try:
        fixture.fixture(data,[(0,4),(size-8,8),(size-8-footer,footer)],(offset,col.total_compressed_size))
        # Keep the fixture's canonical source key/ETag; all response identities
        # remain exact. Replace the corresponding invented inventory entry.
        old_key=chosen['key'];sources[sources.index(chosen)]=fixture.source
        oracle[fixture.source['key']]=oracle.pop(old_key);chosen=fixture.source
        collector.save(fixture.repo/'inventory.json',{'objects':sources})
        fixture.original_plan['source_union']['sha256']=collector.file_sha(fixture.repo/'inventory.json')
        collector.save(fixture.parent/'frozen_plan.json',fixture.original_plan);fixture.refresh()
        identities={x['url']:x for x in sources}
        class Oracle:
            def __init__(self):self.calls=0
            def open(self,request,timeout):
                source=identities[request.full_url]
                start,end=map(int,request.get_header('Range').removeprefix('bytes=').split('-'))
                self.calls+=1
                return helper.Response(source,start,oracle[source['key']][start:end+1])
        opener=Oracle();session=fixture.make(opener)
        session.reacquire_pending_range()
        plan={'study_start':study[0],'study_end_exclusive':'2022-03-28','accepted_header_anchors':[],
            'limits':{'max_transaction_rows_per_day':100,'max_log_rows_per_day':100,
                      'max_selected_transactions_per_case_day':100,'max_selected_logs_per_day':100}}
        readers={}
        def open_source(source):
            reader=collector.CompactSourceReader(source,session,session.storage_dir,pa,pq).open()
            readers[source['key']]=reader;return reader
        payload=pipeline.prepare_sources(plan,{'objects':sources},configs,config_shas,open_source,
            fixture.runtime,{},p,pa,pc,np)
        session.close('COMPLETE')
        assert payload['transport_sources']==113 and payload['study_days']==37
        assert len(readers)==113 and len(payload['selection_manifests'])==2
        for item in payload['selection_manifests'].values():
            assert item['days']==30 and item['transactions']==30
        assert not list(fixture.runtime.rglob('*.parquet'))
        storage=pipeline.read_json(fixture.runtime/'runtime_source_storage.json')
        assert len(storage)==113 and all(v['storage_kind']=='compact_descriptor' for v in storage.values())
        assert payload['runtime_source_storage_sha256']==pipeline.file_sha(fixture.runtime/'runtime_source_storage.json')
        assert payload['transport_sources_sha256']==pipeline.file_sha(fixture.runtime/'transport_sources.json')
        # Exercise final producer descriptors with the independently implemented
        # reader and unchanged row auditor for a day where both cases overlap.
        day='2022-02-26';offline={kind:[] for kind in ('blocks','logs','transactions')}
        for source in (x for x in sources if x['day_utc']==day):
            prod=readers[source['key']];descriptor=pipeline.read_json(prod.path)
            blobs=[{'start':x['start'],'length':x['length'],'path':str(prod.path.parent/x['blob_path']),
                    'sha256':x['blob_sha256']} for x in descriptor['segments']]
            proof={'source_key':source['key'],'source':source,'storage_kind':'compact_descriptor',
                'verified_blobs':blobs,'available_ranges':[[b['start'],b['start']+b['length']] for b in blobs]}
            offline[source['table']].append(IndependentCompactSource(source,prod.manifest(),proof,pa,pq))
        header_table,_=audit.header_rows(offline['blocks'],day,pa,pc)
        prepared,summary=audit.audit_day(day,offline,header_table,headers['2022-02-25'],headers['2022-02-27'],
             configs,fixture.runtime/'days'/day,pa,pc,np)
        assert len(prepared['cases'])==2 and all(v['selected_transactions']==1 for v in summary['cases'].values())
        return {'status':'PASS_INVENTED_REAL_COLLECTOR_PIPELINE_API_INTEGRATION_ONLY',
            'sources':113,'study_days':37,'case_days':60,'local_response_oracle_calls':opener.calls,
            'real_ResourceSession_and_CompactSourceReader':True,'unchanged_prepare_day':True,
            'actual_scientific_acceptance_gate_exercised':False,'independent_both_case_row_audit_days':1,
            'actual_acquired_payloads_read':0,'network_requests':0,'new_sparse_parquet_files':0,
            'pipeline_sha256':pipeline.file_sha(HERE/'pipeline.py'),
            'collector_sha256':pipeline.file_sha(HERE/'compact_collector.py'),
            'test_sha256':pipeline.file_sha(__file__)}
    finally:fixture.doCleanups()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--dependencies',required=True);parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args();report=run(args.dependencies);args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
