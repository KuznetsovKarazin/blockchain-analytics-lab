"""New compact-storage integration through the unchanged independent row audit.

Only invented tiny tables are used. The old check suites are not executed.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'qa'))
import audit_prepared_sources as original
import streaming_fault_checks as fixture_helpers
from independent_compact_reader import IndependentCompactSource


def run(dependencies):
    sys.path.insert(0, dependencies)
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.parquet as pq
    import numpy as np
    _, producer = fixture_helpers.load_pipeline()
    f = fixture_helpers.fixture(pa)
    with tempfile.TemporaryDirectory(prefix='compact_row_invented_') as directory:
        root = Path(directory); offline = {'blocks': [], 'transactions': [], 'logs': []}; readers = copy.deepcopy(offline)
        parts = [('blocks', [f['header']], 0), ('transactions', f['transactions'], 0),
                 ('logs', f['logs'][:2], 0), ('logs', f['logs'][2:], 2)]
        omitted = 0
        for part, (kind, rows, offset) in enumerate(parts):
            raw = fixture_helpers.arrow_table(rows, kind, pa)
            stream = pa.BufferOutputStream(); pq.write_table(raw, stream, row_group_size=1)
            data = stream.getvalue().to_pybytes(); metadata = pq.ParquetFile(pa.BufferReader(data)).metadata
            footer = len(data) - 8 - int.from_bytes(data[-8:-4], 'little')
            spans = [(0, 4), (footer, len(data))]
            for group in range(metadata.num_row_groups):
                rg = metadata.row_group(group)
                for index in range(rg.num_columns):
                    c = rg.column(index); top = c.path_in_schema.split('.', 1)[0]
                    if kind == 'logs' and group + offset == 4 and top in ('topics', 'data'):
                        omitted += 1; continue
                    start = min(x for x in (c.dictionary_page_offset, c.data_page_offset) if x is not None and x >= 4)
                    spans.append((start, start+c.total_compressed_size))
            blobs = []
            for index, (start, end) in enumerate(sorted(spans)):
                path = root / f'blob-{part}-{index}'; value=data[start:end];path.write_bytes(value)
                blobs.append({'start': start, 'length': len(value), 'path': str(path), 'sha256': hashlib.sha256(value).hexdigest()})
            identity = {'key':f'{kind}-{part}','size_bytes':len(data),'day_utc':f['day'],'table':kind,
                        'etag_opaque':'invented','url':f'https://example.invalid/{part}'}
            manifest = {'source':identity,'row_count_metadata':metadata.num_rows,
                'row_group_count':metadata.num_row_groups,'row_group_rows':[1]*metadata.num_row_groups}
            proof = {'source_key':identity['key'],'source':identity,'storage_kind':'compact_descriptor',
                     'verified_blobs':blobs,'available_ranges':[[x['start'],x['start']+x['length']] for x in blobs]}
            offline[kind].append(IndependentCompactSource(identity|{'irrelevant_inventory_annotation':True},manifest,proof,pa,pq))
            reader=fixture_helpers.Reader(identity['key'],[raw.slice(i,1) for i in range(len(raw))])
            reader.manifest=lambda value=manifest:value
            readers[kind].append(reader)
        assert omitted==2
        headers,_=original.header_rows(offline['blocks'],f['day'],pa,pc)
        cfg={'case_a':{'population_addresses':[f['a']]},'case_b':{'population_addresses':[f['b']]}}
        limits={'max_transaction_rows_per_day':100,'max_log_rows_per_day':100,
                'max_selected_transactions_per_case_day':100,'max_selected_logs_per_day':100}
        folder=root/'prepared'; producer.prepare_day(f['day'],readers,headers,f['previous'],f['following'],cfg,folder,pa,pc,np,limits)
        prepared, summary=original.audit_day(f['day'],offline,headers,f['previous'],f['following'],cfg,folder,pa,pc,np)
        assert summary['all_transaction_rows']==4 and summary['all_log_identity_rows']==6
        for case,address in [('case_a',f['a']),('case_b',f['b'])]:
            selection,baseline=fixture_helpers.pure_expected(f,address)
            assert prepared['cases'][case]['selected_transactions']==selection['transactions']
            assert prepared['cases'][case]['bundles']==baseline['normalized_transactions']
        checks=['compact_multipart_arrow_projection_matches_frozen_pure_adapter_for_both_cases',
                'all_identity_rows_audited_with_nonselected_transfer_payload_absent']
        wrong=copy.deepcopy(prepared);wrong['cases']['case_a']['bundles'][0]['logs'][1]['data']='0x'+'0'*64
        parts=original.read_json(folder/'source_parts.json');parts['prepared_cases_sha256']=original.value_sha(wrong['cases'])
        wrong['partition_manifest_sha256']=original.write(folder/'source_parts.json',parts);original.write(folder/'prepared.json',wrong)
        try:original.audit_day(f['day'],offline,headers,f['previous'],f['following'],cfg,folder,pa,pc,np)
        except ValueError as exc:assert 'independently reread source' in str(exc)
        else:raise AssertionError('coherently rehashed prepared forgery accepted')
        checks.append('coherently_rehashed_selected_payload_forgery_rejected_against_compact_original_bytes')
    return {'status':'PASS_NEW_SYNTHETIC_COMPACT_ROW_CHECKS_ONLY','checks_passed':len(checks),'checks':checks,
        'original_row_auditor_sha256':original.file_sha(original.__file__),
        'compact_reader_sha256':original.file_sha(HERE/'independent_compact_reader.py'),
        'test_sha256':original.file_sha(__file__),'actual_sources_read':False,'network_requests':0,
        'original_suites_rerun':False,'detector_scores':0}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--dependencies',required=True);p.add_argument('--report',type=Path,required=True)
    args=p.parse_args();report=run(args.dependencies);args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'checks':report['checks_passed']}))
