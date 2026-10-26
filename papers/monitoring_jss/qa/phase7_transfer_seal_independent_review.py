"""Independent allowlist, CRC/hash/size and audited-runtime equality verification."""
from pathlib import Path,PurePosixPath
import hashlib,json,zipfile
W=Path('/workspace/scratch/159bf77d8682');R=W/'monitoring-work';P=R/'papers/monitoring_jss'
D=P/'runs/transfer_sample_design_20261026T075504_353899Z'
T=Path('/tmp/article2-transfer-development-jv8ffr08')
ARCHIVE=R/'data/raw/monitoring_jss/transfer_samples/transfer_sample_20261026T075822_228291Z_sealed_evidence.zip'
EXPECTED_SHA='c9e9c2672a5be4256dcc775e369f7c44168b6c69225d42710223d48dadac7cf8'
SOURCE=R/'data/raw/monitoring_jss/protocol_logs/2023-03-01/protocol_logs_20261025T083346_282558Z'
def h(data):return hashlib.sha256(data).hexdigest()
freeze=json.loads((D/'design_freeze.json').read_text());actual_audit=json.loads((W/'phase7_transfer_actual_independent_review.json').read_text())
assert actual_audit['status']=='PASS' and h(ARCHIVE.read_bytes())==EXPECTED_SHA and ARCHIVE.stat().st_size==2122767
expected={}
for name in ('selected_logs.jsonl','matching_headers.jsonl'):expected['archived_input/'+name]=SOURCE/name
for name in ['design_freeze.json',*freeze['frozen_file_sha256']]:expected['design/'+name]=D/name
for name in freeze['source_sha256']:expected['executed_source/'+name]=T/'source_snapshot'/name
expected['execution/phase7_transfer_execution.json']=W/'phase7_transfer_execution.json'
expected['recovery/phase7_transfer_selection.json']=W/'phase7_transfer_selection.json'
for name in ('sample_summary.json','collection_aggregate.json'):expected['run/public/'+name]=T/'public'/name
for i in range(10):
    folder=T/'raw'/f'tx_{i:02d}'
    record=json.loads((folder/'source_record.json').read_text())
    for name in ['source_record.json','normalized_bundle.json','transaction_summary.json','transfer_observation.json']:
        expected[f'run/raw/tx_{i:02d}/'+name]=folder/name
    for source in [record['metadata'],*record['pages']]:
        name=source['key'];expected[f'run/raw/tx_{i:02d}/'+name]=folder/name
        expected[f'run/raw/tx_{i:02d}/'+name+'.receipt.json']=folder/(name+'.receipt.json')
with zipfile.ZipFile(ARCHIVE) as z:
    assert len(z.infolist())==len(set(z.namelist()))==102
    assert set(z.namelist())==set(expected)|{'ARCHIVE_MANIFEST.json'}
    assert all(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts for name in z.namelist())
    manifest=json.loads(z.read('ARCHIVE_MANIFEST.json'));entries={r['path']:r for r in manifest['files']}
    assert set(entries)==set(expected) and len(entries)==len(manifest['files'])==101
    for name,path in expected.items():
        body=z.read(name);entry=entries[name]
        assert len(body)==entry['bytes'] and h(body)==entry['sha256']
        assert body==path.read_bytes(),name
    aggregate=json.loads(z.read('run/public/collection_aggregate.json'))
    assert aggregate['observation_counts_summed']==actual_audit['aggregate_counts']
    assert aggregate['matched_archived_core_logs']==actual_audit['selected_core_logs']==58
    assert aggregate['accepted_observations']==actual_audit['accepted_transactions_independently_recomputed']==10
    assert aggregate['requests_attempted']==len(actual_audit['request_receipts'])==21
    assert aggregate['http_response_bytes']==sum(r['bytes'] for r in actual_audit['request_receipts'])==564966
    assert aggregate['unique_tokens_with_monitored_erc20_shaped_activity']==actual_audit['distinct_monitored_boundary_token_emitters']==11
    emitters=set()
    for i in range(10):
        bundle=json.loads(z.read(f'run/raw/tx_{i:02d}/normalized_bundle.json'))
        emitters.update(r['address'] for r in bundle['logs'])
    assert len(emitters)==aggregate['unique_provider_log_emitters']==46
report={'schema_version':'phase7_transfer_seal_independent_review_v1','status':'PASS','archive_path':str(ARCHIVE),'archive_sha256':EXPECTED_SHA,'archive_bytes':ARCHIVE.stat().st_size,'zip_entries':102,'manifested_members':101,'allowlist_independently_reconstructed':True,'all_member_crc_sha256_size_verified':True,'all_members_equal_audited_runtime_frozen_sources_or_bound_archive_input':True,'semantic_audit_sha256':h((W/'phase7_transfer_actual_independent_review.json').read_bytes()),'auditor_sha256':h(Path(__file__).read_bytes()),'request_response_bytes':564966,'unique_provider_log_emitters':46,'unique_monitored_token_emitters':11,'source_aggregate_pending_status_preserved_as_created':True,'network_calls':0}
q=W/'phase7_transfer_seal_independent_review.json';q.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps({'status':report['status'],'archive_sha256':EXPECTED_SHA,'entries':102,'report_sha256':h(q.read_bytes())}))
