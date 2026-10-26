"""Read-only selection audit independent of transfer/collector implementations."""
from collections import OrderedDict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

WORK=Path('/workspace/scratch/159bf77d8682')
REPO=WORK/'monitoring-work'
SELECTION=WORK/'phase7_transfer_selection.json'
MANIFEST_PATH='papers/monitoring_jss/runs/protocol_logs_20261025T083346_282558Z/acquisition_manifest.json'
ADDRESS='0x27182842e098f60e3d576794a5bffb0777e025d3'

def sha(data):return hashlib.sha256(data).hexdigest()
def check_hex(value,size=None):
    assert type(value) is str and re.fullmatch(r'0x(?:[0-9a-fA-F]{2})*',value)
    assert size is None or len(value)==2+2*size
    return value.lower()
def check_int(value,minimum=0):
    assert type(value) is int and value>=minimum
    return value
def strict_json(data):
    def pairs(values):
        result={}
        for k,v in values:
            assert k not in result
            result[k]=v
        return result
    def invalid(value):raise AssertionError(value)
    return json.loads(data,object_pairs_hook=pairs,parse_constant=invalid)
def main():
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip()
    manifest_bytes=subprocess.check_output(['git','show','HEAD:'+MANIFEST_PATH],cwd=REPO)
    assert (REPO/MANIFEST_PATH).read_bytes()==manifest_bytes
    manifest=strict_json(manifest_bytes)
    selection_bytes=SELECTION.read_bytes();selection=strict_json(selection_bytes)
    members={Path(r['path']).name:r for r in manifest['files']}
    raw={}
    for name,record in members.items():
        data=(REPO/record['path']).read_bytes()
        assert len(data)==record['bytes'] and sha(data)==record['sha256']
        rows=[strict_json(line) for line in data.splitlines()]
        assert len(rows)==record['rows']
        raw[name]=rows
    headers={}
    for row in raw['matching_headers.jsonl']:
        number=check_int(row['block_number'])
        assert number not in headers
        check_hex(row['block_hash'],32)
        check_int(row['event_time_ns'])
        headers[number]=row
    grouped=OrderedDict();prior=None;positions={};identities=set()
    start=int(datetime(2023,3,1,tzinfo=timezone.utc).timestamp())*1_000_000_000
    end=start+86_400_000_000_000
    for row in raw['selected_logs.jsonl']:
        assert check_int(row['chain_id'],1)==1
        assert check_hex(row['address'],20)==ADDRESS
        for key in ('block_number','transaction_index','log_index','event_time_ns'):check_int(row[key])
        assert start<=row['event_time_ns']<end
        for key in ('block_hash','transaction_hash'):check_hex(row[key],32)
        assert type(row['topics']) is list and len(row['topics'])<=4
        for topic in row['topics']:check_hex(topic,32)
        check_hex(row['data'])
        key=(row['block_number'],row['transaction_index'],row['log_index'])
        assert prior is None or prior<key
        prior=key
        identity=(row['block_hash'],row['transaction_hash'],row['log_index'])
        assert identity not in identities
        identities.add(identity)
        txpos=(row['block_number'],row['transaction_index'])
        assert positions.setdefault(txpos,row['transaction_hash'])==row['transaction_hash']
        header=headers[row['block_number']]
        assert row['block_hash']==header['block_hash'] and row['event_time_ns']==header['event_time_ns']
        assert row.get('observed_time') is None and row.get('label_available_time') is None
        grouped.setdefault(row['transaction_hash'],[]).append(row)
    assert len(raw['selected_logs.jsonl'])==1247 and len(grouped)==218 and len(headers)==215
    first=list(grouped.items())[:10]
    expected=[]
    for tx,rows in first:
        representative=rows[0]
        for row in rows:
            assert all(row[k]==representative[k] for k in ('chain_id','block_number','block_hash','transaction_hash','transaction_index','event_time_ns'))
        expected.append({k:representative[k] for k in ('chain_id','block_number','block_hash','transaction_hash','transaction_index','event_time_ns')}|{'archived_core_logs':rows})
    assert expected==selection['selected_transactions']
    assert selection['accepted_source_rows']==1247 and selection['accepted_source_transactions']==218
    assert selection['monitored_addresses']==[ADDRESS]
    assert selection['new_transfer_results_observed'] is False
    count=sum(len(rows) for _,rows in first)
    assert count==58
    report={'schema_version':'phase7_selection_independent_review_v1','status':'PASS','head':head,
            'auditor_sha256':sha(Path(__file__).read_bytes()),'selection_sha256':sha(selection_bytes),
            'committed_acquisition_manifest_sha256':sha(manifest_bytes),'source_files':list(members.values()),
            'all_source_rows':1247,'all_source_transactions':218,'matching_headers':215,
            'selected_transactions':10,'selected_core_logs':count,'checks':['Committed manifest anchors exact restored byte sizes and SHA-256.','Strict source integers/hex/UTC range, unique log identity and canonical ordering.','Every selected-source log matches retained header hash and timestamp.','First ten distinct transaction hashes independently regrouped from entire source.','All 58 original dictionaries and selected transaction metadata exactly equal prior selection artifact.'],
            'selected':[{'transaction_hash':tx,'block_number':rows[0]['block_number'],'transaction_index':rows[0]['transaction_index'],'core_logs':len(rows),'first_log_index':rows[0]['log_index'],'last_log_index':rows[-1]['log_index']} for tx,rows in first],
            'limitations':['Archive outer bytes/CRC claim not independently re-read by this audit; source member bytes independently match committed acquisition manifest.','No new provider request or transfer outcome was read; selection timestamp/exposure assertion is a retained provenance statement, not independently reconstructed system history.']}
    output=WORK/'phase7_selection_independent_review.json'
    output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:report[k] for k in ('status','all_source_rows','all_source_transactions','selected_transactions','selected_core_logs','selection_sha256')}))
if __name__=='__main__':main()
