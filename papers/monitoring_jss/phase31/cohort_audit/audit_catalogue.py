#!/usr/bin/env python3
"""Reconcile every PoC source file in the immutable seven-month directory frame.

No retrospective rule is represented as the original nomination rule. Source
code is read from a separate git checkout and is not redistributed here.
"""
import argparse
import collections
import csv
import hashlib
import json
import re
import subprocess
from pathlib import Path

HERE=Path(__file__).resolve().parent
PAPER=HERE.parents[1]
COMMIT='0a9b9fd81c50767ff49f81089fbf8934f2f45b02'
SOURCE_REPO='SunWeb3Sec/DeFiHackLabs'
MONTHS=[f'src/test/2022-{m:02}' for m in range(3,10)]
INITIAL={
    'src/test/2022-03/Bacon_exp.sol':'Bacon Protocol',
    'src/test/2022-03/LiFi_exp.sol':'Li.Fi',
    'src/test/2022-03/Revest_exp.sol':'Revest',
    'src/test/2022-04/Rari_exp.sol':'Rari Fuse',
}

def git(repo,*args):
    return subprocess.check_output(['git','-C',str(repo),*args])

def collect(repo):
    tree=git(repo,'ls-tree','-r',COMMIT,*MONTHS).decode().splitlines()
    entries=[]
    for line in tree:
        meta,path=line.split('\t');mode,kind,blob=meta.split()
        if not path.endswith('.sol'):
            raise ValueError('Unexpected non-Solidity entry: '+path)
        content=git(repo,'show',COMMIT+':'+path)
        text=content.decode()
        # All 67 sources have literal network arguments in executable fork calls.
        no_block_comments=re.sub(r'/\*.*?\*/','',text,flags=re.S)
        no_comments=re.sub(r'//[^\n]*','',no_block_comments)
        aliases=sorted(set(re.findall(r'\bcreateSelectFork\s*\(\s*"([^"]+)"',no_comments)))
        if len(aliases)!=1:
            raise ValueError(f'Ambiguous fork chain {path}: {aliases}')
        entries.append({'source_path':path,'git_blob_sha1':blob,
                        'source_sha256':hashlib.sha256(content).hexdigest(),
                        'fork_rpc_alias':aliases[0],
                        'source_url':f'https://github.com/{SOURCE_REPO}/blob/{COMMIT}/{path}'})
    return {'schema':'phase31_frozen_catalogue_source_inventory_v1','source_repository':SOURCE_REPO,
            'source_commit':COMMIT,'directory_frame':MONTHS,
            'classification_rule':'Literal createSelectFork network alias in executable source; mainnet means Ethereum mainnet in pinned foundry.toml.',
            'poc_source_files':entries}

def main():
    p=argparse.ArgumentParser();p.add_argument('--source-repo',type=Path);a=p.parse_args()
    inventory_path=HERE/'SOURCE_INVENTORY.json'
    if a.source_repo:
        inventory=collect(a.source_repo)
        inventory_path.write_text(json.dumps(inventory,indent=2)+'\n')
        config=git(a.source_repo,'show',COMMIT+':foundry.toml')
        config_text=config.decode()
        aliases=re.findall(r'^mainnet\s*=\s*(.+)$',config_text,re.M)
        assert len(aliases)==1 and 'mainnet' in aliases[0].lower()
        (HERE/'FOUNDRY_MAINNET_BINDING.json').write_text(json.dumps({
            'source_commit':COMMIT,'source_path':'foundry.toml',
            'sha256':hashlib.sha256(config).hexdigest(),
            'mainnet_rpc_endpoint_template':aliases[0],
            'source_url':f'https://github.com/{SOURCE_REPO}/blob/{COMMIT}/foundry.toml'
        },indent=2)+'\n')
    else:
        inventory=json.loads(inventory_path.read_text())
    frame_path=PAPER/'phase28/CANDIDATE_FRAME.json'
    frame=json.loads(frame_path.read_text())
    nominated={case['source_path']:case for case in frame['cases']}
    assert len(nominated)==16
    rows=[]
    for item in inventory['poc_source_files']:
        path=item['source_path'];network=item['fork_rpc_alias']
        if path in nominated:
            case=nominated[path];disposition='PHASE28_NOMINATED'
            reason='Original frame supplies a fixed component nomination; no exhaustive inclusion algorithm is documented.'
        elif path in INITIAL:
            case={};disposition='INITIAL_FOUR_FAMILY_SOURCE'
            reason='Source corresponds to one of the four initial study families; this is a retrospective correspondence, not a recorded exclusion rule.'
        elif network!='mainnet':
            case={};disposition='NON_ETHEREUM_MAINNET'
            reason='Executable PoC forks '+network+'; outside stated Ethereum-mainnet eligibility.'
        else:
            case={};disposition='ETHEREUM_NOT_NOMINATED_REASON_UNDOCUMENTED'
            reason='Ethereum-mainnet source omitted from the 16 nominations; no original exclusion rationale located in frozen frame/protocol or their introduction commits.'
        rows.append({**item,'disposition':disposition,'phase28_id':case.get('id',''),
                     'family':case.get('family',INITIAL.get(path,'')),
                     'nominated_core_address':case.get('core_address',''),
                     'disposition_explanation':reason})
    assert set(nominated)<=set(x['source_path'] for x in rows)
    counts=dict(collections.Counter(x['disposition'] for x in rows))
    assert len(rows)==67 and sum(x['fork_rpc_alias']=='mainnet' for x in rows)==28
    assert counts=={'NON_ETHEREUM_MAINNET':39,'PHASE28_NOMINATED':16,'INITIAL_FOUR_FAMILY_SOURCE':4,'ETHEREUM_NOT_NOMINATED_REASON_UNDOCUMENTED':8},counts
    result={'schema':'phase31_catalogue_reconciliation_v1','source_commit':COMMIT,
            'unit':'PoC source file, not independent incident or attack execution',
            'original_selection_interpretation':'16 investigator-informed convenience component nominations frozen before their source traffic census; not an exhaustive or random sample.',
            'audit_timing':'Retrospective catalogue audit after V6.1 and reviewer feedback; not preregistration.',
            'original_frame_introduction_commit':'7a4646d11d198487acdcf8d3a97e36cb2bb6fe47',
            'original_protocol_introduction_commit':'66c4b0fb73de80d3eae2426fa3805a773743e028',
            'inputs_sha256':{str(frame_path.relative_to(PAPER)):hashlib.sha256(frame_path.read_bytes()).hexdigest(),
                             'SOURCE_INVENTORY.json':hashlib.sha256(inventory_path.read_bytes()).hexdigest()},
            'counts':{'source_files':len(rows),'ethereum_mainnet_files':28,'other_chain_files':39,**counts},
            'rows':rows}
    (HERE/'CATALOGUE_DISPOSITION.json').write_text(json.dumps(result,indent=2)+'\n')
    with (HERE/'CATALOGUE_DISPOSITION.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator='\n');writer.writeheader();writer.writerows(rows)
    print(json.dumps(result['counts'],indent=2))

if __name__=='__main__':main()
