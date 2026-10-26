"""Independent finite-population Transfer-shape arithmetic; no production imports.

This oracle deliberately derives boundary indicators and signed contributions
from raw integer words, separately from the production category-branch loop.
Only used after source identity/completeness checks by the independent auditor.
"""
import re

SIG='0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
ZERO='0x'+'0'*40

def exact_hex(value,size=None):
    assert type(value) is str and re.fullmatch('0x[0-9a-fA-F]*',value) and len(value)%2==0
    assert size is None or len(value)==2+2*size
    return value.lower()

def raw_flow_oracle(logs,monitored,chain_id):
    monitored=set(exact_hex(v,20) for v in monitored)
    assert monitored and ZERO not in monitored
    counts={'logs':len(logs),'erc20_shaped':0,'erc721_shaped':0,'opaque':0,'monitored_erc20_shaped':0,'zero_value_transfers':0}
    transfers=[]
    for log in logs:
        token=exact_hex(log['address'],20)
        assert type(log['topics']) is list and len(log['topics'])<=4
        topics=[exact_hex(v,32) for v in log['topics']]
        data=exact_hex(log['data'])
        if not topics or topics[0]!=SIG:
            counts['opaque']+=1;continue
        assert len(topics) in (3,4)
        assert int(topics[1][2:26],16)==0 and int(topics[2][2:26],16)==0
        sender='0x'+topics[1][-40:];recipient='0x'+topics[2][-40:]
        if len(topics)==4:
            assert data=='0x'
            counts['erc721_shaped']+=1;continue
        assert len(data)==66
        amount=int(data[2:],16)
        counts['erc20_shaped']+=1
        counts['zero_value_transfers']+=int(amount==0)
        from_inside=sender in monitored;to_inside=recipient in monitored
        if from_inside or to_inside:
            counts['monitored_erc20_shaped']+=1
            transfers.append((token,sender,recipient,amount,from_inside,to_inside))
    rows=[]
    for token in sorted({t[0] for t in transfers}):
        group=[t for t in transfers if t[0]==token]
        row={'chain_id':chain_id,'token_address':token,'transfer_log_count':len(group)}
        categories={
          'external_in':lambda s,r,v,fi,ti:ti and not fi and s!=ZERO,
          'external_out':lambda s,r,v,fi,ti:fi and not ti and r!=ZERO,
          'internal':lambda s,r,v,fi,ti:fi and ti,
          'mint_from_zero':lambda s,r,v,fi,ti:s==ZERO and ti,
          'burn_to_zero':lambda s,r,v,fi,ti:r==ZERO and fi,
        }
        for name,predicate in categories.items():
            chosen=[t[3] for t in group if predicate(*t[1:])]
            row[name+'_raw']=str(sum(chosen));row[name+'_count']=len(chosen)
        assert sum(row[k+'_count'] for k in categories)==len(group)
        signed=sum(v*(int(ti)-int(fi)) for _,s,r,v,fi,ti in group)
        external=sum(v*(int(ti)-int(fi)) for _,s,r,v,fi,ti in group if s!=ZERO and r!=ZERO)
        row['net_event_in_raw']=str(signed);row['net_external_in_raw']=str(external)
        assert signed==int(row['external_in_raw'])-int(row['external_out_raw'])+int(row['mint_from_zero_raw'])-int(row['burn_to_zero_raw'])
        rows.append(row)
    return counts,rows
