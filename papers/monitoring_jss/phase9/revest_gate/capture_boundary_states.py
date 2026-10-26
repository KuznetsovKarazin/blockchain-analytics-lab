#!/usr/bin/env python3
"""Frozen Revest boundary/code/state gate, with explicit finite stopping.

No transaction, event, detector, or attack-feature stream is acquired. This
program stops at boundary states even if they agree; agreement cannot prove
continuous routing. Historical proofs are provider responses, not verified
Merkle proofs.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
from probe_historical_capabilities import Probe, save, stamp, word, code
from revest_gate_primitives import registry_keys, keccak256, selftest

ROLES=["registry","revest","lock_manager","token_vault","fnft_handler"]
CORE={"REVEST":"revest","LOCK_MANAGER":"lock_manager","TOKEN_VAULT":"token_vault","FNFT":"fnft_handler"}

class GateStop(Exception):
    def __init__(self, disposition, detail):
        self.disposition,self.detail=disposition,detail
        super().__init__(detail)

def require(condition, detail, disposition="UNAVAILABLE_UNDER_CAP_OR_SOURCE_SEMANTICS"):
    if not condition:raise GateStop(disposition,detail)

def checked_header(value, number):
    require(isinstance(value,dict),"Missing historical header")
    require(value.get("number")==hex(number),"Header number mismatch")
    require(word(value.get("hash")) and word(value.get("parentHash")),"Malformed header hash")
    try: timestamp=int(value["timestamp"],16)
    except (ValueError,TypeError,KeyError):raise GateStop("UNAVAILABLE_UNDER_CAP_OR_SOURCE_SEMANTICS","Invalid header timestamp")
    return {"number":number,"hash":value["hash"],"parent_hash":value["parentHash"],"timestamp":timestamp,"timestamp_utc":datetime.fromtimestamp(timestamp,timezone.utc).isoformat()}

def parse_proof(body,address,keys,runtime):
    require(isinstance(body,dict),"Missing historical batch-state proof response")
    require(body.get("address","").lower()==address.lower(),"Proof address mismatch")
    require(word(body.get("codeHash")) and body["codeHash"].lower()=="0x"+keccak256(runtime).hex(),"Proof codeHash differs from exact historical runtime")
    require(word(body.get("storageHash")),"Malformed storageHash")
    require(isinstance(body.get("accountProof"),list) and bool(body["accountProof"]),"Missing accountProof")
    require(all(code(x) and x!="0x" for x in body["accountProof"]),"Malformed accountProof node")
    for field in ("balance","nonce"):
        try: n=int(body[field],16)
        except (ValueError,KeyError,TypeError):raise GateStop("UNAVAILABLE_UNDER_CAP_OR_SOURCE_SEMANTICS","Invalid account scalar")
        require(n>=0,"Negative account scalar")
    proof=body.get("storageProof")
    require(isinstance(proof,list),"Missing storageProof")
    values={}
    for item in proof:
        try:k=int(item["key"],16);v=int(item["value"],16)
        except (ValueError,KeyError,TypeError):raise GateStop("UNAVAILABLE_UNDER_CAP_OR_SOURCE_SEMANTICS","Invalid storage entry")
        require(k not in values and 0<=k<2**256 and 0<=v<2**256,"Duplicate or out-of-range storage entry")
        require(isinstance(item.get("proof"),list) and all(code(n) and n!="0x" for n in item["proof"]),"Invalid storage proof nodes")
        values[k]=v
    require(set(values)=={int(x,16) for x in keys.values()},"Incomplete or excess returned storage slot set")
    result={name:values[int(key,16)] for name,key in keys.items()}
    require(all(v<2**160 for k,v in result.items() if k!="next_dex"),"Address word has nonzero high bytes")
    return result

def main():
    ap=argparse.ArgumentParser()
    for name in ("plan","compilation","sources","deployment-review","prior-capability","batch-state","write-review","output"):
        ap.add_argument("--"+name,type=Path,required=True)
    ap.add_argument("--accepted-plan-sha256",required=True)
    args=ap.parse_args()
    planbytes=args.plan.read_bytes();digest=hashlib.sha256(planbytes).hexdigest()
    if digest!=args.accepted_plan_sha256:raise ValueError("Frozen plan digest mismatch")
    plan=json.loads(planbytes);selftest()
    batch=json.loads((args.batch_state/"summary.json").read_text())
    require(batch["valid_result"] and batch["cumulative_rpc_methods"]==12,"Prior batch-state gate is not accepted")
    require(batch["plan_sha256"]==digest,"Prior batch-state frozen plan differs")
    review=json.loads(args.write_review.read_text())
    require(review["no_forbidden_runtime_opcodes"] and review["no_routing_storage_alias_candidates"],"Static audit contains unresolved hazards")
    require(review.get("human_review",{}).get("accepted") is True,"Missing explicit static write-path review")
    compilation=json.loads((args.compilation/"summary.json").read_text())
    require(compilation["all_exact"],"Recompilation not exact")
    cby={x["role"]:x for x in compilation["roles"]}
    require(len(review["roles"])==5 and {r["role"] for r in review["roles"]}==set(ROLES),"Static review roles missing or duplicated")
    for r in review["roles"]:
        require(r["compiler_output_sha256"]==cby[r["role"]]["output_sha256"],"Static review compiler binding differs")
    deployment=json.loads(args.deployment_review.read_text())
    addresses={r["role"]:r["address"].lower() for r in deployment["creations"]}
    require(set(addresses)==set(ROLES),"Unexpected source-role population")
    expected_code={}
    for role in ROLES:
        source=(args.sources/(role+"_verified_contract.json")).read_bytes()
        require(hashlib.sha256(source).hexdigest()==cby[role]["retained_response_sha256"],"Retained source binding changed")
        expected_code[role]=bytes.fromhex(json.loads(source)["deployed_bytecode"].removeprefix("0x"))
    keys={"registry":registry_keys(plan["required_registry_keys"],plan["caps"]["maximum_dex_slots"])}
    for role in ROLES[1:]:
        fields={x["label"]:x for x in cby[role]["storage_layout"]["storage"]}
        require(all(fields[f]["offset"]==0 for f in ("_owner","addressesProvider")),"Unexpected packed routing field")
        keys[role]={"owner":"0x"+int(fields["_owner"]["slot"]).to_bytes(32,"big").hex(),"provider":"0x"+int(fields["addressesProvider"]["slot"]).to_bytes(32,"big").hex()}
    args.output.mkdir(parents=True,exist_ok=False)
    (args.output/"frozen_plan.json").write_bytes(planbytes)
    started=datetime.fromisoformat(json.loads((args.batch_state/"acceptance.json").read_text())["started_utc"])
    elapsed=(datetime.now(timezone.utc)-started).total_seconds()
    remaining=plan["caps"]["total_wall_seconds"]-elapsed
    require(remaining>0,"Continuation wall cap expired")
    caps={"rpc_methods_total":plan["caps"]["additional_rpc_methods"]-batch["rpc_methods"],"per_request_seconds":plan["caps"]["per_request_seconds"],"total_wall_seconds":remaining,"retained_response_bytes":plan["caps"]["additional_retained_bytes"]-batch["response_bytes"],"per_response_bytes":plan["caps"]["per_response_bytes"]}
    runner=Probe({"caps":caps},args.output)
    provider={"id":"drpc","endpoint":plan["endpoint"]}
    header_file=args.prior_capability/"07_drpc_eth_getBlockByNumber_response.bin"
    headers={14300000:checked_header(json.loads(header_file.read_bytes())["result"],14300000)}
    header_calls=0
    boundary={};states={};membership=[];disposition="UNAVAILABLE_UNDER_CAP_OR_SOURCE_SEMANTICS";detail="Not completed"
    def header(number):
        nonlocal header_calls
        if number not in headers:
            require(header_calls<36,"Boundary header sub-cap reached")
            header_calls+=1
            headers[number]=checked_header(runner.call(provider,"eth_getBlockByNumber",[hex(number),False]),number)
        return headers[number]
    def first_at(timestamp,lo,hi):
        require(header(lo)["timestamp"]<timestamp<=header(hi)["timestamp"],"Initial boundary bracket invalid")
        while hi-lo>1:
            middle=(lo+hi)//2
            if header(middle)["timestamp"]<timestamp:lo=middle
            else:hi=middle
        require(header(hi)["parent_hash"].lower()==header(lo)["hash"].lower(),"Boundary predecessor linkage differs")
        return {"predecessor":header(lo),"first_at_or_after":header(hi)}
    try:
        for name,iso,lo,hi in [("start",plan["window_utc"][0],14250000,14300000),("end",plan["window_utc"][1],14300000,14500000)]:
            boundary[name]=first_at(int(datetime.fromisoformat(iso.replace("Z","+00:00")).timestamp()),lo,hi)
        save(args.output/"boundaries.json",boundary)
        for label in ("start","end"):
            block=boundary[label]["predecessor"]["number"]
            states[label]={}
            for role in ROLES:
                runtime=runner.call(provider,"eth_getCode",[addresses[role],hex(block)])
                require(code(runtime),"Missing or malformed historical runtime: "+label+"/"+role)
                require(bytes.fromhex(runtime[2:])==expected_code[role],"Historical runtime mismatch: "+label+"/"+role,"CONTRADICTORY_FROZEN_CORE_ROUTING")
                proof=runner.call(provider,"eth_getProof",[addresses[role],list(keys[role].values()),hex(block)])
                values=parse_proof(proof,addresses[role],keys[role],bytes.fromhex(runtime[2:]))
                if role=="registry":require(values["next_dex"]<=plan["caps"]["maximum_dex_slots"],"DEX slot cap exceeded")
                states[label][role]={"address":addresses[role],"block_number":block,"runtime_sha256":hashlib.sha256(bytes.fromhex(runtime[2:])).hexdigest(),"code_hash":"0x"+keccak256(bytes.fromhex(runtime[2:])).hex(),"values":values}
                save(args.output/"boundary_states.json",states)
        for label in ("start","end"):
            for key,role in CORE.items():
                observed="0x"+states[label]["registry"]["values"][key].to_bytes(20,"big").hex()
                if observed!=addresses[role]:membership.append({"boundary":label,"kind":"registry_core_binding","role":role,"expected":addresses[role],"observed":observed})
            for role in ROLES[1:]:
                observed="0x"+states[label][role]["values"]["provider"].to_bytes(20,"big").hex()
                if observed!=addresses["registry"]:membership.append({"boundary":label,"kind":"component_registry_provider","role":role,"expected":addresses["registry"],"observed":observed})
        if membership:
            disposition="POPULATION_EXPANSION_UNRESOLVED"
            detail="At least one historical boundary routes outside the frozen original four components/registry. This is a concrete counterexample to unchanged original-core activation; new/disabled routes need independent treatment before admission. Administrative histories are not fetched after this terminal gate."
        else:
            disposition="BOUNDARY_STATES_MATCH_CONTINUITY_UNPROVED"
            detail="Boundary snapshots match the frozen core population; full ownership and administrative mutation history remains mandatory, so this stage cannot close routing."
    except GateStop as exc:
        disposition,detail=exc.disposition,exc.detail
    except RuntimeError as exc:
        disposition,detail="UNAVAILABLE_UNDER_CAP_OR_SOURCE_SEMANTICS",str(exc)
    result={"schema":"phase9_revest_boundary_state_gate_v1","plan_sha256":digest,"completed_utc":stamp(),"disposition":disposition,"detail":detail,"rpc_methods":runner.calls,"cumulative_rpc_methods":12+runner.calls,"response_bytes":runner.bytes,"cumulative_response_bytes":42538+batch["response_bytes"]+runner.bytes,"boundary_header_calls":header_calls,"boundary_states_completed":sum(len(x) for x in states.values()),"boundaries":boundary,"membership_differences":membership,"new_case_admission_count":0,"continuity_proved":False,"proofs_cryptographically_verified":False,"evidence_tier":plan["evidence_tier"]}
    save(args.output/"summary.json",result)
    print(json.dumps(result,indent=2))

if __name__=="__main__":main()
