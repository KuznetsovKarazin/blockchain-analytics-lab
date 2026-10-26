#!/usr/bin/env python3
"""Execute only the first, predeclared batch-state continuation gate.

A passing result authorizes no subsequent acquisition by this program.
All returned proof and state bytes remain private. Merkle nodes are retained,
not verified against a canonical stateRoot.
"""
import argparse
import hashlib
import json
from pathlib import Path
from probe_historical_capabilities import Probe, save, stamp, word
from revest_gate_primitives import registry_keys, keccak256, selftest

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--plan",type=Path,required=True)
    ap.add_argument("--accepted-plan-sha256",required=True)
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    raw=args.plan.read_bytes()
    digest=hashlib.sha256(raw).hexdigest()
    if digest != args.accepted_plan_sha256:
        raise ValueError("accepted plan digest mismatch")
    plan=json.loads(raw)
    selftest()
    args.output.mkdir(parents=True,exist_ok=False)
    (args.output/"frozen_plan.json").write_bytes(raw)
    save(args.output/"acceptance.json",{"accepted_plan_sha256":digest,"started_utc":stamp(),"scope":"Only step batch_state_capability of root-accepted plan."})
    caps=plan["caps"]
    execution_plan={"caps":{"rpc_methods_total":1,"per_request_seconds":caps["per_request_seconds"],"total_wall_seconds":60,"retained_response_bytes":caps["additional_retained_bytes"],"per_response_bytes":caps["per_response_bytes"]}}
    runner=Probe(execution_plan,args.output)
    keys=registry_keys(plan["required_registry_keys"],caps["maximum_dex_slots"])
    registry="0xd721a90dd7e010c8c5e022cc0100c55ac78e0fc4"
    body=runner.call({"id":"drpc","endpoint":plan["endpoint"]},"eth_getProof",[registry,list(keys.values()),hex(14300000)])
    reasons=[]
    values={}
    if not isinstance(body,dict):
        reasons.append("No valid successful getProof result")
    else:
        if body.get("address","").lower()!=registry:reasons.append("wrong address")
        if not word(body.get("codeHash")):reasons.append("invalid codeHash")
        if not isinstance(body.get("accountProof"),list) or not body["accountProof"]:reasons.append("missing account proof nodes")
        for name in ["balance","nonce"]:
            try:
                assert isinstance(body[name],str) and body[name].startswith("0x")
                int(body[name],16)
            except (AssertionError,ValueError,TypeError,KeyError):reasons.append("invalid "+name)
        returned=body.get("storageProof")
        if not isinstance(returned,list):
            reasons.append("missing storageProof list")
        else:
            by_key={}
            try:
                for item in returned:
                    key=int(item["key"],16)
                    if key in by_key:raise ValueError("duplicate key")
                    value=int(item["value"],16)
                    if not 0 <= value < 2**256:raise ValueError("bad value")
                    if not isinstance(item.get("proof"),list):raise ValueError("missing proof nodes")
                    by_key[key]=value
                if set(by_key)!=set(int(x,16) for x in keys.values()):raise ValueError("incomplete/excess key set")
                values={name:by_key[int(key,16)] for name,key in keys.items()}
                if values["next_dex"]>caps["maximum_dex_slots"]:reasons.append("next_dex exceeds frozen slot cap")
                if any(v >= 2**160 for k,v in values.items() if k!="next_dex"):reasons.append("address word has nonzero high bits")
            except (KeyError,TypeError,ValueError) as exc:reasons.append("invalid storage proof shape: "+str(exc))
    result={"schema":"phase9_revest_batch_state_gate_result_v1","plan_sha256":digest,"completed_utc":stamp(),"rpc_methods":runner.calls,"cumulative_rpc_methods":plan["prior_rpc_calls"]+runner.calls,"response_bytes":runner.bytes,"requested_storage_slots":len(keys),"valid_result":not reasons,"reasons":reasons,"disposition":"BATCH_STATE_CAPABILITY_AVAILABLE_CONTINUITY_UNPROVED" if not reasons else "UNAVAILABLE_UNDER_FROZEN_BATCH_STATE_ROUTE","new_case_admission_count":0,"continuity_proved":False,"state_values":values,"note":"Narrow frozen route disposition only. Existing eth_getStorageAt capability is preserved; no claim of global historical-state unavailability. Returned proof nodes are not verified stateRoot proofs."}
    save(args.output/"summary.json",result)
    print(json.dumps(result,indent=2))

if __name__=="__main__":main()
