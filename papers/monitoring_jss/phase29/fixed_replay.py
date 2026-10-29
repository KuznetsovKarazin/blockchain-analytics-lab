#!/usr/bin/env python3
"""Phase29 deterministic replay of *fixed*, previously published monitoring methods.

This code is read-only, runs offline from source-matched indexer observations.
Method decisions are computed without attack labels. Reference join is separate,
conditional and explicitly does not estimate population recall/precision/FPR.
"""
import argparse, csv, gzip, hashlib, json, sys
from pathlib import Path

CASE_IDS=("cohort28_02","cohort28_09","cohort28_10","cohort28_13")
MODES=("daily_reset","lookback_7d","cumulative_in_window")
METHODS=("outflow_rank_1_20","outflow_rank_1_10","core_count_60s_10")
POLICIES=("greedy","paced_cumulative","token_bucket")
BUDGETS=(1,5,20)

def check(b,msg):
    if not b: raise ValueError(msg)
def canonical(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
def sha(x):return hashlib.sha256(x).hexdigest()

def replay(case,indexed_dir,output,ref_ledger_path=None):
    root=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(root))
    sys.path.insert(0,str(root/"phase18"))
    sys.path.insert(0,str(root/"phase22"))
    from initialization_full_replay import build_method_decisions,apply_policy
    from phase22_science_replay import count_method,compute_mode_diagnostics
    mraw=(indexed_dir/"acquisition_manifest.json").read_bytes()
    m=json.loads(mraw)
    check(m["case"]==case and m["schema"]=="article2_phase29_indexed_all_emitter_bundles_v1","wrong source provenance")
    check(m["status"]=="COMPLETE_INDEXED_SOURCE_MATCHED" and m["processed"]==m["input_transactions"],"incomplete selected source")
    check(not m["detector_scores_computed"] and not m["reference_labels_used"],"contaminated source")
    inp=indexed_dir/"indexer_observations.jsonl.gz"
    with gzip.open(inp,"rt",encoding="utf-8") as f:
        records=[json.loads(x) for x in f if x.strip()]
    check(sha(canonical(records))==m["indexed_rows_sha256"] and len(records)==m["processed"],"indexed source digest differs")
    obs=[]
    for r in records:
        check(r["case"]==case and r["source_tier"]=="pinned_AWS_selected_identity_and_indexed_Blockscout_all_emitter_logs_v1","incorrect source tier")
        v=r["views"].get("fixed_core")
        check(v and v["archived_core_log_count"]>0,"not a selected nominated-core transaction")
        obs.append({"transaction":r["transaction"],"archived_core_log_count":v["archived_core_log_count"],"token_flows":v["token_flows"]})
    check(len(obs)==len(records),"source selection changed")
    check(all((a["transaction"]["block_number"],a["transaction"]["transaction_index"])<
       (b["transaction"]["block_number"],b["transaction"]["transaction_index"]) for a,b in zip(obs,obs[1:])),
       "noncausal transaction order")
    result=[]
    traces={}
    for mode in MODES:
        for method in METHODS:
            if method=="core_count_60s_10":
                if mode!="daily_reset":continue
                decisions=count_method(obs)
            else:
                decisions=build_method_decisions(obs,mode,int(method.rsplit("_",1)[-1]))
            key=f"{mode}/{method}"
            traces[key]=decisions
            for policy in POLICIES:
                for B in BUDGETS:
                    admissions=apply_policy(decisions,policy,B)
                    selected=[r["tx"] for r in admissions if r["notification_emitted"]]
                    result.append({"case":case,"method":method,"init":mode,"policy":policy,"B":B,
                       "selected_tx":len(obs),"eligible_tx":sum(x["eligible_count"]>0 for x in decisions) if method.startswith("outflow") else None,
                       "raw_triggers":sum(x["raw_trigger"] for x in decisions),
                       "group_candidates":sum(x["group_candidate"] for x in decisions),
                       "notifications":len(selected),"notified_transactions":selected,
                       "suppression_due_to_budget":sum(x["suppression_reason"] in ("hard_daily_cap","paced_quota","token_shortage") for x in admissions)})
    output.mkdir(parents=True,exist_ok=False)
    sealed={"schema":"article2_phase29_label_blind_replay_v1","status":"COMPLETE","case":case,
        "input_manifest_sha256":sha(mraw),"input_indexer_sha256":sha(inp.read_bytes()),
        "modes":MODES,"methods":METHODS,"policies":POLICIES,"budgets":BUDGETS,
        "case_score_rows":result,"case_token_feasibility":compute_mode_diagnostics(obs),
        "labels_used":False,"reference_join_performed":False,"source_tier":m["source_tier"]}
    data=canonical(sealed)
    (output/"label_blind_replay.json").write_bytes(data+b"\n")
    # Join existing documented references only after complete replay.
    ledger=json.loads(ref_ledger_path.read_bytes()) if ref_ledger_path else None
    ref=next(x for x in ledger["case_records"] if x["case_id"]==case) if ledger else None
    documented=[]
    if ref:
        documented=sorted(set(([ref["independently_supported_reference_hash"]] if ref["independently_supported_reference_hash"] else [])+
           ref["additional_reference_candidates"]))
    in_selection=set(x["transaction"]["transaction_hash"] for x in records)
    joins=[]
    for row in result:
        hits=[x for x in documented if x in row["notified_transactions"]]
        joins.append({**{k:v for k,v in row.items() if k!="notified_transactions"},
           "n_documented_reference_candidates":len(documented),
           "n_references_in_selected_population":sum(x in in_selection for x in documented),
           "known_subset_exact_tx_matches":len(hits),"hit_tx_candidates":hits,
           "other_notifications_status":"UNADJUDICATED_NOT_FALSE_POSITIVES",
           "new_family_detector_performance_admitted":False})
    report={"schema":"article2_phase29_conditional_reference_join_v1","case":case,
        "source_tier":m["source_tier"],"status":"COMPLETE_EXPLORATORY_NOT_ADMITTED",
        "replay_sha256":sha(data),"reference_ledger_sha256":sha(ref_ledger_path.read_bytes()) if ref_ledger_path else None,
        "reference_roles":"INCOMPLETE_HISTORICAL_ATTACK_INVENTORY",
        "sampled_incident_source_outcome":"No population recall, precision or FPR inference",
        "cells":joins}
    (output/"reference_join.json").write_text(json.dumps(report,indent=2)+"\n")
    with (output/"method_policy_cells.csv").open("w",newline="") as f:
        cols=[k for k in joins[0] if k!="hit_tx_candidates"]
        wr=csv.DictWriter(f,fieldnames=cols);wr.writeheader()
        for row in joins:wr.writerow({k:row[k] for k in cols})
    print("REPLAY COMPLETE",case,len(obs),"selected transactions",len(joins),"policy cells; no new family admitted")

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--case",required=True,choices=CASE_IDS)
    p.add_argument("--indexed-dir",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    p.add_argument("--reference-ledger",type=Path,required=True)
    a=p.parse_args()
    replay(a.case,a.indexed_dir,a.out,a.reference_ledger)
