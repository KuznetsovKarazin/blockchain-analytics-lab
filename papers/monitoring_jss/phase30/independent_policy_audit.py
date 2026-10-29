#!/usr/bin/env python3
"""Independent stand-alone reimplementation of rank/count and dispatch QA.

Does not import Phase18/22/29 scoring or policy logic. Reads only published
observation records and label-blind output; never opens reference-join files.
Compares 63 original method/policy cells per case exactly, 252 total for four.
"""
import argparse
from collections import defaultdict, deque
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path

DAY=86400_000_000_000

def need(x,m):
    if not x:raise AssertionError(m)

def scalar(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()

def open_inputs(path):
    meta=json.loads((path/"acquisition_manifest.json").read_bytes())
    need(meta["status"]=="COMPLETE_INDEXED_SOURCE_MATCHED","incomplete indexed source")
    with gzip.open(path/"indexer_observations.jsonl.gz","rt",encoding="utf8") as z:
        rows=[json.loads(line) for line in z if line.strip()]
    need(hashlib.sha256(scalar(rows)).hexdigest()==meta["indexed_rows_sha256"],"indexer input bytes differ")
    return rows

def stand_alone_method(records,method,mode):
    out=[]
    histories=defaultdict(deque)
    window=deque()
    last_day=None
    last_candidate=None
    for row in records:
        tx=row["transaction"]
        t=tx["event_time_ns"]
        day=datetime.fromtimestamp(t//10**9,timezone.utc).date().isoformat()
        if day!=last_day:
            if mode=="daily_reset": histories.clear()
            window.clear()
            last_candidate=None
            last_day=day
        if method.startswith("outflow_rank"):
            bound=20 if method.endswith("20") else 10
            proposals=[]
            ready=False
            for flow in row["views"]["fixed_core"]["token_flows"]:
                a=int(flow["external_out_raw"])
                if a<=0:continue
                token=flow["token_address"]
                old=histories[token]
                if mode=="lookback_7d":
                    while old and old[0][0]<t-7*DAY:old.popleft()
                n=len(old)
                if n>=19:
                    ready=True
                    k=1+sum(v>=a for _,v in old)
                    if k*bound<=n+1:
                        proposals.append(token)
            raw=bool(proposals)
            for flow in row["views"]["fixed_core"]["token_flows"]:
                a=int(flow["external_out_raw"])
                if a>0:
                    old=histories[flow["token_address"]]
                    old.append((t,a))
                    while len(old)>128:old.popleft()
        else:
            need(mode=="daily_reset","count baseline not history-dependent")
            while window and window[0][0]<=t-60*10**9:
                window.popleft()
            window.append((t,row["views"]["fixed_core"]["archived_core_log_count"]))
            raw=sum(n for _,n in window)>=10
            ready=None
        candidate=raw and (last_candidate is None or t-last_candidate>=300*10**9)
        if candidate:last_candidate=t
        out.append({"day":day,"time":t,"tx":tx["transaction_hash"],
                    "raw":raw,"candidate":candidate,"eligible":ready})
    return out

def independent_policy(seq,policy,cap):
    sent=0
    credit=DAY
    clock=0
    last=None
    emitted=[]
    suppress=0
    for row in seq:
        day=row["day"]
        t=row["time"]
        if day!=last:
            sent=0
            credit=DAY
            clock=(t//DAY)*DAY
            last=day
        if policy=="token_bucket":
            credit=min(DAY,credit+(t-clock)*cap)
        quota=min(cap,1+cap*(t%DAY)//DAY) if policy=="paced_cumulative" else cap
        permitted=(row["candidate"] and sent<cap
            and (policy!="paced_cumulative" or sent<quota)
            and (policy!="token_bucket" or credit>=DAY))
        if row["candidate"] and not permitted:suppress+=1
        if permitted:
            sent+=1
            emitted.append(row["tx"])
            if policy=="token_bucket":credit-=DAY
        clock=t
    return emitted,suppress

def compare_one(case,paper):
    phase="phase30" if case in {"cohort28_07","cohort28_11","cohort28_14"} else "phase29"
    raw=paper/phase/"indexed"/case
    records=open_inputs(raw)
    published=json.loads((paper/phase/"results"/case/"label_blind_replay.json").read_bytes())
    need(published["status"]=="COMPLETE" and published["case"]==case,"wrong frozen output")
    truth={(x["method"],x["init"],x["policy"],x["B"]):x for x in published["case_score_rows"]}
    need(len(truth)==63,"unexpected policy cells")
    checked=0
    for method in ("outflow_rank_1_20","outflow_rank_1_10","core_count_60s_10"):
        modes=("daily_reset",) if method=="core_count_60s_10" else (
            "daily_reset","lookback_7d","cumulative_in_window")
        for mode in modes:
            scores=stand_alone_method(records,method,mode)
            for policy in ("greedy","paced_cumulative","token_bucket"):
                for cap in (1,5,20):
                    exp=truth[(method,mode,policy,cap)]
                    alerts,suppressed=independent_policy(scores,policy,cap)
                    got={
                        "selected_tx":len(scores),
                        "eligible_tx":sum(x["eligible"] for x in scores) if method.startswith("outflow_rank") else None,
                        "raw_triggers":sum(x["raw"] for x in scores),
                        "group_candidates":sum(x["candidate"] for x in scores),
                        "notifications":len(alerts),
                        "suppression_due_to_budget":suppressed,
                        "notified_transactions":alerts}
                    for k,v in got.items():
                        need(exp[k]==v,f"{case} {method}/{mode}/{policy}/{cap} {k}: {exp[k]} != {v}")
                    checked+=1
    return {"case":case,"cells_matched":checked,"transactions":len(records),"status":"PASS_INDEPENDENT_ALGORITHM"}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--paper",type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    checks=[compare_one(case,a.paper) for case in
        ("cohort28_02","cohort28_07","cohort28_09","cohort28_10","cohort28_11","cohort28_13","cohort28_14")]
    result={"schema":"article2_phase30_independent_reimplementation_audit_v1",
        "source":"self-contained independently written Python implementation",
        "cases":checks,"total_cells":sum(x["cells_matched"] for x in checks),
        "total_transactions":sum(x["transactions"] for x in checks),
        "used_attack_labels":False,"status":"PASS" }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
