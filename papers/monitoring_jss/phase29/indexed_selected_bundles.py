#!/usr/bin/env python3
"""Phase29: source-matched Blockscout full bundles for selected historical TXs.

Selection is the original AWS label-blind fixed-emitter population. This step
does not access known attack hashes or run detector scores. Exact source tier:
original AWS identities+counts, Blockscout topics/data and execution statuses.
"""
import argparse, gzip, hashlib, json, sys, time
from pathlib import Path

def check(b,msg):
    if not b: raise ValueError(msg)

def canon(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
def sha(x):return hashlib.sha256(x).hexdigest()

def source_bounded_logs(txid, expected_count, rate_log, limits, old):
    """Read complete indexed event pages up to the pinned original AWS log count.

    The frozen Phase22 helper allowed <=12 pages, but the new independent Omni
    incident has >600 event logs in one source-pinned transaction. The cap
    depends solely on AWS declared event volume, not any attack label.
    """
    import math, urllib.parse
    check(type(expected_count) is int and 0<expected_count<5000,
          "unreasonable original source event count")
    max_pages=max(12,math.ceil(expected_count/10)+4)
    current=None
    seen=set()
    rows=[]
    pages=0
    while True:
        pages+=1
        check(pages<=max_pages,"source-bounded page cap")
        url=old.BASE+txid+"/logs"
        if current:
            check(isinstance(current,dict) and 0<len(current)<=5,"bad pagination cursor")
            url+="?"+urllib.parse.urlencode(current)
        payload=old.fetch_json(url,rate_log,limits)
        check(type(payload) is dict and type(payload.get("items")) is list,"unexpected indexer response")
        items=payload["items"]
        check(0<len(items)<=50,"empty or oversized indexer page")
        rows.extend(items)
        check(len(rows)<=expected_count,"indexer has more events than original AWS")
        next_page=payload.get("next_page_params")
        if next_page is None:break
        ident=json.dumps(next_page,sort_keys=True)
        check(ident not in seen and next_page!=current,"repeating indexer cursor")
        seen.add(ident)
        current=next_page
    check(len(rows)==expected_count,"incomplete indexed all-emitter transaction bundle")
    return rows,pages

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--case",required=True,choices=("cohort28_02","cohort28_07","cohort28_09","cohort28_10","cohort28_11","cohort28_13","cohort28_14"))
    p.add_argument("--identities-dir",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    paper=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(paper/"phase22"))
    sys.path.insert(0,str(paper/"phase15/adapter"))
    import phase22_indexed_bundles as old
    m=json.loads((a.identities_dir/"source_identity_manifest.json").read_bytes())
    check(m["status"]=="COMPLETE_SOURCE_ONLY" and m["case"]==a.case and not m["incident_admitted"],"not accepted original S3 identities")
    with gzip.open(a.identities_dir/"selected_tx_identities.jsonl.gz","rt",encoding="utf8") as f:
        ids=[json.loads(s) for s in f if s.strip()]
    check(len(ids)==m["transaction_count"] and sha(canon(ids))==m["ids_sha256"],"source identity digest differs")
    check(all(x["case_id"]==a.case for x in ids),"source case mix")
    check(len(set(x["transaction_hash"] for x in ids))==len(ids),"duplicate source transaction identity")
    frame=json.loads((paper/"phase28/CANDIDATE_FRAME.json").read_text())
    entry=next(x for x in frame["cases"] if x["id"]==a.case)
    check(entry["core_address"].lower()==m["core_emitter"],"source core nomination changed")
    cores={"fixed_core":entry["core_address"].lower()}
    a.out.mkdir(parents=True,exist_ok=False)
    log=[];limits={"max_requests":6000,"start":time.monotonic(),"wall_seconds":2100,
          "max_bytes":250000000,"bytes":0}
    out=[];failure=None
    try:
        for i,src in enumerate(ids):
            expect={
              **src,"case":a.case,"all_emitter_log_count":src["all_emitter_logs"],
              "core_log_counts":{"fixed_core":src["core_emitter_logs"]}}
            tx=old.fetch_json(old.BASE+src["transaction_hash"],log,limits)
            check(tx["hash"].lower()==src["transaction_hash"] and tx["status"]=="ok","indexed tx failed, missing or mismatched")
            check(tx["block_number"]==src["block_number"] and tx["position"]==src["transaction_index"],"indexed tx source identity mismatch")
            check(old.parse_time(tx["timestamp"])==src["event_time_ns"],"indexed tx timestamp mismatch")
            events,pages=source_bounded_logs(src["transaction_hash"],expect["all_emitter_log_count"],log,limits,old)
            rows=old.normalized_indexed_rows(events,expect)
            record=old.feature_record(rows,expect,cores)
            record["indexed_pages"]=pages
            out.append(record)
            if (i+1)%20==0:
                print("INDEXED",a.case,i+1,"/",len(ids),"calls",len(log),flush=True)
            time.sleep(.16)
    except Exception as e:
        failure={"type":type(e).__name__,"reason":str(e),"at_index":len(out)}
        print("STOP",failure,flush=True)
    ok=failure is None and len(out)==len(ids)
    result={"schema":"article2_phase29_indexed_all_emitter_bundles_v1",
      "case":a.case,"status":"COMPLETE_INDEXED_SOURCE_MATCHED" if ok else "INCOMPLETE",
      "source_tier":"AWS_Parquet_selected_log_identities_and_counts_plus_Blockscout_indexed_full_logs_and_status",
      "s3_manifest_sha256":sha((a.identities_dir/"source_identity_manifest.json").read_bytes()),
      "s3_ids_sha256":m["ids_sha256"],
      "input_transactions":len(ids),"processed":len(out),"reference_labels_used":False,
      "reference_inventory_complete":False,"known_exploit_hits_computed":False,
      "detector_scores_computed":False,"receipt_root_verified":False,
      "failure":failure,"indexed_rows_sha256":sha(canon(out)),
      "http_requests":len(log),"indexed_response_bytes":limits["bytes"]}
    (a.out/"acquisition_manifest.json").write_text(json.dumps(result,indent=2)+"\n")
    with (a.out/"indexer_observations.jsonl.gz").open("wb") as f:
        with gzip.GzipFile(fileobj=f,filename="",mtime=0,mode="wb") as gz:
            for row in out:gz.write((json.dumps(row,sort_keys=True,separators=(",",":"))+"\n").encode())
    (a.out/"indexer_response_receipts.json").write_text(json.dumps(log,indent=2)+"\n")
    print("FINAL",result["status"],"count",len(out),"source",len(ids),flush=True)
    if not ok:raise SystemExit(1)

if __name__=="__main__":main()
