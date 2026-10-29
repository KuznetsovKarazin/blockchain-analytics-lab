#!/usr/bin/env python3
"""Indexer-only reference preflight. No attacker labels admitted, no detector scores."""
import argparse,hashlib,json
from datetime import datetime,timedelta
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.parse import urlencode
BASE="https://eth.blockscout.com/api/v2"
def fetch(path):
    q=Request(BASE+path,headers={"User-Agent":"article2-phase28-indexer-check/1","Accept":"application/json"})
    with urlopen(q,timeout=20) as f:
        if f.status!=200:raise ValueError("non-200 status")
        raw=f.read(2000001)
    if len(raw)>2000000:raise ValueError("oversized indexer response")
    return json.loads(raw)
def main():
    p=argparse.ArgumentParser()
    for flag in ("frame","windows","candidates","output"):p.add_argument("--"+flag,type=Path,required=True)
    a=p.parse_args()
    fr=json.loads(a.frame.read_bytes());win=json.loads(a.windows.read_bytes())
    raw=a.candidates.read_bytes();refs=json.loads(raw)
    if len(fr["cases"])!=16 or len(refs["rows"])!=17:raise ValueError("frame/ref count changed")
    known={x["id"]:x for x in fr["cases"]};windows={x["id"]:x for x in win["results"]}
    out={"schema":"article2_phase28_indexed_reference_preflight_v1",
         "references_sha256":hashlib.sha256(raw).hexdigest(),
         "tier":"BLOCKSCOUT_INDEXED_METADATA_NO_ORIGINAL_RECEIPT_ROOT",
         "incident_admissions":0,"monitor_scores":0,"rows":[]}
    for ref in refs["rows"]:
        core=known[ref["id"]]["core_address"]
        row={**ref,"core_address":core,"state":"UNAVAILABLE","core_emitter_logs":None,"log_bundle_complete":False}
        try:
            tx=fetch("/transactions/"+ref["tx"])
            if tx.get("hash","").lower()!=ref["tx"]:raise ValueError("hash mismatch")
            date=datetime.fromisoformat(tx["timestamp"].replace("Z","+00:00"))
            if date.utcoffset()!=timedelta():raise ValueError("non UTC")
            row.update(state="INDEXED_TX_METADATA",status=tx.get("status"),block=tx.get("block"),
              timestamp_utc=date.isoformat(),
              in_poc_fork_window=windows[ref["id"]]["window_first"]<=date.date().isoformat()<=windows[ref["id"]]["window_last_inclusive"],
              sender=(tx.get("from") or {}).get("hash") if isinstance(tx.get("from"),dict) else None,
              recipient=(tx.get("to") or {}).get("hash") if isinstance(tx.get("to"),dict) else None)
            url="/transactions/"+ref["tx"]+"/logs";seen=set();logs=[];complete=False
            for _ in range(12):
                if url in seen:raise ValueError("repeated pagination")
                seen.add(url);j=fetch(url)
                if not isinstance(j.get("items"),list):raise ValueError("invalid logs")
                logs.extend(j["items"])
                if len(logs)>1200:raise ValueError("too many logs")
                params=j.get("next_page_params")
                if not params:complete=True;break
                if not isinstance(params,dict):raise ValueError("invalid next page")
                url="/transactions/"+ref["tx"]+"/logs?"+urlencode(params)
            if complete:
                addr=[]
                for log in logs:
                    emitter=log.get("address")
                    if isinstance(emitter,dict):emitter=emitter.get("hash")
                    if not isinstance(emitter,str):raise ValueError("log address malformed")
                    addr.append(emitter.lower())
                row.update(core_emitter_logs=sum(x==core for x in addr),
                    indexed_all_emitter_logs=len(logs),log_bundle_complete=True)
        except Exception as e:
            row["error"]=type(e).__name__+": "+str(e)[:180]
        out["rows"].append(row)
        print(ref["id"],ref["tx"][:10],row["state"],row.get("status"),row["core_emitter_logs"],flush=True)
    out["indexed_count"]=sum(x["state"]=="INDEXED_TX_METADATA" for x in out["rows"])
    out["core_present_count"]=sum(x["core_emitter_logs"] is not None and x["core_emitter_logs"]>0 for x in out["rows"])
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(out,sort_keys=True,indent=2)+"\n")
    if out["indexed_count"]!=17:raise SystemExit("Partial indexed reference lookup; no case admission")
if __name__=="__main__":main()
