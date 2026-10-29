#!/usr/bin/env python3
"""Phase28 source-window metadata preflight. No labels, chain logs or detection."""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
import hashlib,json,urllib.request
from pathlib import Path

def fetch(url):
    req=urllib.request.Request(url,headers={"User-Agent":"article2-candidate-metadata/1.0","Accept":"application/json"})
    with urllib.request.urlopen(req,timeout=17) as resp:
        if resp.status!=200: raise ValueError("bad status")
        data=resp.read(300001)
        if len(data)>300000: raise ValueError("response size cap")
    return json.loads(data)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--frame",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    data=args.frame.read_bytes()
    frame=json.loads(data)
    if frame["schema"]!="article2_phase28_candidate_frame_v1" or len(frame["cases"])!=16:
        raise ValueError("unrecognized frozen frame")
    out={"schema":"phase28_fork_block_window_v1","frame_sha256":hashlib.sha256(data).hexdigest(),
         "tier":"BLOCKSCOUT_INDEXED_BLOCK_METADATA_NOT_RAW_CHAIN_AUTHENTICATION",
         "no_scores":True,"no_labels":True,"results":[]}
    for c in frame["cases"]:
        row={"id":c["id"],"family":c["family"],"poC_fork_block":c["poC_fork_block"],"status":"UNAVAILABLE"}
        try:
            x=fetch("https://eth.blockscout.com/api/v2/blocks/"+str(c["poC_fork_block"]))
            h=x.get("height",x.get("number"))
            if h is None or int(h)!=c["poC_fork_block"]: raise ValueError("fork block height mismatch")
            stamp=x["timestamp"]
            t=datetime.fromisoformat(stamp.replace("Z","+00:00"))
            if t.utcoffset()!=timedelta(): raise ValueError("timestamp is not UTC")
            end=t.date()
            first=end-timedelta(days=29)
            row.update({"status":"INDEXED_BLOCK_DATE","fork_block_utc":t.isoformat(),
                        "window_first":first.isoformat(),"window_last_inclusive":end.isoformat(),
                        "block_hash":x.get("hash"),"block_parent_hash":x.get("parent_hash")})
        except Exception as e:
            row["error"]=type(e).__name__+": "+str(e)[:160]
        out["results"].append(row)
        print(c["id"],row["status"],row.get("window_last_inclusive"),flush=True)
    out["complete"]=sum(x["status"]=="INDEXED_BLOCK_DATE" for x in out["results"])
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    if out["complete"]!=16:
        raise SystemExit("Incomplete metadata: do not silently infer dates")
if __name__=="__main__":
    main()
