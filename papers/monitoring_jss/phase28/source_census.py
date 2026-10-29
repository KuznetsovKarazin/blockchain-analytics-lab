#!/usr/bin/env python3
"""Fixed incident-derived emitter census; no attack labels, features or scores.

Use existing pinned Phase16 original-byte AWS ranged reader. Eight batches, two
fixed candidates per batch. See PROTOCOL.md for scientific unit/limitations.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import date, timedelta
import hashlib, json, statistics, sys, urllib.parse, urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

def need(test,message):
    if not test: raise ValueError(message)

def hash_bytes(x): return hashlib.sha256(x).hexdigest()

def get_listing(rc, day):
    prefix=f"v1.0/eth/logs/date={day}/"
    url=rc.ENDPOINT+"?"+urllib.parse.urlencode({"list-type":"2","prefix":prefix,"max-keys":"100"})
    req=urllib.request.Request(url,headers={"User-Agent":"article2-phase28-source-census/1.0"})
    with urllib.request.urlopen(req,timeout=18) as h:
        need(h.status==200,"S3 list status")
        body=h.read(300001)
        need(len(body)<=300000,"S3 listing oversized")
    root=ET.fromstring(body)
    def node_name(x):return x.tag.rsplit("}",1)[-1]
    def field(node,name):return next((c.text for c in node if node_name(c)==name),None)
    need(field(root,"IsTruncated")=="false","incomplete/truncated S3 listing")
    obj=[x for x in root if node_name(x)=="Contents"]
    need(len(obj)==1,"require exactly one original daily Parquet part")
    k=field(obj[0],"Key");size=int(field(obj[0],"Size"));etag=field(obj[0],"ETag")
    need(k.startswith(prefix) and k.endswith(".snappy.parquet"),"invalid S3 key")
    need(10000<size<800_000_000 and etag,"unbounded source size / ETag")
    return {"table":"logs","day_utc":day,"key":k,"size_bytes":size,
            "etag_opaque":etag,"listing_sha256":hash_bytes(body)}

def run_case(case, window, session, rc, pa,pq,pc,workroot):
    first=date.fromisoformat(window["window_first"])
    last=date.fromisoformat(window["window_last_inclusive"])
    need((last-first).days==29,"window not 30 calendar days")
    emitter=case["core_address"].lower()
    out={"id":case["id"],"family":case["family"],"core_address":emitter,
         "candidate_status":case["source_status"],"window_first":str(first),
         "window_last_inclusive":str(last),"poC_fork_block":case["poC_fork_block"],
         "days":[],"status":"INCOMPLETE","label_used":False,"score_computed":False}
    for index in range(30):
        day=(first+timedelta(days=index)).isoformat()
        row={"day":day,"status":"SOURCE_UNAVAILABLE"}
        try:
            source=get_listing(rc,day)
            before_n=len(session.requests);before_b=session.bytes
            reader=rc.SourceReader({k:source[k] for k in ("table","day_utc","key","size_bytes","etag_opaque")},
                                   session,workroot/"sparse"/case["id"],pa,pq).open()
            tx_ids=set()
            source_rows=core_events=0
            for group,tab in reader.iter_row_groups(["address","block_number","transaction_index"]):
                source_rows+=len(tab)
                addrs=pc.utf8_lower(tab.column("address"))
                mask=pc.equal(addrs,emitter)
                matched=tab.filter(mask).select(["block_number","transaction_index"])
                core_events+=matched.num_rows
                for x in matched.to_pylist():
                    b,i=x["block_number"],x["transaction_index"]
                    need(type(b) is int and type(i) is int and b>=0 and i>=0,
                         "invalid source selected transaction coordinates")
                    tx_ids.add((b,i))
            need(source_rows==reader.metadata.num_rows,"incomplete source row coverage")
            need(len(tx_ids)<=core_events,"core event/selected TX contradiction")
            need(all(t[0]>=0 for t in tx_ids),"invalid source transaction")
            row.update({"status":"COMPLETE_ORIGINAL_PROJECTED_SOURCE",
                        "source_key":source["key"],"source_etag":source["etag_opaque"],
                        "source_size":source["size_bytes"],
                        "listing_sha256":source["listing_sha256"],
                        "row_groups":reader.metadata.num_row_groups,
                        "original_log_rows":source_rows,
                        "core_emitted_events":core_events,
                        "distinct_core_selected_tx":len(tx_ids),
                        "http_ranges":len(session.requests)-before_n,
                        "response_bytes":session.bytes-before_b,
                        "byte_range_sha256":[r["response_sha256"] for r in reader.ranges]})
        except Exception as e:
            row["error"]=type(e).__name__+": "+str(e)[:230]
            print("FAILED",case["id"],day,row["error"],flush=True)
            out["days"].append(row)
            break
        out["days"].append(row)
        print(case["id"],day,"core logs",core_events,"selected tx",len(tx_ids),flush=True)
    completed=[r for r in out["days"] if r["status"]=="COMPLETE_ORIGINAL_PROJECTED_SOURCE"]
    if len(completed)==30 and len(out["days"])==30:
        n=[r["distinct_core_selected_tx"] for r in completed]
        out["summary"]={"days":30,"total_distinct_selected_tx":sum(n),
            "total_core_emitted_events":sum(r["core_emitted_events"] for r in completed),
            "days_lt20":sum(x<20 for x in n),"days_ge20":sum(x>=20 for x in n),
            "days_zero":sum(x==0 for x in n),"median_tx_per_day":statistics.median(n),
            "min_tx_per_day":min(n),"max_tx_per_day":max(n),
            "days_lt6":sum(x<6 for x in n),
            "days_lt11":sum(x<11 for x in n),
            "days_lt40":sum(x<40 for x in n)}
        out["status"]="COMPLETE_SOURCE_READY_NOT_DETECTOR_ADMITTED"
    return out

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--frame",type=Path,required=True)
    p.add_argument("--windows",type=Path,required=True)
    p.add_argument("--batch",type=int,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    need(0<=a.batch<8,"batch outside frozen eight")
    fb=a.frame.read_bytes();wb=a.windows.read_bytes()
    frame=json.loads(fb);windows=json.loads(wb)
    need(frame["schema"]=="article2_phase28_candidate_frame_v1" and len(frame["cases"])==16,"frame mismatch")
    need(windows["complete"]==16 and windows["frame_sha256"]==hash_bytes(fb),"unfrozen fork windows")
    need([c["id"] for c in frame["cases"]]==[w["id"] for w in windows["results"]],"window order mismatch")
    selected=frame["cases"][a.batch*2:a.batch*2+2]
    lookup={r["id"]:r for r in windows["results"]}
    root=Path(__file__).resolve().parents[3]
    collector=root/"papers/monitoring_jss/phase16/collector"
    sys.path.insert(0,str(collector))
    import range_collector as rc
    import pyarrow as pa,pyarrow.parquet as pq,pyarrow.compute as pc
    plan={"schema_version":"article2_phase16_range_source_plan_v1","endpoint":rc.ENDPOINT,
      "caps":{"requests":1000,"total_response_bytes":1_400_000_000,"wall_seconds":1000,
      "request_timeout_seconds":35,"max_range_bytes":18_000_000,"max_footer_bytes":1_000_000,
      "max_rows":7_000_000,"max_row_groups":64,"max_top_level_columns":60,
      "max_leaf_columns":80,"max_source_bytes":800_000_000,"retries":0,"concurrency":1},
      "required_columns":{"logs":["address","block_number","transaction_index"]}}
    a.output.mkdir(parents=True,exist_ok=False)
    result={"schema":"article2_phase28_source_census_batch_v1","batch":a.batch,
       "frame_sha256":hash_bytes(fb),"windows_sha256":hash_bytes(wb),
       "source_tier":"original_S3_address_block_tx_index_projected_all_rowgroups",
       "case_results":[],"complete_cases":0,"status":"INCOMPLETE",
       "source_traffic_label_blind":True,"attack_reference_join":False,
       "new_detector_hits":None,"no_missing_day_imputation":True}
    s=rc.RangeSession(plan,a.output/"range_session")
    try:
        for case in selected:
            row=run_case(case,lookup[case["id"]],s,rc,pa,pq,pc,a.output)
            result["case_results"].append(row)
            if row["status"]!="COMPLETE_SOURCE_READY_NOT_DETECTOR_ADMITTED":
                break
        result["complete_cases"]=sum(x["status"]=="COMPLETE_SOURCE_READY_NOT_DETECTOR_ADMITTED" for x in result["case_results"])
        result["status"]="COMPLETE_TWO_CASE_SOURCE_CENSUS" if result["complete_cases"]==2 else "INCOMPLETE_UNAVAILABLE"
    finally:
        try:s.close("COMPLETE" if not s.failed and result["status"]=="COMPLETE_TWO_CASE_SOURCE_CENSUS" else "INCOMPLETE")
        except Exception as e:result["close_error"]=str(e)
        result["range_requests"]=len(s.requests);result["response_bytes"]=s.bytes
        (a.output/"source_census.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
        print("FINAL",a.batch,result["status"],result["range_requests"],result["response_bytes"],flush=True)
    if result["status"]!="COMPLETE_TWO_CASE_SOURCE_CENSUS":
        raise SystemExit("incomplete source census: do not impute missing days")
if __name__=="__main__": main()
