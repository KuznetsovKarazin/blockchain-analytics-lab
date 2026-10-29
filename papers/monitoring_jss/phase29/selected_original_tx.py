#!/usr/bin/env python3
"""Phase29: recover all selected transaction IDs from original pinned AWS source.
Read-only, label-free; no detector computation, scores or attack joins.
"""
import argparse, collections, datetime as dt, gzip, hashlib, json, shutil, sys
from pathlib import Path

CASES = ("cohort28_02", "cohort28_07", "cohort28_09", "cohort28_10", "cohort28_11", "cohort28_13", "cohort28_14")
COLS = ["address","block_number","transaction_index","transaction_hash",
        "block_hash","block_timestamp","log_index"]

def check(ok, why):
    if not ok: raise ValueError(why)

def sha(b): return hashlib.sha256(b).hexdigest()

def ts_ns(value):
    if isinstance(value,str): value=dt.datetime.fromisoformat(value.replace("Z","+00:00"))
    check(isinstance(value,dt.datetime),"timestamp not datetime")
    if value.tzinfo is None: value=value.replace(tzinfo=dt.timezone.utc)
    x=value.astimezone(dt.timezone.utc)
    delta=x-dt.datetime(1970,1,1,tzinfo=dt.timezone.utc)
    return (delta.days*86400+delta.seconds)*10**9+delta.microseconds*1000

def match_positions(tab, positions, pa,pc):
    blocks=pc.cast(tab.column("block_number"),pa.int64())
    indexes=pc.cast(tab.column("transaction_index"),pa.int64())
    coords=pc.add(pc.multiply(blocks,pa.scalar(65536,pa.int64())),indexes)
    vs=pa.array([b*65536+i for b,i in sorted(positions)],type=pa.int64())
    return pc.is_in(coords,value_set=vs)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--case",choices=CASES,required=True)
    ap.add_argument("--out",type=Path,required=True)
    args=ap.parse_args()
    import pyarrow as pa, pyarrow.compute as pc, pyarrow.parquet as pq
    root=Path(__file__).resolve().parents[3]
    paper=root/"papers/monitoring_jss"
    sys.path.insert(0,str(paper/"phase16/collector"))
    import range_collector as rc
    frame_bytes=(paper/"phase28/CANDIDATE_FRAME.json").read_bytes()
    frame=json.loads(frame_bytes)
    check(frame["schema"]=="article2_phase28_candidate_frame_v1" and len(frame["cases"])==16,"bad frozen frame")
    frame_case=next(x for x in frame["cases"] if x["id"]==args.case)
    batch=int(args.case[-2:])-1
    batch_json=json.loads((paper/f"phase28/results/batch_{batch//2}.json").read_bytes())
    check(batch_json["status"]=="COMPLETE_TWO_CASE_SOURCE_CENSUS","Phase28 incomplete")
    check(batch_json["frame_sha256"]==sha(frame_bytes),"Phase28 frame changed")
    case=next(x for x in batch_json["case_results"] if x["id"]==args.case)
    check(case["core_address"]==frame_case["core_address"] and case["status"]=="COMPLETE_SOURCE_READY_NOT_DETECTOR_ADMITTED","core/source mismatch")
    days=case["days"]
    check(len(days)==30,"not thirty days")
    check(all(x["status"]=="COMPLETE_ORIGINAL_PROJECTED_SOURCE" for x in days),"missing original source")
    start=dt.date.fromisoformat(days[0]["day"])
    check([x["day"] for x in days]==[(start+dt.timedelta(days=i)).isoformat() for i in range(30)],"nonconsecutive days")
    check(sum(x["distinct_core_selected_tx"] for x in days)==case["summary"]["total_distinct_selected_tx"],"Phase28 sum disagrees")
    args.out.mkdir(parents=True,exist_ok=False)
    caps={"requests":1400,"total_response_bytes":(3600000000 if args.case in {"cohort28_10","cohort28_07","cohort28_11","cohort28_14"} else 2800000000),"wall_seconds":1550,
          "request_timeout_seconds":45,"max_range_bytes":32000000,"max_footer_bytes":1500000,
          "max_rows":10000000,"max_row_groups":100,"max_top_level_columns":100,
          "max_leaf_columns":120,"max_source_bytes":850000000,"retries":0,"concurrency":1}
    plan={"schema_version":"article2_phase16_range_source_plan_v1","endpoint":rc.ENDPOINT,
          "caps":caps,"required_columns":{"logs":COLS}}
    session=rc.RangeSession(plan,args.out/"range_capture")
    results=[];daily=[];failure=None;emitter=frame_case["core_address"].lower()
    try:
        for source_day in days:
            day=source_day["day"]
            src={"table":"logs","day_utc":day,"key":source_day["source_key"],
                 "size_bytes":source_day["source_size"],"etag_opaque":source_day["source_etag"]}
            start_b=session.bytes;start_r=len(session.requests)
            reader=rc.SourceReader(src,session,args.out/"sparse",pa,pq).open()
            core_events=0;positions=set();rows_by_pos=collections.defaultdict(list)
            scanned=0
            # Pass 1: find the complete daily selected-transaction set using only
            # core address and transaction coordinates. An individual transaction
            # can straddle a Parquet row-group boundary; an unrelated row group
            # with no core log can still contain other logs of a selected tx.
            for rg,tab in reader.iter_row_groups(["address","block_number","transaction_index"]):
                scanned+=len(tab)
                addr=pc.utf8_lower(tab.column("address"))
                core=tab.filter(pc.equal(addr,emitter))
                core_events+=len(core)
                rg_pos={(int(r["block_number"]),int(r["transaction_index"]))
                    for r in core.select(["block_number","transaction_index"]).to_pylist()}
                check(all(0<=b and 0<=i<65536 for b,i in rg_pos),
                      "invalid historical transaction key")
                positions.update(rg_pos)
            # Pass 2: now inspect all row groups for those *same* selected keys.
            # Failing to do this silently truncates cross-rowgroup bundles.
            if positions:
                for rg in range(reader.metadata.num_row_groups):
                    keys=reader.read_row_group(rg,["block_number","transaction_index"])
                    mask=match_positions(keys,positions,pa,pc)
                    if bool(pc.any(mask).as_py()):
                        full=reader.read_row_group(rg,COLS)
                        for row in full.filter(mask).to_pylist():
                            pos=(int(row["block_number"]),int(row["transaction_index"]))
                            check(pos in positions,"unselected transaction row")
                            rows_by_pos[pos].append(row)
            check(scanned==source_day["original_log_rows"]==reader.metadata.num_rows,"source row coverage mismatch")
            check(core_events==source_day["core_emitted_events"],"Phase28 core count changed")
            check(len(positions)==source_day["distinct_core_selected_tx"],"Phase28 tx count changed")
            check(set(rows_by_pos)==positions,"selected bundle missing")
            local=[]
            for pos,items in sorted(rows_by_pos.items()):
                items=sorted(items,key=lambda x:int(x["log_index"]))
                log_idx=[int(x["log_index"]) for x in items]
                check(all(v==u+1 for u,v in zip(log_idx,log_idx[1:])),"gapped all-emitter transaction logs")
                hashes={str(x["transaction_hash"]).lower() for x in items}
                blockhashes={str(x["block_hash"]).lower() for x in items}
                stamps={ts_ns(x["block_timestamp"]) for x in items}
                check(len(hashes)==len(blockhashes)==len(stamps)==1,"mixed tx identity/time")
                t=next(iter(stamps));utc=dt.datetime.fromtimestamp(t/1e9,tz=dt.timezone.utc).date().isoformat()
                check(utc==day,"source timestamp outside day")
                ncore=sum(str(x["address"]).lower()==emitter for x in items)
                check(ncore>0,"selected tx lacks actual nominated-core log")
                local.append({"day_utc":day,"chain_id":1,"case_id":args.case,
                  "block_number":pos[0],"transaction_index":pos[1],
                  "transaction_hash":next(iter(hashes)),"block_hash":next(iter(blockhashes)),
                  "event_time_ns":t,"core_emitter_logs":ncore,"all_emitter_logs":len(items),
                  "first_log_index":log_idx[0],"last_log_index":log_idx[-1]})
            check(sum(x["core_emitter_logs"] for x in local)==core_events,"core group sum mismatch")
            check(len(local)==len(positions),"selected tx count mismatch")
            results.extend(local)
            daily.append({"day_utc":day,"selected_transactions":len(local),"core_emitter_logs":core_events,
              "all_emitter_logs":sum(x["all_emitter_logs"] for x in local),
              "source_key":src["key"],"source_etag":src["etag_opaque"],
              "source_declared_bytes":src["size_bytes"],"source_original_rows":scanned,
              "source_range_requests":len(session.requests)-start_r,
              "source_range_bytes":session.bytes-start_b,
              "range_hashes":[{"start":r["start"],"length":r["length"],"sha256":r["response_sha256"]} for r in reader.ranges]})
            shutil.rmtree(reader.directory)
            print("SOURCE_OK",args.case,day,"tx",len(local),"GET bytes",session.bytes,flush=True)
        session.close("COMPLETE")
    except Exception as exc:
        failure={"type":type(exc).__name__,"reason":str(exc),"completed_days":len(daily)}
        try:session.close("INCOMPLETE")
        except Exception:pass
    result={"schema":"article2_phase29_pinned_source_tx_identity_v1",
      "case":args.case,"frame_sha256":sha(frame_bytes),"source_batch_sha256":sha((paper/f"phase28/results/batch_{batch//2}.json").read_bytes()),
      "core_emitter":emitter,"status":"COMPLETE_SOURCE_ONLY" if not failure and len(daily)==30 else "INCOMPLETE",
      "failure":failure,"attack_labels_used":False,"detector_scores_computed":False,"incident_admitted":False,
      "indexed_transaction_status_read":False,"all_emitter_event_payloads_read":False,"day_rows":daily,
      "transaction_count":len(results),"source_range_requests":len(session.requests),
      "source_range_bytes":session.bytes,
      "ids_sha256":sha(json.dumps(results,sort_keys=True,separators=(",",":")).encode())}
    (args.out/"source_identity_manifest.json").write_text(json.dumps(result,indent=2)+"\n")
    with (args.out/"selected_tx_identities.jsonl.gz").open("wb") as f:
        with gzip.GzipFile(fileobj=f,filename="",mode="wb",mtime=0) as zipped:
            for row in results:zipped.write((json.dumps(row,sort_keys=True,separators=(",",":"))+"\n").encode())
    print("FINAL",result["status"],"records",len(results),"ranges",len(session.requests),"bytes",session.bytes,flush=True)
    if result["status"]!="COMPLETE_SOURCE_ONLY":raise SystemExit(1)
if __name__=="__main__":main()
