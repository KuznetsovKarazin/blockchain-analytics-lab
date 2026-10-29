#!/usr/bin/env python3
"""Offline, independent verifier of Phase29 original-source-selected TX files.

No network and no attack labels. Verifies every daily identity/count against the
immutable Phase28 original AWS census, checks chronology, source keys and SHA256.
"""
import argparse, csv, datetime as dt, gzip, hashlib, json, re
from collections import Counter
from pathlib import Path

HEX=re.compile(r"0x[0-9a-f]{64}\Z")

def need(x,msg):
    if not x:raise ValueError(msg)
def sha(x):return hashlib.sha256(x).hexdigest()

def verify(case,source_dir,paper):
    manfile=source_dir/"source_identity_manifest.json"
    man=json.loads(manfile.read_bytes())
    need(man["schema"]=="article2_phase29_pinned_source_tx_identity_v1","schema")
    need(man["case"]==case and man["status"]=="COMPLETE_SOURCE_ONLY","source incomplete/mixed")
    need(not man["attack_labels_used"] and not man["detector_scores_computed"]
         and not man["incident_admitted"] and not man["indexed_transaction_status_read"]
         and not man["all_emitter_event_payloads_read"],"source tier inflated")
    frame=(paper/"phase28/CANDIDATE_FRAME.json").read_bytes()
    need(sha(frame)==man["frame_sha256"],"source frame digest mismatch")
    entry=next(x for x in json.loads(frame)["cases"] if x["id"]==case)
    need(entry["core_address"]==man["core_emitter"],"core mismatch")
    batch=(int(case[-2:])-1)//2
    batch_bytes=(paper/f"phase28/results/batch_{batch}.json").read_bytes()
    need(sha(batch_bytes)==man["source_batch_sha256"],"source batch hash")
    data=json.loads(batch_bytes)
    source=next(x for x in data["case_results"] if x["id"]==case)
    need(source["status"]=="COMPLETE_SOURCE_READY_NOT_DETECTOR_ADMITTED","Phase28 case invalid")
    need(len(source["days"])==len(man["day_rows"])==30,"incomplete source days")
    with gzip.open(source_dir/"selected_tx_identities.jsonl.gz","rt",encoding="utf8") as f:
        rows=[json.loads(line) for line in f if line.strip()]
    canonical=json.dumps(rows,sort_keys=True,separators=(",",":")).encode()
    need(sha(canonical)==man["ids_sha256"] and len(rows)==man["transaction_count"],"TX file SHA/count mismatch")
    need(len({x["transaction_hash"] for x in rows})==len(rows),"duplicate TX hash")
    ordered=[(x["block_number"],x["transaction_index"]) for x in rows]
    need(ordered==sorted(set(ordered)),"transactions not uniquely ordered")
    byday={}
    for row in rows:
        need(row["case_id"]==case and row["chain_id"]==1,"case/chain")
        need(type(row["block_number"])==type(row["transaction_index"])==int,"tx identity types")
        need(HEX.fullmatch(row["transaction_hash"]) and HEX.fullmatch(row["block_hash"]),"TX or block hash")
        need(0<row["core_emitter_logs"]<=row["all_emitter_logs"],"core count")
        need(row["last_log_index"]-row["first_log_index"]+1==row["all_emitter_logs"],"gapped selected log indices")
        timestamp=dt.datetime.fromtimestamp(row["event_time_ns"]//10**9,dt.timezone.utc).date().isoformat()
        need(timestamp==row["day_utc"],"timestamp/day mismatch")
        byday.setdefault(row["day_utc"],[]).append(row)
    day_bytes=0;range_count=0
    for original,published in zip(source["days"],man["day_rows"]):
        day=original["day"]
        need(published["day_utc"]==day,"day order")
        need(published["source_key"]==original["source_key"]
             and published["source_etag"]==original["source_etag"]
             and published["source_declared_bytes"]==original["source_size"]
             and published["source_original_rows"]==original["original_log_rows"],"original source identity changed")
        arr=byday.get(day,[])
        need(len(arr)==published["selected_transactions"]==original["distinct_core_selected_tx"],"daily selected count")
        need(sum(x["core_emitter_logs"] for x in arr)==published["core_emitter_logs"]==original["core_emitted_events"],"daily core count")
        need(sum(x["all_emitter_logs"] for x in arr)==published["all_emitter_logs"],"all-emitter log count")
        ranges=published["range_hashes"]
        need(all(type(r["start"])==type(r["length"])==int and r["length"]>0
            and re.fullmatch(r"[0-9a-f]{64}",r["sha256"]) for r in ranges),"bad range receipts")
        day_bytes+=published["source_range_bytes"];range_count+=published["source_range_requests"]
    need(len(byday)<=30,"source dates")
    need(day_bytes==man["source_range_bytes"] and range_count==man["source_range_requests"],"transport bounds")
    need(len(rows)==source["summary"]["total_distinct_selected_tx"],"Phase28 total TX mismatch")
    return {"schema":"article2_phase29_independent_source_verification_v1","case":case,
      "status":"PASS_COMPLETE_SOURCE_IDENTITY_ONLY","days":30,
      "selected_tx":len(rows),"source_ranges":range_count,"source_response_bytes":day_bytes,
      "label_used":False,"scores_computed":False,"AWS_original_event_topic_data_verified":False,
      "manifest_sha256":sha(manfile.read_bytes()),"source_selected_ids_sha256":man["ids_sha256"]}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--case",required=True)
    ap.add_argument("--source-dir",required=True,type=Path)
    ap.add_argument("--out",required=True,type=Path)
    a=ap.parse_args()
    paper=Path(__file__).resolve().parents[1]
    outcome=verify(a.case,a.source_dir,paper)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(outcome,indent=2,sort_keys=True)+"\n")
    print(json.dumps(outcome,sort_keys=True))

if __name__=="__main__":main()
