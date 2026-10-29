#!/usr/bin/env python3
"""Verify Phase29 indexed selected bundles against permanently pinned original AWS identities.

No external requests, no attack labels and no detector scoring.
This audit does not authenticate receipt roots or reconstruct topics/data from S3.
"""
import argparse, gzip, hashlib, json, re
from pathlib import Path

HEX=re.compile(r"0x[0-9a-f]{64}\Z")

def need(b,msg):
    if not b: raise ValueError(msg)
def canonical(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()

def verify(case,original,indexed):
    srcman=(original/"source_identity_manifest.json").read_bytes()
    src=json.loads(srcman)
    need(src["status"]=="COMPLETE_SOURCE_ONLY" and src["case"]==case,"invalid original S3 input")
    with gzip.open(original/"selected_tx_identities.jsonl.gz","rt") as f:
        txs=[json.loads(x) for x in f if x.strip()]
    need(src["ids_sha256"]==sha(canonical(txs)),"S3 transaction digest differs")
    indexed_man_bytes=(indexed/"acquisition_manifest.json").read_bytes()
    m=json.loads(indexed_man_bytes)
    need(m["schema"]=="article2_phase29_indexed_all_emitter_bundles_v1"
         and m["case"]==case and m["status"]=="COMPLETE_INDEXED_SOURCE_MATCHED","indexed incomplete/mixed")
    need(m["processed"]==m["input_transactions"]==len(txs),"selected transaction count changed")
    need(m["s3_manifest_sha256"]==sha(srcman) and m["s3_ids_sha256"]==src["ids_sha256"],"wrong source pin")
    need(not m["reference_labels_used"] and not m["detector_scores_computed"]
         and not m["receipt_root_verified"],"source evidence tier overstated")
    with gzip.open(indexed/"indexer_observations.jsonl.gz","rt") as f:
        recs=[json.loads(x) for x in f if x.strip()]
    need(len(recs)==len(txs) and sha(canonical(recs))==m["indexed_rows_sha256"],"indexer rows differ")
    for input_tx,rec in zip(txs,recs):
        tx=rec["transaction"]
        need(rec["case"]==case and tx["transaction_hash"]==input_tx["transaction_hash"],"candidate source mismatch")
        need(tx["block_number"]==input_tx["block_number"] and tx["transaction_index"]==input_tx["transaction_index"]
             and tx["block_hash"]==input_tx["block_hash"] and tx["event_time_ns"]==input_tx["event_time_ns"],"transaction identity diverged")
        need(rec["all_emitter_log_count"]==input_tx["all_emitter_logs"],"all-emitter count diverged")
        need(rec["core_log_counts"]=={"fixed_core":input_tx["core_emitter_logs"]},"core log count diverged")
        need(rec["source_tier"]=="pinned_AWS_selected_identity_and_indexed_Blockscout_all_emitter_logs_v1"
             and rec["dataset_execution_status_source"]=="Blockscout_v2_success_status","incorrect indexer source tier")
        view=rec["views"].get("fixed_core")
        need(view and view["archived_core_log_count"]==input_tx["core_emitter_logs"],"missing fixed-core view")
        need(HEX.fullmatch(rec["all_emitter_logs_sha256"]),"no indexer event payload checksum")
    return {"schema":"article2_phase29_independent_mixed_source_verification_v1",
            "case":case,"status":"PASS_SOURCE_MATCHED_INDEXED_ONLY",
            "source_selected_transactions":len(txs),
            "indexed_all_emitter_rows":sum(r["all_emitter_log_count"] for r in recs),
            "AWS_event_payloads_fully_reacquired":False,"receipt_root_authenticated":False,
            "reference_labels_used":False,"detector_scores_computed":False,
            "indexed_manifest_sha256":sha(indexed_man_bytes),"indexed_rows_sha256":m["indexed_rows_sha256"]}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--case",required=True)
    p.add_argument("--original-dir",type=Path,required=True)
    p.add_argument("--indexed-dir",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    result=verify(a.case,a.original_dir,a.indexed_dir)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,sort_keys=True))

if __name__=="__main__":main()
