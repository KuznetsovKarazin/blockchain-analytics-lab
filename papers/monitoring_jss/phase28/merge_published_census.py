#!/usr/bin/env python3
"""Publish-source QA: eight original AWS ranged-read batch JSONs, no labels."""
import csv,hashlib,json,statistics,sys
from pathlib import Path
def sha(raw):return hashlib.sha256(raw).hexdigest()
def need(ok,msg):
 if not ok:raise ValueError(msg)
def main():
 root=Path("papers/monitoring_jss/phase28")
 frame=(root/"CANDIDATE_FRAME.json").read_bytes()
 windows=(root/"FORK_WINDOWS.json").read_bytes()
 f=json.loads(frame);w=json.loads(windows)
 need(len(f["cases"])==len(w["results"])==16,"source frame size")
 folder=root/"results";folder.mkdir(exist_ok=True)
 all_cases=[];daily=[];manifest=[]
 for batch in range(8):
  source=Path(sys.argv[1])/str(batch)/"source_census.json"
  raw=source.read_bytes();data=json.loads(raw)
  need(data["schema"]=="article2_phase28_source_census_batch_v1","batch schema")
  need(data["status"]=="COMPLETE_TWO_CASE_SOURCE_CENSUS" and data["complete_cases"]==2,"incomplete batch")
  need(data["frame_sha256"]==sha(frame) and data["windows_sha256"]==sha(windows),"changed frozen data")
  need(data["batch"]==batch and len(data["case_results"])==2,"batch order")
  for c in data["case_results"]:
   expected=f["cases"][len(all_cases)]
   need(c["id"]==expected["id"] and c["status"]=="COMPLETE_SOURCE_READY_NOT_DETECTOR_ADMITTED","case identity/status")
   obs=c["days"]; need(len(obs)==30 and all(x["status"]=="COMPLETE_ORIGINAL_PROJECTED_SOURCE" for x in obs),"missing date")
   counts=[x["distinct_core_selected_tx"] for x in obs]
   need(sum(counts)==c["summary"]["total_distinct_selected_tx"],"TX total mismatch")
   need(sum(x["core_emitted_events"] for x in obs)==c["summary"]["total_core_emitted_events"],"log total mismatch")
   need(all(x["distinct_core_selected_tx"]<=x["core_emitted_events"] for x in obs),"TX exceeds logs")
   need(sum(n<20 for n in counts)==c["summary"]["days_lt20"],"readiness total mismatch")
   all_cases.append({"id":c["id"],"family":c["family"],"first":c["window_first"],
      "last":c["window_last_inclusive"],"total_tx":sum(counts),
      "total_core_events":c["summary"]["total_core_emitted_events"],
      "days_lt20":sum(n<20 for n in counts),"days_zero":sum(n==0 for n in counts),
      "active_days_lt20":sum(0<n<20 for n in counts),"max_tx_day":max(counts),
      "median_tx_per_day":statistics.median(counts),"status":"SOURCE_CENSUS_ONLY"})
   for row in obs:
    need(row["day"] in [x["day"] for x in obs],"invalid day")
    daily.append({"id":c["id"],"day":row["day"],"tx":row["distinct_core_selected_tx"],
      "core_events":row["core_emitted_events"],"original_source":row["source_key"],
      "etag":row["source_etag"],"original_rows":row["original_log_rows"],
      "http_ranges":row["http_ranges"],"response_bytes":row["response_bytes"]})
  (folder/f"batch_{batch}.json").write_bytes(raw)
  manifest.append({"batch":batch,"sha256":sha(raw),"ranges":data["range_requests"],"response_bytes":data["response_bytes"]})
 need(len(all_cases)==16 and len(daily)==480,"missing cases or days")
 sums={"schema":"phase28_external_candidate_source_census_v1","candidate_views":16,
   "total_emitter_days":480,"active_emitter_days":sum(x["tx"]>0 for x in daily),
   "zero_emitter_days":sum(x["tx"]==0 for x in daily),
   "days_lt20":sum(x["tx"]<20 for x in daily),
   "days_positive_lt20":sum(0<x["tx"]<20 for x in daily),
   "days_ge20":sum(x["tx"]>=20 for x in daily),
   "selected_tx":sum(x["tx"] for x in daily),"source_ranges":sum(x["ranges"] for x in manifest),
   "source_bytes":sum(x["response_bytes"] for x in manifest),
   "admitted_additional_attack_families":0,"new_detector_results":None,
   "critical_limit":"PoC fork-block dates are not certified exploit dates; counts are an upper bound on possible per-token positive-history readiness, not actual rank scores."}
 (folder/"CENSUS_SUMMARY.json").write_text(json.dumps(sums,indent=2,sort_keys=True)+"\n")
 (folder/"SOURCE_RECEIPTS.json").write_text(json.dumps({"batch_receipts":manifest,"source_actions_run":40914786131,"frame_sha256":sha(frame),"windows_sha256":sha(windows)},indent=2)+"\n")
 for name,values in (("CENSUS_CASES.csv",all_cases),("CENSUS_DAILY.csv",daily)):
  with (folder/name).open("w",newline="") as out:
   writer=csv.DictWriter(out,fieldnames=values[0].keys());writer.writeheader();writer.writerows(values)
 print("PASS independent merge",json.dumps(sums,sort_keys=True))
if __name__=="__main__":main()
