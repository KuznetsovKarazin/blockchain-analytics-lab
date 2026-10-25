"""Independent sealed phase5 audit; stdlib only, no production imports.

Phase4 accepted B5 decisions/states anchor exact semantic preservation. Prefix
states are reconstructed from accepted decision prefixes and the accepted full
identity ledger, not by running the policy implementation. FCFS uses cumulative
work/max-offset algebra; occupancy uses binary searches, independently of the
summarizer's recursion and interval sweep. This does not audit OS clock truth.
"""
from __future__ import annotations

import argparse
import bisect
from collections import Counter, deque
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
from pathlib import Path
import statistics
import zipfile

ROOT = Path(__file__).resolve().parents[3]
PAPER = ROOT / "papers/monitoring_jss"
STAGES = ("read_ns", "parse_ns", "decode_ns", "core_ns", "encode_ns", "write_ns")
BASE_SHA = "4efd4681f7229986bd7c47a1384848b837ad44ee5fdf5ec0e2c5e59b962c537b"
NS = 1_000_000_000
DAY = 86400 * NS


def canonical(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def digest(x):
    return hashlib.sha256(x).hexdigest()


def zjson(z, name):
    return json.loads(z.read(name))


def gzlines(z, name):
    with z.open(name) as source, gzip.GzipFile(fileobj=source, mode="rb") as f:
        yield from f


def state_value(z, name):
    with z.open(name) as source, gzip.GzipFile(fileobj=source, mode="rb") as f:
        raw = f.read()
    return json.loads(raw), raw


def quantile(values, p):
    return sorted(values)[max(0, (len(values) * p + 99) // 100 - 1)] if values else None


def exact(a, b, where):
    if isinstance(a, float) or isinstance(b, float):
        assert a is not None and b is not None and math.isclose(a, b, rel_tol=1e-12, abs_tol=1e-9), (where, a, b)
    else:
        assert a == b, (where, a, b)


def independent_fifo(arrivals, services):
    """Closed-form workload maxima plus monotone binary-search occupancy."""
    assert arrivals and len(arrivals) == len(services)
    assert all(type(x) is int and x >= 0 for x in [*arrivals, *services])
    assert arrivals == sorted(arrivals)
    cumulative, maximum_offset = 0, None
    starts, finishes, waits, responses = [], [], [], []
    for a, c in zip(arrivals, services):
        offset = a - cumulative
        maximum_offset = offset if maximum_offset is None else max(maximum_offset, offset)
        begin = cumulative + maximum_offset
        cumulative += c
        end = cumulative + maximum_offset
        starts.append(begin); finishes.append(end)
        waits.append(begin-a); responses.append(end-a)
    horizon = finishes[-1] - arrivals[0]
    # Counts all half-open intervals, automatically cancelling zero intervals.
    peak_wait = max(bisect.bisect_right(arrivals, t)-bisect.bisect_right(starts, t) for t in set(arrivals))
    peak_system = max(bisect.bisect_right(arrivals, t)-bisect.bisect_right(finishes, t) for t in set(arrivals))
    out = {"arrival_horizon_ns": arrivals[-1]-arrivals[0], "makespan_ns": horizon,
           "peak_waiting_records": peak_wait, "peak_in_system_records": peak_system,
           "waiting_maximum_ns": max(waits), "response_maximum_ns": max(responses),
           "modeled_busy_fraction": cumulative/horizon if horizon else None,
           "completion_throughput_records_per_second": len(arrivals)*NS/horizon if horizon else None}
    for name, values in (("waiting", waits), ("response", responses)):
        for p in (50, 95, 99):
            out[f"{name}_p{p}_ns"] = quantile(values, p)
    return out


def selfcheck():
    cases = [([0,0,0],[5,2,3],[0,5,7],2,3),
             ([0,5,5],[5,0,2],[0,0,0],0,1),
             ([0,1,2],[5,0,2],[0,4,3],2,3),
             ([0,0],[0,0],[0,0],0,0),
             ([0,10,20],[3,4,5],[0,0,0],0,1)]
    for arrivals, costs, waits, q, system in cases:
        observed = independent_fifo(arrivals,costs)
        assert observed["waiting_maximum_ns"] == max(waits)
        assert observed["waiting_p50_ns"] == quantile(waits,50)
        assert observed["peak_waiting_records"] == q
        assert observed["peak_in_system_records"] == system
    return len(cases)


def reference_audit(base_seal, reference):
    assert sha(base_seal) == reference["source_seal_sha256"] == BASE_SHA
    cells, prefix_states, checked = {}, {}, []
    with zipfile.ZipFile(base_seal) as z:
        for cid, ref in sorted(reference["cells"].items()):
            full_state, _ = state_value(z, f"cells/{cid}/final_state.json.gz")
            canonical_full = canonical(full_state)
            assert digest(canonical_full) == ref["final_state_sha256"]
            assert len(canonical_full) == ref["final_state_bytes"]
            selected = {int(x) for x in ref["prefix_decision_stream_sha256"]}
            assert selected == {1000,5000,10000,ref["records"]}
            h, identities, window, alerts, daily = hashlib.sha256(), set(), deque(), [], Counter()
            last_emitted = None
            n = notifications = 0
            for n, raw in enumerate(gzlines(z, f"cells/{cid}/decisions.jsonl.gz"),1):
                d=json.loads(raw)
                encoded=canonical(d)+b"\n"
                assert encoded == raw
                assert d["accepted"] is True and d["suppression_reason"] not in ("late","duplicate")
                assert d["observed_time"] is None and d["daily_budget"] == 5
                h.update(encoded);identities.add(d["event_id"])
                t=d["event_time_ns"]
                while window and window[0] <= t-60*NS:window.popleft()
                window.append(t)
                if d["notification_emitted"]:
                    alerts.append(d["alert_id"]);daily[d["budget_day_utc"]]+=1
                    last_emitted=t;notifications+=1
                if n in selected:
                    assert h.hexdigest() == ref["prefix_decision_stream_sha256"][str(n)]
                    reconstructed={"schema_version":full_state["schema_version"],"config":full_state["config"],
                        "seen":{k:v for k,v in full_state["seen"].items() if k in identities},
                        "order_keys":{k:v for k,v in full_state["order_keys"].items() if v in identities},
                        "watermark":[d["block_number"],d["transaction_index"],d["log_index"]],
                        "window":list(window),"policy_clock_ns":d["policy_clock_ns"],
                        "last_emitted_time_ns":last_emitted,"daily_counts":dict(daily),
                        "token_credit_units":d["token_credit_units"] if ref["policy"]=="token_bucket" else DAY,
                        "alert_ids":list(alerts)}
                    assert len(reconstructed["seen"]) == len(reconstructed["order_keys"]) == n
                    if n==ref["records"]:assert reconstructed == full_state
                    data=canonical(reconstructed)
                    prefix_states[(cid,n)]={"sha256":digest(data),"bytes":len(data),
                        "rolling_window_entries":len(window),"notification_ids":len(alerts)}
            assert n==ref["records"] and notifications==ref["notifications"]
            assert h.hexdigest()==ref["decision_stream_sha256"]
            assert max(daily.values(),default=0)<=5
            cells[cid]={"records":n,"notifications":notifications,"decision_stream_sha256":h.hexdigest()}
            checked.append({"cell_id":cid,"records":n,"prefixes":sorted(selected)})
    return cells,prefix_states,checked


def inspect_seal(path):
    z=zipfile.ZipFile(path)
    manifest=zjson(z,"ARCHIVE_MANIFEST.json")
    names=[r["path"] for r in manifest["files"]]
    assert len(names)==len(set(names))
    assert set(z.namelist())==set(names)|{"ARCHIVE_MANIFEST.json"}
    for r in manifest["files"]:
        with z.open(r["path"]) as f:assert hashlib.file_digest(f,"sha256").hexdigest()==r["sha256"],r["path"]
        assert z.getinfo(r["path"]).file_size==r["bytes"]
    return z,manifest


def audit_actual(archive, base_seal, summary_path):
    z, seal_manifest=inspect_seal(archive)
    with z:
        frozen=zjson(z,"design_freeze.json"); execution=zjson(z,"execution_manifest.json")
        assert execution["status"]=="complete" and len(execution["jobs"])==len(frozen["jobs"])==54
        assert digest(z.read("design_freeze.json"))==execution["design_freeze_sha256"]
        for name,h in frozen["source_hashes"].items():assert digest(z.read("source_snapshot/"+name))==h,name
        config=zjson(z,"source_snapshot/resource_benchmark_config.json")
        assert digest(z.read("source_snapshot/resource_benchmark_config.json"))==frozen["config_sha256"]
        references=zjson(z,"source_snapshot/resource_semantic_reference.json")
        cells,prefix_states,ref_check=reference_audit(base_seal,references)
        study=zjson(z,"source_snapshot/budget_policy_study_config.json")
        emitters={e["id"]:e for e in study["emitters"]}
        assert config["timing_repetitions"]==5 and config["memory_repetitions"]==1
        summary=json.loads(Path(summary_path).read_text()) if summary_path else None
        if summary:
            assert summary["status"]=="complete" and summary["timing_workers"]==30 and summary["memory_workers"]==24
            assert summary["virtual_scenarios"]==150
            assert summary["execution_manifest_sha256"]==digest(z.read("execution_manifest.json"))
            assert summary["config_sha256"]==frozen["config_sha256"]
            assert summary["summarizer_sha256"]==frozen["source_hashes"]["summarize_resource_benchmark.py"]
            for name,receipt in summary["artifacts"].items():
                p=Path(summary_path).parent/name
                assert sha(p)==receipt["sha256"] and p.stat().st_size==receipt["bytes"]
            timing_report={r["job_id"]:r for r in summary["timing_runs"]}
            memory_report={r["job_id"]:r for r in summary["memory_probes"]}
            queue_report={(r["job_id"],r["schedule"]):r for r in summary["virtual_queue_runs"]}
            assert len(timing_report)==30 and len(memory_report)==24 and len(queue_report)==150
        expected={(pop,pol,rep) for pop in config["populations"] for pol in config["policies"] for rep in range(1,6)}
        expected_memory={(pop,pol,n if n!="full" else cells[f"{pop}__{pol}__B5"]["records"])
                         for pop in config["populations"] for pol in config["policies"] for n in config["memory_prefixes"]}
        got_timing=set();got_memory=set();pids=set();all_rows=queue_rows=0;checked=[]
        for spec,run in zip(frozen["jobs"],execution["jobs"]):
            assert all(run[k]==v for k,v in spec.items())
            assert run["exit_code"]==0
            job_raw=z.read(run["job_path"]);assert digest(job_raw)==spec["job_sha256"]
            job=json.loads(job_raw);cid=f"{run['population_id']}__{run['policy']}__B5";n=job["reference"]["records"]
            folder=run["output_path"]
            result_raw=z.read(folder+"/summary.json");assert digest(result_raw)==run["summary_sha256"]
            result=json.loads(result_raw)
            assert result["status"]=="complete" and result["records"]==n and result["job_source_sha256"]==digest(job_raw)
            assert json.loads(z.read(folder+"/job.json"))==job
            assert result["cell_id"]==job["cell_id"]==run["job_id"]
            assert result["source_sha256"]==job["source_sha256"]
            assert all(frozen["source_hashes"][k]==v for k,v in job["source_sha256"].items())
            assert job["cpu_affinity"]==frozen["actual_cpu_affinity"]==result["environment"]["cpu_affinity"]
            assert result["environment"]["thread_environment"]==config["thread_environment"]
            assert result["environment"]["pid"] not in pids;pids.add(result["environment"]["pid"])
            emitter=emitters[run["population_id"]]
            policy_config={"policy":run["policy"],"daily_budget":5,"window_start_ns":study["window"]["start_ns"],
                "window_end_ns":study["window"]["end_ns"],"address":emitter["address"],"chain_id":emitter["chain_id"],**study["detector"]}
            assert result["policy_config"]==job["policy_config"]==policy_config
            expected_prefix=prefix_states[(cid,n)]
            state,raw_state=state_value(z,folder+"/final_state.json.gz")
            assert raw_state==canonical(state)
            assert digest(raw_state)==result["final_state_sha256"]==expected_prefix["sha256"]
            assert len(raw_state)==result["canonical_state_bytes"]==expected_prefix["bytes"]
            assert len(state["seen"])==result["seen_entries"]==len(state["order_keys"])==result["order_key_entries"]==n
            assert len(state["window"])==result["rolling_window_entries"]==expected_prefix["rolling_window_entries"]
            assert len(state["alert_ids"])==result["notification_ids"]==expected_prefix["notification_ids"]
            assert result["decision_stream_sha256"]==job["reference"]["decision_stream_sha256"]==references["cells"][cid]["prefix_decision_stream_sha256"][str(n)]
            for name,r in result["artifacts"].items():
                assert digest(z.read(folder+"/"+name))==r["sha256"]
                assert z.getinfo(folder+"/"+name).file_size==r["bytes"]
            for k in ("loop_wall_ns","loop_cpu_ns","preflight_ns","source_open_close_ns","eof_read_ns","output_close_ns"):
                assert type(result[k]) is int and result[k]>=0
            for mem in (result["baseline_memory"],result["before_serialization_memory"]):
                assert all(type(v) is int and v>0 for v in mem.values())
            if run["mode"]=="memory":
                got_memory.add((run["population_id"],run["policy"],n))
                assert result["service_total_ns"] is None and result["stage_total_ns"] is None
                if summary:
                    r=memory_report[run["job_id"]]
                    assert r["population_id"]==run["population_id"] and r["policy"]==run["policy"] and r["daily_budget"]==5
                    exact(r["baseline_current_rss_bytes"],result["baseline_memory"]["current_rss_bytes"],"baseline RSS")
                    for k in ("records","canonical_state_bytes","seen_entries","order_key_entries","rolling_window_entries","notification_ids"):exact(r[k],result[k],k)
                    exact(r["current_rss_before_serialization_bytes"],result["before_serialization_memory"]["current_rss_bytes"],"RSS")
                    exact(r["process_peak_rss_before_serialization_bytes"],result["before_serialization_memory"]["process_peak_rss_bytes"],"peak RSS")
                    exact(r["rss_difference_from_baseline_bytes"],result["before_serialization_memory"]["current_rss_bytes"]-result["baseline_memory"]["current_rss_bytes"],"RSS diff")
                checked.append({"job_id":run["job_id"],"mode":"memory","records":n,"state_exact":True})
                continue
            got_timing.add((run["population_id"],run["policy"],run["repetition"]))
            vals={k:[] for k in (*STAGES,"service_ns")};event_times=[];h=hashlib.sha256();i=0
            with zipfile.ZipFile(base_seal) as base:
                prior=iter(gzlines(base,f"cells/{cid}/decisions.jsonl.gz"))
                times=iter(gzlines(z,folder+"/timings.jsonl.gz"))
                for i,line in enumerate(gzlines(z,folder+"/decisions.jsonl.gz"),1):
                    assert line==next(prior)
                    d=json.loads(line);t=json.loads(next(times));h.update(line)
                    assert t["record_index"]==i-1 and t["event_time_ns"]==d["event_time_ns"]
                    assert all(type(t[k]) is int and t[k]>=0 for k in vals)
                    assert t["service_ns"]==sum(t[k] for k in STAGES)
                    event_times.append(t["event_time_ns"])
                    for k in vals:vals[k].append(t[k])
                assert next(prior,None) is None and next(times,None) is None
            assert i==n and h.hexdigest()==result["decision_stream_sha256"]
            assert event_times==sorted(event_times)
            assert {k:sum(vals[k]) for k in STAGES}==result["stage_total_ns"]
            assert sum(vals["service_ns"])==result["service_total_ns"]<=result["loop_wall_ns"]
            all_rows+=n
            if summary:
                r=timing_report[run["job_id"]]
                assert r["population_id"]==run["population_id"] and r["policy"]==run["policy"] and r["daily_budget"]==5 and r["repetition"]==run["repetition"]
                exact(r["current_rss_before_serialization_bytes"],result["before_serialization_memory"]["current_rss_bytes"],"timing RSS")
                exact(r["process_peak_rss_before_serialization_bytes"],result["before_serialization_memory"]["process_peak_rss_bytes"],"timing peak RSS")
                for k in ("records","loop_wall_ns","loop_cpu_ns","service_total_ns","source_open_close_ns","eof_read_ns","trace_encode_ns","trace_write_ns","output_close_ns","preflight_ns"):exact(r[k],result[k],k)
                exact(r["nonservice_loop_ns"],result["loop_wall_ns"]-result["service_total_ns"],"residual")
                exact(r["loop_throughput_records_per_second"],n*NS/result["loop_wall_ns"],"throughput")
                exact(r["subprocess_wall_ns"],run["subprocess_wall_ns"],"subprocess wall")
                for k,v in vals.items():
                    for p in (50,95,99):exact(r[k.removesuffix("_ns")+f"_p{p}_ns"],quantile(v,p),"quantile")
                for schedule in config["virtual_schedules"]:
                    if schedule["kind"]=="event_gaps":
                        arrivals=[(x-event_times[0])//schedule["scale"] for x in event_times]
                        name=f"event_gaps_x{schedule['scale']}"
                    else:
                        assert schedule["kind"]=="constant_rate"
                        arrivals=[i*NS//schedule["events_per_second"] for i in range(n)]
                        name=f"constant_{schedule['events_per_second']}_per_second"
                    metrics=independent_fifo(arrivals,vals["service_ns"])
                    actual=queue_report[(run["job_id"],name)]
                    assert actual["population_id"]==run["population_id"] and actual["policy"]==run["policy"] and actual["daily_budget"]==5 and actual["repetition"]==run["repetition"] and actual["records"]==n
                    for k,v in metrics.items():exact(actual[k],v,"queue "+k)
                    queue_rows+=n
            checked.append({"job_id":run["job_id"],"mode":"timing","records":n,"decisions_exact":True,"state_exact":True})
        assert got_timing==expected and got_memory==expected_memory and len(pids)==54
        if summary:
            assert summary["timing_records"]==all_rows==725400
            assert len(summary["timing_group_summaries"])==156
            assert len(summary["virtual_queue_group_summaries"])==240
            # Recompute every published repetition aggregate from independently checked run rows.
            for rows,grouped,keys in [(summary["timing_runs"],summary["timing_group_summaries"],("population_id","policy")),
                                     (summary["virtual_queue_runs"],summary["virtual_queue_group_summaries"],("population_id","policy","schedule"))]:
                assert len({tuple(g[k] for k in keys)+(g["metric"],) for g in grouped})==len(grouped)
                for g in grouped:
                    vs=[r[g["metric"]] for r in rows if all(r[k]==g[k] for k in keys)]
                    assert len(vs)==g["repetitions"]==5
                    exact(g["minimum"],min(vs),"group min");exact(g["maximum"],max(vs),"group max")
                    exact(g["median"],statistics.median(vs),"group median")
        calibration=zjson(z,"clock_calibration.json")
        return {"status":"PASS","archive_sha256":sha(archive),"archive_bytes":Path(archive).stat().st_size,
                "archive_members":len(z.infolist()),"manifested_members_all_sha_crc_size_verified":len(seal_manifest["files"]),
                "base_reference_sha256":BASE_SHA,"reference_cells":ref_check,"memory_prefix_states_independently_reconstructed":24,
                "workers_verified":54,"fresh_worker_pids":len(pids),"decision_rows_compared_exactly":all_rows,
                "timing_rows_recomputed":all_rows,"queue_scenarios_checked":150 if summary else 0,"queue_rows_recomputed":queue_rows,
                "summary_sha256":sha(summary_path) if summary_path else None,"clock_calibration_keys":sorted(calibration),
                "checks":checked,"production_imports":False,
                "limits":"Verifies recorded durations/arithmetic/semantic preservation, not truth of OS clocks, dedicated hardware isolation, live arrival, detection quality or durable delivery."}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive",type=Path)
    p.add_argument("--summary",type=Path)
    p.add_argument("--base-seal",type=Path,default=ROOT/"data/raw/monitoring_jss/budget/budget_policy_20261025T125143_314640Z_sealed_evidence.zip")
    p.add_argument("--reference",type=Path,default=PAPER/"resource_semantic_reference.json")
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args();fixtures=selfcheck()
    if args.archive:
        report=audit_actual(args.archive,args.base_seal,args.summary)
    else:
        cells,states,checked=reference_audit(args.base_seal,json.loads(args.reference.read_text()))
        report={"status":"PASS","scope":"pre-measurement semantic reference and reconstructed prefix states",
            "reference_sha256":sha(args.reference),"base_seal_sha256":sha(args.base_seal),"cells":checked,
            "prefix_states":{cid+"__prefix"+str(n):v for (cid,n),v in states.items()},"production_imports":False}
    report.update(completed_utc=datetime.now(timezone.utc).isoformat(),independent_fifo_fixture_cases=fixtures,
                  audit_source_sha256=sha(__file__))
    with args.output.open("x") as f:json.dump(report,f,indent=2,sort_keys=True,allow_nan=False);f.write("\n")
    print(json.dumps({k:report[k] for k in ("status","scope","workers_verified","decision_rows_compared_exactly","queue_scenarios_checked") if k in report}))


if __name__=="__main__":main()
