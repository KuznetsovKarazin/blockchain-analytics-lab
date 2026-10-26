#!/usr/bin/env python3
"""A separate, bounded provider attempt with a retained-log positive control.

Successful controls and complete returned chunks do not prove index completeness,
all intermediate states, hidden writes, initializer effects or consensus validity.
"""
import argparse
from collections import Counter
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(ok, message):
    if not ok:
        raise ValueError(message)


def bound(path, digest):
    raw = path.read_bytes()
    need(sha(raw) == digest, "Frozen input differs: " + path.name)
    return json.loads(raw)


def module(name, path, digest):
    need(sha(path.read_bytes()) == digest, "Frozen module differs: " + path.name)
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def new_seen():
    return {"log_ids": set(), "block_hashes": {}, "tx_positions": {}, "tx_contexts": {}}


def verify_header(value, expected, transport, codec):
    need(isinstance(value, dict), "Header is not an object")
    number = transport.quantity(value.get("number"))
    timestamp = transport.quantity(value.get("timestamp"))
    block_hash = "0x" + codec.hx(value.get("hash"), 32).hex()
    state_root = "0x" + codec.hx(value.get("stateRoot"), 32).hex()
    transactions = value.get("transactions")
    need(isinstance(transactions, list), "Header transaction list missing")
    transactions = ["0x" + codec.hx(x, 32).hex() for x in transactions]
    need(len(transactions) == len(set(transactions)), "Duplicate header transaction hash")
    need(number == expected["number"] and block_hash == expected["hash"]
         and state_root == expected["state_root"]
         and timestamp == transport.utc_seconds(expected["timestamp_utc"])
         and transactions == expected["transaction_hashes"], "Provider header differs from retained reference")
    return {"number": number, "hash": block_hash, "state_root": state_root,
            "timestamp_utc": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
            "transaction_count": len(transactions), "full_transaction_hash_list_equal": True}


def canonical_log(value, transport, codec):
    return {"address": "0x" + codec.hx(value.get("address"), 20).hex(),
            "topics": ["0x" + codec.hx(x, 32).hex() for x in value["topics"]],
            "data": "0x" + codec.hx(value.get("data")).hex(),
            "blockHash": "0x" + codec.hx(value.get("blockHash"), 32).hex(),
            "transactionHash": "0x" + codec.hx(value.get("transactionHash"), 32).hex(),
            **{key: transport.quantity(value.get(key)) for key in ("blockNumber", "transactionIndex", "logIndex")},
            "removed": value.get("removed")}


def verify_control(logs, expected_logs, plan, headers, helper, transport, codec, topic_names):
    need(isinstance(logs, list) and len(logs) <= plan["caps"]["max_event_logs"], "Control log shape/cap")
    block = plan["positive_control"]["block_number"]
    seen, records, canonical = new_seen(), [], []
    for log in logs:
        records.append(helper.validate_log(log, {"from_block": block, "to_block": block}, plan,
                                           transport, codec, topic_names, headers, seen))
        if "blockTimestamp" in log:
            need(transport.quantity(log["blockTimestamp"]) == transport.utc_seconds(headers["creation"]["timestamp_utc"]),
                 "Control optional timestamp differs")
        canonical.append(canonical_log(log, transport, codec))
    expected = [canonical_log(log, transport, codec) for log in expected_logs]
    need(len(expected) == 2 and {x["logIndex"] for x in expected} == {122, 123}, "Retained constructor control differs")
    need(all(record in canonical for record in expected), "Known constructor logs absent or different")
    return {"status": "PASS_RETAINED_CONSTRUCTOR_LOG_SUBSET", "returned_logs": len(logs),
            "expected_logs_matched": len(expected), "additional_logs_allowed": len(logs) - len(expected),
            "block_number": block, "block_hash": plan["positive_control"]["block_hash"],
            "decoded_event_counts": dict(Counter(row["decoded"]["event"] for row in records)),
            "included_in_window_replay": False}


def fold(events, seed, target, plan, helper, codec):
    events.sort(key=lambda row: (row["block_number"], row["transaction_index"], row["log_index"]))
    last = {}
    for row in events:
        need(row["log_index"] > last.get(row["block_number"], -1), "Transaction order conflicts with log order")
        last[row["block_number"]] = row["log_index"]
    model = helper.seed_registry(codec, seed, plan["diamond"], plan["caps"])
    applied, error = 0, None
    for index, row in enumerate(events):
        trial = copy.deepcopy(model)
        try:
            trial.apply(row["decoded"])
            model, applied = trial, applied + 1
        except ValueError as exc:
            error = {"event_index": index, "block_number": row["block_number"], "log_index": row["log_index"], "detail": str(exc)}
            break
    target = helper.project_state(target)
    return {"nominal_replay_performed": True, "nominal_replay_events_applied": applied,
            "nominal_replay_error": error, "nominal_replay_end": model.snapshot() if error is None else None,
            "end_checkpoint_comparison": {key + "_equal": error is None and model.snapshot()[key] == target[key]
                                          for key in ("owner", "facets", "selector_map")}}


def main():
    parser = argparse.ArgumentParser()
    for name in ("plan", "checkpoints", "phase12-failed", "phase13-failed", "constructor-receipt", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--accepted-plan-sha256", required=True)
    parser.add_argument("--accepted-runner-sha256", required=True)
    args = parser.parse_args()
    plan = bound(args.plan, args.accepted_plan_sha256)
    need(sha(Path(__file__).read_bytes()) == args.accepted_runner_sha256, "Accepted runner differs")
    need(plan["schema_version"] == "article2_phase13_publicnode_history_plan_v1", "Wrong plan schema")
    paper = Path(__file__).resolve().parents[2]
    loaded = {key: module("phase13_publicnode_" + key, paper / row["path"], row["sha256"])
              for key, row in plan["module_bindings"].items()}
    transport, codec, helper, primitive = (loaded[k] for k in ("transport", "event_codec", "window_helper", "keccak"))
    prior = plan["prior_bindings"]
    checkpoints = bound(args.checkpoints, prior["checkpoint_summary_sha256"])
    failed12 = bound(args.phase12_failed, prior["phase12_failed_summary_sha256"])
    failed13 = bound(args.phase13_failed, prior["phase13_failed_summary_sha256"])
    receipt = bound(args.constructor_receipt, prior["constructor_receipt_sha256"])["result"]
    old_plan = bound(paper / prior["original_plan_path"], prior["original_plan_sha256"])
    for row in plan["document_bindings"]:
        bound(paper / row["path"], row["sha256"])
    need(failed12["disposition"] == failed13["disposition"] == "UNAVAILABLE_UNDER_FROZEN_CAP"
         and failed12["completed_log_chunks"] == failed13["completed_log_chunks"] == 0,
         "Prior closed failures differ")
    need(all(plan[key] == old_plan[key] for key in ("diamond", "events", "window_utc", "event_range")),
         "Original window, chunks, event shapes or target differ")
    need(plan["rpc_endpoint"] == "https://ethereum-rpc.publicnode.com"
         and plan["caps"]["rpc_methods"] == 43 and len(plan["event_range"]["chunks"]) == 39,
         "Provider or request bound differs")
    headers, states = failed12["headers"], {x["name"]: x for x in checkpoints["states"]}
    need(plan["positive_control"]["block_hash"] == headers["creation"]["hash"]
         and plan["positive_control"]["block_number"] == headers["creation"]["number"], "Positive-control block differs")
    expected_logs = [x for x in receipt["logs"] if x["address"].lower() == plan["diamond"]]
    need(receipt["blockHash"] == headers["creation"]["hash"] and transport.quantity(receipt["transactionIndex"]) == 75,
         "Retained constructor receipt context differs")
    topic_names = {x["topic0"]: x["name"] for x in plan["events"]}
    for event in plan["events"]:
        need(event["topic0"] == "0x" + primitive.keccak256(event["signature"].encode()).hex(), "Topic signature differs")
    helper.seed_registry(codec, states["start"], plan["diamond"], plan["caps"])
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "frozen_plan.json").write_bytes(args.plan.read_bytes())
    (args.output / "runner_source.py").write_bytes(Path(__file__).read_bytes())
    transport.save(args.output / "acceptance.json", {"started_utc": transport.stamp(), "plan_sha256": args.accepted_plan_sha256,
                   "runner_sha256": args.accepted_runner_sha256, "authority": "Root accepted exact plan and runner before first request."})
    capture = transport.Capture(plan, args.output)
    result = {"schema_version": "article2_phase13_publicnode_history_result_v1",
              "plan_sha256": args.accepted_plan_sha256, "runner_sha256": args.accepted_runner_sha256,
              "headers": {}, "positive_control": None, "events": [], "completed_log_chunks": 0,
              "nominal_replay_performed": False, "window_event_coverage_complete_under_query_schedule": False,
              "historical_routing_proved": False, "index_completeness_proved": False,
              "proofs_cryptographically_verified": False, "unlogged_mutation_paths_excluded": False,
              "prior_failed_attempts_preserved": True, "scientific_admissions": 0, "detector_scores": 0,
              "fresh_code_requests": 0, "new_compiler_invocations": 0, "incident_transaction_payload_queries": 0}
    seen = new_seen()
    facets = set(checkpoints["discovered_nonzero_facets"])
    selectors = set(checkpoints["discovered_selectors"])
    try:
        need(transport.quantity(capture.rpc("chain_id", "eth_chainId", [])) == 1, "Unexpected chain ID")
        result["chain_id"] = 1
        for name in ("start", "end"):
            value = capture.rpc(name + "_header", "eth_getBlockByNumber", [hex(headers[name]["number"]), False])
            result["headers"][name] = verify_header(value, headers[name], transport, codec)
        control = capture.rpc("creation_control_logs", "eth_getLogs", [{"blockHash": headers["creation"]["hash"],
                              "address": plan["diamond"], "topics": [list(topic_names)]}])
        result["positive_control"] = verify_control(control, expected_logs, plan, headers, helper, transport, codec, topic_names)
        transport.save(args.output / "progress.json", result)
        for index, chunk in enumerate(plan["event_range"]["chunks"]):
            logs = capture.rpc("window_admin_logs_" + str(index), "eth_getLogs", [{"fromBlock": hex(chunk["from_block"]),
                               "toBlock": hex(chunk["to_block"]), "address": plan["diamond"], "topics": [list(topic_names)]}])
            need(isinstance(logs, list) and len(result["events"]) + len(logs) <= plan["caps"]["max_event_logs"],
                 "Window event shape/cap")
            for log in logs:
                row = helper.validate_log(log, chunk, plan, transport, codec, topic_names, headers, seen)
                row["chunk_index"] = index
                result["events"].append(row)
                if row["decoded"]["event"] == "DiamondCut":
                    facets.update(cut["facet"] for cut in row["decoded"]["cuts"] if cut["facet"] != codec.ZERO)
                    selectors.update(selector for cut in row["decoded"]["cuts"] for selector in cut["selectors"])
                need(len(facets) <= plan["caps"]["max_facets"] and len(selectors) <= plan["caps"]["max_selectors"],
                     "Run-wide discovery union cap exceeded")
            result["completed_log_chunks"] += 1
            transport.save(args.output / "progress.json", result)
        result["window_event_coverage_complete_under_query_schedule"] = True
        result.update(fold(result["events"], states["start"], states["end"], plan, helper, codec))
        result["disposition"] = ("EVENT_REPLAY_SEMANTICS_UNRESOLVED" if result["nominal_replay_error"] else
            "WINDOW_EVENT_CHECKPOINT_CONSISTENCY_ROUTING_UNRESOLVED" if all(result["end_checkpoint_comparison"].values())
            else "WINDOW_EVENT_CHECKPOINT_MISMATCH_UNRESOLVED")
    except transport.Stop as exc:
        result.update(disposition="UNAVAILABLE_UNDER_FROZEN_CAP", detail=str(exc))
    except Exception as exc:
        result.update(disposition="MALFORMED_OR_OVER_CAP_OR_CONFLICTING_EVIDENCE", detail=type(exc).__name__ + ": " + str(exc))
    finally:
        result.update(completed_utc=transport.stamp(), rpc_methods=capture.rpc_calls, retained_response_bytes=capture.bytes,
            chain_id_queries=sum(x["key"] == "chain_id" for x in capture.requests),
            fresh_headers=sum(x["key"] in ("start_header", "end_header") for x in capture.requests),
            positive_control_log_queries=sum(x["key"] == "creation_control_logs" for x in capture.requests),
            window_log_requests=sum(x["key"].startswith("window_admin_logs_") for x in capture.requests),
            event_type_counts=dict(Counter(x["decoded"]["event"] for x in result["events"])),
            nonzero_initializer_event_count=sum(x["decoded"].get("initializer_effects_unclosed", False) for x in result["events"]),
            discovered_nonzero_facets=sorted(facets), discovered_selectors=sorted(selectors))
        transport.save(args.output / "summary.json", result)
    print(json.dumps({k: v for k, v in result.items() if k not in {"events", "nominal_replay_end", "discovered_selectors"}}, indent=2))


if __name__ == "__main__":
    main()
