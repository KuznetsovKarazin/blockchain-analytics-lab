#!/usr/bin/env python3
"""Bounded observed-pair runtime capture and fixed window administrative queries.

Code observations do not establish source semantics or continuous code identity.
The event fold starts from a separately observed pre-window state. It does not
prove provider index completeness, exclude unlogged writes or model initializers.
"""
import argparse
from collections import Counter
import copy
import hashlib
import importlib.util
import json
from pathlib import Path


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def need(value, message):
    if not value:
        raise ValueError(message)


def bound_json(path, expected):
    raw = path.read_bytes()
    need(sha(raw) == expected, "Frozen input differs: " + path.name)
    return json.loads(raw)


def bound_module(name, path, expected):
    need(sha(path.read_bytes()) == expected, "Frozen module differs: " + path.name)
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def project_state(state):
    return {"owner": state["owner"],
            "facets": [{k: row[k] for k in ("address", "facet_position", "selectors")} for row in state["facets"]],
            "selector_map": state["selector_map"]}


def seed_registry(codec, state, diamond, caps):
    """Seed exactly the retained ordered enumeration, including backreferences."""
    model = codec.EventImpliedRegistry(diamond, caps["max_facets"], caps["max_selectors"])
    model.owner = "0x" + codec.hx(state["owner"], 20).hex()
    for index, row in enumerate(state["facets"]):
        facet = "0x" + codec.hx(row["address"], 20).hex()
        need(facet != codec.ZERO and facet not in model.by_facet and row["facet_position"] == index,
             "Invalid seed facet ordering or duplicate/zero address")
        need(bool(row["selectors"]), "Empty seed facet")
        model.add_facet(facet)
        for position, selector in enumerate(row["selectors"]):
            selector = "0x" + codec.hx(selector, 4).hex()
            need(selector not in model.selectors and len(model.selectors) < caps["max_selectors"],
                 "Duplicate or over-cap seed selector")
            model.by_facet[facet].append(selector)
            model.selectors[selector] = (facet, position)
    need(model.snapshot() == project_state(state), "Seed mapping differs from retained array/backreferences")
    return model


def expected_pairs(checkpoints):
    return [{"checkpoint": state["name"], "block_number": state["block_number"],
             "block_hash": state["block_hash"], "address": row["address"]}
            for state in checkpoints["states"] for row in state["facets"]]


def code_observation(body, row, transport, hash_fn, source):
    need(transport.hexbytes(body), "Malformed runtime bytes")
    raw = bytes.fromhex(body[2:])
    return {**{k: row[k] for k in ("checkpoint", "block_number", "block_hash", "address")},
            "runtime_bytes": len(raw), "runtime_sha256": sha(raw),
            "runtime_keccak256": "0x" + hash_fn(raw).hex(), "code_empty": not bool(raw),
            "evidence_source": source, "source_semantics_newly_verified": False,
            "historical_block_mapping_cryptographically_verified": False}


def validate_log(log, chunk, plan, transport, codec, topic_names, headers, seen):
    need(isinstance(log, dict) and log.get("removed") is False
         and "0x" + codec.hx(log.get("address"), 20).hex() == plan["diamond"], "Log emitter/removed state differs")
    block, position, index = (transport.quantity(log.get(k)) for k in ("blockNumber", "transactionIndex", "logIndex"))
    block_hash, tx_hash = ("0x" + codec.hx(log.get(k), 32).hex() for k in ("blockHash", "transactionHash"))
    need(chunk["from_block"] <= block <= chunk["to_block"], "Log outside frozen requested range")
    need((block, index) not in seen["log_ids"], "Duplicate block/log index")
    need(block not in seen["block_hashes"] or seen["block_hashes"][block] == block_hash, "Conflicting log block hash")
    need((block, position) not in seen["tx_positions"] or seen["tx_positions"][(block, position)] == tx_hash,
         "Conflicting transaction position")
    context = (block, block_hash, position)
    need(tx_hash not in seen["tx_contexts"] or seen["tx_contexts"][tx_hash] == context,
         "Transaction hash has conflicting block/position context")
    for header in headers.values():
        if header["number"] == block:
            need(block_hash == header["hash"] and position < len(header["transaction_hashes"])
                 and header["transaction_hashes"][position] == tx_hash, "Log differs from retained checkpoint header")
    decoded = codec.decode_event(log.get("topics"), log.get("data"), topic_names, plan["caps"])
    seen["log_ids"].add((block, index))
    seen["block_hashes"][block] = block_hash
    seen["tx_positions"][(block, position)] = tx_hash
    seen["tx_contexts"][tx_hash] = context
    return {"block_number": block, "block_hash": block_hash, "transaction_index": position,
            "transaction_hash": tx_hash, "log_index": index,
            "raw_data_sha256": sha(codec.hx(log["data"])), "decoded": decoded}


def main():
    parser = argparse.ArgumentParser()
    for name in ("plan", "checkpoints", "failed-attempt", "phase10-attempt", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--accepted-plan-sha256", required=True)
    parser.add_argument("--accepted-runner-sha256", required=True)
    args = parser.parse_args()
    plan = bound_json(args.plan, args.accepted_plan_sha256)
    need(sha(Path(__file__).read_bytes()) == args.accepted_runner_sha256, "Accepted runner digest differs")
    need(plan["schema_version"] == "article2_phase13_code_and_window_events_plan_v1", "Wrong plan schema")
    paper = Path(__file__).resolve().parents[2]
    modules = plan["module_bindings"]
    transport = bound_module("phase13_transport", paper / modules["transport"]["path"], modules["transport"]["sha256"])
    codec = bound_module("phase13_codec", paper / modules["event_codec"]["path"], modules["event_codec"]["sha256"])
    primitive = bound_module("phase13_keccak", paper / modules["keccak"]["path"], modules["keccak"]["sha256"])
    prior = plan["prior_bindings"]
    checkpoints = bound_json(args.checkpoints, prior["checkpoint_summary_sha256"])
    failed = bound_json(args.failed_attempt, prior["failed_attempt_summary_sha256"])
    review = bound_json(paper / prior["checkpoint_review_path"], prior["checkpoint_review_sha256"])
    scope = bound_json(paper / prior["scope_review_path"], prior["scope_review_sha256"])
    bound_json(paper / prior["phase13_scope_review_path"], prior["phase13_scope_review_sha256"])
    old_plan = bound_json(paper / prior["phase12_plan_path"], prior["phase12_plan_sha256"])
    need(scope["status"] == "RETAIN_ACCEPTED_ROUTING_POPULATION_SCOPE_BOUNDED_DISCOVERY_ONLY",
         "Accepted scientific scope differs")
    need(review["status"] == "PASS_INDEPENDENT_CHECKPOINT_EVIDENCE_AUDIT", "Checkpoint review not accepted")
    need(checkpoints["disposition"] == "CHECKPOINT_ARRAYS_OBSERVED_HISTORY_UNAVAILABLE"
         and failed["disposition"] == "UNAVAILABLE_UNDER_FROZEN_CAP"
         and failed["completed_log_chunks"] == 0, "Prior immutable attempt disposition differs")
    pairs = expected_pairs(checkpoints)
    need([{k: row[k] for k in ("checkpoint", "block_number", "block_hash", "address")} for row in plan["code_observations"]] == pairs,
         "Code schedule differs from observed facet/checkpoint pairs")
    need(len(pairs) == 19 and len({row["address"] for row in pairs}) == 14, "Unexpected observed-pair population")
    states = {state["name"]: state for state in checkpoints["states"]}
    for name, header in checkpoints["headers"].items():
        retained_header = failed["headers"][name]
        need(all(header[key] == retained_header[key] for key in ("number", "hash", "state_root", "timestamp_utc"))
             and isinstance(retained_header.get("transaction_hashes"), list), "Retained header reuse differs")
    chunks = plan["event_range"]["chunks"]
    start, end = states["start"]["block_number"] + 1, states["end"]["block_number"]
    expected_chunks = [{"from_block": value, "to_block": min(value + 4999, end)} for value in range(start, end + 1, 5000)]
    need(start == 14233163 and end == 14426367 and chunks == expected_chunks and len(chunks) == 39,
         "Window/chunk schedule differs from accepted fixed range")
    need(plan["events"] == old_plan["events"] and plan["diamond"] == old_plan["diamond"]
         and plan["window_utc"] == old_plan["window_utc"], "Target, event shape or scientific window changed")
    topic_names = {}
    for event in plan["events"]:
        need(event["topic0"] == "0x" + primitive.keccak256(event["signature"].encode()).hex(), "Event signature hash differs")
        topic_names[event["topic0"]] = event["name"]
    nominal = seed_registry(codec, states["start"], plan["diamond"], plan["caps"])
    reused = {}
    for row in plan["code_observations"]:
        need(row["mode"] in ("fresh", "reused_phase10"), "Unrecognized observation mode")
        if row["mode"] == "reused_phase10":
            record = row["reused_record"]
            request = bound_json(args.phase10_attempt / record["request_file"], record["request_sha256"])
            response = bound_json(args.phase10_attempt / record["response_file"], record["response_sha256"])
            need(request["url"] == plan["rpc_endpoint"] and request["method"] == "POST"
                 and request["json"]["method"] == "eth_getCode"
                 and request["json"]["params"] == [row["address"], hex(row["block_number"])], "Reused code request differs")
            need(response.get("jsonrpc") == "2.0" and type(response.get("id")) is int
                 and response["id"] == request["json"]["id"] and "error" not in response and "result" in response,
                 "Reused code response envelope differs")
            reused[(row["address"], row["block_number"])] = response["result"]
    need(len(reused) == 1 and sum(row["mode"] == "fresh" for row in plan["code_observations"]) == 18,
         "Unexpected new/reused runtime counts")
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "frozen_plan.json").write_bytes(args.plan.read_bytes())
    (args.output / "runner_source.py").write_bytes(Path(__file__).read_bytes())
    save(args.output / "acceptance.json", {"started_utc": transport.stamp(), "plan_sha256": args.accepted_plan_sha256,
         "runner_sha256": args.accepted_runner_sha256, "authority": "Root accepted exact plan and runner hashes before first request."})
    runner = transport.Capture(plan, args.output)
    result = {"schema_version": "article2_phase13_code_and_window_events_result_v1",
              "plan_sha256": args.accepted_plan_sha256, "runner_sha256": args.accepted_runner_sha256,
              "runtime_observations": [], "events": [], "completed_log_chunks": 0,
              "reused_code_pairs": 1, "fresh_headers": 0, "chain_id_queries": 0,
              "detector_scores": 0, "scientific_admissions": 0, "incident_transaction_payload_queries": 0,
              "historical_routing_proved": False, "index_completeness_proved": False,
              "proofs_cryptographically_verified": False, "unlogged_mutation_paths_excluded": False,
              "nominal_replay_performed": False, "window_event_coverage_complete_under_query_schedule": False,
              "new_source_runtime_recompilations": 0, "prior_failed_attempt_preserved": True,
              "prewindow_event_history_acquired": False}
    seen = {"log_ids": set(), "block_hashes": {}, "tx_positions": {}, "tx_contexts": {}}
    discovered_facets = {row["address"] for row in pairs}
    discovered_selectors = set(checkpoints["discovered_selectors"])
    try:
        for index, row in enumerate(plan["code_observations"]):
            if row["mode"] == "fresh":
                value = runner.rpc("facet_code_" + str(index), "eth_getCode", [row["address"], hex(row["block_number"])])
                origin = {"kind": "fresh_phase13", "request_ordinal": runner.rpc_calls}
            else:
                value = reused[(row["address"], row["block_number"])]
                origin = {"kind": "reused_phase10", "response_sha256": row["reused_record"]["response_sha256"]}
            result["runtime_observations"].append(code_observation(value, row, transport, primitive.keccak256, origin))
            save(args.output / "progress.json", result)
        for index, chunk in enumerate(chunks):
            logs = runner.rpc("window_admin_logs_" + str(index), "eth_getLogs", [{"fromBlock": hex(chunk["from_block"]),
                "toBlock": hex(chunk["to_block"]), "address": plan["diamond"], "topics": [list(topic_names)]}])
            need(isinstance(logs, list), "Log response is not an array")
            need(len(result["events"]) + len(logs) <= plan["caps"]["max_event_logs"], "Administrative log cap exceeded")
            for log in logs:
                row = validate_log(log, chunk, plan, transport, codec, topic_names, failed["headers"], seen)
                row["chunk_index"] = index
                result["events"].append(row)
                event = row["decoded"]
                if event["event"] == "DiamondCut":
                    discovered_facets.update(cut["facet"] for cut in event["cuts"] if cut["facet"] != codec.ZERO)
                    discovered_selectors.update(selector for cut in event["cuts"] for selector in cut["selectors"])
                need(len(discovered_facets) <= plan["caps"]["max_facets"] and len(discovered_selectors) <= plan["caps"]["max_selectors"],
                     "Run-wide discovery union cap exceeded")
            result["completed_log_chunks"] += 1
            save(args.output / "progress.json", result)
        result["window_event_coverage_complete_under_query_schedule"] = True
        result["events"].sort(key=lambda row: (row["block_number"], row["transaction_index"], row["log_index"]))
        previous_by_block = {}
        for row in result["events"]:
            need(row["log_index"] > previous_by_block.get(row["block_number"], -1), "Transaction ordering conflicts with block log ordering")
            previous_by_block[row["block_number"]] = row["log_index"]
        replay_error = None
        applied = 0
        for index, row in enumerate(result["events"]):
            trial = copy.deepcopy(nominal)
            try:
                trial.apply(row["decoded"])
                nominal = trial
                applied += 1
            except ValueError as exc:
                replay_error = {"event_index": index, "block_number": row["block_number"], "log_index": row["log_index"], "detail": str(exc)}
                break
        result["nominal_replay_performed"] = True
        result["nominal_replay_events_applied"] = applied
        result["nominal_replay_error"] = replay_error
        result["nominal_replay_end"] = nominal.snapshot() if replay_error is None else None
        end_state = project_state(states["end"])
        result["end_checkpoint_comparison"] = {
            key + "_equal": replay_error is None and nominal.snapshot()[key] == end_state[key]
            for key in ("owner", "facets", "selector_map")}
        result["disposition"] = ("EVENT_REPLAY_SEMANTICS_UNRESOLVED" if replay_error else
            "SAMPLED_CODE_AND_WINDOW_EVENT_CONSISTENCY_ROUTING_UNRESOLVED"
            if all(result["end_checkpoint_comparison"].values()) else "WINDOW_EVENT_CHECKPOINT_MISMATCH_UNRESOLVED")
    except transport.Stop as exc:
        result.update(disposition="UNAVAILABLE_UNDER_FROZEN_CAP", detail=str(exc))
    except Exception as exc:
        result.update(disposition="MALFORMED_OR_OVER_CAP_OR_CONFLICTING_EVIDENCE", detail=type(exc).__name__ + ": " + str(exc))
    finally:
        result.update(completed_utc=transport.stamp(), rpc_methods=runner.rpc_calls,
            retained_response_bytes=runner.bytes,
            fresh_code_requests=sum(record["key"].startswith("facet_code_") for record in runner.requests),
            window_log_requests=sum(record["key"].startswith("window_admin_logs_") for record in runner.requests),
            event_type_counts=dict(Counter(row["decoded"]["event"] for row in result["events"])),
            nonzero_initializer_event_count=sum(row["decoded"].get("initializer_effects_unclosed", False) for row in result["events"]),
            discovered_nonzero_facets=sorted(discovered_facets), discovered_selectors=sorted(discovered_selectors),
            newly_nominated_event_facets_without_adaptive_code_query=sorted(discovered_facets - {row["address"] for row in pairs}),
            completed_runtime_observations=len(result["runtime_observations"]),
            empty_runtime_observation_count=sum(row["code_empty"] for row in result["runtime_observations"]))
        save(args.output / "summary.json", result)
    print(json.dumps({k: v for k, v in result.items() if k not in {"runtime_observations", "events", "nominal_replay_end", "discovered_selectors"}}, indent=2))


if __name__ == "__main__":
    main()
