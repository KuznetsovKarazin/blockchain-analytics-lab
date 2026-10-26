#!/usr/bin/env python3
"""Continue only frozen checkpoint observations after an unavailable log query.

Reuses the exact former chain/header responses and unchanged verified state
reader. No administrative-event decode/fold, new header, log retry or fallback.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def bound(path, expected):
    raw = path.read_bytes()
    if sha(raw) != expected:
        raise ValueError("Frozen file changed: " + path.name)
    return raw


def main():
    parser = argparse.ArgumentParser()
    for name in ("plan", "layout", "layout-review", "bootstrap", "historical-summary", "previous", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--accepted-plan-sha256", required=True)
    parser.add_argument("--accepted-runner-sha256", required=True)
    args = parser.parse_args()
    plan_bytes = bound(args.plan, args.accepted_plan_sha256)
    runner_bytes = bound(Path(__file__), args.accepted_runner_sha256)
    plan = json.loads(plan_bytes)
    if plan["schema_version"] != "article2_phase12_lifi_checkpoint_only_plan_v1":
        raise ValueError("Wrong continuation schema")
    folder, paper = Path(__file__).resolve().parent, Path(__file__).resolve().parents[2]
    bindings = plan["source_bindings"]
    implementation_path = folder / "capture_admin_checkpoints.py"
    bound(implementation_path, bindings["state_implementation_sha256"])
    spec = importlib.util.spec_from_file_location("frozen_checkpoint_implementation", implementation_path)
    implementation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(implementation)
    need = implementation.need
    codec = implementation.import_bound("frozen_checkpoint_hex", folder / "admin_event_codec.py", bindings["event_codec_sha256"])
    transport = implementation.import_bound("frozen_checkpoint_transport", paper / "phase10/lifi_gate/capture_factory_continuation.py", bindings["transport_module_sha256"])
    primitive = implementation.import_bound("frozen_checkpoint_keccak", paper / "phase9/revest_gate/revest_gate_primitives.py", bindings["keccak_module_sha256"])
    load = implementation.load_bound
    decision = load(folder / "checkpoint_continuation_decision.json", plan["decision_sha256"])
    initial_audit = load(paper / "phase12/qa/admin_attempt1_independent_review.json", plan["initial_attempt_audit_sha256"])
    need(initial_audit["status"].startswith("PASS"), "Initial attempt audit not accepted")
    old_plan = load(args.previous / "frozen_plan.json", plan["initial_plan_sha256"])
    previous = load(args.previous / "summary.json", plan["initial_summary_sha256"])
    old_requests = load(args.previous / "requests.json", plan["initial_requests_sha256"])
    need(decision["initial_summary_sha256"] == plan["initial_summary_sha256"]
         and decision["initial_requests_sha256"] == plan["initial_requests_sha256"], "Root decision differs from prior attempt")
    need(old_plan["rpc_endpoint"] == plan["rpc_endpoint"] and old_plan["diamond"] == plan["diamond"]
         and old_plan["checkpoints"] == plan["checkpoints"], "Provider/target/checkpoint changed")
    need(all(old_plan[key] == plan[key] for key in ("verified_layout_spec_sha256", "independent_layout_review_sha256",
         "independent_layout_review_status", "expected_diamond_code_hash"))
         and all(plan["source_bindings"][key] == value for key, value in old_plan["source_bindings"].items()),
         "Previously accepted layout/source semantics changed")
    bound(args.previous / "runner_source.py", bindings["state_implementation_sha256"])
    need(plan["rpc_methods"] == ["eth_getProof"] and plan["caps"]["rpc_methods"] <= 24, "Continuation method scope differs")
    need(previous["rpc_methods"] == len(old_requests) == plan["initial_rpc_methods"] == 5
         and previous["retained_response_bytes"] == plan["initial_retained_response_bytes"] == 29835
         and previous["completed_log_chunks"] == 0 and previous["enumerated_checkpoint_count"] == 0,
         "Initial closed-attempt counters differ")
    need(plan["caps"]["total_retained_response_bytes"] + previous["retained_response_bytes"] == plan["cumulative_caps"]["retained_response_bytes_max"],
         "Cumulative byte envelope differs")
    retained, total = {}, 0
    for record in old_requests:
        request_raw = bound(args.previous / record["request_file"], record["request_sha256"])
        response_raw = bound(args.previous / record["response_file"], record["response_sha256"])
        need(len(response_raw) == record["response_bytes"] and record["key"] not in retained, "Prior response size/key differs")
        total += len(response_raw)
        retained[record["key"]] = {"record": record, "request": json.loads(request_raw), "body": json.loads(response_raw)}
    need(total == previous["retained_response_bytes"], "Prior byte total differs")
    failed = retained["admin_logs_0"]
    need(failed["record"]["http_status"] == 400
         and failed["record"]["response_sha256"] == decision["observed_failure"]["response_sha256"], "Original log failure changed")
    need({x["key"] for x in plan["reused_successful_records"]} == {"chain", "header_creation", "header_start", "header_end"}, "Unexpected reuse set")
    for expected in plan["reused_successful_records"]:
        item = retained[expected["key"]]
        need(all(item["record"][k] == v for k, v in expected.items()), "Exact reused receipt differs")
        request, response = item["request"], item["body"]
        need(item["record"]["http_status"] == 200 and item["record"]["transport_json_ok"] is True
             and request["url"] == plan["rpc_endpoint"] and response.get("jsonrpc") == "2.0"
             and response.get("id") == request["json"]["id"] and "error" not in response, "Reused RPC binding differs")
    chain = retained["chain"]
    need(chain["request"]["json"]["method"] == "eth_chainId" and chain["request"]["json"]["params"] == []
         and chain["body"]["result"] == "0x1", "Reused chain identity differs")
    headers = {}
    for checkpoint in plan["checkpoints"]:
        item = retained["header_" + checkpoint["name"]]
        body, request = item["body"]["result"], item["request"]["json"]
        need(request["method"] == "eth_getBlockByNumber" and request["params"] == [hex(checkpoint["block_number"]), False]
             and transport.quantity(body["number"]) == checkpoint["block_number"]
             and body["hash"].lower() == checkpoint["block_hash"]
             and transport.quantity(body["timestamp"]) == transport.utc_seconds(checkpoint["timestamp_utc"]), "Reused header context differs")
        headers[checkpoint["name"]] = {"number": checkpoint["block_number"], "hash": checkpoint["block_hash"],
            "state_root": "0x" + codec.hx(body["stateRoot"], 32).hex(), "timestamp_utc": checkpoint["timestamp_utc"],
            "original_response_sha256": item["record"]["response_sha256"]}
    layout = load(args.layout, plan["verified_layout_spec_sha256"])
    review = load(args.layout_review, plan["independent_layout_review_sha256"])
    need(review["status"] == plan["independent_layout_review_status"]
         and review["producer_result_sha256"] == plan["verified_layout_spec_sha256"], "Layout review binding differs")
    scope = load(paper / "phase12/scope_review/admission_scope_review.json", bindings["admission_scope_review_sha256"])
    need(scope["status"] == "RETAIN_ACCEPTED_ROUTING_POPULATION_SCOPE_BOUNDED_DISCOVERY_ONLY", "Scientific scope differs")
    compilation = load(paper / "phase11/compilation/compilation_results.json", bindings["phase11_compilation_results_sha256"])
    need(compilation["all_exact"] is True, "Exact target compilation missing")
    bootstrap = load(args.bootstrap, bindings["phase11_bootstrap_results_sha256"])
    historical = load(args.historical_summary, bindings["phase10_factory_summary_sha256"])
    need(bootstrap["status"] == "PASS_ACTUAL_CONSTRUCTOR_RECEIPT_CHECK"
         and layout["delegated_storage_context"]["address"] == bootstrap["diamond"] == plan["diamond"], "Bootstrap/storage context differs")
    diamond_history = next(x for x in historical["contracts"] if x["role"] == "diamond")
    creation_body = retained["header_creation"]["body"]["result"]
    creation_hashes = ["0x" + codec.hx(x, 32).hex() for x in creation_body["transactions"]]
    need(creation_hashes.count(diamond_history["creation_tx"]) == 1, "Creation hash absent from reused header")
    creation_position = creation_hashes.index(diamond_history["creation_tx"])
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "frozen_plan.json").write_bytes(plan_bytes)
    (args.output / "runner_source.py").write_bytes(runner_bytes)
    implementation.save(args.output / "acceptance.json", {"started_utc": transport.stamp(), "plan_sha256": args.accepted_plan_sha256,
        "runner_sha256": args.accepted_runner_sha256, "initial_summary_sha256": plan["initial_summary_sha256"],
        "state_implementation_sha256": bindings["state_implementation_sha256"]})
    result = {"schema_version": "article2_phase12_lifi_checkpoint_only_result_v1", "plan_sha256": args.accepted_plan_sha256,
        "runner_sha256": args.accepted_runner_sha256, "initial_summary_sha256": plan["initial_summary_sha256"],
        "reused_chain_and_header_records": 4, "headers": headers, "states": [],
        "administrative_history_status": "UNAVAILABLE_AFTER_PRESERVED_PROVIDER_REFUSAL", "event_replay_performed": False,
        "successful_log_chunks": 0, "log_retries": 0, "fresh_headers": 0, "provider_fallbacks": 0,
        "proofs_cryptographically_verified": False, "orphan_mapping_keys_excluded": False, "historical_routing_proved": False,
        "scientific_admissions": 0, "detector_scores": 0, "new_incident_transaction_payloads": 0}
    runner = transport.Capture(plan, args.output)
    population = implementation.PopulationBound(plan["caps"])
    reader = implementation.StateReader(runner, plan, layout, primitive.keccak256, codec, population, args.output)
    try:
        for checkpoint in plan["checkpoints"]:
            state = reader.checkpoint(checkpoint)
            result["states"].append(state)
            implementation.save(args.output / "progress.json", result)
        creation, start, end = result["states"]
        expected_facets = [{"address": bootstrap["initial_diamond_cut_facet"], "facet_position": 0,
                            "selectors": [bootstrap["diamond_cut_selector"]]}]
        expected_map = {bootstrap["diamond_cut_selector"]: {"facet": bootstrap["initial_diamond_cut_facet"], "selector_position": 0}}
        creation_facets = [{k: row[k] for k in ("address", "facet_position", "selectors")} for row in creation["facets"]]
        comparison = {"owner_equal": creation["owner"] == bootstrap["owner_at_constructor"],
                      "facet_array_equal": creation_facets == expected_facets, "selector_mapping_equal": creation["selector_map"] == expected_map,
                      "constructor_transaction_position": creation_position, "checkpoint_is_block_end": True,
                      "same_block_intervening_mutations_excluded": False,
                      "limit": "Constructor receipt describes its execution; later same-block transactions can validly change block-end state."}
        result["constructor_to_creation_block_end_comparison"] = comparison
        start_map, end_map = start["selector_map"], end["selector_map"]
        result["window_checkpoint_differences"] = {"owner_equal": start["owner"] == end["owner"],
            "facet_addresses_equal_in_order": [x["address"] for x in start["facets"]] == [x["address"] for x in end["facets"]],
            "selectors_added_in_enumeration": sorted(set(end_map) - set(start_map)),
            "selectors_absent_from_end_enumeration": sorted(set(start_map) - set(end_map)),
            "selectors_with_changed_enumerated_binding": sorted(x for x in set(start_map) & set(end_map) if start_map[x] != end_map[x]),
            "source_guided_cbridge_word_equal": start["source_guided_cbridge_fields"] == end["source_guided_cbridge_fields"],
            "intermediate_epochs_or_effective_configuration_proved": False}
        matched = comparison["owner_equal"] and comparison["facet_array_equal"] and comparison["selector_mapping_equal"]
        result["disposition"] = "CHECKPOINT_ARRAYS_OBSERVED_HISTORY_UNAVAILABLE" if matched else "CHECKPOINT_BOOTSTRAP_DIFFERENCE_HISTORY_UNAVAILABLE"
    except implementation.GateStop as exc:
        result.update(disposition=exc.status, detail=exc.detail)
    except transport.Stop as exc:
        result.update(disposition="UNAVAILABLE_UNDER_FROZEN_CAP", detail=str(exc))
    except Exception as exc:
        result.update(disposition="MALFORMED_OR_CONFLICTING_PROVIDER_EVIDENCE", detail=type(exc).__name__ + ": " + str(exc))
    finally:
        result.update(completed_utc=transport.stamp(), rpc_methods=runner.rpc_calls, retained_response_bytes=runner.bytes,
            cumulative_phase_rpc_methods=plan["initial_rpc_methods"] + runner.rpc_calls,
            cumulative_phase_retained_response_bytes=plan["initial_retained_response_bytes"] + runner.bytes,
            storage_keys_requested=reader.keys_requested, enumerated_checkpoint_count=len(result["states"]),
            discovered_nonzero_facets=sorted(population.facets), discovered_selectors=sorted(population.selectors),
            achieved_evidence_tier="provider_returned_three_enumerated_checkpoint_arrays" if len(result["states"]) == 3 else "partial_provider_returned_checkpoint_data",
            planned_evidence_tier="provider_returned_three_enumerated_checkpoint_arrays")
        implementation.save(args.output / "summary.json", result)
    print(json.dumps({k: v for k, v in result.items() if k not in {"headers", "states", "discovered_selectors"}}, indent=2))


if __name__ == "__main__":
    main()
