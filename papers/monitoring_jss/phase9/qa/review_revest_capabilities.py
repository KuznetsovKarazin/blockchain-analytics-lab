#!/usr/bin/env python3
"""Reconstruct capability findings offline from retained request/response bytes."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def main():
    ap = argparse.ArgumentParser()
    for name in ("capture", "originals", "compilation-review", "report"):
        ap.add_argument("--" + name, required=True, type=Path)
    a = ap.parse_args()
    plan = read(a.capture / "frozen_plan.json")
    accepted = read(a.capture / "acceptance.json")
    assert accepted["accepted_plan_sha256"] == sha((a.capture / "frozen_plan.json").read_bytes())
    records = read(a.capture / "requests.json")
    assert len(records) == 11
    actual = []
    for ident, record in enumerate(records, 1):
        assert record["id"] == ident
        prefix = f'{ident:02d}_{record["provider"]}_{record["method"]}'
        req = (a.capture / (prefix + "_request.json")).read_bytes()
        reply = (a.capture / (prefix + "_response.bin")).read_bytes()
        assert sha(req) == record["request_sha256"]
        assert sha(reply) == record["response_sha256"] and len(reply) == record["response_bytes"]
        request, response = json.loads(req), json.loads(reply)
        assert request["id"] == response["id"] == ident
        assert request["jsonrpc"] == response["jsonrpc"] == "2.0"
        assert request["method"] == record["method"]
        success = "error" not in response and "result" in response and record["http_status"] == 200
        assert success == record["transport_rpc_ok"] and not record.get("response_truncated_at_cap")
        actual.append({"request": request, "response": response, "record": record})
    assert sum(r["response_bytes"] for r in records) == 42538
    assert Counter(r["provider"] for r in records) == {"publicnode": 5, "drpc": 6}
    caps = plan["caps"]
    assert len(records) <= caps["rpc_methods_total"]
    assert max(Counter(r["provider"] for r in records).values()) <= caps["rpc_methods_per_provider"]
    assert max(r["response_bytes"] for r in records) <= caps["per_response_bytes"]
    assert sum(r["response_bytes"] for r in records) <= caps["retained_response_bytes"]
    first = datetime.fromisoformat(records[0]["started_utc"])
    last = datetime.fromisoformat(records[-1]["completed_utc"])
    assert (last - first).total_seconds() <= caps["total_wall_seconds"]
    assert all((datetime.fromisoformat(r["completed_utc"]) - datetime.fromisoformat(r["started_utc"])).total_seconds()
               <= caps["per_request_seconds"] for r in records)
    assert actual[0]["response"]["result"] == actual[5]["response"]["result"] == "0x1"
    assert [r["record"]["method"] for r in actual[:5]] == ["eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt", "trace_filter"]
    assert [r["record"]["method"] for r in actual[5:]] == ["eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt", "eth_getCode", "trace_filter"]
    assert all("error" in r["response"] for r in actual[1:5])
    sample = hex(plan["historical_probe_block"])
    registry = plan["registry"]
    assert actual[6]["request"]["params"] == [sample, False]
    assert actual[7]["request"]["params"] == [registry, sample]
    assert actual[8]["request"]["params"] == [registry, "0x0", sample]
    header = actual[6]["response"]["result"]
    assert header["number"] == sample
    stamp = int(header["timestamp"], 16)
    assert 1645833600 <= stamp < 1648425600
    expected_sample_date = datetime.fromtimestamp(stamp, timezone.utc).isoformat()
    assert expected_sample_date == "2022-03-01T08:25:09+00:00"
    runtime = bytes.fromhex(actual[7]["response"]["result"][2:])
    independent = read(a.compilation_review)
    registry_compile = next(r for r in independent["source_sets"] if r["role"] == "registry")
    assert len(runtime) == registry_compile["runtime_bytes"] == 6348
    assert sha(runtime) == registry_compile["runtime_sha256"]
    owner_word = bytes.fromhex(actual[8]["response"]["result"][2:])
    assert len(owner_word) == 32 and owner_word[:12] == b"\0" * 12
    owner_address = "0x" + owner_word[12:].hex()
    assert actual[9]["request"]["params"] == [owner_address, sample]
    owner_runtime = bytes.fromhex(actual[9]["response"]["result"][2:])
    assert len(owner_runtime) == 170
    admin_block = plan["known_admin_initialization_block"]
    assert actual[10]["request"]["params"] == [{"fromBlock": hex(admin_block), "toBlock": hex(admin_block),
                                               "toAddress": [registry], "after": 0, "count": 2}]
    traces = actual[10]["response"]["result"]
    assert len(traces) == 1
    trace = traces[0]
    original_tx = read(a.originals / "registry_initialize.json")
    original_block = read(a.originals / "registry_initialize_block.json")
    assert trace["blockNumber"] == original_tx["block_number"] == original_block["height"] == admin_block
    assert trace["blockHash"].lower() == original_block["hash"].lower()
    assert trace["transactionHash"].lower() == original_tx["hash"].lower() == plan["known_admin_initialization_tx"].lower()
    assert trace["transactionPosition"] == original_tx["position"]
    assert trace["type"] == "call" and trace["action"]["callType"] == "call"
    assert trace["traceAddress"] == [] and trace["subtraces"] == 0
    assert "error" not in trace and trace["result"]["output"] == "0x" and original_tx["status"] == "ok"
    assert trace["action"]["input"].lower() == original_tx["raw_input"].lower()
    assert trace["action"]["to"].lower() == original_tx["to"]["hash"].lower() == registry.lower()
    assert trace["action"]["from"].lower() == original_tx["from"]["hash"].lower()
    assert int(trace["action"]["value"], 16) == int(original_tx["value"])
    summary = read(a.capture / "summary.json")
    assert summary["rpc_methods"] == 11 and summary["response_bytes"] == 42538
    assert summary["disposition"] == "CAPABILITY_AVAILABLE_ROUTING_UNPROVED"
    assert summary["new_case_admission_count"] == 0 and summary["continuity_proved"] is False
    result = {
        "schema_version": "phase9_revest_independent_capability_review_v1", "status": "PASS_AT_CAPABILITY_SCOPE",
        "checked_at_utc": datetime.now(timezone.utc).isoformat(), "new_network_requests": 0,
        "rpc_methods_reconstructed": 11, "response_bytes_recomputed": 42538,
        "frozen_plan_sha256": sha((a.capture / "frozen_plan.json").read_bytes()),
        "capture_summary_sha256": sha((a.capture / "summary.json").read_bytes()),
        "request_ledger_sha256": sha((a.capture / "requests.json").read_bytes()),
        "all_request_response_hashes_and_envelopes_match": True, "all_actual_caps_satisfied": True,
        "historical_registry_runtime_bytes": len(runtime), "historical_registry_runtime_sha256": sha(runtime),
        "historical_sample_time_utc": expected_sample_date, "sample_is_not_utc_boundary": True,
        "historical_owner_has_code": True, "historical_owner_code_bytes": len(owner_runtime),
        "historical_owner_code_sha256": sha(owner_runtime), "eoa_everywhere_shortcut_refuted_at_sample": True,
        "known_admin_trace_matches_full_original_input": True, "known_admin_trace_is_successful_root_call": True,
        "known_admin_trace_has_rollback_ambiguity": False,
        "unproved": ["trace indexing completeness or absence of omitted rows", "whole-window code identity",
                     "whole-window ownership and registry/provider continuity", "candidate eligibility or detector quality"],
        "producer_validator_limitations": [
            "Aggregate capability Boolean does not require header validity or in-window timestamp; both were independently verified for the actual successful sample.",
            "Trace-schema Boolean mainly checks field presence and selector, not complete types/calldata/success/call kind; actual sample was independently checked against the full original transaction and block.",
            "A successful root-call sample cannot establish rollback semantics for filtered child calls or index completeness."
        ],
        "continuation_requirements": [
            "Pin each UTC boundary by proving predecessor timestamp < boundary <= first included block timestamp; use state at immediately preceding block for initial state.",
            "Require canonical block hashes, deterministic ordering, complete pagination, deduplication and terminal page evidence; offset pagination alone is not a completeness proof.",
            "For every potential mutation, inspect root receipt and complete ancestor error context or equivalent full transaction traces; a locally successful child can still be reverted by an ancestor.",
            "Cover all relevant registry setters, initialization, ownership changes and each mutable addressesProvider setter, with exact runtime write-path analysis and correct storage context for CALL versus DELEGATECALL/CALLCODE.",
            "Track newly routed component addresses within a predefined graph-closure rule or terminate unresolved; do not infer whole-protocol continuity from five fixed addresses.",
            "Retain failed/unavailable outcomes and stop at remaining request/byte/time bounds without switching estimand after outcomes."
        ],
        "audit_script_sha256": sha(Path(__file__).read_bytes())
    }
    a.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("PASS: 11 calls, 42538 bytes, successful root admin call, historical contract owner; routing unproved")


if __name__ == "__main__":
    main()
