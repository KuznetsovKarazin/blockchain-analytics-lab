#!/usr/bin/env python3
"""Bounded deployment/source and boundary-code observations, never a replay.

The two nominated contracts are identity targets, not a complete facet roster.
Explorer verification is not independent recompilation. Equal runtime at sampled
blocks does not establish selector routing or continuous code identity.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.request


def stamp():
    return datetime.now(timezone.utc).isoformat()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def parse(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value
    def constant(_):
        raise ValueError("nonfinite JSON value")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def hexbytes(value, length=None):
    return (isinstance(value, str) and re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value) is not None
            and (length is None or len(value) == 2 + 2 * length))


def quantity(value):
    require(isinstance(value, str) and re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value) is not None,
            "Invalid RPC quantity")
    return int(value, 16)


def utc_seconds(value):
    require(isinstance(value, str) and (value.endswith("Z") or value.endswith("+00:00")), "UTC time required")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.microsecond == 0, "Unexpected subsecond block time")
    return int(parsed.timestamp())


class Stop(Exception):
    def __init__(self, detail, status="SOURCE_OR_HISTORICAL_STATE_UNRESOLVED"):
        self.detail, self.status = detail, status
        super().__init__(detail)


def require(condition, detail, status="SOURCE_OR_HISTORICAL_STATE_UNRESOLVED"):
    if not condition:
        raise Stop(detail, status)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Capture:
    def __init__(self, plan, output):
        self.plan, self.output = plan, output
        self.started = time.monotonic()
        self.requests, self.rpc_calls, self.get_calls, self.bytes = [], 0, 0, 0
        self.opener = urllib.request.build_opener(NoRedirect())

    def fetch(self, key, url, payload=None):
        caps = self.plan["caps"]
        remaining = caps["wall_seconds"] - (time.monotonic() - self.started)
        require(remaining > 0 and self.bytes < caps["total_retained_response_bytes"], "Time or byte cap closed")
        rpc = payload is not None
        if rpc:
            require(self.rpc_calls < caps["rpc_methods"] and url == self.plan["rpc_endpoint"], "RPC cap/endpoint violation")
            require(payload["method"] in self.plan["rpc_methods"], "RPC method not permitted")
            self.rpc_calls += 1
        else:
            require(self.get_calls < caps["explorer_gets"] and url.startswith(self.plan["explorer_base"] + "/api/v2/"),
                    "Explorer cap/endpoint violation")
            self.get_calls += 1
        ordinal = len(self.requests) + 1
        prefix = f"{ordinal:03d}_{key}"
        request_body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        request_record = {"url": url, "method": "POST" if rpc else "GET", "json": payload}
        save(self.output / (prefix + "_request.json"), request_record)
        record = {"ordinal": ordinal, "key": key, "started_utc": stamp(), "request_file": prefix + "_request.json",
                  "request_sha256": sha((self.output / (prefix + "_request.json")).read_bytes()), "kind": "rpc" if rpc else "explorer_get"}
        self.requests.append(record)
        save(self.output / "requests.json", self.requests)
        raw = bytearray()
        try:
            headers = {"User-Agent": "Article2-LiFi-identity-gate/1", "Accept": "application/json"}
            if rpc:
                headers["Content-Type"] = "application/json"
            request = urllib.request.Request(url, data=request_body, headers=headers)
            try:
                response = self.opener.open(request, timeout=min(caps["request_timeout_seconds"], remaining))
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                record["http_status"] = response.status
                record["content_type"] = response.headers.get("Content-Type")
                limit = min(caps["per_response_bytes"], caps["total_retained_response_bytes"] - self.bytes)
                while len(raw) < limit:
                    require(time.monotonic() - self.started < caps["wall_seconds"], "Time cap reached while reading")
                    chunk = response.read(min(65536, limit - len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
                # Never probe one byte beyond the frozen retained-byte allowance.
                record["response_at_cap_eof_unproved"] = len(raw) == limit
            require(not record["response_at_cap_eof_unproved"], "Response reached byte cap; EOF unproved")
            require(record["http_status"] == 200, "HTTP response not successful")
            body = parse(bytes(raw))
            if rpc:
                require(isinstance(body, dict) and body.get("jsonrpc") == "2.0"
                        and type(body.get("id")) is int and body["id"] == payload["id"]
                        and "error" not in body and "result" in body, "Invalid/error RPC envelope")
                body = body["result"]
            record["transport_json_ok"] = True
            return body
        except Exception as exc:
            record["failure"] = type(exc).__name__ + ": " + str(exc)
            record["transport_json_ok"] = False
            raise Stop("Request failed: " + key + ": " + str(exc)) from exc
        finally:
            retained = bytes(raw)
            self.bytes += len(retained)
            (self.output / (prefix + "_response.bin")).write_bytes(retained)
            record.update(completed_utc=stamp(), response_file=prefix + "_response.bin",
                          response_bytes=len(retained), response_sha256=sha(retained))
            save(self.output / "requests.json", self.requests)

    def get(self, key, path):
        return self.fetch(key, self.plan["explorer_base"] + path)

    def rpc(self, key, method, params):
        return self.fetch(key, self.plan["rpc_endpoint"],
                          {"jsonrpc": "2.0", "id": self.rpc_calls + 1, "method": method, "params": params})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--accepted-plan-sha256", required=True)
    parser.add_argument("--accepted-runner-sha256", required=True)
    parser.add_argument("--stage-a", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--previous", required=True, type=Path)
    args = parser.parse_args()
    plan_bytes, runner_bytes = args.plan.read_bytes(), Path(__file__).read_bytes()
    require(sha(plan_bytes) == args.accepted_plan_sha256, "Accepted plan hash mismatch")
    require(sha(runner_bytes) == args.accepted_runner_sha256, "Accepted runner hash mismatch")
    plan = parse(plan_bytes)
    require(plan["schema_version"] == "article2_phase10_lifi_factory_continuation_plan_v1", "Wrong plan schema")
    previous_summary = (args.previous / "summary.json").read_bytes()
    previous_requests = (args.previous / "requests.json").read_bytes()
    require(sha(previous_summary) == plan["previous_summary_sha256"]
            and sha(previous_requests) == plan["previous_requests_sha256"], "Previous attempt receipts changed")
    prior = parse(previous_summary)
    require(prior["retained_response_bytes"] == plan["previous_response_bytes"]
            and prior["explorer_gets"] == plan["previous_explorer_gets"] and prior["rpc_methods"] == plan["previous_rpc_methods"],
            "Previous counters differ")
    reused = {}
    for record in plan["reused_responses"]:
        raw = (args.previous / record["file"]).read_bytes()
        require(sha(raw) == record["sha256"], "Reused response changed")
        reused[record["key"]] = parse(raw)
    require(set(reused) == {"diamond_source", "diamond_creation"}, "Unexpected reuse set")
    repository = Path(__file__).resolve().parents[4]
    helper_path = repository / plan["keccak_implementation"]["path"]
    require(sha(helper_path.read_bytes()) == plan["keccak_implementation"]["sha256"], "Keccak implementation changed")
    spec = importlib.util.spec_from_file_location("frozen_keccak", helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.selftest()
    targets = plan["targets"]
    require(len(targets) == 2 and {x["role"] for x in targets} == {"diamond", "cbridge_facet"}, "Unexpected targets")
    for target in targets:
        raw = (args.stage_a / target["stage_a_address_file"]).read_bytes()
        require(sha(raw) == target["stage_a_address_sha256"], "StageA source hash changed")
        source = parse(raw)
        require(source["hash"].lower() == target["address"] and source["creation_transaction_hash"].lower() == target["creation_tx"],
                "StageA target binding mismatch")
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "frozen_plan.json").write_bytes(plan_bytes)
    (args.output / "runner_source.py").write_bytes(runner_bytes)
    save(args.output / "acceptance.json", {"started_utc": stamp(), "plan_sha256": sha(plan_bytes),
         "runner_sha256": sha(runner_bytes), "authority": "Root accepted exact plan and runner hashes before first request."})
    collector = Capture(plan, args.output)
    result = {"schema_version": "article2_phase10_lifi_factory_continuation_result_v1", "plan_sha256": sha(plan_bytes),
              "runner_sha256": sha(runner_bytes), "contracts": [], "boundaries": {}, "boundary_states": [],
              "scientific_admissions": 0, "detector_scores": 0, "full_population_or_routing_proved": False,
              "source_independently_recompiled": False, "cryptographic_state_proofs_verified": False}
    sources, transactions, blocks, headers = {}, {}, {}, {}
    try:
        for target in targets:
            role, address, txhash = target["role"], target["address"], target["creation_tx"]
            source = reused["diamond_source"] if role == "diamond" else collector.get(role + "_source", "/api/v2/smart-contracts/" + address)
            require(isinstance(source, dict) and source.get("name") == target["expected_name"] and source.get("is_verified") is True,
                    "Verified source identity differs: " + role)
            require(hexbytes(source.get("creation_bytecode")) and source["creation_bytecode"] != "0x"
                    and hexbytes(source.get("deployed_bytecode")) and source["deployed_bytecode"] != "0x", "Source bytecode absent")
            require(isinstance(source.get("source_code"), str) and bool(source["source_code"])
                    and isinstance(source.get("additional_sources"), list), "Source inputs unavailable")
            sources[role] = source
            tx = reused["diamond_creation"] if role == "diamond" else collector.get(role + "_creation", "/api/v2/transactions/" + txhash)
            require(isinstance(tx, dict) and tx.get("hash", "").lower() == txhash and tx.get("status") == "ok"
                    and isinstance(tx.get("to"), dict) and tx["to"].get("hash", "").lower() == target["creator"]
                    and tx.get("created_contract") is None, "Factory transaction identity/status differs")
            require(isinstance(tx.get("from"), dict) and hexbytes(tx["from"].get("hash"), 20), "Factory caller unavailable")
            require(hexbytes(tx.get("raw_input")), "Factory input unavailable")
            raw_input = bytes.fromhex(tx["raw_input"][2:])
            creation = bytes.fromhex(source["creation_bytecode"][2:])
            require(len(raw_input) >= 32 and raw_input[32:] == creation, "Factory wrapper differs from salt+exact initcode")
            predicted = "0x" + helper.keccak256(b"\xff" + bytes.fromhex(target["creator"][2:]) + raw_input[:32]
                                               + helper.keccak256(creation))[-20:].hex()
            require(predicted == address, "CREATE2 address formula differs", "FACTORY_CREATION_TRACE_CONFLICT")
            number = tx.get("block_number")
            require(type(number) is int and 0 < number <= plan["maximum_header_number"] and type(tx.get("position")) is int
                    and tx["position"] >= 0, "Creation block/position invalid")
            utc_seconds(tx.get("timestamp"))
            transactions[role] = tx
            block = collector.get(role + "_creation_block", "/api/v2/blocks/" + str(number))
            require(isinstance(block, dict) and block.get("height") == number and hexbytes(block.get("hash"), 32)
                    and hexbytes(block.get("parent_hash"), 32) and utc_seconds(block.get("timestamp")) == utc_seconds(tx["timestamp"]),
                    "Explorer creation block identity/time differs")
            blocks[role] = block
            result["contracts"].append({"role": role, "address": address, "creation_tx": txhash, "creation_block": number,
                "creation_block_hash": block["hash"].lower(), "creation_time_utc": tx["timestamp"],
                "creator": target["creator"], "source_name": source["name"], "compiler_version": source.get("compiler_version"),
                "source_file_occurrences": 1 + len(source["additional_sources"]),
                "runtime_bytes": len(bytes.fromhex(source["deployed_bytecode"][2:])),
                "explorer_runtime_sha256": sha(bytes.fromhex(source["deployed_bytecode"][2:])),
                "factory_input_suffix_matches_explorer_creation_bytecode": True,
                "create2_formula_matches_address": True, "factory_salt_hex": raw_input[:32].hex(),
                "creation_before_window": utc_seconds(tx["timestamp"]) < utc_seconds(plan["window_utc"][0]),
                "initial_activation_time_proved": False})
            save(args.output / "progress.json", result)
        require(collector.rpc("chain_id", "eth_chainId", []) == "0x1", "Archive provider did not return chain1")

        def header(number):
            require(type(number) is int and 0 <= number <= plan["maximum_header_number"], "Header outside frozen bounds")
            if number not in headers:
                body = collector.rpc("header_" + str(number), "eth_getBlockByNumber", [hex(number), False])
                require(isinstance(body, dict) and quantity(body.get("number")) == number
                        and hexbytes(body.get("hash"), 32) and hexbytes(body.get("parentHash"), 32), "Malformed archive header")
                timestamp = quantity(body.get("timestamp"))
                require(isinstance(body.get("transactions"), list) and all(hexbytes(x, 32) for x in body["transactions"]),
                        "Header transaction hash list malformed")
                headers[number] = {"number": number, "hash": body["hash"].lower(), "parent_hash": body["parentHash"].lower(),
                    "timestamp": timestamp, "timestamp_utc": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
                    "transaction_hashes": [x.lower() for x in body["transactions"]]}
            return headers[number]

        def runtime(target, number, key):
            value = collector.rpc(key, "eth_getCode", [target["address"], hex(number)])
            require(hexbytes(value), "Malformed archive runtime")
            return bytes.fromhex(value[2:])

        for target, record in zip(targets, result["contracts"]):
            role = target["role"]
            tx, block = transactions[role], blocks[role]
            number = tx["block_number"]
            rpc_tx = collector.rpc(role + "_rpc_creation", "eth_getTransactionByHash", [target["creation_tx"]])
            receipt = collector.rpc(role + "_rpc_creation_receipt", "eth_getTransactionReceipt", [target["creation_tx"]])
            require(isinstance(rpc_tx, dict) and isinstance(receipt, dict), "Missing factory transaction/receipt")
            for value, hash_field in ((rpc_tx, "hash"), (receipt, "transactionHash")):
                require(value.get(hash_field, "").lower() == target["creation_tx"]
                        and value.get("blockHash", "").lower() == block["hash"].lower()
                        and quantity(value.get("blockNumber")) == number
                        and quantity(value.get("transactionIndex")) == tx["position"]
                        and value.get("to", "").lower() == target["creator"]
                        and value.get("from", "").lower() == tx["from"]["hash"].lower(), "Factory transaction/receipt context differs")
            require(rpc_tx.get("input", "").lower() == tx["raw_input"].lower()
                    and quantity(receipt.get("status")) == 1 and receipt.get("contractAddress") is None,
                    "Factory input/success receipt differs")
            trace = collector.rpc(role + "_creation_trace", "trace_transaction", [target["creation_tx"]])
            require(isinstance(trace, list) and bool(trace), "Creation trace unavailable")
            paths = {}
            for item in trace:
                require(isinstance(item, dict) and isinstance(item.get("traceAddress"), list)
                        and all(type(x) is int and x >= 0 for x in item["traceAddress"]), "Malformed trace path")
                path = tuple(item["traceAddress"])
                require(path not in paths, "Duplicate trace path")
                paths[path] = item
                require(item.get("transactionHash", "").lower() == target["creation_tx"]
                        and item.get("blockHash", "").lower() == block["hash"].lower()
                        and type(item.get("blockNumber")) is int and item["blockNumber"] == number
                        and type(item.get("transactionPosition")) is int and item["transactionPosition"] == tx["position"],
                        "Creation trace context differs")
            root_trace = paths.get(())
            require(isinstance(root_trace, dict) and root_trace.get("type") == "call"
                    and isinstance(root_trace.get("action"), dict), "Factory root trace unavailable")
            root_action = root_trace["action"]
            require(root_action.get("from", "").lower() == tx["from"]["hash"].lower()
                    and root_action.get("to", "").lower() == target["creator"]
                    and root_action.get("input", "").lower() == tx["raw_input"].lower()
                    and root_action.get("callType") == "call", "Factory root trace differs")
            creates = [(path, item) for path, item in paths.items() if item.get("type") == "create"
                       and isinstance(item.get("result"), dict)
                       and item["result"].get("address", "").lower() == target["address"]]
            require(len(creates) == 1, "Unique target creation child unavailable", "FACTORY_CREATION_TRACE_CONFLICT")
            path, create = creates[0]
            require(bool(path) and isinstance(create.get("action"), dict)
                    and create["action"].get("from", "").lower() == target["creator"]
                    and create["action"].get("init", "").lower() == sources[role]["creation_bytecode"].lower()
                    and create["result"].get("code", "").lower() == sources[role]["deployed_bytecode"].lower(),
                    "Creation child init/address/runtime differs", "FACTORY_CREATION_TRACE_CONFLICT")
            for length in range(len(path) + 1):
                ancestor = paths.get(path[:length])
                require(isinstance(ancestor, dict) and "error" not in ancestor
                        and isinstance(ancestor.get("result"), dict), "Creation or ancestor reverted/unavailable")
            record.update(archive_factory_transaction_receipt_match=True, archive_creation_trace_matches=True,
                          creation_trace_path=list(path), creation_trace_entries=len(trace))
            save(args.output / "progress.json", result)
            observed, previous = header(number), header(number - 1)
            require(observed["hash"] == block["hash"].lower() and observed["parent_hash"] == block["parent_hash"].lower()
                    and observed["timestamp"] == utc_seconds(tx["timestamp"]), "Explorer/archive creation header differs")
            require(observed["parent_hash"] == previous["hash"] and previous["timestamp"] < observed["timestamp"],
                    "Creation predecessor link/time differs")
            require(tx["position"] < len(observed["transaction_hashes"])
                    and observed["transaction_hashes"][tx["position"]] == target["creation_tx"], "Creation hash/position absent from header")
            before = runtime(target, number - 1, role + "_code_precreation")
            at = runtime(target, number, role + "_code_creation")
            record.update(archive_creation_header_matches=True, archive_creation_hash_position_matches=True,
                          code_before_creation_empty=before == b"", archive_creation_runtime_matches_explorer=at == bytes.fromhex(sources[role]["deployed_bytecode"][2:]),
                          archive_creation_runtime_sha256=sha(at), archive_precreation_runtime_sha256=sha(before))
            save(args.output / "progress.json", result)
            require(before == b"" and at == bytes.fromhex(sources[role]["deployed_bytecode"][2:]),
                    "Creation code checkpoint differs from empty-before/explorer-at expectation", "CREATION_CODE_CHECKPOINT_CONFLICT")

        for spec in plan["boundary_searches"]:
            timestamp = utc_seconds(spec["utc"])
            lo, hi = spec["bracket"]
            require(header(lo)["timestamp"] < timestamp <= header(hi)["timestamp"], "Frozen boundary bracket invalid")
            while hi - lo > 1:
                mid = (lo + hi) // 2
                if header(mid)["timestamp"] < timestamp:
                    lo = mid
                else:
                    hi = mid
            require(header(hi)["parent_hash"] == header(lo)["hash"], "Boundary neighbor parent linkage differs")
            boundary = {"predecessor": {k: v for k, v in header(lo).items() if k != "transaction_hashes"},
                        "first_at_or_after": {k: v for k, v in header(hi).items() if k != "transaction_hashes"}}
            result["boundaries"][spec["name"]] = boundary
            for target in targets:
                role = target["role"]
                value = runtime(target, lo, role + "_code_" + spec["name"])
                result["boundary_states"].append({"boundary": spec["name"], "role": role, "address": target["address"],
                    "block_number": lo, "runtime_bytes": len(value), "runtime_sha256": sha(value),
                    "code_empty": value == b"", "matches_explorer_runtime": value == bytes.fromhex(sources[role]["deployed_bytecode"][2:])})
            save(args.output / "progress.json", result)
        result.update(disposition="DEPLOYMENT_AND_BOUNDARY_CODE_OBSERVED_ROUTING_UNRESOLVED",
                      detail="Two nominated factory creations and boundary code are observed; source recompilation, all facet/selector epochs, predecessor entrypoints, mutation coverage and full population remain open.")
    except Stop as exc:
        result.update(disposition=exc.status, detail=exc.detail)
    except Exception as exc:
        result.update(disposition="RUNNER_OR_SCHEMA_FAILURE", detail=type(exc).__name__ + ": " + str(exc))
    finally:
        creation_checks = sum(bool(row.get("archive_factory_transaction_receipt_match")
                              and row.get("archive_creation_trace_matches")
                              and row.get("archive_creation_header_matches")
                              and row.get("archive_creation_hash_position_matches")
                              and row.get("code_before_creation_empty")
                              and row.get("archive_creation_runtime_matches_explorer")) for row in result["contracts"])
        boundary_checks = len(result["boundary_states"])
        achieved = ("provider_returned_creation_and_boundary_code_consistency" if creation_checks == 2 and boundary_checks == 4
                    else "partial_provider_returned_creation_code_consistency" if creation_checks
                    else "explorer_creation_source_metadata_consistency_only" if result["contracts"]
                    else "acquisition_attempt_without_completed_identity_check")
        result.update(completed_utc=stamp(), rpc_methods=collector.rpc_calls, explorer_gets=collector.get_calls,
                      total_requests=len(collector.requests), retained_response_bytes=collector.bytes,
                      cumulative_response_bytes=plan["previous_response_bytes"] + collector.bytes,
                      cumulative_explorer_gets=plan["previous_explorer_gets"] + collector.get_calls,
                      cumulative_rpc_methods=plan["previous_rpc_methods"] + collector.rpc_calls,
                      reused_response_count=len(reused),
                      completed_factory_trace_checks=sum(bool(x.get("archive_creation_trace_matches")) for x in result["contracts"]),
                      elapsed_seconds=time.monotonic() - collector.started,
                      completed_explorer_identity_checks=len(result["contracts"]),
                      completed_archive_creation_checks=creation_checks, completed_boundary_code_observations=boundary_checks,
                      achieved_evidence_tier=achieved,
                      planned_evidence_tier="provider_returned_creation_and_boundary_code_consistency")
        save(args.output / "summary.json", result)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
