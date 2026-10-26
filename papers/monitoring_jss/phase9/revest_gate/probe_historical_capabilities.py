#!/usr/bin/env python3
"""Bounded read-only capability probe; raw replies are private evidence."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

def stamp():
    return datetime.now(timezone.utc).isoformat()

def sha(value):
    return hashlib.sha256(value).hexdigest()

def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

def word(value):
    return isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{64}", value) is not None

def code(value):
    return isinstance(value, str) and re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value) is not None

class Probe:
    def __init__(self, plan, output):
        self.plan, self.output = plan, output
        self.started = time.monotonic()
        self.calls, self.bytes, self.records = 0, 0, []

    def call(self, provider, method, params):
        caps = self.plan["caps"]
        if self.calls >= caps["rpc_methods_total"] or time.monotonic() - self.started >= caps["total_wall_seconds"]:
            raise RuntimeError("global request or wall cap reached")
        if self.bytes >= caps["retained_response_bytes"]:
            raise RuntimeError("global response cap reached")
        self.calls += 1
        payload = json.dumps({"jsonrpc": "2.0", "id": self.calls, "method": method, "params": params}).encode()
        prefix = f'{self.calls:02d}_{provider["id"]}_{method}'
        (self.output / (prefix + "_request.json")).write_bytes(payload)
        rec = {"id": self.calls, "provider": provider["id"], "method": method, "started_utc": stamp(), "request_sha256": sha(payload)}
        self.records.append(rec)
        save(self.output / "requests.json", self.records)
        raw = b""
        try:
            request = urllib.request.Request(provider["endpoint"], data=payload, headers={"Content-Type": "application/json", "User-Agent": "Article2-historical-capability/1"})
            try:
                response = urllib.request.urlopen(request, timeout=caps["per_request_seconds"])
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                rec["http_status"] = response.status
                limit = min(caps["per_response_bytes"], caps["retained_response_bytes"] - self.bytes)
                raw = response.read(limit + 1)
                if len(raw) > limit:
                    raw = raw[:limit]
                    rec["response_truncated_at_cap"] = True
            self.bytes += len(raw)
            (self.output / (prefix + "_response.bin")).write_bytes(raw)
            rec.update(response_bytes=len(raw), response_sha256=sha(raw))
            body = json.loads(raw)
            if rec.get("response_truncated_at_cap") or rec["http_status"] != 200:
                raise ValueError("HTTP failure or truncated response")
            if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or body.get("id") != self.calls or "error" in body:
                rec["rpc_error"] = body.get("error") if isinstance(body, dict) else "invalid envelope"
                raise ValueError("invalid/error RPC envelope")
            if "result" not in body:
                raise ValueError("missing result")
            rec["transport_rpc_ok"] = True
            return body["result"]
        except Exception as exc:
            rec["failure"] = type(exc).__name__ + ": " + str(exc)
            rec["transport_rpc_ok"] = False
            return None
        finally:
            rec["completed_utc"] = stamp()
            save(self.output / "requests.json", self.records)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", type=Path, required=True)
    ap.add_argument("--accepted-plan-sha256", required=True)
    ap.add_argument("--compilation-summary", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    plan_bytes = args.plan.read_bytes()
    if sha(plan_bytes) != args.accepted_plan_sha256:
        raise ValueError("accepted plan digest mismatch")
    plan = json.loads(plan_bytes)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "frozen_plan.json").write_bytes(plan_bytes)
    save(args.output / "acceptance.json", {"accepted_plan_sha256": args.accepted_plan_sha256, "started_utc": stamp(), "authorization": "Root coordinator explicitly accepted this exact plan before execution."})
    compiled = json.loads(args.compilation_summary.read_text())
    assert compiled["all_exact"]
    registry_compile = next(x for x in compiled["roles"] if x["role"] == "registry")
    assert next(x for x in registry_compile["storage_layout"]["storage"] if x["label"] == "_owner")["slot"] == "0"
    runner = Probe(plan, args.output)
    results = []
    for provider in plan["providers_in_order"]:
        start_count = runner.calls
        result = {"provider": provider["id"]}
        chain = runner.call(provider, "eth_chainId", [])
        result["chain_id_1"] = chain == "0x1"
        if chain != "0x1":
            result.update(disposition="PROVIDER_UNAVAILABLE_OR_WRONG_CHAIN", request_count=runner.calls-start_count)
            results.append(result)
            continue
        block = hex(plan["historical_probe_block"])
        header = runner.call(provider, "eth_getBlockByNumber", [block, False])
        header_valid = isinstance(header, dict) and header.get("number") == block and word(header.get("hash"))
        result["historical_header_valid"] = header_valid
        if header_valid:
            stamp_int = int(header["timestamp"], 16)
            result["historical_header_hash"] = header["hash"]
            result["historical_header_time_utc"] = datetime.fromtimestamp(stamp_int, timezone.utc).isoformat()
            result["sample_in_proposed_window"] = 1645833600 <= stamp_int < 1648425600
        runtime = runner.call(provider, "eth_getCode", [plan["registry"], block])
        result["historical_runtime_valid"] = code(runtime) and runtime != "0x"
        result["historical_runtime_matches_retained_source"] = code(runtime) and sha(bytes.fromhex(runtime[2:])) == registry_compile["compiled_runtime_sha256"]
        owner = runner.call(provider, "eth_getStorageAt", [plan["registry"], "0x0", block])
        owner_valid = word(owner) and owner[2:26] == "0" * 24
        result["historical_owner_word_valid"] = owner_valid
        if owner_valid and int(owner, 16) != 0:
            owner_address = "0x" + owner[-40:]
            result["historical_owner_address"] = owner_address
            owner_code = runner.call(provider, "eth_getCode", [owner_address, block])
            result["historical_owner_code_valid"] = code(owner_code)
            result["historical_owner_has_code"] = code(owner_code) and owner_code != "0x"
        admin_block = hex(plan["known_admin_initialization_block"])
        traces = runner.call(provider, "trace_filter", [{"fromBlock": admin_block, "toBlock": admin_block, "toAddress": [plan["registry"]], "after": 0, "count": 2}])
        expected = []
        if isinstance(traces, list):
            for row in traces:
                action = row.get("action", {})
                if row.get("blockNumber") != plan["known_admin_initialization_block"]:
                    raise ValueError("unexpected out-of-scope trace block")
                valid = all(k in row for k in ["type", "traceAddress", "transactionHash", "transactionPosition", "blockHash", "blockNumber"])
                valid = valid and all(k in action for k in ["from", "to", "input"]) and ("result" in row or "error" in row)
                if row.get("transactionHash", "").lower() == plan["known_admin_initialization_tx"].lower():
                    expected.append(valid and action.get("to", "").lower() == plan["registry"].lower() and action.get("input", "").startswith("0xf5e95acb"))
        result["known_admin_trace_schema_available"] = any(expected)
        result["historical_state_and_trace_capability"] = bool(result["historical_runtime_matches_retained_source"] and owner_valid and any(expected))
        result["request_count"] = runner.calls - start_count
        result["disposition"] = "CAPABILITY_AVAILABLE_ROUTING_UNPROVED" if result["historical_state_and_trace_capability"] else "REQUIRED_CAPABILITY_NOT_ESTABLISHED"
        results.append(result)
    available = any(x.get("historical_state_and_trace_capability") for x in results)
    summary = {"schema": "phase9_revest_historical_capability_result_v1", "plan_sha256": sha(plan_bytes), "completed_utc": stamp(), "providers": results, "rpc_methods": runner.calls, "response_bytes": runner.bytes, "disposition": "CAPABILITY_AVAILABLE_ROUTING_UNPROVED" if available else "UNAVAILABLE_WITHIN_FROZEN_PROVIDER_PLAN", "new_case_admission_count": 0, "continuity_proved": False, "limitation": "Unavailable means this bounded provider/method plan could not establish the required evidence. It is not a statement that all providers lack it or that the protocol cannot be monitored."}
    save(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()
