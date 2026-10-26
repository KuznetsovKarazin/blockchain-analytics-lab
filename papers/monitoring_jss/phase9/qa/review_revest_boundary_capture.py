#!/usr/bin/env python3
"""Independent offline reconstruction of the bounded Revest boundary capture.

No producer modules are imported. RPC Merkle nodes are syntax-checked only;
the reported evidence tier remains provider-index/state consistency.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from independent_keccak import digest256, verify_oracle

ROLES = ("registry", "revest", "lock_manager", "token_vault", "fnft_handler")
CORE = {"REVEST": "revest", "LOCK_MANAGER": "lock_manager", "TOKEN_VAULT": "token_vault", "FNFT": "fnft_handler"}
SLOTS = {"revest": (2, 3), "lock_manager": (3, 4), "token_vault": (2, 3), "fnft_handler": (4, 5)}


def load(p):
    return json.loads(p.read_bytes())


def sha(b):
    return hashlib.sha256(b).hexdigest()


def quantity(s, width=256):
    assert isinstance(s, str) and re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", s)
    v = int(s, 16)
    assert 0 <= v < 1 << width
    return v


def datahex(s, size=None):
    assert isinstance(s, str) and re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", s)
    value = bytes.fromhex(s[2:])
    assert size is None or len(value) == size
    return value


def main():
    ap = argparse.ArgumentParser()
    for name in ("capture", "prior-capability", "batch-state", "originals", "compilation-review", "prefetch-review", "report", "private-review"):
        ap.add_argument("--" + name, type=Path, required=True)
    ap.add_argument("--expected-plan-sha256", required=True)
    a = ap.parse_args()
    oracle_checks = verify_oracle()
    plan = load(a.capture / "frozen_plan.json")
    plan_sha = sha((a.capture / "frozen_plan.json").read_bytes())
    assert re.fullmatch(r"[0-9a-f]{64}", a.expected_plan_sha256)
    assert plan_sha == a.expected_plan_sha256
    prefetch = load(a.prefetch_review)
    assert prefetch["status"] == "GO_WITHIN_ROOT_FROZEN_BOUNDARY_STATE_SCOPE"
    assert prefetch["code_and_plan"]["continuity_continuation_plan.json"]["sha256"] == plan_sha
    records = load(a.capture / "requests.json")
    assert records and datetime.fromisoformat(records[0]["started_utc"]) >= datetime.fromisoformat(prefetch["accepted_at_utc"])
    calls = []
    for i, rec in enumerate(records, 1):
        assert rec["id"] == i and rec["provider"] == "drpc"
        assert rec["method"] in ("eth_getBlockByNumber", "eth_getCode", "eth_getProof")
        prefix = f'{i:02d}_drpc_{rec["method"]}'
        req_raw = (a.capture / (prefix + "_request.json")).read_bytes()
        res_raw = (a.capture / (prefix + "_response.bin")).read_bytes()
        req, res = json.loads(req_raw), json.loads(res_raw)
        assert sha(req_raw) == rec["request_sha256"] and sha(res_raw) == rec["response_sha256"]
        assert len(res_raw) == rec["response_bytes"]
        assert req["id"] == res["id"] == i and req["jsonrpc"] == res["jsonrpc"] == "2.0"
        assert req["method"] == rec["method"]
        assert rec["http_status"] == 200 and rec["transport_rpc_ok"] and "error" not in res
        assert not rec.get("response_truncated_at_cap")
        assert (datetime.fromisoformat(rec["completed_utc"]) - datetime.fromisoformat(rec["started_utc"])).total_seconds() <= plan["caps"]["per_request_seconds"]
        calls.append((req, res["result"]))
    method_counts = Counter(x[0]["method"] for x in calls)
    assert method_counts["eth_getBlockByNumber"] <= 36
    assert method_counts["eth_getCode"] == method_counts["eth_getProof"] == 10
    assert len(calls) <= 108
    batch = load(a.batch_state / "summary.json")
    assert batch["rpc_methods"] == 1 and batch["response_bytes"] == 22377 and batch["plan_sha256"] == plan_sha
    assert sum(r["response_bytes"] for r in records) + batch["response_bytes"] <= plan["caps"]["additional_retained_bytes"]
    assert max(r["response_bytes"] for r in records) <= plan["caps"]["per_response_bytes"]
    elapsed = (datetime.fromisoformat(records[-1]["completed_utc"]) - datetime.fromisoformat(load(a.batch_state / "acceptance.json")["started_utc"])).total_seconds()
    assert elapsed <= plan["caps"]["total_wall_seconds"]
    cached = load(a.prior_capability / "07_drpc_eth_getBlockByNumber_response.bin")["result"]
    headers = {quantity(cached["number"]): cached}
    for req, result in calls:
        if req["method"] != "eth_getBlockByNumber":
            continue
        num = quantity(req["params"][0])
        assert req["params"][1] is False and quantity(result["number"]) == num
        datahex(result["hash"], 32); datahex(result["parentHash"], 32)
        quantity(result["timestamp"], 64)
        assert num not in headers
        headers[num] = result
    sorted_headers = sorted(headers.items())
    assert all(quantity(left[1]["timestamp"]) < quantity(right[1]["timestamp"])
               for left, right in zip(sorted_headers, sorted_headers[1:]))
    boundaries = {}
    for label, iso in zip(("start", "end"), plan["window_utc"]):
        epoch = int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())
        before = max(n for n, h in sorted_headers if quantity(h["timestamp"]) < epoch)
        after = min(n for n, h in sorted_headers if quantity(h["timestamp"]) >= epoch)
        assert after == before + 1
        assert headers[after]["parentHash"].lower() == headers[before]["hash"].lower()
        def summarize(n):
            h = headers[n]; stamp = quantity(h["timestamp"])
            return {"number": n, "hash": h["hash"], "parent_hash": h["parentHash"], "timestamp": stamp,
                    "timestamp_utc": datetime.fromtimestamp(stamp, timezone.utc).isoformat()}
        boundaries[label] = {"predecessor": summarize(before), "first_at_or_after": summarize(after)}
    assert boundaries == load(a.capture / "boundaries.json")
    addresses = {r: load(a.originals / (r + "_creation.json"))["created_contract"]["hash"].lower() for r in ROLES}
    registry_keys = {"owner": 0, "next_dex": 1}
    for name in plan["required_registry_keys"]:
        padded_ascii = name.encode("ascii").ljust(32, b"\0")
        assert len(padded_ascii) == 32
        registry_keys[name] = int.from_bytes(digest256(padded_ascii + (2).to_bytes(32, "big")), "big")
    for i in range(8):
        registry_keys["dex_" + str(i)] = int.from_bytes(digest256(i.to_bytes(32, "big") + (3).to_bytes(32, "big")), "big")
    keys = {"registry": registry_keys}
    keys.update({r: {"owner": slots[0], "provider": slots[1]} for r, slots in SLOTS.items()})
    independent_compilation = load(a.compilation_review)
    compiler_roles = {r["role"]: r for r in independent_compilation["source_sets"]}
    for r, (owner, provider) in SLOTS.items():
        fields = {f["label"]: int(f["slot"]) for f in compiler_roles[r]["storage_fields"]}
        assert fields["_owner"] == owner and fields["addressesProvider"] == provider
    reconstructed = {"start": {}, "end": {}}
    state_calls = [(req, res) for req, res in calls if req["method"] != "eth_getBlockByNumber"]
    assert [req["method"] for req, _ in state_calls] == ["eth_getCode", "eth_getProof"] * 10
    for index, (label, role) in enumerate((l, r) for l in ("start", "end") for r in ROLES):
        code_req, returned_code = state_calls[2 * index]
        proof_req, proof = state_calls[2 * index + 1]
        block = boundaries[label]["predecessor"]["number"]
        assert code_req["params"] == [addresses[role], hex(block)]
        assert proof_req["params"] == [addresses[role], ["0x" + n.to_bytes(32, "big").hex() for n in keys[role].values()], hex(block)]
        runtime = datahex(returned_code)
        assert sha(runtime) == compiler_roles[role]["runtime_sha256"]
        expected = datahex(load(a.originals / (role + "_verified_contract.json"))["deployed_bytecode"])
        assert runtime == expected
        assert proof["address"].lower() == addresses[role]
        expected_code_hash = digest256(runtime)
        assert datahex(proof["codeHash"], 32) == expected_code_hash
        datahex(proof["storageHash"], 32)
        quantity(proof["balance"]); quantity(proof["nonce"])
        assert proof["accountProof"] and all(datahex(node) for node in proof["accountProof"])
        actual_slots = {}
        for row in proof["storageProof"]:
            slot = int.from_bytes(datahex(row["key"], 32), "big")
            assert slot not in actual_slots
            actual_slots[slot] = quantity(row["value"])
            assert isinstance(row["proof"], list) and all(datahex(node) for node in row["proof"])
        assert set(actual_slots) == set(keys[role].values())
        values = {name: actual_slots[k] for name, k in keys[role].items()}
        assert all(v < 1 << 160 for k, v in values.items() if k != "next_dex")
        if role == "registry":
            assert values["next_dex"] <= 8
        reconstructed[label][role] = {"address": addresses[role], "block_number": block, "runtime_sha256": sha(runtime),
                                       "code_hash": "0x" + expected_code_hash.hex(), "values": values}
    assert reconstructed == load(a.capture / "boundary_states.json")
    differences = []
    for label in ("start", "end"):
        for key, role in CORE.items():
            observed = "0x" + reconstructed[label]["registry"]["values"][key].to_bytes(20, "big").hex()
            if observed != addresses[role]:
                differences.append({"boundary": label, "kind": "registry_core_binding", "role": role,
                                    "expected": addresses[role], "observed": observed})
        for role in ROLES[1:]:
            observed = "0x" + reconstructed[label][role]["values"]["provider"].to_bytes(20, "big").hex()
            if observed != addresses["registry"]:
                differences.append({"boundary": label, "kind": "component_registry_provider", "role": role,
                                    "expected": addresses["registry"], "observed": observed})
    disposition = "POPULATION_EXPANSION_UNRESOLVED" if differences else "BOUNDARY_STATES_MATCH_CONTINUITY_UNPROVED"
    summary = load(a.capture / "summary.json")
    assert summary["disposition"] == disposition and summary["membership_differences"] == differences
    assert summary["rpc_methods"] == len(records)
    assert summary["response_bytes"] == sum(r["response_bytes"] for r in records)
    assert summary["cumulative_rpc_methods"] == 12 + len(records)
    assert summary["cumulative_response_bytes"] == 42538 + 22377 + sum(r["response_bytes"] for r in records)
    assert summary["continuity_proved"] is False and summary["new_case_admission_count"] == 0
    assert summary["proofs_cryptographically_verified"] is False and summary["boundary_states_completed"] == 10
    a.private_review.mkdir(parents=True, exist_ok=False)
    (a.private_review / "reconstructed_boundary_states.json").write_text(json.dumps(reconstructed, indent=2, sort_keys=True) + "\n")
    (a.private_review / "reconstructed_differences.json").write_text(json.dumps(differences, indent=2, sort_keys=True) + "\n")
    result = {
        "schema_version": "phase9_revest_independent_boundary_capture_review_v1", "status": "PASS",
        "checked_at_utc": datetime.now(timezone.utc).isoformat(), "new_network_requests": 0,
        "producer_modules_imported": False, "independent_sponge_validation": oracle_checks,
        "rpc_methods": len(records), "method_counts": dict(method_counts), "response_bytes": sum(r["response_bytes"] for r in records),
        "cumulative_rpc_methods": summary["cumulative_rpc_methods"], "cumulative_response_bytes": summary["cumulative_response_bytes"],
        "all_request_response_hashes_and_frozen_parameters_exact": True, "prefetch_precedes_first_call": True,
        "all_actual_resource_caps_satisfied": True, "boundary_headers_independently_bracketed": True,
        "included_first_block": boundaries["start"]["first_at_or_after"]["number"],
        "included_last_block": boundaries["end"]["predecessor"]["number"],
        "all_10_full_runtimes_exact": True, "all_10_codehashes_independently_recomputed": True,
        "all_10_state_slot_sets_and_widths_exact": True, "all_state_values_independently_reconstructed": True,
        "membership_difference_count": len(differences),
        "membership_difference_kinds": [{"boundary": r["boundary"], "kind": r["kind"], "role": r["role"],
                                          "observed_zero_address": int(r["observed"], 16) == 0} for r in differences],
        "independently_derived_disposition": disposition, "case_admission_count": 0, "continuity_proved": False,
        "proofs_cryptographically_verified": False,
        "scope": "Endpoint counterexample or agreement at provider-returned state consistency tier only; no transition time, continuous population, detector outcome or global RPC-completeness conclusion.",
        "source_bindings": {"capture_summary_sha256": sha((a.capture / "summary.json").read_bytes()),
                            "request_ledger_sha256": sha((a.capture / "requests.json").read_bytes()),
                            "prefetch_review_sha256": sha(a.prefetch_review.read_bytes()), "plan_sha256": plan_sha,
                            "audit_script_sha256": sha(Path(__file__).read_bytes()),
                            "independent_keccak_sha256": sha(Path(__file__).with_name("independent_keccak.py").read_bytes())}
    }
    a.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: result[k] for k in ("status", "rpc_methods", "response_bytes", "membership_difference_count", "independently_derived_disposition")}))


if __name__ == "__main__":
    main()
