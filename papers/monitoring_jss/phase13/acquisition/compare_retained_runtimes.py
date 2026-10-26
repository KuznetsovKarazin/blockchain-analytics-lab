#!/usr/bin/env python3
"""Full-byte comparison to every contract in a previously reproduced output.

This is an offline follow-on analysis, not a compilation, settings search, source
fetch or new historical code query. Nonmatches do not prove semantic difference.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


EXPECTED_COMPILER_OUTPUT = "2aa02601b74f98184ac79af132271dca6c328a4e53ded616e605d0ad7a5a1919"
EXPECTED_COMPILATION_RESULT = "7c59ce06ac9c3034c86e8caba5e0c881a9605e328ab52b7c9f92b0124b263b64"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path, expected=None):
    raw = path.read_bytes()
    if expected is not None and sha(raw) != expected:
        raise ValueError("Bound input differs: " + path.name)
    return json.loads(raw)


def runtime(value):
    if not isinstance(value, str) or re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value) is None:
        raise ValueError("Malformed provider runtime byte string")
    return bytes.fromhex(value[2:])


def main():
    parser = argparse.ArgumentParser()
    for name in ("attempt", "phase10-attempt", "compiled-output", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    paper = Path(__file__).resolve().parents[2]
    compiler = load(args.compiled_output, EXPECTED_COMPILER_OUTPUT)
    prior = load(paper / "phase11/compilation/compilation_results.json", EXPECTED_COMPILATION_RESULT)
    if prior.get("all_exact") is not True:
        raise ValueError("Prior exact-compilation result missing")
    summary = load(args.attempt / "summary.json")
    plan = load(args.attempt / "frozen_plan.json", summary["plan_sha256"])
    requests = load(args.attempt / "requests.json")
    candidates, candidate_bytes = [], {}
    for source_path, contracts in sorted(compiler["contracts"].items()):
        for contract_name, contract in sorted(contracts.items()):
            deployed = contract.get("evm", {}).get("deployedBytecode", {})
            value = deployed.get("object")
            label = source_path + ":" + contract_name
            row = {"source_path": source_path, "contract_name": contract_name,
                   "full_runtime_includes_compiler_metadata": True,
                   "link_reference_file_count": len(deployed.get("linkReferences", {})),
                   "immutable_reference_count": len(deployed.get("immutableReferences", {}))}
            if value == "":
                row.update(status="EMPTY_RUNTIME_NOT_A_COMPARISON_CANDIDATE", runtime_bytes=0)
            elif not isinstance(value, str):
                row.update(status="MISSING_RUNTIME_OBJECT_NOT_A_COMPARISON_CANDIDATE")
            elif re.fullmatch(r"(?:[0-9a-fA-F]{2})+", value) is None:
                row.update(status="NONHEX_OR_UNRESOLVED_LINK_PLACEHOLDER_NOT_A_COMPARISON_CANDIDATE",
                           object_text_bytes=len(value.encode()))
            else:
                raw = bytes.fromhex(value)
                candidate_bytes[label] = raw
                row.update(status="NONEMPTY_FULL_BYTES_COMPARISON_CANDIDATE", runtime_bytes=len(raw), runtime_sha256=sha(raw))
            candidates.append(row)
    observations = []
    for observed in summary["runtime_observations"]:
        pair = next(row for row in plan["code_observations"] if row["address"] == observed["address"]
                    and row["block_number"] == observed["block_number"])
        if observed["evidence_source"]["kind"] == "fresh_phase13":
            ordinal = observed["evidence_source"]["request_ordinal"]
            record = next(row for row in requests if row["ordinal"] == ordinal)
            folder = args.attempt
        else:
            record, folder = pair["reused_record"], args.phase10_attempt
        request = load(folder / record["request_file"], record["request_sha256"])
        response = load(folder / record["response_file"], record["response_sha256"])
        if request["json"]["method"] != "eth_getCode" or request["json"]["params"] != [pair["address"], hex(pair["block_number"])]:
            raise ValueError("Runtime observation request does not bind observed pair")
        if response.get("jsonrpc") != "2.0" or response.get("id") != request["json"]["id"] or "error" in response:
            raise ValueError("Runtime response envelope differs")
        raw = runtime(response["result"])
        if len(raw) != observed["runtime_bytes"] or sha(raw) != observed["runtime_sha256"]:
            raise ValueError("Provider runtime differs from capture observation")
        matches = [label for label, compiled in candidate_bytes.items() if raw == compiled]
        observations.append({**{key: observed[key] for key in ("checkpoint", "block_number", "block_hash", "address", "runtime_bytes", "runtime_sha256", "runtime_keccak256")},
            "exact_matching_compiled_contracts": matches, "full_bytes_equal": bool(matches),
            "equality_includes_metadata": True, "masked_bytes": 0, "response_sha256": record["response_sha256"]})
    matched = [row for row in observations if row["full_bytes_equal"]]
    result = {"schema_version": "article2_phase13_retained_compiler_runtime_comparison_v1",
        "status": "OFFLINE_ALL_RETAINED_CONTRACTS_FULL_BYTES_COMPARED",
        "analysis_type": "Retrospective follow-on identity comparison after the frozen acquisition; no new runtime target or source fetch.",
        "input_bindings": {"compiled_output_sha256": EXPECTED_COMPILER_OUTPUT,
            "phase11_compilation_result_sha256": EXPECTED_COMPILATION_RESULT,
            "capture_summary_sha256": sha((args.attempt / "summary.json").read_bytes()),
            "capture_plan_sha256": summary["plan_sha256"], "capture_requests_sha256": sha((args.attempt / "requests.json").read_bytes()),
            "comparison_program_sha256": sha(Path(__file__).read_bytes())},
        "compiled_contract_count": len(candidates), "compiled_source_path_count": len(compiler["contracts"]),
        "nonempty_full_bytes_candidate_count": len(candidate_bytes),
        "excluded_empty_count": sum(row["status"].startswith("EMPTY_") for row in candidates),
        "excluded_missing_or_nonhex_count": sum(row["status"].startswith(("MISSING_", "NONHEX_")) for row in candidates),
        "comparison_pair_count": len(observations) * len(candidate_bytes),
        "observation_count": len(observations), "exact_match_observation_count": len(matched),
        "unique_observed_addresses": len({row["address"] for row in observations}),
        "exact_match_unique_addresses": len({row["address"] for row in matched}),
        "unique_observed_full_runtime_digests": len({row["runtime_sha256"] for row in observations}),
        "candidate_inventory": candidates, "observations": observations,
        "new_compiler_invocations": 0, "new_network_requests": 0, "settings_searches": 0,
        "masked_bytes": 0, "new_case_admissions": 0, "detector_scores": 0,
        "limits": ["Exact matches bind the full sampled runtime to an existing reproduced compiler output under its retained source/settings provenance.",
                   "The same compiler was used for the earlier independent reproduction; this is not compiler diversity or formal proof.",
                   "No match does not establish semantic difference, malicious code, unavailable source or a failed scientific case.",
                   "Equality at sampled blocks does not prove continuous identity or historical selector activation between samples.",
                   "Full compiler output and source-bearing metadata remain private; this table contains hashes, lengths and contract identifiers only."]}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key not in {"candidate_inventory", "observations", "limits"}}, indent=2))


if __name__ == "__main__":
    main()
