#!/usr/bin/env python3
"""Reconstruct two retained Li.Fi source sets with one fixed compiler/settings.

No network or EVM execution. Constructor boundaries come from reproduced
creation bytes and compiler ABI; explorer constructor annotations are ignored.
All output, including third-party source content, belongs in private evidence.
"""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import resource
import subprocess
import time


def stamp():
    return datetime.now(timezone.utc).isoformat()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def strict_json(raw):
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise ValueError("Duplicate JSON key")
            obj[key] = value
        return obj
    return json.loads(raw, object_pairs_hook=pairs)


class Stop(Exception):
    def __init__(self, detail, disposition="SOURCE_OR_SETTINGS_UNRESOLVED"):
        self.disposition, self.detail = disposition, detail
        super().__init__(detail)


def require(ok, detail, disposition="SOURCE_OR_SETTINGS_UNRESOLVED"):
    if not ok:
        raise Stop(detail, disposition)


def bytecode(value, prefix=False):
    require(isinstance(value, str), "Missing bytecode")
    if prefix:
        require(value.startswith("0x"), "Missing bytecode prefix")
        value = value[2:]
    require(re.fullmatch(r"(?:[0-9a-fA-F]{2})*", value) is not None, "Non-byte or unresolved bytecode")
    return bytes.fromhex(value)


def bound(path, expected):
    raw = path.read_bytes()
    require(digest(raw) == expected, "Frozen input changed: " + path.name)
    return raw


def records(directory, expected_hash):
    rows = strict_json(bound(directory / "requests.json", expected_hash))
    result = {}
    for row in rows:
        require(row["key"] not in result, "Duplicate retained request key")
        response = bound(directory / row["response_file"], row["response_sha256"])
        require(len(response) == row["response_bytes"] and row.get("http_status") == 200
                and row.get("transport_json_ok") is True, "Retained transport was not successful")
        request = strict_json(bound(directory / row["request_file"], row["request_sha256"]))
        body = strict_json(response)
        if row["kind"] == "rpc":
            payload = request["json"]
            require(body.get("jsonrpc") == "2.0" and body.get("id") == payload["id"]
                    and "error" not in body and "result" in body, "Retained RPC envelope differs")
            body = body["result"]
        result[row["key"]] = {"body": body, "raw_sha256": digest(response), "request": request}
    return result


def resource_limits(limits):
    def apply():
        resource.setrlimit(resource.RLIMIT_CPU, (limits["per_compile_cpu_seconds"], limits["per_compile_cpu_seconds"]))
        resource.setrlimit(resource.RLIMIT_AS, (limits["per_compile_address_space_bytes"], limits["per_compile_address_space_bytes"]))
        resource.setrlimit(resource.RLIMIT_FSIZE, (limits["per_output_file_bytes"], limits["per_output_file_bytes"]))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return apply


def compile_role(spec, source_entry, captured, solc, output, limits, run_result):
    source = source_entry["body"]
    role = spec["role"]
    require(source_entry["raw_sha256"] == spec["source_response_sha256"], "Source response binding differs")
    require(source["file_path"] == spec["source_file"] and source["name"] == spec["contract_name"], "Source identity differs")
    require(source["compiler_settings"] == spec["compiler_settings"], "Compiler settings changed")
    pieces = [{"file_path": source["file_path"], "source_code": source["source_code"]}] + source["additional_sources"]
    require(len(pieces) == spec["source_file_occurrences"] <= limits["source_files_per_role_max"], "Source-file count differs")
    sources, total = {}, 0
    for piece in pieces:
        name, content = piece["file_path"], piece["source_code"]
        require(isinstance(name, str) and name and isinstance(content, str) and name not in sources, "Duplicate/invalid literal source")
        sources[name] = {"content": content}
        total += len(content.encode())
    require(total <= limits["source_total_bytes_per_role_max"], "Source byte cap exceeded")
    settings = copy.deepcopy(spec["compiler_settings"])
    require("outputSelection" not in settings, "Unexpected original output selection")
    settings["outputSelection"] = {"*": {"*": ["abi", "metadata", "storageLayout", "evm.bytecode.object",
        "evm.bytecode.linkReferences", "evm.deployedBytecode.object", "evm.deployedBytecode.linkReferences",
        "evm.deployedBytecode.immutableReferences", "evm.methodIdentifiers"], "": ["ast"]}}
    standard = {"language": "Solidity", "sources": sources, "settings": settings}
    role_dir = output / role
    role_dir.mkdir()
    work = role_dir / "empty_compiler_workdir"
    work.mkdir()
    input_bytes = json.dumps(standard, sort_keys=True, separators=(",", ":")).encode()
    input_path, output_path, stderr_path = role_dir / "compiler_input.json", role_dir / "compiler_output.json", role_dir / "compiler_stderr.txt"
    input_path.write_bytes(input_bytes)
    invocation = {"started_utc": stamp(), "command": ["PINNED_SOLC", "--standard-json"],
                  "source_response_sha256": source_entry["raw_sha256"], "input_sha256": digest(input_bytes)}
    save(role_dir / "invocation.json", invocation)
    started = time.monotonic()
    try:
        require(run_result["compiler_invocations"] < limits["producer_compiler_invocations_max"], "Compiler invocation cap")
        run_result["compiler_invocations"] += 1
        save(output / "progress.json", run_result)
        with input_path.open("rb") as stdin, output_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            proc = subprocess.run([str(solc), "--standard-json"], stdin=stdin, stdout=stdout, stderr=stderr,
                                  cwd=work, timeout=limits["per_compile_wall_seconds"], preexec_fn=resource_limits(limits))
        invocation["returncode"] = proc.returncode
        require(proc.returncode == 0, "Compiler returned nonzero", "COMPILATION_FAILURE_OR_RESOURCE_CAP")
    except subprocess.TimeoutExpired as exc:
        invocation["failure"] = "wall_timeout"
        raise Stop("Compiler wall-time cap reached", "COMPILATION_FAILURE_OR_RESOURCE_CAP") from exc
    finally:
        invocation.update(completed_utc=stamp(), elapsed_seconds=time.monotonic() - started)
        for label, path in (("output", output_path), ("stderr", stderr_path)):
            if path.exists():
                raw = path.read_bytes()
                invocation[label + "_sha256"] = digest(raw)
                invocation[label + "_bytes"] = len(raw)
        save(role_dir / "invocation.json", invocation)
    require(output_path.stat().st_size < limits["per_output_file_bytes"], "Compiler output at file cap", "COMPILATION_FAILURE_OR_RESOURCE_CAP")
    compiled = strict_json(output_path.read_bytes())
    errors = [x for x in compiled.get("errors", []) if x.get("severity") == "error"]
    require(not errors, "Compiler error diagnostics retained", "COMPILATION_FAILURE_OR_RESOURCE_CAP")
    target = compiled["contracts"][spec["source_file"]][spec["contract_name"]]
    evm = target["evm"]
    require(not evm["bytecode"]["linkReferences"] and not evm["deployedBytecode"]["linkReferences"]
            and not evm["deployedBytecode"].get("immutableReferences", {}), "Unresolved links/immutables outside frozen plan")
    creation, runtime = bytecode(evm["bytecode"]["object"]), bytecode(evm["deployedBytecode"]["object"])
    require(bool(creation) and bool(runtime), "Empty target bytecode")
    actual_creation, actual_runtime = bytecode(source["creation_bytecode"], True), bytecode(source["deployed_bytecode"], True)
    require(len(actual_creation) == spec["expected_explorer_creation_bytes"]
            and len(actual_runtime) == spec["expected_explorer_runtime_bytes"], "Expected source byte length differs")
    constructors = [x for x in target["abi"] if x.get("type") == "constructor"]
    require(len(constructors) <= 1, "Multiple constructor ABI entries")
    inputs = constructors[0]["inputs"] if constructors else []
    require([x["type"] for x in inputs] == spec["expected_constructor_abi_types"], "Compiler constructor ABI differs")
    expected_length = 32 * len(inputs)
    require(expected_length == spec["expected_constructor_suffix_bytes"], "Constructor width differs")
    prefix_matches = actual_creation.startswith(creation)
    suffix = actual_creation[len(creation):] if prefix_matches else b""
    ctor_matches = prefix_matches and len(suffix) == expected_length
    arguments = []
    if ctor_matches:
        for index, item in enumerate(inputs):
            word = suffix[32 * index:32 * (index + 1)]
            require(item["type"] == "address" and word[:12] == bytes(12), "Constructor address padding is not canonical")
            arguments.append({"name": item["name"], "type": item["type"], "address": "0x" + word[12:].hex(),
                              "byte_offset_in_factory_initcode": len(creation) + 32 * index})
    evidence = captured[role]
    trace = evidence["trace"]
    checks = {"compiled_creation_prefix_matches": prefix_matches, "compiler_abi_constructor_suffix_matches": ctor_matches,
              "full_creation_plus_constructor_matches_explorer": ctor_matches and creation + suffix == actual_creation,
              "full_creation_plus_constructor_matches_trace": ctor_matches and creation + suffix == bytecode(trace["action"]["init"], True),
              "full_runtime_matches_explorer": runtime == actual_runtime,
              "full_runtime_matches_creation_trace": runtime == bytecode(trace["result"]["code"], True)}
    for label, raw_code in evidence["runtime"].items():
        checks["full_runtime_matches_" + label] = runtime == raw_code
    metadata = strict_json(target["metadata"])
    require(metadata.get("compiler", {}).get("version") == source["compiler_version"], "Compiler output metadata version differs")
    result = {"role": role, "source_response_sha256": source_entry["raw_sha256"], "source_file_occurrences": len(sources),
        "source_text_bytes": total, "source_files": [{"path": k, "sha256": digest(v["content"].encode()),
            "bytes": len(v["content"].encode())} for k, v in sorted(sources.items())],
        "input_sha256": digest(input_bytes), "output_sha256": digest(output_path.read_bytes()),
        "compiler_creation_bytes_without_constructor": len(creation), "constructor_suffix_bytes": len(suffix) if prefix_matches else None,
        "runtime_bytes": len(runtime), "compiled_creation_sha256": digest(creation), "compiled_runtime_sha256": digest(runtime),
        "constructor_arguments_from_exact_compiled_boundary": arguments, "explorer_constructor_annotations_used": False,
        "metadata_retained_without_stripping": True, "compiler_metadata": metadata, "abi": target["abi"],
        "storage_layout": target["storageLayout"], "method_identifiers": evm["methodIdentifiers"],
        "compiler_warnings": [x.get("errorCode") for x in compiled.get("errors", []) if x.get("severity") == "warning"],
        "checks": checks, "all_exact": all(checks.values()),
        "limit": "Source/compiler bytecode consistency for this target; no selector activation or complete routing proof."}
    save(role_dir / "comparison.json", result)
    require(result["all_exact"], "Bytecode or constructor mismatch: " + role, "BYTECODE_OR_CONSTRUCTOR_MISMATCH")
    return result


def main():
    ap = argparse.ArgumentParser()
    for name in ("plan", "solc", "manifest", "initial", "factory", "output"):
        ap.add_argument("--" + name, type=Path, required=True)
    ap.add_argument("--accepted-plan-sha256", required=True)
    ap.add_argument("--accepted-runner-sha256", required=True)
    args = ap.parse_args()
    plan_bytes = bound(args.plan, args.accepted_plan_sha256)
    runner_bytes = bound(Path(__file__), args.accepted_runner_sha256)
    plan = strict_json(plan_bytes)
    require(plan["schema_version"] == "article2_phase11_lifi_compiler_reconstruction_plan_v1", "Wrong plan schema")
    manifest = strict_json(bound(args.manifest, plan["compiler"]["source_manifest_sha256"]))
    builds = [x for x in manifest["builds"] if x.get("longVersion") == plan["compiler"]["version"]]
    require(len(builds) == 1 and builds[0]["sha256"].removeprefix("0x") == plan["compiler"]["sha256"], "Compiler manifest binding differs")
    solc = args.solc.resolve()
    bound(solc, plan["compiler"]["sha256"])
    prior = records(args.initial, plan["evidence"]["phase10_initial_requests_sha256"])
    current = records(args.factory, plan["evidence"]["phase10_factory_requests_sha256"])
    summary = strict_json(bound(args.factory / "summary.json", plan["evidence"]["phase10_factory_summary_sha256"]))
    require(summary["disposition"] == "DEPLOYMENT_AND_BOUNDARY_CODE_OBSERVED_ROUTING_UNRESOLVED", "Historical evidence incomplete")
    require([x["role"] for x in plan["roles"]] == ["diamond", "cbridge_facet"], "Target order/set differs")
    sources = {"diamond": prior["diamond_source"], "cbridge_facet": current["cbridge_facet_source"]}
    historical, roles = {}, {x["role"]: x for x in summary["contracts"]}
    for spec in plan["roles"]:
        role = spec["role"]
        source = sources[role]["body"]
        require(source["compiler_version"] == plan["compiler"]["version"], "Source compiler version differs")
        trace = current[role + "_creation_trace"]["body"]
        target_trace = [x for x in trace if x.get("type") == "create" and isinstance(x.get("result"), dict)
                        and x["result"].get("address", "").lower() == roles[role]["address"]]
        require(len(target_trace) == 1 and "error" not in target_trace[0], "Historical creation trace binding differs")
        runtime = {}
        for label in ("creation", "start", "end"):
            item = current[role + "_code_" + label]
            block = roles[role]["creation_block"] if label == "creation" else summary["boundaries"][label]["predecessor"]["number"]
            require(item["request"]["json"]["method"] == "eth_getCode"
                    and item["request"]["json"]["params"] == [roles[role]["address"], hex(block)], "Historical code address/block differs")
            runtime[label] = bytecode(item["body"], True)
        historical[role] = {"trace": target_trace[0], "runtime": runtime}
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "frozen_plan.json").write_bytes(plan_bytes)
    (args.output / "runner_source.py").write_bytes(runner_bytes)
    save(args.output / "acceptance.json", {"started_utc": stamp(), "plan_sha256": digest(plan_bytes),
        "runner_sha256": digest(runner_bytes), "compiler_sha256": plan["compiler"]["sha256"]})
    result = {"schema_version": "article2_phase11_lifi_source_reconstruction_result_v1", "plan_sha256": digest(plan_bytes),
        "runner_sha256": digest(runner_bytes), "compiler_sha256": plan["compiler"]["sha256"],
        "roles": [], "compiler_invocations": 0, "version_probes": 0, "new_network_requests": 0,
        "scientific_admissions": 0, "detector_scores": 0, "routing_continuity_proved": False, "formal_verification": False}
    try:
        result["version_probes"] += 1
        version = subprocess.run([str(solc), "--version"], capture_output=True, timeout=10, check=False)
        (args.output / "compiler_version_stdout.txt").write_bytes(version.stdout)
        (args.output / "compiler_version_stderr.txt").write_bytes(version.stderr)
        require(version.returncode == 0 and plan["compiler"]["version"] in version.stdout.decode(), "Compiler executable version differs")
        for spec in plan["roles"]:
            result["roles"].append(compile_role(spec, sources[spec["role"]], historical, solc, args.output, plan["compilation"], result))
            save(args.output / "progress.json", result)
        result.update(disposition="EXACT_SOURCE_COMPILER_BYTECODE_CONSISTENCY", all_exact=True)
    except Stop as exc:
        result.update(disposition=exc.disposition, detail=exc.detail, all_exact=False)
    except Exception as exc:
        result.update(disposition="COMPILATION_FAILURE_OR_RESOURCE_CAP", detail=type(exc).__name__ + ": " + str(exc), all_exact=False)
    finally:
        result.update(completed_utc=stamp(), achieved_evidence_tier="exact_source_compiler_bytecode_consistency"
                      if result.get("all_exact") else "incomplete_compiler_reconstruction_attempt")
        save(args.output / "summary.json", result)
    print(json.dumps({k: v for k, v in result.items() if k != "roles"}, indent=2))
    for role in result["roles"]:
        print(role["role"], role["all_exact"], role["compiler_creation_bytes_without_constructor"], role["runtime_bytes"],
              json.dumps(role["constructor_arguments_from_exact_compiled_boundary"]))


if __name__ == "__main__":
    main()
