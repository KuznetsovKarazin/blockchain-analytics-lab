#!/usr/bin/env python3
"""Recompile five retained explorer source sets and compare exact bytecode.

Outputs include third-party sources and bytecode: retain privately. No network,
chain interaction, source rewriting, or Solidity execution is performed.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
from datetime import datetime, timezone

EXPECTED_SOLC = "f7115ccaf11899dcf3aaa888949f8614421f2d10af65a74870bcfd67010da7f8"
ROLES = ["registry", "revest", "lock_manager", "token_vault", "fnft_handler"]

def digest(value):
    return hashlib.sha256(value).hexdigest()

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

def nodes(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from nodes(child)
    elif isinstance(value, list):
        for child in value:
            yield from nodes(child)

def compile_one(role, source_dir, solc, output_dir):
    raw = (source_dir / (role + "_verified_contract.json")).read_bytes()
    data = json.loads(raw)
    assert data["compiler_version"] == "0.8.4+commit.c7e474f2"
    sources = {data["file_path"]: {"content": data["source_code"]}}
    for src in data["additional_sources"]:
        name = src["file_path"]
        item = {"content": src["source_code"]}
        if name in sources and sources[name] != item:
            raise ValueError("conflicting source: " + name)
        sources[name] = item
    settings = copy.deepcopy(data["compiler_settings"])
    settings.pop("compilationTarget", None)
    settings["outputSelection"] = {"*": {"*": ["abi", "storageLayout", "evm.bytecode.object", "evm.deployedBytecode.object", "evm.deployedBytecode.immutableReferences", "evm.methodIdentifiers"], "": ["ast"]}}
    standard = {"language": "Solidity", "sources": sources, "settings": settings}
    private = output_dir / role
    private.mkdir()
    in_bytes = json.dumps(standard, sort_keys=True).encode()
    (private / "compiler_input.json").write_bytes(in_bytes)
    started = datetime.now(timezone.utc).isoformat()
    proc = subprocess.run([str(solc), "--standard-json"], input=in_bytes, capture_output=True, timeout=180)
    (private / "compiler_output.json").write_bytes(proc.stdout)
    (private / "compiler_stderr.txt").write_bytes(proc.stderr)
    output = json.loads(proc.stdout)
    errors = [x for x in output.get("errors", []) if x.get("severity") == "error"]
    if proc.returncode or errors:
        raise ValueError("compile failed for " + role + ": " + json.dumps(errors))
    target = output["contracts"][data["file_path"]][data["name"]]
    creation = target["evm"]["bytecode"]["object"]
    args = (data.get("constructor_args") or "").removeprefix("0x")
    runtime = bytearray.fromhex(target["evm"]["deployedBytecode"]["object"])
    immutable_refs = target["evm"]["deployedBytecode"].get("immutableReferences", {})
    ast_nodes = {x["id"]: x for item in output["sources"].values() for x in nodes(item["ast"]) if "id" in x}
    applied = []
    for ident, refs in immutable_refs.items():
        decl = ast_nodes[int(ident)]
        if role != "revest" or decl.get("name") != "WETH" or len(args) != 128:
            raise ValueError("unrecognized immutable; no generic masking permitted")
        word = bytes.fromhex(args[64:128])
        for ref in refs:
            if ref["length"] != 32:
                raise ValueError("unexpected immutable width")
            runtime[ref["start"]:ref["start"] + 32] = word
            applied.append({"name": "WETH", **ref})
    expected_runtime = bytes.fromhex(data["deployed_bytecode"].removeprefix("0x"))
    expected_creation = bytes.fromhex(data["creation_bytecode"].removeprefix("0x"))
    result = {"role": role, "contract_name": data["name"], "source_file": data["file_path"], "retained_response_sha256": digest(raw), "source_count": len(sources), "sources": [{"path": k, "sha256": digest(v["content"].encode()), "bytes": len(v["content"].encode())} for k, v in sorted(sources.items())], "input_sha256": digest(in_bytes), "output_sha256": digest(proc.stdout), "started_utc": started, "completed_utc": datetime.now(timezone.utc).isoformat(), "creation_with_constructor_args_match": bytes.fromhex(creation + args) == expected_creation, "runtime_with_constructor_immutables_match": bytes(runtime) == expected_runtime, "compiled_runtime_sha256": digest(runtime), "explorer_runtime_sha256": digest(expected_runtime), "runtime_bytes": len(runtime), "immutable_substitutions": applied, "storage_layout": target["storageLayout"], "method_identifiers": target["evm"]["methodIdentifiers"], "compiler_warnings": [x.get("errorCode") for x in output.get("errors", []) if x.get("severity") == "warning"], "claim_scope": "Exact retained explorer bytecode/source consistency only; historical boundary/state/continuous routing still unproved."}
    write_json(private / "comparison.json", result)
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--solc", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if digest(args.solc.read_bytes()) != EXPECTED_SOLC:
        raise ValueError("compiler digest mismatch")
    args.output.mkdir(parents=True, exist_ok=False)
    version = subprocess.run([str(args.solc), "--version"], capture_output=True, check=True, timeout=5).stdout.decode()
    if "0.8.4+commit.c7e474f2" not in version:
        raise ValueError("compiler version mismatch")
    write_json(args.output / "compiler_identity.json", {"sha256": EXPECTED_SOLC, "version_output": version})
    results = []
    for role in ROLES:
        result = compile_one(role, args.sources, args.solc, args.output)
        results.append(result)
        print(role, result["creation_with_constructor_args_match"], result["runtime_with_constructor_immutables_match"], flush=True)
    write_json(args.output / "summary.json", {"schema": "phase9_revest_recompilation_v1", "compiler_sha256": EXPECTED_SOLC, "roles": results, "all_exact": all(r["creation_with_constructor_args_match"] and r["runtime_with_constructor_immutables_match"] for r in results)})

if __name__ == "__main__":
    main()
