#!/usr/bin/env python3
"""Independent offline audit; full compiler outputs remain in --private-output.

Does not import the producer's compilation helper. Rebuilds source sets from
the original retained responses and checks constructor inputs, AST-derived
immutable bindings, complete runtime bytes and independently allocated slots.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
from datetime import datetime, timezone

SOLC_SHA = "f7115ccaf11899dcf3aaa888949f8614421f2d10af65a74870bcfd67010da7f8"
ROLES = ("registry", "revest", "lock_manager", "token_vault", "fnft_handler")
OUTPUTS = ["abi", "storageLayout", "evm.bytecode.object", "evm.deployedBytecode.object",
           "evm.deployedBytecode.immutableReferences", "evm.methodIdentifiers"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def decode_hex(value):
    if value is None:
        return b""
    return bytes.fromhex(value[2:] if value.startswith("0x") else value)


def c3(contract_id, definitions):
    """Solidity's rightmost base has priority; independently merge base lists."""
    parents = [b["baseName"]["referencedDeclaration"]
               for b in definitions[contract_id]["baseContracts"]][::-1]
    sequences = [c3(p, definitions) for p in parents] + [parents[:]]
    merged = []
    while any(sequences):
        sequences = [s for s in sequences if s]
        candidate = next((s[0] for s in sequences
                          if not any(s[0] in t[1:] for t in sequences)), None)
        assert candidate is not None, "inconsistent C3 graph"
        merged.append(candidate)
        for s in sequences:
            if s[0] == candidate:
                s.pop(0)
    return [contract_id] + merged


def independently_allocate(target_id, definitions):
    # All top-level fields in these five contracts are covered by this small
    # explicit allocator. Unsupported types fail, never assume a slot width.
    slot = offset = 0
    result = []
    linearized = c3(target_id, definitions)
    assert linearized == definitions[target_id]["linearizedBaseContracts"]
    for cid in reversed(linearized):
        for node in definitions[cid]["nodes"]:
            if node.get("nodeType") != "VariableDeclaration" or not node.get("stateVariable"):
                continue
            if node.get("constant") or node.get("mutability") == "immutable":
                continue
            typename = node["typeDescriptions"]["typeString"]
            full_slot = typename.startswith("mapping(") or typename in ("string", "bytes")
            if full_slot:
                width = 32
            elif typename in ("address", "address payable") or typename.startswith("contract "):
                width = 20
            elif typename == "bool":
                width = 1
            elif re.fullmatch(r"u?int\d*", typename):
                width = int(re.search(r"\d+", typename).group() if re.search(r"\d+", typename) else 256) // 8
            elif re.fullmatch(r"bytes\d+", typename):
                width = int(typename[5:])
            else:
                raise AssertionError("unsupported storage type: " + typename)
            if (full_slot and offset) or offset + width > 32:
                slot += 1
                offset = 0
            result.append({"label": node["name"], "slot": str(slot), "offset": offset})
            offset += width
            if offset == 32:
                slot += 1
                offset = 0
    return result, [definitions[c]["name"] for c in linearized]


def main():
    p = argparse.ArgumentParser()
    for name in ("sources", "producer", "solc", "private-output", "report", "repo"):
        p.add_argument("--" + name, required=True, type=Path)
    a = p.parse_args()
    a.private_output.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    assert sha(a.solc.read_bytes()) == SOLC_SHA
    version = subprocess.run([str(a.solc), "--version"], capture_output=True, check=True, timeout=5).stdout.decode()
    assert version == load(a.producer / "compiler_identity.json")["version_output"]
    assert "0.8.4+commit.c7e474f2" in version
    fetch = {r["file"]: r for r in load(a.sources / "fetch_manifest.json")}
    source_before = {p.name: sha(p.read_bytes()) for p in a.sources.iterdir() if p.is_file()}
    producer_before = {str(p.relative_to(a.producer)): sha(p.read_bytes())
                       for p in a.producer.rglob("*") if p.is_file()}
    assert not subprocess.check_output(["git", "diff", "--name-only", "7fbd06d85dbc9870428e377e9fb55d9398b42efa"], cwd=a.repo)
    rows = []
    for role in ROLES:
        original_name = role + "_verified_contract.json"
        raw = (a.sources / original_name).read_bytes()
        assert sha(raw) == fetch[original_name]["sha256"]
        assert len(raw) == fetch[original_name]["bytes"]
        d = json.loads(raw)
        assert d["compiler_version"] == "0.8.4+commit.c7e474f2"
        assert d["language"] == "solidity"
        sources = {d["file_path"]: {"content": d["source_code"]}}
        for source in d["additional_sources"]:
            key, content = source["file_path"], {"content": source["source_code"]}
            assert key not in sources or sources[key] == content
            sources[key] = content
        settings = copy.deepcopy(d["compiler_settings"])
        compilation_target = settings.pop("compilationTarget", None)
        assert compilation_target is None or compilation_target == {d["file_path"]: d["name"]}
        assert settings["optimizer"] == {"enabled": True, "runs": 10000}
        assert settings["evmVersion"] == "istanbul"
        assert settings["metadata"] == {"bytecodeHash": "ipfs", "useLiteralContent": True}
        assert settings["libraries"] == {} and settings["remappings"] == []
        settings["outputSelection"] = {"*": {"*": OUTPUTS, "": ["ast"]}}
        request = {"language": "Solidity", "sources": sources, "settings": settings}
        raw_request = json.dumps(request, sort_keys=True).encode()
        assert raw_request == (a.producer / role / "compiler_input.json").read_bytes()
        role_dir = a.private_output / role
        role_dir.mkdir()
        (role_dir / "compiler_input.json").write_bytes(raw_request)
        proc = subprocess.run([str(a.solc), "--standard-json"], input=raw_request,
                              capture_output=True, timeout=180)
        (role_dir / "compiler_output.json").write_bytes(proc.stdout)
        (role_dir / "compiler_stderr.txt").write_bytes(proc.stderr)
        assert proc.returncode == 0 and not proc.stderr
        compiled = json.loads(proc.stdout)
        assert not [e for e in compiled.get("errors", []) if e["severity"] == "error"]
        assert proc.stdout == (a.producer / role / "compiler_output.json").read_bytes()
        product = compiled["contracts"][d["file_path"]][d["name"]]
        original_constructor = [n for n in d["abi"] if n["type"] == "constructor"]
        constructor = [n for n in product["abi"] if n["type"] == "constructor"]
        assert constructor == original_constructor and len(constructor) == 1
        params = constructor[0]["inputs"]
        assert all(p["type"] == "address" for p in params)
        args = decode_hex(d["constructor_args"])
        assert len(args) == 32 * len(params)
        words = [args[i:i + 32] for i in range(0, len(args), 32)]
        assert all(w[:12] == b"\0" * 12 for w in words)
        for word, decoded in zip(words, d["decoded_constructor_args"] or []):
            assert word[12:].hex() == decoded[0][2:].lower()
        creation = bytes.fromhex(product["evm"]["bytecode"]["object"])
        creation_with_args = creation + args
        assert creation_with_args == decode_hex(d["creation_bytecode"])
        creation_name = role + "_creation.json"
        creation_raw = (a.sources / creation_name).read_bytes()
        assert sha(creation_raw) == fetch[creation_name]["sha256"]
        tx = json.loads(creation_raw)
        assert tx["status"] == "ok" and tx["to"] is None
        assert creation_with_args == decode_hex(tx["raw_input"])
        node_map = {n["id"]: n for s in compiled["sources"].values()
                    for n in walk(s["ast"]) if "id" in n}
        definitions = {k: v for k, v in node_map.items() if v.get("nodeType") == "ContractDefinition"}
        target = next(n for n in compiled["sources"][d["file_path"]]["ast"]["nodes"]
                      if n.get("nodeType") == "ContractDefinition" and n["name"] == d["name"])
        runtime = bytes.fromhex(product["evm"]["deployedBytecode"]["object"])
        expected_runtime = decode_hex(d["deployed_bytecode"])
        assert len(runtime) == len(expected_runtime)
        rebuilt = bytearray(runtime)
        substitutions = []
        locations = set()
        refs = product["evm"]["deployedBytecode"].get("immutableReferences", {})
        for decl_id, patches in refs.items():
            declaration = node_map[int(decl_id)]
            assert role == "revest" and declaration["name"] == "WETH"
            assert declaration["mutability"] == "immutable"
            assert declaration["typeDescriptions"]["typeString"] == "address"
            constructor_ast = next(n for n in target["nodes"] if n.get("kind") == "constructor")
            assignments = [n for n in walk(constructor_ast["body"])
                           if n.get("nodeType") == "Assignment"
                           and n["leftHandSide"].get("referencedDeclaration") == int(decl_id)]
            assert len(assignments) == 1 and assignments[0]["operator"] == "="
            rhs = assignments[0]["rightHandSide"]
            assert rhs["nodeType"] == "Identifier"
            ast_params = constructor_ast["parameters"]["parameters"]
            argument_index = next(i for i, param in enumerate(ast_params)
                                  if param["id"] == rhs["referencedDeclaration"])
            assert params[argument_index]["name"] == "weth" and argument_index == 1
            for patch in patches:
                start, length = patch["start"], patch["length"]
                assert length == 32 and 0 <= start <= len(runtime) - length
                assert not locations.intersection(range(start, start + length))
                locations.update(range(start, start + length))
                assert runtime[start:start + length] == b"\0" * length
                rebuilt[start:start + length] = words[argument_index]
                substitutions.append({"name": "WETH", "start": start, "length": length,
                                      "constructor_argument_index": argument_index})
        assert bytes(rebuilt) == expected_runtime
        differences = {i for i, (x, y) in enumerate(zip(runtime, expected_runtime)) if x != y}
        assert differences <= locations
        metadata_size = int.from_bytes(runtime[-2:], "big") + 2
        assert 2 < metadata_size < len(runtime)
        assert runtime[-metadata_size:] == expected_runtime[-metadata_size:]
        assert not locations.intersection(range(len(runtime) - metadata_size, len(runtime)))
        independent_layout, inheritance = independently_allocate(target["id"], definitions)
        compiler_layout = [{k: n[k] for k in ("label", "slot", "offset")}
                           for n in product["storageLayout"]["storage"]]
        assert independent_layout == compiler_layout
        # Local negative controls require no further compile or network calls.
        altered = bytearray(rebuilt); altered[0] ^= 1
        assert bytes(altered) != expected_runtime
        if args:
            altered_args = bytearray(args); altered_args[-1] ^= 1
            assert creation + altered_args != decode_hex(tx["raw_input"])
        if substitutions:
            altered = bytearray(rebuilt); altered[substitutions[0]["start"] + 31] ^= 1
            assert bytes(altered) != expected_runtime
        reported = load(a.producer / role / "comparison.json")
        assert reported["runtime_bytes"] == len(rebuilt)
        assert reported["compiled_runtime_sha256"] == sha(rebuilt)
        assert reported["storage_layout"] == product["storageLayout"]
        assert reported["input_sha256"] == sha(raw_request) and reported["output_sha256"] == sha(proc.stdout)
        assert reported["retained_response_sha256"] == sha(raw)
        assert reported["sources"] == [{"path": k, "bytes": len(v["content"].encode()),
                                        "sha256": sha(v["content"].encode())} for k, v in sorted(sources.items())]
        assert reported["immutable_substitutions"] == [{k: p[k] for k in ("name", "start", "length")}
                                                        for p in substitutions]
        rows.append({"role": role, "source_count": len(sources), "retained_source_sha256": sha(raw),
                     "retained_creation_response_sha256": sha(creation_raw),
                     "compiler_input_sha256": sha(raw_request), "compiler_output_sha256": sha(proc.stdout),
                     "creation_bytes_with_args": len(creation_with_args), "constructor_argument_words": len(words),
                     "runtime_bytes": len(runtime), "runtime_sha256": sha(rebuilt),
                     "exact_creation_and_retained_transaction_match": True, "exact_complete_runtime_match": True,
                     "metadata_bytes_including_length": metadata_size, "metadata_exact": True,
                     "immutable_substitutions": substitutions, "unpatched_runtime_differing_bytes": len(differences),
                     "storage_fields": independent_layout, "independent_c3_inheritance_order": inheritance,
                     "producer_output_byte_identical": True, "source_hash_inventory_exact": True})
        print(role, "PASS", flush=True)
    assert source_before == {p.name: sha(p.read_bytes()) for p in a.sources.iterdir() if p.is_file()}
    assert producer_before == {str(p.relative_to(a.producer)): sha(p.read_bytes())
                              for p in a.producer.rglob("*") if p.is_file()}
    assert not subprocess.check_output(["git", "diff", "--name-only", "7fbd06d85dbc9870428e377e9fb55d9398b42efa"], cwd=a.repo)
    report = {"schema_version": "phase9_revest_independent_compilation_review_v1", "status": "PASS",
              "started_at_utc": started, "completed_at_utc": datetime.now(timezone.utc).isoformat(),
              "compiler_sha256": SOLC_SHA, "independent_compile_invocations": 5,
              "new_network_requests": 0, "original_source_files_unchanged": True,
              "producer_artifacts_unchanged": True, "tracked_phase8_tree_unchanged": True,
              "producer_helper_not_imported_or_executed": True, "source_sets": rows,
              "negative_checks": "Single non-immutable runtime-byte changes, constructor-word changes for four contracts, and a WETH substitution change are detected by exact comparisons.",
              "scope": "Independent repeat with the same pinned compiler, not compiler diversity or formal verification. Retained explorer source/creation/runtime consistency only.",
              "remaining_limits": ["No historical boundary eth_getCode/state proof checked by this review.",
                                   "No continuous ownership, routing, provider-address or code continuity established.",
                                   "No complete protocol population, label eligibility, detector outcome or incident admission follows.",
                                   "Full third-party sources, runtime/creation bytes and compiler output remain private; public report carries owned analysis and factual hashes/counts only."],
              "audit_script_sha256": sha(Path(__file__).read_bytes()),
              "producer_summary_sha256": sha((a.producer / "summary.json").read_bytes())}
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
