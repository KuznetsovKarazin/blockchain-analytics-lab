#!/usr/bin/env python3
"""Inventory routing writes in compiler ASTs plus forbidden runtime opcodes.

This is a reproducible audit aid, not a formal Solidity/EVM verifier. It records
assignment/reference and alias candidates for human review and fails closure
when expected write paths differ. Compiler artifacts remain private inputs.
"""
import argparse
import hashlib
import json
from pathlib import Path
from compile_retained_sources import nodes, ROLES
from revest_gate_primitives import keccak256, selftest

RELEVANT = {"_owner", "addressesProvider", "addressProvider", "_addresses", "_dex", "next_dex"}
FORBIDDEN = {0xf0:"CREATE",0xf2:"CALLCODE",0xf4:"DELEGATECALL",0xf5:"CREATE2",0xff:"SELFDESTRUCT"}

def sha(data):return hashlib.sha256(data).hexdigest()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--compilation",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    selftest()
    results=[]
    for role in ROLES:
        source=args.compilation/role/"compiler_output.json"
        compiled=json.loads(source.read_bytes())
        comparison=json.loads((args.compilation/role/"comparison.json").read_bytes())
        indexed={x["id"]:x for src in compiled["sources"].values() for x in nodes(src["ast"]) if "id" in x}
        target=next(n for n in indexed.values() if n.get("nodeType")=="ContractDefinition" and n.get("name")==comparison["contract_name"])
        bases=[indexed[i] for i in target["linearizedBaseContracts"]]
        definitions=[n for b in bases for n in b["nodes"]]
        state={n["id"]:n for n in definitions if n.get("nodeType")=="VariableDeclaration" and n.get("stateVariable") and n.get("name") in RELEVANT}
        relevant_ids=set(state)
        writes=[]; aliases=[]; assembly=[]; access_overrides=[]
        for contract in bases:
            for fn in contract["nodes"]:
                if fn.get("nodeType") not in ("FunctionDefinition","ModifierDefinition") or not fn.get("body"):continue
                name=fn.get("name") or fn.get("kind")
                modifiers=[m["modifierName"].get("name") for m in fn.get("modifiers",[])]
                calls=[]
                for call in nodes(fn["body"]):
                    if call.get("nodeType")=="FunctionCall":
                        exp=call["expression"];decl=indexed.get(exp.get("referencedDeclaration"),{})
                        calls.append({"kind":call.get("kind"),"expression_type":exp.get("nodeType"),"name":exp.get("name") or exp.get("memberName"),"declaration_name":decl.get("name"),"declaration_type":decl.get("nodeType"),"function_type":exp.get("typeDescriptions",{}).get("typeString")})
                for item in nodes(fn["body"]):
                    ntype=item.get("nodeType")
                    expr=item.get("leftHandSide") if ntype=="Assignment" else item.get("subExpression") if ntype=="UnaryOperation" and item.get("operator") in ("++","--","delete") else None
                    if expr:
                        refs={n.get("referencedDeclaration") for n in nodes(expr)} & relevant_ids
                        if refs:writes.append({"contract":contract["name"],"function":name,"visibility":fn.get("visibility"),"modifiers":modifiers,"variables":sorted(state[i]["name"] for i in refs),"operator":item.get("operator"),"source_span":item["src"],"calls_in_function":calls})
                    if ntype=="VariableDeclarationStatement":
                        storage_locals=[n for n in item.get("declarations",[]) if n and n.get("storageLocation")=="storage"]
                        refs={n.get("referencedDeclaration") for n in nodes(item.get("initialValue"))} & relevant_ids
                        if storage_locals and refs:aliases.append({"function":name,"source_span":item["src"]})
                    if ntype=="InlineAssembly":
                        names=[n.get("name") for n in nodes(item.get("AST")) if n.get("nodeType")=="YulIdentifier"]
                        assembly.append({"contract":contract["name"],"function":name,"source_span":item["src"],"yul_names":sorted(set(names)),"storage_write_detected":bool({"sstore","tstore"}&set(names))})
                if name in ("owner","_msgSender","_setOwner","onlyOwner","transferOwnership","renounceOwnership"):
                    access_overrides.append({"contract":contract["name"],"function":name,"visibility":fn.get("visibility"),"modifiers":modifiers,"source_span":fn["src"],"calls":calls})
        runtime=bytes.fromhex(compiled["contracts"][comparison["source_file"]][comparison["contract_name"]]["evm"]["deployedBytecode"]["object"])
        metadata_len=int.from_bytes(runtime[-2:],"big")
        if metadata_len+2>=len(runtime):raise ValueError("invalid metadata length")
        instructions=runtime[:-(metadata_len+2)];bad=[];pos=0
        while pos<len(instructions):
            op=instructions[pos]
            if op in FORBIDDEN:bad.append({"offset":pos,"opcode":FORBIDDEN[op]})
            pos+=2+op-0x60 if 0x60<=op<=0x7f else 1
        selector_checks={signature:keccak256(signature.encode()).hex()[:8]==selector for signature,selector in comparison["method_identifiers"].items()}
        if not all(selector_checks.values()):raise ValueError("Keccak/compiler selector disagreement")
        results.append({"role":role,"compiler_output_sha256":sha(source.read_bytes()),"c3_bases":[b["name"] for b in bases],"routing_state_variables":[{"name":v["name"],"source_span":v["src"]} for v in state.values()],"writes":writes,"storage_alias_candidates":aliases,"inherited_inline_assembly":assembly,"access_functions":access_overrides,"forbidden_runtime_opcodes":bad,"compiler_selector_crosschecks":len(selector_checks),"runtime_instruction_bytes":len(instructions),"runtime_metadata_bytes":metadata_len+2})
    result={"schema":"phase9_revest_ast_write_inventory_v1","scope":"Audit aid over exact compiled retained source; not proof of historical state, provider completeness or arbitrary compiler correctness.","roles":results,"compiler_selector_crosschecks":sum(x["compiler_selector_crosschecks"] for x in results),"no_forbidden_runtime_opcodes":all(not x["forbidden_runtime_opcodes"] for x in results),"no_routing_storage_alias_candidates":all(not x["storage_alias_candidates"] for x in results)}
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({"roles":len(results),"selector_crosschecks":result["compiler_selector_crosschecks"],"no_forbidden_runtime_opcodes":result["no_forbidden_runtime_opcodes"],"no_routing_storage_alias_candidates":result["no_routing_storage_alias_candidates"]}))

if __name__=="__main__":main()
