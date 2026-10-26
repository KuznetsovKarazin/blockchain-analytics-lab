#!/usr/bin/env python3
"""Source-free findings from immutable capture and full-byte match records."""
import argparse
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    for name in ("attempt", "checkpoints", "comparison", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    load = lambda p: json.loads(p.read_text())
    summary = load(args.attempt / "summary.json")
    records = load(args.attempt / "requests.json")
    comparison = load(args.comparison)
    checkpoints = load(args.checkpoints)
    if comparison["input_bindings"]["capture_summary_sha256"] != sha(args.attempt / "summary.json"):
        raise ValueError("Comparison/capture binding differs")
    rows = comparison["observations"]
    groups = []
    for address in sorted({row["address"] for row in rows}):
        subset = [row for row in rows if row["address"] == address]
        groups.append({"address": address, "checkpoints": [row["checkpoint"] for row in subset],
            "runtime_sha256_set": sorted({row["runtime_sha256"] for row in subset}),
            "runtime_bytes_set": sorted({row["runtime_bytes"] for row in subset}),
            "exact_matching_compiled_contracts": sorted({name for row in subset for name in row["exact_matching_compiled_contracts"]}),
            "all_observed_runtime_bytes_same": len({row["runtime_sha256"] for row in subset}) == 1,
            "continuous_runtime_identity_proved": False})
    states = {row["name"]: row for row in checkpoints["states"]}
    by_pair = {(row["checkpoint"], row["address"]): row for row in rows}
    transitions = []
    for selector in sorted(set(states["start"]["selector_map"]) & set(states["end"]["selector_map"])):
        left = states["start"]["selector_map"][selector]
        right = states["end"]["selector_map"][selector]
        if left["facet"] == right["facet"]:
            continue
        before, after = by_pair[("start", left["facet"])], by_pair[("end", right["facet"])]
        transitions.append({"selector": selector, "start_facet": left["facet"], "end_facet": right["facet"],
            "start_runtime_sha256": before["runtime_sha256"], "end_runtime_sha256": after["runtime_sha256"],
            "full_runtime_bytes_same": before["runtime_sha256"] == after["runtime_sha256"],
            "semantic_difference_proved": False, "change_time_or_count_proved": False})
    failures = []
    for record in records:
        if record.get("transport_json_ok") is True:
            continue
        request = load(args.attempt / record["request_file"])
        raw = args.attempt / record["response_file"]
        if sha(raw) != record["response_sha256"]:
            raise ValueError("Failure response hash differs")
        try:
            body = load(raw)
            error = body.get("error")
        except Exception:
            error = None
        failures.append({"ordinal": record["ordinal"], "method": request["json"]["method"],
            "parameters": request["json"]["params"], "http_status": record.get("http_status"),
            "provider_error": error, "response_bytes": record["response_bytes"], "response_sha256": record["response_sha256"]})
    administrative = []
    for label, selector in [("diamondCut", "0x1f931c1c"), ("transferOwnership", "0xf2fde38b")]:
        bindings = []
        for name in ("creation", "start", "end"):
            binding = states[name]["selector_map"].get(selector)
            if binding:
                row = by_pair[(name, binding["facet"])]
                bindings.append({"checkpoint": name, "facet": binding["facet"],
                    "runtime_sha256": row["runtime_sha256"], "exact_matching_compiled_contracts": row["exact_matching_compiled_contracts"]})
        administrative.append({"entrypoint": label, "selector": selector, "observed_bindings": bindings,
            "interval_authority_or_exhaustive_writer_coverage_proved": False})
    result = {"schema_version": "article2_phase13_attempt1_code_binding_findings_v1",
        "status": "SAMPLED_RUNTIME_BINDINGS_AVAILABLE_FIRST_WINDOW_HISTORY_QUERY_REFUSED",
        "scope": "Phase13 code_window_attempt1 and its offline existing-compiler-output comparison only. Any separately accepted later retrieval attempt requires a separate receipt and accounting.",
        "input_bindings": {"capture_summary_sha256": sha(args.attempt / "summary.json"),
            "capture_requests_sha256": sha(args.attempt / "requests.json"), "checkpoint_summary_sha256": sha(args.checkpoints),
            "runtime_match_table_sha256": sha(args.comparison), "findings_program_sha256": sha(Path(__file__))},
        "acquisition": {key: summary[key] for key in ("disposition", "rpc_methods", "retained_response_bytes", "fresh_code_requests",
            "window_log_requests", "completed_runtime_observations", "empty_runtime_observation_count", "completed_log_chunks", "nominal_replay_performed")},
        "reused_prior_code_pairs": 1, "complete_window_event_observations_available": False,
        "observed_zero_events_in_window": False, "provider_general_range_limit_established": False,
        "failure_observations": failures,
        "runtime_groups": groups,
        "full_byte_match_counts": {key: comparison[key] for key in ("compiled_contract_count", "compiled_source_path_count",
            "nonempty_full_bytes_candidate_count", "excluded_empty_count", "excluded_missing_or_nonhex_count", "comparison_pair_count",
            "observation_count", "exact_match_observation_count", "unique_observed_addresses", "exact_match_unique_addresses", "unique_observed_full_runtime_digests")},
        "previously_exact_source_bound_addresses": ["0x73a499e043b03fc047189ab1ba72eb595ff1fc8e"],
        "new_exact_source_runtime_bound_unique_addresses": [row["address"] for row in groups if row["exact_matching_compiled_contracts"]
            and row["address"] != "0x73a499e043b03fc047189ab1ba72eb595ff1fc8e"],
        "changed_selector_endpoint_runtime_comparisons": transitions,
        "changed_selector_bindings_count": len(transitions),
        "changed_bindings_with_different_full_runtime_bytes": sum(not row["full_runtime_bytes_same"] for row in transitions),
        "administrative_entrypoint_checkpoint_bindings": administrative,
        "next_relevant_work": [
            "Administrative history availability remains unresolved. A separately justified and frozen retrieval design is required before more requests; retain both refused attempts.",
            "Use the now exact-bound DiamondCutFacet and OwnershipFacet plus the already reviewed LibDiamond source to anchor source-shaped administrative writer analysis.",
            "Any nonzero initializer or additional facet nominated by future successful history must be handled explicitly; none is identified by an unavailable event response.",
            "Eight observed facet addresses do not match the retained compiler-output candidates; investigate only relevant reached code under a separate bounded source-binding plan.",
            "The endpoint CBridge successor at 0x2abfcca3672a853370f59421c6c6f72e5f215d96 remains source-unbound; equal old namespace words do not establish its effective semantics."
        ],
        "limits": [
            "All code and registry statements concern sampled provider observations; no account proof or header state-root verification was added.",
            "Different full runtime bytes can include compiler metadata differences; they do not by themselves prove changed execution semantics.",
            "A same-address same-code endpoint pair cannot exclude change-and-restore or intervening routing changes.",
            "Exact existing-compiler-output matches use the prior reproducibility chain with the same compiler, not independent compiler diversity or formal verification.",
            "No nominal event replay or initializer analysis was possible because the first log query returned an error, not an event array.",
            "There are no new detector scores, incident payloads, case admissions, exclusion decisions, or changes to the monitoring criteria."
        ],
        "new_compiler_invocations": 0, "new_network_requests_for_offline_analysis": 0,
        "scientific_admissions": 0, "detector_scores": 0, "historical_routing_proved": False}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    md = ["# Sampled runtime bindings and unavailable window events", "",
        "This record covers the first Phase13 acquisition and its offline comparison with already retained compiler output. It does not cover any separately accepted later retrieval attempt.", "",
        "The acquisition made **19 new RPC requests**, retaining **154,568 response bytes**: 18 successful historical `eth_getCode` calls followed by one refused event query. One exact Phase10 code response was reused, giving 19 nonempty `(address, checkpoint)` runtime observations across 14 facet addresses. The original 19-pair observation schedule was used; no unobserved facet/checkpoint grid was added.", "",
        "## Exact comparison with existing compiler output", "",
        "The retained, previously independently reproduced Phase11 output contains 59 compiled contracts across 44 source paths. All 36 nonempty full-runtime objects were compared with every observed code value: 684 byte-for-byte comparisons. Twenty-three empty objects were excluded explicitly; there were no missing/nonhex/placeholder objects. No compiler invocation, settings search, metadata masking or new source fetch occurred.", "",
        "Eleven observed pairs match six unique addresses exactly, including compiler metadata. Five addresses add source/runtime bindings beyond the previously bound CBridge target:", "",
        "| Compiled target | Address | Matching checkpoints | Runtime bytes |",
        "|---|---|---|---:|"]
    for row in groups:
        if row["exact_matching_compiled_contracts"]:
            name = ", ".join(value.rsplit(":", 1)[1] for value in row["exact_matching_compiled_contracts"])
            md.append(f"| {name} | `{row['address']}` | {', '.join(row['checkpoints'])} | {row['runtime_bytes_set'][0]} |")
    md += ["", "Eight addresses have no exact match among these retained outputs. This does not show semantic difference, malicious behavior, unavailable source or a failed scientific case. The full compiler output and source-bearing metadata stay private; [runtime_match_table.json](runtime_match_table.json) records the complete candidate inventory and source-free match results.", "",
        "The 14 distinct addresses have 14 distinct observed full-runtime digests. All four addresses shared by the window endpoint enumerations return the same bytes at those two samples. For each of the 14 shared selectors with a changed facet address, its endpoint facet runtimes differ in full bytes. This strengthens the sampled identity distinction; different metadata alone can change full bytes, so execution-semantic difference and exact upgrade times are not inferred.", "",
        "## Preserved provider refusal", "",
        "The first fixed window query covered blocks **14,233,163–14,238,162**, exactly **5,000 inclusive blocks**. It returned HTTP 400 / JSON-RPC error 35 with the provider text `ranges over 10000 blocks are not supported on free plan`. The 113-byte response is retained. No event chunk completed and no event array was observed. The program stopped without retry, splitting, fallback or further queries. No nominal replay was performed.", "",
        "The earlier Phase12 10,000-block refusal remains unchanged. These two failures establish that the specific requests were refused; the text does not determine the provider's actual general range limit or explain the refusal. They are not zero-event observations, case exclusions or detector failures.", "",
        "## Relevant remaining work", "",
        "At the sampled checkpoints, the canonical `diamondCut` selector binds to exact-compiled DiamondCutFacet; `transferOwnership` binds to exact-compiled OwnershipFacet at both window endpoints. Their code can now support the already identified source-shaped mutation paths in LibDiamond. This does not establish interval authority, all writes, or absence of other reachable storage writers.", "",
        "Administrative history still requires a separately justified and frozen availability strategy. Future nonzero initializers or additional reached facets need explicit evidence. The eight unmatched addresses remain bounded source-binding candidates, including the endpoint CBridge successor. Do not assign its effective configuration from old namespace values alone or require unrelated unused helper contracts for fixed-address workload claims.", "",
        "**No complete historical routing, detector score or new independent case admission is claimed.** The scientific window, candidate order, methods and budgets are unchanged. [findings.json](findings.json) binds the exact acquisition and comparison artifacts.", ""]
    args.output.with_name("FINDINGS.md").write_text("\n".join(md))
    print(json.dumps({"findings_sha256": sha(args.output), "markdown_sha256": sha(args.output.with_name("FINDINGS.md")),
                      "new_unique_exact_address_bindings": len(result["new_exact_source_runtime_bound_unique_addresses"]),
                      "new_network_requests": 0, "new_compiler_invocations": 0}, indent=2))


if __name__ == "__main__":
    main()
