#!/usr/bin/env python3
"""Frozen admin-event discovery and source-guided raw checkpoint comparison.

No loupe calls, incident transactions, receipt/trace crawl or detector replay.
Provider proof values are not cryptographically verified. Enumerated arrays do
not establish absence of orphan mapping keys or unlogged initializer writes.
"""
import argparse
from collections import Counter
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re


MASK = 2**256 - 1
ADDRESS_MASK = 2**160 - 1


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def load_bound(path, expected):
    raw = path.read_bytes()
    if sha(raw) != expected:
        raise ValueError("Frozen input differs: " + path.name)
    return json.loads(raw)


def import_bound(name, path, expected):
    if sha(path.read_bytes()) != expected:
        raise ValueError("Frozen module differs: " + path.name)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GateStop(Exception):
    def __init__(self, detail, status="MALFORMED_OR_CONFLICTING_PROVIDER_EVIDENCE"):
        self.detail, self.status = detail, status
        super().__init__(detail)


def need(ok, detail, status="MALFORMED_OR_CONFLICTING_PROVIDER_EVIDENCE"):
    if not ok:
        raise GateStop(detail, status)


def hex_word(value):
    return "0x" + (value & MASK).to_bytes(32, "big").hex()


def storage_uint(value):
    need(isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]+", value) is not None, "Malformed storage integer")
    integer = int(value, 16)
    need(0 <= integer <= MASK, "Storage integer outside uint256")
    return integer


class PopulationBound:
    def __init__(self, caps):
        self.caps, self.facets, self.selectors = caps, set(), set()

    def add(self, facets=(), selectors=()):
        self.facets.update(f for f in facets if int(f, 16) != 0)
        self.selectors.update(selectors)
        need(len(self.facets) <= self.caps["max_facets"] and len(self.selectors) <= self.caps["max_selectors"],
             "Run-wide facet/selector discovery cap reached", "UNAVAILABLE_UNDER_FROZEN_CAP")


class StateReader:
    def __init__(self, runner, plan, layout, hash_fn, codec, population, output):
        self.runner, self.plan, self.layout, self.hash_fn = runner, plan, layout, hash_fn
        self.codec, self.population, self.output = codec, population, output
        self.keys_requested = 0

    def hash_slot(self, number):
        return int.from_bytes(self.hash_fn((number & MASK).to_bytes(32, "big")), "big")

    def map_slot(self, key, base):
        need(len(key) == 32, "Mapping key width")
        return int.from_bytes(self.hash_fn(key + (base & MASK).to_bytes(32, "big")), "big")

    def checkpoint(self, checkpoint):
        name, block = checkpoint["name"], checkpoint["block_number"]
        caps, target = self.plan["caps"], self.plan["diamond"]
        result = {"name": name, "block_number": block, "block_hash": checkpoint["block_hash"],
                  "raw_words": {}, "proof_requests": 0, "storage_keys_requested": 0,
                  "proofs_cryptographically_verified": False, "selector_mapping_exhaustive": False}
        fingerprint = None

        def slots(keys, stage):
            nonlocal fingerprint
            keys = [x & MASK for x in keys]
            need(len(keys) == len(set(keys)), "Duplicate derived requested slot")
            keys.sort()
            values = {}
            for offset in range(0, len(keys), caps["proof_keys_per_request"]):
                group = keys[offset:offset + caps["proof_keys_per_request"]]
                need(self.keys_requested + len(group) <= caps["storage_keys_requested_total"], "Total requested storage-key cap", "UNAVAILABLE_UNDER_FROZEN_CAP")
                before = self.runner.rpc_calls
                try:
                    body = self.runner.rpc(name + "_" + stage + "_" + str(offset), "eth_getProof",
                                           [target, [hex_word(x) for x in group], hex(block)])
                finally:
                    if self.runner.rpc_calls > before:
                        self.keys_requested += len(group)
                        result["storage_keys_requested"] += len(group)
                        result["proof_requests"] += 1
                        save(self.output / ("state_" + name + "_partial.json"), result)
                need(isinstance(body, dict) and body.get("address", "").lower() == target, "Proof account address differs")
                code_hash = "0x" + self.codec.hx(body.get("codeHash"), 32).hex()
                storage_hash = "0x" + self.codec.hx(body.get("storageHash"), 32).hex()
                need(code_hash == self.plan["expected_diamond_code_hash"], "Returned proof codeHash differs from compiled target")
                current = {"code_hash": code_hash, "storage_hash": storage_hash,
                           "balance": str(storage_uint(body.get("balance"))), "nonce": str(storage_uint(body.get("nonce")))}
                need(fingerprint is None or fingerprint == current, "Account fields changed between same-checkpoint proof batches")
                fingerprint = current
                account_proof = body.get("accountProof")
                need(isinstance(account_proof, list) and bool(account_proof), "Missing account proof nodes")
                for node in account_proof:
                    need(bool(self.codec.hx(node)), "Empty account proof node")
                entries = body.get("storageProof")
                need(isinstance(entries, list), "Missing storage proof entries")
                batch = {}
                for item in entries:
                    need(isinstance(item, dict), "Malformed storage proof entry")
                    key, value = storage_uint(item.get("key")), storage_uint(item.get("value"))
                    need(key not in batch, "Duplicate normalized proof key")
                    nodes = item.get("proof")
                    need(isinstance(nodes, list), "Missing storage proof node array")
                    for node in nodes:
                        need(bool(self.codec.hx(node)), "Empty storage proof node")
                    batch[key] = value
                need(set(batch) == set(group), "Missing or extra normalized proof keys")
                for key, value in batch.items():
                    label = hex_word(key)
                    need(label not in result["raw_words"] or result["raw_words"][label] == hex_word(value), "Repeated slot value changed")
                    result["raw_words"][label] = hex_word(value)
                values.update(batch)
                result["account_fields"] = current
                save(self.output / ("state_" + name + "_partial.json"), result)
            return values

        diamond_root = storage_uint(self.layout["diamond_namespace_hex"])
        bridge_root = storage_uint(self.layout["cbridge_namespace_hex"])
        fields = self.layout["diamond_fields"]
        owner_slot = (diamond_root + fields["owner"]) & MASK
        facet_array_slot = (diamond_root + fields["facet_addresses"]) & MASK
        basics = slots([owner_slot, facet_array_slot, bridge_root], "base")
        count = basics[facet_array_slot]
        need(count <= caps["max_facets"], "Checkpoint facet cap reached", "UNAVAILABLE_UNDER_FROZEN_CAP")
        owner_word, bridge_word = basics[owner_slot], basics[bridge_root]
        owner = "0x" + (owner_word & ADDRESS_MASK).to_bytes(20, "big").hex()
        result.update(owner=owner, owner_unused_high_bits=hex(owner_word >> 160),
                      source_guided_cbridge_fields={"bridge": "0x" + (bridge_word & ADDRESS_MASK).to_bytes(20, "big").hex(),
                          "chain_id": (bridge_word >> 160) & (2**64 - 1), "undeclared_high_bits": hex(bridge_word >> 224),
                          "effective_configuration_proved": False}, facet_count=count)
        array_base = self.hash_slot(facet_array_slot)
        array_keys = [(array_base + i) & MASK for i in range(count)]
        address_words = slots(array_keys, "facet_array")
        facets = ["0x" + (address_words[key] & ADDRESS_MASK).to_bytes(20, "big").hex() for key in array_keys]
        need(len(set(facets)) == len(facets) and all(int(x, 16) != 0 for x in facets), "Facet array duplicate/zero entry")
        self.population.add(facets=facets)
        facet_bases = {address: self.map_slot(bytes(12) + self.codec.hx(address, 20), diamond_root + fields["facet_mapping"])
                       for address in facets}
        length_keys = [base for base in facet_bases.values()]
        position_keys = [(base + 1) & MASK for base in facet_bases.values()]
        meta = slots(length_keys + position_keys, "facet_metadata")
        lengths = {address: meta[base] for address, base in facet_bases.items()}
        need(all(0 < n <= caps["max_selectors"] for n in lengths.values()), "Facet selector length empty/outside cap", "UNAVAILABLE_UNDER_FROZEN_CAP")
        total = sum(lengths.values())
        need(total <= caps["max_selectors"], "Total checkpoint selector cap", "UNAVAILABLE_UNDER_FROZEN_CAP")
        for index, address in enumerate(facets):
            need(meta[(facet_bases[address] + 1) & MASK] == index, "Facet array/position backreference differs")
        packed_keys = {address: [(self.hash_slot(facet_bases[address]) + j) & MASK for j in range((lengths[address] + 7) // 8)]
                       for address in facets}
        packed = slots([key for address in facets for key in packed_keys[address]], "selector_arrays")
        by_facet = {}
        for address in facets:
            by_facet[address] = ["0x" + ((packed[packed_keys[address][i // 8]] >> (32 * (i % 8))) & (2**32 - 1)).to_bytes(4, "big").hex()
                                 for i in range(lengths[address])]
        selectors = [selector for address in facets for selector in by_facet[address]]
        need(len(set(selectors)) == total, "Selector arrays contain duplicate selectors")
        self.population.add(selectors=selectors)
        selector_keys = {selector: self.map_slot(self.codec.hx(selector, 4) + bytes(28), diamond_root + fields["selector_mapping"])
                         for selector in selectors}
        mapping = slots(list(selector_keys.values()), "selector_mapping")
        selector_map = {}
        for address in facets:
            for index, selector in enumerate(by_facet[address]):
                value = mapping[selector_keys[selector]]
                decoded = {"facet": "0x" + (value & ADDRESS_MASK).to_bytes(20, "big").hex(), "selector_position": value >> 160}
                need(decoded == {"facet": address, "selector_position": index}, "Selector inverse mapping differs from enumerated arrays")
                selector_map[selector] = decoded
        result.update(facets=[{"address": address, "facet_position": index, "selectors": by_facet[address],
                              "address_array_unused_high_bits": hex(address_words[array_keys[index]] >> 160),
                              "selector_tail_unused_bits": hex(packed[packed_keys[address][-1]] >> (32 * (((lengths[address] - 1) % 8) + 1)))}
                             for index, address in enumerate(facets)], selector_count=total, selector_map=dict(sorted(selector_map.items())),
                      status="ENUMERATED_ARRAYS_AND_BACKREFERENCES_CONSISTENT")
        save(self.output / ("state_" + name + ".json"), result)
        return result


def main():
    parser = argparse.ArgumentParser()
    for name in ("plan", "layout", "layout-review", "bootstrap", "historical-summary", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--accepted-plan-sha256", required=True)
    parser.add_argument("--accepted-runner-sha256", required=True)
    args = parser.parse_args()
    plan = load_bound(args.plan, args.accepted_plan_sha256)
    need(sha(Path(__file__).read_bytes()) == args.accepted_runner_sha256, "Accepted runner digest differs")
    need(plan["schema_version"] == "article2_phase12_lifi_admin_event_checkpoint_plan_v1", "Wrong plan schema")
    paper = Path(__file__).resolve().parents[2]
    source = plan["source_bindings"]
    codec = import_bound("frozen_admin_codec", Path(__file__).with_name("admin_event_codec.py"), source["event_codec_sha256"])
    transport = import_bound("frozen_transport", paper / "phase10/lifi_gate/capture_factory_continuation.py", source["transport_module_sha256"])
    primitive = import_bound("frozen_slot_hash", paper / "phase9/revest_gate/revest_gate_primitives.py", source["keccak_module_sha256"])
    layout = load_bound(args.layout, plan["verified_layout_spec_sha256"])
    review = load_bound(args.layout_review, plan["independent_layout_review_sha256"])
    need(review["status"] == plan["independent_layout_review_status"]
         and review["producer_result_sha256"] == plan["verified_layout_spec_sha256"], "Independent layout review not accepted/bound")
    scope = load_bound(paper / "phase12/scope_review/admission_scope_review.json", source["admission_scope_review_sha256"])
    need(scope["status"] == "RETAIN_ACCEPTED_ROUTING_POPULATION_SCOPE_BOUNDED_DISCOVERY_ONLY"
         and scope["current_disposition"]["retain_accepted_routing_population_scope"] is True
         and scope["current_disposition"]["automatic_fixed_emitter_fallback"] is False,
         "Accepted scientific discovery scope differs")
    compilation = load_bound(paper / "phase11/compilation/compilation_results.json", source["phase11_compilation_results_sha256"])
    need(compilation["all_exact"] is True, "Exact target compilation not established")
    bootstrap = load_bound(args.bootstrap, source["phase11_bootstrap_results_sha256"])
    historical = load_bound(args.historical_summary, source["phase10_factory_summary_sha256"])
    need(layout["delegated_storage_context"]["address"] == plan["diamond"], "Namespace storage context differs")
    need(layout["diamond_namespace_hex"] == "0x" + primitive.keccak256(b"diamond.standard.diamond.storage").hex()
         and layout["cbridge_namespace_hex"] == "0x" + primitive.keccak256(b"com.lifi.facets.cbridge2").hex(), "Namespace hash differs")
    need(layout["diamond_fields"] == {"selector_mapping": 0, "facet_mapping": 1, "facet_addresses": 2, "supported_interfaces": 3, "owner": 4}, "Unexpected verified namespace offsets")
    need(layout["selector_mapping_value"] == {"facet_address": {"byte_offset": 0, "bytes": 20}, "selector_position": {"byte_offset": 20, "bytes": 12}}, "Unexpected verified selector packing")
    need(layout["facet_struct"] == {"selectors_length_slot": 0, "facet_position_slot": 1}, "Unexpected verified facet struct")
    need(layout["bytes4_array"]["elements_per_word"] == 8 and layout["bytes4_array"]["element_bytes"] == 4
         and layout["address_array"]["elements_per_word"] == 1 and layout["address_array"]["element_bytes"] == 20
         and layout["address_array"]["bit_offset"] == 0, "Unexpected array packing")
    need(layout["cbridge_word"] == {"bridge": {"byte_offset": 0, "bytes": 20}, "chain_id": {"byte_offset": 20, "bytes": 8}, "undeclared_high_bytes": 4}, "Unexpected CBridge packing")
    topic_to_name = {}
    for event in plan["events"]:
        entry = next(x for x in layout["events"] if x["name"] == event["name"])
        topic = "0x" + primitive.keccak256(event["signature"].encode()).hex()
        need(topic == event["topic0"] == entry["topic0"] and entry["signature"] == event["signature"]
             and [x["indexed"] for x in entry["fields"]] == event["indexed"], "Verified event ABI binding differs")
        topic_to_name[topic] = event["name"]
    need(bootstrap["status"] == "PASS_ACTUAL_CONSTRUCTOR_RECEIPT_CHECK", "Bootstrap was not verified")
    diamond_history = next(x for x in historical["contracts"] if x["role"] == "diamond")
    need(diamond_history["address"] == plan["diamond"], "Historical target differs")
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "frozen_plan.json").write_bytes(args.plan.read_bytes())
    (args.output / "runner_source.py").write_bytes(Path(__file__).read_bytes())
    (args.output / "codec_source.py").write_bytes(Path(__file__).with_name("admin_event_codec.py").read_bytes())
    save(args.output / "acceptance.json", {"started_utc": transport.stamp(), "plan_sha256": args.accepted_plan_sha256,
        "runner_sha256": args.accepted_runner_sha256, "layout_sha256": plan["verified_layout_spec_sha256"],
        "independent_layout_review_sha256": plan["independent_layout_review_sha256"], "codec_sha256": source["event_codec_sha256"]})
    runner = transport.Capture(plan, args.output)
    population = PopulationBound(plan["caps"])
    reader = StateReader(runner, plan, layout, primitive.keccak256, codec, population, args.output)
    result = {"schema_version": "article2_phase12_lifi_admin_checkpoint_result_v1", "plan_sha256": args.accepted_plan_sha256,
              "runner_sha256": args.accepted_runner_sha256, "headers": {}, "events": [], "states": [], "comparisons": [],
              "completed_log_chunks": 0, "new_incident_transaction_payloads": 0, "detector_scores": 0,
              "scientific_admissions": 0, "historical_routing_proved": False, "proofs_cryptographically_verified": False,
              "index_completeness_proved": False, "orphan_mapping_keys_excluded": False}
    try:
        need(runner.rpc("chain", "eth_chainId", []) == "0x1", "Provider chain identity differs")
        for checkpoint in plan["checkpoints"]:
            number = checkpoint["block_number"]
            body = runner.rpc("header_" + checkpoint["name"], "eth_getBlockByNumber", [hex(number), False])
            need(isinstance(body, dict) and transport.quantity(body.get("number")) == number
                 and "0x" + codec.hx(body.get("hash"), 32).hex() == checkpoint["block_hash"]
                 and transport.quantity(body.get("timestamp")) == transport.utc_seconds(checkpoint["timestamp_utc"]), "Checkpoint header differs from retained history")
            need(isinstance(body.get("transactions"), list), "Checkpoint transaction hash list missing")
            transactions = ["0x" + codec.hx(x, 32).hex() for x in body["transactions"]]
            result["headers"][checkpoint["name"]] = {"number": number, "hash": checkpoint["block_hash"],
                "state_root": "0x" + codec.hx(body.get("stateRoot"), 32).hex(), "timestamp_utc": checkpoint["timestamp_utc"],
                "transaction_hashes": transactions}
        creation_header_hashes = result["headers"]["creation"]["transaction_hashes"]
        need(creation_header_hashes.count(diamond_history["creation_tx"]) == 1, "Unique nominated creation transaction absent from header")
        creation_position = creation_header_hashes.index(diamond_history["creation_tx"])
        log_ids, block_hashes, tx_positions, tx_contexts = set(), {}, {}, {}
        for index, chunk in enumerate(plan["event_range"]["chunks"]):
            logs = runner.rpc("admin_logs_" + str(index), "eth_getLogs", [{"fromBlock": hex(chunk["from_block"]),
                    "toBlock": hex(chunk["to_block"]), "address": plan["diamond"], "topics": [list(topic_to_name)]}])
            need(isinstance(logs, list), "Log query did not return array")
            need(len(result["events"]) + len(logs) <= plan["caps"]["max_event_logs"], "Administrative log cap", "UNAVAILABLE_UNDER_FROZEN_CAP")
            for log in logs:
                need(isinstance(log, dict) and log.get("removed") is False
                     and "0x" + codec.hx(log.get("address"), 20).hex() == plan["diamond"], "Log emitter/removed state differs")
                block, position, log_index = (transport.quantity(log.get(k)) for k in ("blockNumber", "transactionIndex", "logIndex"))
                block_hash, tx_hash = ("0x" + codec.hx(log.get(k), 32).hex() for k in ("blockHash", "transactionHash"))
                need(chunk["from_block"] <= block <= chunk["to_block"], "Log outside requested chunk")
                need((block, log_index) not in log_ids, "Duplicate block log index")
                log_ids.add((block, log_index))
                need(block not in block_hashes or block_hashes[block] == block_hash, "Conflicting log block hash")
                block_hashes[block] = block_hash
                need((block, position) not in tx_positions or tx_positions[(block, position)] == tx_hash, "Conflicting transaction position")
                tx_positions[(block, position)] = tx_hash
                context = (block, block_hash, position)
                need(tx_hash not in tx_contexts or tx_contexts[tx_hash] == context, "Transaction hash appears at conflicting block/position")
                tx_contexts[tx_hash] = context
                for header in result["headers"].values():
                    if header["number"] == block:
                        need(header["hash"] == block_hash and position < len(header["transaction_hashes"])
                             and header["transaction_hashes"][position] == tx_hash, "Log differs from retained checkpoint header")
                decoded = codec.decode_event(log.get("topics"), log.get("data"), topic_to_name, plan["caps"])
                if decoded["event"] == "DiamondCut":
                    population.add(facets=[x["facet"] for x in decoded["cuts"]],
                                   selectors=[s for x in decoded["cuts"] for s in x["selectors"]])
                result["events"].append({"block_number": block, "block_hash": block_hash, "transaction_index": position,
                    "transaction_hash": tx_hash, "log_index": log_index, "chunk_index": index,
                    "raw_data_sha256": sha(codec.hx(log["data"])), "decoded": decoded})
            result["completed_log_chunks"] += 1
            save(args.output / "progress.json", result)
        result["events"].sort(key=lambda x: (x["block_number"], x["transaction_index"], x["log_index"]))
        previous_by_block = {}
        for row in result["events"]:
            block = row["block_number"]
            need(row["log_index"] > previous_by_block.get(block, -1), "Transaction ordering conflicts with block log ordering")
            previous_by_block[block] = row["log_index"]
        creation_events = [x for x in result["events"] if x["transaction_hash"] == diamond_history["creation_tx"]]
        expected_owner = {"event": "OwnershipTransferred", "previous_owner": codec.ZERO, "new_owner": bootstrap["owner_at_constructor"]}
        expected_cut = {"event": "DiamondCut", "cuts": [{"facet": bootstrap["initial_diamond_cut_facet"], "action": 0,
                         "selectors": [bootstrap["diamond_cut_selector"]]}], "initializer": codec.ZERO,
                        "initializer_calldata": "0x", "initializer_effects_unclosed": False}
        result["bootstrap_logs_match_retained_receipt"] = (len(creation_events) == 2
            and all(x["block_number"] == diamond_history["creation_block"]
                    and x["block_hash"] == diamond_history["creation_block_hash"]
                    and x["transaction_index"] == creation_position for x in creation_events)
            and [x["log_index"] for x in creation_events] == [bootstrap["ownership_log_index"], bootstrap["cut_log_index"]]
            and [x["decoded"] for x in creation_events] == [expected_owner, expected_cut])
        nominal = codec.EventImpliedRegistry(plan["diamond"], plan["caps"]["max_facets"], plan["caps"]["max_selectors"])
        replay, consumed, replay_error = {}, 0, None
        for checkpoint in plan["checkpoints"]:
            while consumed < len(result["events"]) and result["events"][consumed]["block_number"] <= checkpoint["block_number"]:
                row = result["events"][consumed]
                if replay_error is None:
                    trial = copy.deepcopy(nominal)
                    try:
                        trial.apply(row["decoded"])
                        nominal = trial
                    except ValueError as exc:
                        replay_error = {"event_index": consumed, "block_number": row["block_number"],
                                        "log_index": row["log_index"], "detail": str(exc)}
                consumed += 1
            replay[checkpoint["name"]] = nominal.snapshot() if replay_error is None else None
        result["nominal_replay"] = replay
        result["nominal_replay_error"] = replay_error
        save(args.output / "progress.json", result)
        # This schedule is independent of nominal fold or bootstrap agreement.
        for checkpoint in plan["checkpoints"]:
            state = reader.checkpoint(checkpoint)
            result["states"].append(state)
            nominal_state = replay[checkpoint["name"]]
            projection = {"owner": state["owner"], "facets": [{k: x[k] for k in ("address", "facet_position", "selectors")} for x in state["facets"]],
                          "selector_map": state["selector_map"]}
            result["comparisons"].append({"checkpoint": checkpoint["name"], "nominal_replay_available": nominal_state is not None,
                "owner_equal": nominal_state is not None and nominal_state["owner"] == projection["owner"],
                "facet_array_equal": nominal_state is not None and nominal_state["facets"] == projection["facets"],
                "selector_mapping_equal": nominal_state is not None and nominal_state["selector_map"] == projection["selector_map"],
                "cbridge_event_replay_attempted": False})
            save(args.output / "progress.json", result)
        matched = result["bootstrap_logs_match_retained_receipt"] and all(x["owner_equal"] and x["facet_array_equal"] and x["selector_mapping_equal"] for x in result["comparisons"])
        result["disposition"] = ("EVENT_REPLAY_SEMANTICS_UNRESOLVED" if replay_error else
            "EVENT_AND_CHECKPOINT_CONSISTENCY_ROUTING_UNRESOLVED" if matched else "EVENT_CHECKPOINT_MISMATCH_UNRESOLVED")
    except GateStop as exc:
        result.update(disposition=exc.status, detail=exc.detail)
    except transport.Stop as exc:
        result.update(disposition="UNAVAILABLE_UNDER_FROZEN_CAP", detail=str(exc))
    except Exception as exc:
        result.update(disposition="MALFORMED_OR_CONFLICTING_PROVIDER_EVIDENCE", detail=type(exc).__name__ + ": " + str(exc))
    finally:
        result.update(completed_utc=transport.stamp(), rpc_methods=runner.rpc_calls, retained_response_bytes=runner.bytes,
            storage_keys_requested=reader.keys_requested, enumerated_checkpoint_count=len(result["states"]),
            discovered_nonzero_facets=sorted(population.facets), discovered_selectors=sorted(population.selectors),
            event_type_counts=dict(Counter(x["decoded"]["event"] for x in result["events"])),
            observed_nonzero_initializer_addresses=sorted({x["decoded"]["initializer"] for x in result["events"]
                if x["decoded"]["event"] == "DiamondCut" and x["decoded"]["initializer"] != codec.ZERO}),
            achieved_evidence_tier="provider_admin_events_and_enumerated_checkpoint_arrays" if len(result["states"]) == 3
                else "partial_provider_event_or_checkpoint_observations",
            planned_evidence_tier="provider_admin_events_and_enumerated_checkpoint_arrays",
            nonzero_initializer_event_count=sum(x["decoded"].get("initializer_effects_unclosed", False) for x in result["events"]))
        save(args.output / "summary.json", result)
    print(json.dumps({k: v for k, v in result.items() if k not in {"headers", "events", "states", "nominal_replay", "discovered_selectors"}}, indent=2))


if __name__ == "__main__":
    main()
