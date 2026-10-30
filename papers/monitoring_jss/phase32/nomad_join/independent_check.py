#!/usr/bin/env python3
"""Offline independent Nomad check; deliberately does not import verify_join.py.

Recompute count windows by direct quadratic summation, then grouping and daily
greedy allocation. Verify retained source bytes and documentary membership.
--check compares the regenerated report byte for byte without writing it.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
PAPER = HERE.parent.parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    data = path.read_bytes()
    return json.loads(gzip.decompress(data) if path.suffix == ".gz" else data)


def read_jsonl(path):
    return [json.loads(line) for line in gzip.decompress(path.read_bytes()).splitlines()]


def tx(row):
    return row["transaction"]["transaction_hash"].lower()


def timestamp(row):
    return row["transaction"]["event_time_ns"]


def iso(row):
    return datetime.fromtimestamp(timestamp(row) // 10**9, timezone.utc).isoformat()


def calculate():
    protocol = read_json(HERE / "PROTOCOL.json")
    core = protocol["core_address"].lower()
    for name, expected in protocol["baseline_inputs_sha256"].items():
        require(hashlib.sha256((PAPER / name).read_bytes()).hexdigest() == expected,
                "Baseline SHA256 mismatch: " + name)
    source = HERE / "sources"
    identity = read_json(source / "source_identity.json")
    require(identity["commit"] == protocol["source_commit"], "Source commit mismatch")
    for item in identity["files"]:
        path = source / item["local"]
        retained = path.read_bytes()
        original = gzip.decompress(retained) if path.suffix == ".gz" else retained
        require(hashlib.sha256(retained).hexdigest() == item["retained_sha256"],
                "Retained source SHA256 mismatch: " + item["local"])
        require(hashlib.sha256(original).hexdigest() == item["source_sha256"],
                "Original source SHA256 mismatch: " + item["local"])
        require(len(original) == item["size"], "Source byte length mismatch")
        git_bytes = ("blob " + str(len(original)) + "\0").encode() + original
        require(hashlib.sha1(git_bytes).hexdigest() == item["sha"],
                "Original Git blob mismatch: " + item["local"])

    base = PAPER / "phase31/nomad"
    observations = read_jsonl(base / "data_attempt3/observations.jsonl.gz")
    bundles = read_jsonl(base / "data_attempt3/raw_selected_bundles.jsonl.gz")
    keys = [(r["transaction"]["block_number"],
             r["transaction"]["transaction_index"]) for r in observations]
    require(keys == sorted(keys), "Observation order is not chain order")
    by_hash = {tx(r): r for r in observations}
    raw_by_hash = {tx(r): r for r in bundles}
    require(len(by_hash) == len(observations), "Duplicate selected transaction")
    require(set(by_hash) == set(raw_by_hash), "Observation/raw transaction mismatch")
    times = [timestamp(r) for r in observations]
    require(times == sorted(times), "Nonmonotone timestamps")
    weights = []
    for row in observations:
        bundle = raw_by_hash[tx(row)]
        require(row["transaction"] == bundle["transaction"], "Transaction metadata mismatch")
        n = sum(event["address"].lower() == core for event in bundle["events"])
        require(n == row["core_log_counts"]["fixed_core"], "Core event count mismatch")
        weights.append(n)

    # Independent direct summation, not a deque/sliding-window implementation.
    count_traces = [r for r in read_json(base / "results/method_traces.json")
                    if r["method"] == "core_count_60s_10"]
    require(len(count_traces) == len(observations), "Unexpected count trace cardinality")
    trace_by_hash = {r["tx"]: r for r in count_traces}
    groups, emitted, rejected = [], [], []
    raw_triggers = 0
    last_group, daily_sent = {}, Counter()
    for i, row in enumerate(observations):
        day = row["day_utc"]
        t = times[i]
        total = sum(weights[j] for j in range(i + 1)
                    if times[j] > t - 60 * 10**9
                    and observations[j]["day_utc"] == day)
        trigger = total >= 10
        candidate = trigger and (day not in last_group or t - last_group[day] >= 300 * 10**9)
        raw_triggers += trigger
        trace = trace_by_hash[tx(row)]
        require(trace["time_ns"] == t and trace["day"] == day, "Trace metadata mismatch")
        require(trace["raw_trigger"] == trigger, "Raw count trigger mismatch: " + tx(row))
        require(trace["group_candidate"] == candidate, "Group candidate mismatch: " + tx(row))
        if candidate:
            groups.append(row)
            last_group[day] = t
            if daily_sent[day] < 5:
                emitted.append(row)
                daily_sent[day] += 1
            else:
                rejected.append(row)

    replay = read_json(base / "results/label_blind_replay.json")
    cells = [r for r in replay["case_score_rows"]
             if r["method"] == "core_count_60s_10" and r["policy"] == "greedy"]
    for budget in (5, 20):
        matches = [r for r in cells if r["B"] == budget]
        require(len(matches) == 1, "Nonunique replay cell")
        cell = matches[0]
        expected = emitted if budget == 5 else groups
        require(cell["notified_transactions"] == [tx(r) for r in expected], "Dispatch sequence mismatch")
        require(cell["raw_triggers"] == raw_triggers and cell["group_candidates"] == len(groups),
                "Replay count mismatch")
        require(cell["notifications"] == len(expected), "Replay notification mismatch")
        require(cell["suppression_due_to_budget"] == len(groups) - len(expected), "Suppression mismatch")

    hash_list = [h.lower() for h in read_json(source / "transaction_hashes.json")]
    public = set(hash_list)
    require(len(public) == len(hash_list), "Duplicate documentary transaction hash")
    events = read_json(source / "process_events.json.gz")
    unique = {}
    duplicates = 0
    for event in events:
        key = (event["transactionHash"].lower(), event["logIndex"])
        stripped = {k: v for k, v in event.items() if k != "index"}
        if key in unique:
            require(stripped == {k: v for k, v in unique[key].items() if k != "index"},
                    "Conflicting duplicated Process event")
            duplicates += 1
        else:
            unique[key] = event
    require({k[0] for k in unique} == public, "Source events/hash list mismatch")
    fixed = {h for (h, _), e in unique.items() if e["contractAddress"].lower() == core}
    selected = set(by_hash)
    shared = public & selected
    other = public - fixed
    later = fixed - selected
    require(not (other & selected), "Other-Replica-only hash unexpectedly selected")
    require(public == shared | other | later, "Nonexhaustive source partition")
    end_block = max(r["transaction"]["block_number"] for r in observations)
    require(all(e["blockNumber"] > end_block for (h, _), e in unique.items()
                if h in later and e["contractAddress"].lower() == core),
            "Unselected fixed-Replica source event is not later than captured stream")

    event_matches = 0
    for (h, index), event in unique.items():
        if h not in selected:
            continue
        matches = [e for e in raw_by_hash[h]["events"] if e["log_index"] == index]
        require(len(matches) == 1, "Nonunique retained Process log")
        raw = matches[0]
        for source_field, raw_field in (("contractAddress", "address"), ("blockHash", "block_hash"),
                                      ("blockNumber", "block_number"), ("transactionIndex", "transaction_index"),
                                      ("transactionHash", "transaction_hash"), ("logIndex", "log_index"),
                                      ("data", "data")):
            a, b = event[source_field], raw[raw_field]
            require((a.lower() if isinstance(a, str) else a) == b, "Process metadata mismatch")
        require(raw["topics"] == [
            "0xd42de95a9b26f1be134c8ecce389dc4fcfa18753d01661b7b361233569e8fe48",
            event["messageHash"].lower(), "0x" + format(event["success"], "064x"),
            event["returnData"].lower()], "Process indexed fields mismatch")
        event_matches += 1
    require(event_matches == len(shared), "Shared source transactions do not have one matched Process each")
    require(all(tx(r) in public for r in groups), "Count candidate absent from source list")
    first = min((by_hash[h] for h in shared), key=lambda r: (timestamp(r), r["transaction"]["transaction_index"]))
    first_source = min(unique.values(), key=lambda e: (e["blockNumber"], e["transactionIndex"], e["logIndex"]))
    require(tx(first) == first_source["transactionHash"].lower(), "First source transaction not captured")

    return {
        "status": "PASS",
        "method": "Separate direct O(n^2) rolling count, explicit grouping/cap simulation, source-byte hashes and reference partition checks; no import of verify_join.py.",
        "selected_transactions": len(observations),
        "public_hashes": len(public),
        "selected_public_matches": len(shared),
        "other_replica_only_hashes": len(other),
        "same_replica_later_hashes": len(later),
        "public_process_event_rows": len(events),
        "unique_process_events": len(unique),
        "duplicate_rows_differing_only_in_export_index": duplicates,
        "raw_count_triggers": raw_triggers,
        "grouped_count_candidates": len(groups),
        "listed_count_candidates": sum(tx(r) in public for r in groups),
        "greedy_B5_notifications": len(emitted),
        "greedy_B5_hard_cap_rejections": len(rejected),
        "timing": {"first_listed": iso(first), "first_group": iso(groups[0]),
                   "cap_exhaustion": iso(emitted[-1]), "first_rejection": iso(rejected[0])},
        "network_requests": 0,
        "scope": "Independent check of exact documentary membership, no malicious-intent or exhaustive incident ground truth claim.",
        "matching_unique_protocol_Process_events": event_matches,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Compare bytes without writing")
    parser.add_argument("--out", type=Path, default=HERE / "INDEPENDENT_CHECK.json")
    args = parser.parse_args()
    result = (json.dumps(calculate(), indent=2) + "\n").encode()
    if args.check:
        require(args.out.read_bytes() == result, "Regenerated independent report differs: " + str(args.out))
        print("PASS: independent report regenerated byte-identically; no network requests")
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(result)
        print("Wrote " + str(args.out))


if __name__ == "__main__":
    main()
