"""Independent offline audit of Phase16 projected source bytes and selection.

This reviewer does not import the streaming producer or its validation methods.
It re-reads authenticated Parquet projections, checks every declared part and
row group, reconstructs address-selected TXs and all-emitter raw bundles, and
compares exact prepared output. Transfer shapes and detector scores are not
decoded. A separate original-byte transport audit is mandatory before reading.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from datetime import date, timedelta, datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

PAPER = Path(__file__).resolve().parents[2]
REPO = PAPER.parents[1]
sys.path.insert(0, str(PAPER / "phase15" / "adapter"))
sys.path.insert(0, str(PAPER / "phase15" / "driver"))
import retained_observation_core as frozen_core
import fixed_address_replay as frozen_driver

DAY_NS = 86_400_000_000_000
RAW = {
    "blocks": ["number", "hash", "parent_hash", "timestamp", "transaction_count"],
    "transactions": ["hash", "transaction_index", "block_hash", "block_number", "block_timestamp", "receipt_status"],
    "logs": ["address", "transaction_index", "log_index", "transaction_hash", "block_number", "block_hash", "block_timestamp"],
}
RENAMES = {
    "blocks": {"number": "block_number", "hash": "block_hash", "timestamp": "event_time_ns"},
    "transactions": {"hash": "transaction_hash", "block_timestamp": "event_time_ns", "receipt_status": "dataset_execution_status"},
    "logs": {"block_timestamp": "event_time_ns"},
}
INTEGER_FIELDS = {"block_number", "transaction_index", "log_index", "transaction_count", "dataset_execution_status"}
FROZEN = {
    "phase15/adapter/retained_observation_core.py": "63119a14c1f3fb5a2cf74f24f918181679611633e6e75df63b5dc6b7180ef662",
    "phase15/driver/fixed_address_replay.py": "591a8e09cd1920496ad0acc8fb13a1f4c62a0a224b3d8925ec364fff91ed293d",
    "transfer_observation.py": "eb905fdbdc44033424066e4baebbbc1f6724bd68bd9e0573676f39e4908f429c",
}


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def value_sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(4 * 1024**2), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path):
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, "duplicate JSON field")
            result[k] = v
        return result
    return json.loads(Path(path).read_bytes(), object_pairs_hook=pairs)


def bound(path, expected):
    require(file_sha(path) == expected, "bound bytes differ: " + str(path))
    return read_json(path)


def write(path, value):
    Path(path).write_bytes(canonical(value) + b"\n")
    return file_sha(path)


def days(start, end):
    first, last = date.fromisoformat(start), date.fromisoformat(end)
    return [(first + timedelta(days=i)).isoformat() for i in range((last - first).days)]


def midnight(day):
    return (date.fromisoformat(day) - date(1970, 1, 1)).days * DAY_NS


def all_true(array, pc):
    return array.null_count == 0 and (len(array) == 0 or pc.all(array).as_py() is True)


def normalized(table, kind, pa, pc):
    require(set(RAW[kind]) <= set(table.column_names), "required projection absent")
    output = {}
    for source_name in RAW[kind]:
        name = RENAMES[kind].get(source_name, source_name)
        column = table[source_name]
        require(column.null_count == 0, "null required column: " + source_name)
        if name == "event_time_ns":
            require(pa.types.is_timestamp(column.type) and column.type.unit in ("s", "ms", "us", "ns")
                    and column.type.tz in (None, "UTC"), "unsupported source time")
            column = pc.cast(pc.cast(column, pa.timestamp("ns", tz=column.type.tz)), pa.int64())
            require(all_true(pc.greater_equal(column, 0), pc), "negative source time")
        elif name in INTEGER_FIELDS:
            require(pa.types.is_int64(column.type), "non-int64 field: " + name)
            require(all_true(pc.greater_equal(column, 0), pc), "negative source integer")
        else:
            length = 40 if name == "address" else 64
            require(pa.types.is_string(column.type), "nonstring identity")
            require(all_true(pc.match_substring_regex(column, "^0x[0-9a-fA-F]{" + str(length) + "}$"), pc),
                    "invalid source identity")
            column = pc.utf8_lower(column)
        output[name] = column
    return pa.table(output)


def covered(start, end, spans):
    cursor = start
    for lo, hi in sorted(spans):
        if lo <= cursor < hi:
            cursor = hi
        if cursor >= end:
            return True
    return cursor >= end


class OfflineSource:
    def __init__(self, source, manifest, transport, pa, pq):
        identity = {k: source[k] for k in ("table", "day_utc", "key", "size_bytes", "etag_opaque", "url")}
        self.source, self.manifest, self.transport = identity, manifest, transport
        self.path = Path(transport["path"])
        require(identity == manifest["source"], "source manifest does not match frozen inventory")
        require(source["key"] == transport["source_key"], "transport source identity differs")
        require(self.path.stat().st_size == source["size_bytes"], "source logical size differs")
        self.spans = transport["available_ranges"]
        size = source["size_bytes"]
        require(covered(0, 4, self.spans) and covered(size - 8, size, self.spans), "unverified Parquet envelope")
        with self.path.open("rb") as f:
            require(f.read(4) == b"PAR1", "leading magic differs")
            f.seek(size - 8)
            trailer = f.read(8)
        require(trailer[4:] == b"PAR1", "trailing magic differs")
        self.footer_start = size - 8 - int.from_bytes(trailer[:4], "little")
        require(4 <= self.footer_start < size - 8 and covered(self.footer_start, size, self.spans), "unverified footer")
        self.file = pq.ParquetFile(self.path)
        self.metadata = self.file.metadata
        require(self.metadata.num_rows == manifest["row_count_metadata"]
                and self.metadata.num_row_groups == manifest["row_group_count"], "metadata totals differ")
        require([self.metadata.row_group(i).num_rows for i in range(self.metadata.num_row_groups)]
                == manifest["row_group_rows"], "metadata group sizes differ")
        self.reads = []

    def read(self, group, columns):
        rg = self.metadata.row_group(group)
        found = set()
        for i in range(rg.num_columns):
            c = rg.column(i)
            top = c.path_in_schema.split(".", 1)[0]
            if top not in columns:
                continue
            require(c.file_path in (None, ""), "external column source")
            starts = [n for n in (c.dictionary_page_offset, c.data_page_offset) if type(n) is int and n >= 4]
            require(starts and c.total_compressed_size > 0, "invalid chunk extent")
            lo = min(starts); hi = lo + c.total_compressed_size
            require(hi <= self.footer_start and covered(lo, hi, self.spans), "unacquired column chunk requested")
            found.add(top)
        require(found == set(columns), "missing projected column chunk")
        table = self.file.read_row_group(group, columns=columns, use_threads=False)
        require(len(table) == rg.num_rows, "decoded rowgroup count differs")
        self.reads.append({"source_key": self.source["key"], "row_group": group, "rows": len(table), "columns": columns})
        return table


def full_projection(sources, kind, pa, pc):
    tables, records = [], []
    for source in sources:
        count = 0
        if source.metadata.num_row_groups == 0:
            require(source.metadata.num_rows == 0, "empty source metadata differs")
            schema = pa.schema([source.file.schema_arrow.field(k) for k in RAW[kind]])
            tables.append(normalized(pa.Table.from_batches([], schema=schema), kind, pa, pc))
        for group in range(source.metadata.num_row_groups):
            raw = source.read(group, RAW[kind]); count += len(raw)
            tables.append(normalized(raw, kind, pa, pc))
            records.append({"source_key": source.source["key"], "row_group": group, "rows": len(raw), "columns": RAW[kind]})
        require(count == source.metadata.num_rows, "incomplete source projection")
    require(tables, "no source rowgroups")
    return pa.concat_tables(tables), records


def header_rows(sources, day, pa, pc):
    table, _ = full_projection(sources, "blocks", pa, pc)
    table = table.take(pc.sort_indices(table, sort_keys=[("block_number", "ascending")]))
    rows = table.to_pylist()
    require(rows and len({x["block_hash"] for x in rows}) == len(rows), "empty/duplicate headers")
    for row in rows:
        require(midnight(day) <= row["event_time_ns"] < midnight(day) + DAY_NS, "header outside UTC partition")
    for left, right in zip(rows, rows[1:]):
        link(left, right)
    return table, rows


def link(left, right):
    require(right["block_number"] == left["block_number"] + 1 and right["parent_hash"] == left["block_hash"]
            and right["event_time_ns"] > left["event_time_ns"], "nonconsecutive header chain/time")


def metadata_and_identities(tx, logs, headers, pa, pc, np):
    require(pc.count_distinct(tx["transaction_hash"]).as_py() == len(tx), "duplicate transaction hash")
    require(all_true(pc.is_in(tx["dataset_execution_status"], value_set=pa.array([0, 1], type=pa.int64())), pc), "invalid TX status")
    hp = pc.index_in(tx["block_number"], value_set=headers["block_number"])
    require(hp.null_count == 0, "TX missing header")
    for field in ("block_hash", "event_time_ns"):
        require(all_true(pc.equal(tx[field], pc.take(headers[field], hp)), pc), "TX/header identity differs")
    require(all_true(pc.less(tx["transaction_index"], pc.take(headers["transaction_count"], hp)), pc), "TX index outside block")
    positions = pa.table({"b": tx["block_number"], "t": tx["transaction_index"]})
    sorted_tx = positions.take(pc.sort_indices(positions, sort_keys=[("b", "ascending"), ("t", "ascending")]))
    blocks, indices = sorted_tx["b"].to_numpy(), sorted_tx["t"].to_numpy()
    require(not bool(np.any((blocks[1:] == blocks[:-1]) & (indices[1:] == indices[:-1]))), "duplicate TX position")
    counts = np.bincount(hp.to_numpy(), minlength=len(headers))
    require(bool(np.array_equal(counts, headers["transaction_count"].to_numpy())), "incomplete full TX table")
    tp = pc.index_in(logs["transaction_hash"], value_set=tx["transaction_hash"])
    require(tp.null_count == 0, "log missing TX metadata")
    for field in ("block_number", "block_hash", "transaction_index", "event_time_ns"):
        require(all_true(pc.equal(logs[field], pc.take(tx[field], tp)), pc), "log/TX identity differs")
    require(all_true(pc.equal(pc.take(tx["dataset_execution_status"], tp), 1), pc), "failed TX has committed logs")
    ordered = logs.select(["block_number", "transaction_index", "log_index"])
    ordered = ordered.take(pc.sort_indices(ordered, sort_keys=[(x, "ascending") for x in ordered.column_names]))
    b, t, li = (ordered[x].to_numpy() for x in ordered.column_names)
    sb = b[1:] == b[:-1]; st = sb & (t[1:] == t[:-1])
    require(bool(np.all(li[1:][sb] > li[:-1][sb])), "duplicate/reversed block log index")
    require(bool(np.all(li[1:][st] == li[:-1][st] + 1)), "gapped TX log bundle")


def payload_for_hashes(sources, hashes, pa, pc):
    selected, scans = [], []
    values = pa.array(sorted(hashes), type=pa.string())
    for source in sources:
        for group in range(source.metadata.num_row_groups):
            scan = source.read(group, ["transaction_hash"])
            mask = pc.is_in(pc.utf8_lower(scan["transaction_hash"]), value_set=values)
            count = pc.sum(pc.cast(mask, pa.int64())).as_py() or 0
            scans.append({"source_key": source.source["key"], "row_group": group, "rows_scanned": len(scan),
                          "matched_rows": count, "predicate": "transaction_hash"})
            if count:
                raw = source.read(group, RAW["logs"] + ["topics", "data"])
                require(all_true(pc.equal(pc.utf8_lower(raw["transaction_hash"]), pc.utf8_lower(scan["transaction_hash"])), pc), "unstable source payload predicate")
                identities = normalized(raw, "logs", pa, pc).filter(mask).to_pylist()
                payload = raw.select(["topics", "data"]).filter(mask).to_pylist()
                for identity, fields in zip(identities, payload):
                    selected.append(frozen_core.normalize_log(identity | fields, identity["event_time_ns"]))
    return sorted(selected, key=lambda x: (x["block_number"], x["transaction_index"], x["log_index"])), scans


def audit_day(day, sources, headers, previous, following, configs, folder, pa, pc, np):
    prep = read_json(folder / "prepared.json")
    require(prep["day_utc"] == day and prep["transfer_decoding_performed"] is False and prep["labels_used"] is False,
            "prepared day/scope differs")
    sidecars = {}
    for name, key in (("source_parts.json", "partition_manifest_sha256"), ("headers.json", "header_chain_sha256"),
                      ("scan.json", "address_scan_manifest_sha256"), ("core_selection.json", "core_selection_file_sha256")):
        sidecars[name] = bound(folder / name, prep[key])
    require(sidecars["source_parts.json"]["prepared_cases_sha256"] == value_sha(prep["cases"]), "prepared bundle binding differs")
    require(sidecars["source_parts.json"]["tables"] == {kind: [source.manifest for source in rows] for kind, rows in sources.items()},
            "daily source parts differ from independently transport-audited source manifests")
    require(sidecars["headers.json"] == {"day_utc": day, "headers": headers.to_pylist(), "predecessor": previous, "successor": following},
            "prepared header evidence differs from source")
    require(previous["event_time_ns"] < midnight(day) and following["event_time_ns"] >= midnight(day) + DAY_NS, "UTC endpoint exclusion differs")
    link(previous, headers.slice(0, 1).to_pylist()[0]); link(headers.slice(len(headers) - 1, 1).to_pylist()[0], following)
    tx, tx_records = full_projection(sources["transactions"], "transactions", pa, pc)
    logs, log_records = full_projection(sources["logs"], "logs", pa, pc)
    metadata_and_identities(tx, logs, headers, pa, pc, np)
    addresses = sorted({a for config in configs.values() for a in config["population_addresses"]})
    core = logs.filter(pc.is_in(logs["address"], value_set=pa.array(addresses)))
    selected_hashes = set(core["transaction_hash"].to_pylist())
    expanded, hash_scans = payload_for_hashes(sources["logs"], selected_hashes, pa, pc)
    expected = logs.filter(pc.is_in(logs["transaction_hash"], value_set=pa.array(sorted(selected_hashes), type=pa.string()))).to_pylist()
    expected.sort(key=lambda x: (x["block_number"], x["transaction_index"], x["log_index"]))
    require([{k: x[k] for k in logs.column_names} for x in expanded] == expected, "all-emitter payload membership differs")
    groups = defaultdict(list)
    for row in expanded:
        groups[row["transaction_hash"]].append(row)
    tx_map = {x["transaction_hash"]: {"chain_id": 1, **x} for x in tx.filter(pc.is_in(tx["transaction_hash"],
        value_set=pa.array(sorted(selected_hashes), type=pa.string()))).to_pylist()}
    header_map = {x["block_number"]: x for x in headers.to_pylist()}
    reconstructed = {}
    for case, config in configs.items():
        population = config["population_addresses"]
        records, bundles = [], []
        for group in groups.values():
            relevant = [x for x in group if x["address"] in population]
            if not relevant:
                continue
            identity = {k: 1 if k == "chain_id" else group[0][k] for k in frozen_core.TX_FIELDS}
            selected = {**identity, "archived_core_log_count": len(relevant), "archived_core_payload_sha256": value_sha(relevant)}
            frozen_core.validate_transaction(selected, tx_map[identity["transaction_hash"]], group,
                                             header_map[identity["block_number"]], relevant, population)
            records.append(selected)
            bundles.append({"transaction": identity, "dataset_execution_status": 1, "archived_core_log_count": len(relevant), "logs": group})
        records.sort(key=lambda x: (x["block_number"], x["transaction_index"]))
        bundles.sort(key=lambda x: (x["transaction"]["block_number"], x["transaction"]["transaction_index"]))
        reconstructed[case] = {"population_addresses": population, "selected_transactions": records, "bundles": bundles}
    require(reconstructed == prep["cases"], "prepared cases differ from independently reread source")
    require(sidecars["core_selection.json"]["cases"] == {k: v["selected_transactions"] for k, v in reconstructed.items()}, "daily selection seal differs")
    selected_core = [x for x in expanded if x["address"] in addresses]
    require(sidecars["core_selection.json"]["core_payload_sha256"] == value_sha(selected_core), "core payload seal differs")
    scan = sidecars["scan.json"]
    require(scan["all_log_identity_rows"] == len(logs) and scan["all_transaction_rows"] == len(tx), "scan totals differ")
    require(scan["log_identity_row_groups"] == log_records and scan["transaction_row_groups"] == tx_records,
            "producer scan does not enumerate every source part and rowgroup")
    require(scan["all_log_hash_row_groups"] == hash_scans, "producer all-TX-hash scan differs")
    address_scans = []
    for source in sources["logs"]:
        for group in range(source.metadata.num_row_groups):
            raw = source.read(group, ["address"])
            n = pc.sum(pc.cast(pc.is_in(pc.utf8_lower(raw["address"]), value_set=pa.array(addresses)), pa.int64())).as_py() or 0
            address_scans.append({"source_key": source.source["key"], "row_group": group, "rows_scanned": len(raw), "matched_rows": n, "predicate": "address"})
    require(scan["all_address_row_groups"] == address_scans, "producer all-address scan differs")
    return prep, {"day_utc": day, "all_transaction_rows": len(tx), "all_log_identity_rows": len(logs),
                  "prepared_sha256": file_sha(folder / "prepared.json"), "cases": {case: {
                      "selected_transactions": len(value["selected_transactions"]),
                      "core_log_count": sum(x["archived_core_log_count"] for x in value["selected_transactions"]),
                      "selected_all_emitter_logs": sum(len(x["logs"]) for x in value["bundles"])} for case, value in reconstructed.items()}}


def run(args):
    for relative, expected in FROZEN.items():
        require(file_sha(PAPER / relative) == expected, "frozen reviewer dependency changed")
    require(not args.output.exists(), "fresh audit output directory required")
    start_sha = file_sha(__file__)
    plan = bound(args.plan, args.expected_plan_sha256)
    transport = bound(args.transport_audit, args.expected_transport_audit_sha256)
    require(transport["status"] == "PASS_TRANSPORT_ORIGINAL_BYTES" and transport["plan_sha256"] == args.expected_plan_sha256,
            "independent original-byte transport audit missing")
    collection = bound(args.collection / "collection_result.json", transport["collection_result_sha256"])
    require(collection["status"] == "COMPLETE_PREPARATION_AWAITING_INDEPENDENT_SOURCE_AUDIT"
            and collection["plan_sha256"] == args.expected_plan_sha256 and collection["transfer_decoding_performed"] is False
            and collection["detector_scoring_performed"] is False and collection["labels_used"] is False, "collection not complete/unscored")
    manifests = bound(args.collection / "transport_sources.json", transport["transport_sources_sha256"])
    inventory = bound(REPO / plan["source_union"]["path"], plan["source_union"]["sha256"])
    sys.path.insert(0, str(args.dependencies.resolve()))
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.parquet as pq
    import numpy as np
    require(pa.__version__ == plan["pyarrow_version"] == "26.0.0" and Path(pa.__file__).resolve().is_relative_to(args.dependencies.resolve()), "wrong parser")
    require(np.__version__ == plan["numpy_version"] == "2.3.5", "wrong NumPy runtime")
    configs = {}
    for binding in plan["case_configs"]:
        cfg = bound(REPO / binding["path"], binding["sha256"])
        frozen_driver.validate_config(cfg)
        configs[cfg["case_id"]] = (cfg, binding["sha256"])
    verified = {x["source_key"]: x for x in transport["verified_sources"]}
    # transport_sources.json is an ordered list of final SourceReader manifests.
    if isinstance(manifests, dict):
        manifests = manifests["sources"]
    mm = {x["source"]["key"]: x for x in manifests}
    expected_keys = {x["key"] for x in inventory["objects"]}
    require(len(expected_keys) == len(mm) == len(verified) == 113 and set(mm) == set(verified) == expected_keys,
            "transport audit/source population differs")
    sources = defaultdict(lambda: defaultdict(list))
    for source in inventory["objects"]:
        reader = OfflineSource(source, mm[source["key"]], verified[source["key"]], pa, pq)
        sources[source["day_utc"]][source["table"]].append(reader)
    timeline = {}
    for day in sorted(sources):
        timeline[day] = header_rows(sources[day]["blocks"], day, pa, pc)
    for left, right in zip(sorted(timeline), sorted(timeline)[1:]):
        require(midnight(right) - midnight(left) == DAY_NS, "missing calendar day")
        link(timeline[left][1][-1], timeline[right][1][0])
    for anchor in plan["accepted_header_anchors"]:
        found = [row for _, rows in timeline.values() for row in rows if row["block_number"] == anchor["block_number"]]
        require(len(found) == 1 and all(found[0][k] == v for k, v in anchor.items()), "retained independent anchor differs")
    args.output.mkdir(parents=True)
    prepared, summaries = {}, []
    for item in collection["prepared_days"]:
        path = args.collection / item["path"]
        value = bound(path, item["sha256"])
        day = value["day_utc"]
        prior = (date.fromisoformat(day) - timedelta(days=1)).isoformat()
        following = (date.fromisoformat(day) + timedelta(days=1)).isoformat()
        active = {k: cfg for k, (cfg, _) in configs.items() if day in frozen_driver.expected_days(cfg)}
        prep, summary = audit_day(day, sources[day], timeline[day][0], timeline[prior][1][-1], timeline[following][1][0],
                                  active, path.parent, pa, pc, np)
        prepared[day] = prep; summaries.append(summary)
        write(args.output / "progress.json", {"status": "AUDIT_IN_PROGRESS_NOT_PASS", "completed_days": summaries})
        print(json.dumps({"independently_audited_day": day, "cases": summary["cases"]}), flush=True)
    require(list(prepared) == days(plan["study_start"], plan["study_end_exclusive"]), "not exactly37 ordered study days")
    case_audits = {}
    for case, (config, config_sha) in configs.items():
        selection_bind = collection["selection_manifests"][case]
        selection = bound(args.collection / selection_bind["path"], selection_bind["sha256"])
        expected = {"schema_version": "fixed_address_transaction_selection_v1", "status": "SEALED_BEFORE_SCORING",
                    "config_sha256": config_sha, "rule": "at_least_one_core_emitter_log_no_topic_filter",
                    "days": [{"day_utc": d, "transactions": prepared[d]["cases"][case]["selected_transactions"]}
                             for d in frozen_driver.expected_days(config)]}
        require(selection == expected, "full-window selection differs")
        audit = {"schema_version": "fixed_address_source_audit_v1", "status": "PASS", "config_sha256": config_sha,
                 "selection_manifest_sha256": selection_bind["sha256"], "tier": config["source_tier"],
                 "cross_day_header_links_checked": True, "endpoint_anchors_checked": True, "days": []}
        for day in frozen_driver.expected_days(config):
            prep = prepared[day]; records = prep["cases"][case]["selected_transactions"]
            audit["days"].append({"day_utc": day, "status": "COVERED", "selected_transactions": len(records),
                "core_log_count": sum(x["archived_core_log_count"] for x in records),
                **{k: prep[k] for k in frozen_driver.COVERAGE_HASHES}, **{k: True for k in frozen_driver.COVERAGE_CHECKS}})
        path = args.output / (case + "_source_audit.json")
        case_audits[case] = {"path": str(path.resolve()), "sha256": write(path, audit)}
    require(file_sha(__file__) == start_sha and file_sha(args.transport_audit) == args.expected_transport_audit_sha256,
            "reviewer inputs changed during audit")
    result = {"schema_version": "phase16_independent_actual_source_review_v1", "status": "PASS_SOURCE_SELECTION_AND_RAW_BUNDLES",
              "completed_utc": datetime.now(timezone.utc).isoformat(), "reviewer_sha256": start_sha,
              "plan_sha256": args.expected_plan_sha256, "transport_audit_sha256": args.expected_transport_audit_sha256,
              "collection_result_sha256": transport["collection_result_sha256"], "case_audits": case_audits,
              "days": summaries, "source_objects": 113, "study_days": 37,
              "endpoint_tier": "Source-adjacent complete header boundaries for every case; additionally actual retained independent LiFi RPC header anchors. No independent Revest endpoint anchor inferred.",
              "limitations": ["No receipt-root authentication or proof of archive correctness against full canonical chain.",
                              "All identity/address/hash/status/header projections audited; nonselected topics/data not required or validated.",
                              "Fixed nominated component sets only; source audit does not adjudicate incident labels or detector effectiveness."],
              "network_requests": 0, "transfer_decoding_performed": False, "detector_scores_computed": 0}
    write(args.output / "source_review.json", result)
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("plan", "collection", "transport-audit", "dependencies", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--expected-plan-sha256", required=True)
    p.add_argument("--expected-transport-audit-sha256", required=True)
    args = p.parse_args()
    result = run(args)
    print(json.dumps({"status": result["status"], "case_audits": result["case_audits"]}), flush=True)
