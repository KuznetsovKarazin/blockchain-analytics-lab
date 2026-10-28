"""Independent new Phase16 projected-pipeline checks on invented Arrow rows.

No network, real dataset, prior test suite or detector score is used.  Tiny
invented inputs permit comparison with the unchanged pure full-row adapter.
"""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

PAPER = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PAPER / "phase15" / "adapter"))
import fixed_core_adapter as pure


def load_pipeline():
    path = PAPER / "phase16" / "pipeline" / "streaming_pipeline.py"
    spec = importlib.util.spec_from_file_location("phase16_streaming_under_review", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return path, module


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fixture(pa):
    a, b, token, outside = ("0x" + v * 40 for v in "abcd")
    h = lambda n: "0x" + format(n, "064x")
    day = "2022-02-19"
    start = pure.day_start(day)
    stamp = start + 123 * 10**9
    header = {"block_number": 100, "block_hash": h(100), "parent_hash": h(99),
              "event_time_ns": stamp, "transaction_count": 4}
    previous = {"block_number": 99, "block_hash": h(99), "parent_hash": h(98),
                "event_time_ns": start - 1, "transaction_count": 0}
    following = {"block_number": 101, "block_hash": h(101), "parent_hash": h(100),
                 "event_time_ns": start + pure.DAY_NS, "transaction_count": 0}
    transactions = [{"chain_id": 1, "block_number": 100, "block_hash": h(100),
                     "transaction_hash": h(1000 + i), "transaction_index": i,
                     "event_time_ns": stamp, "dataset_execution_status": 0 if i == 3 else 1}
                    for i in range(4)]
    topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    logs = []
    def add(i, emitter, topics=None, data="0x"):
        logs.append({k: v for k, v in transactions[i].items() if k != "dataset_execution_status"} |
                    {"address": emitter, "topics": topics or [], "data": data,
                     "log_index": len(logs)})
    def transfer(i, amount):
        add(i, token, [topic, "0x" + "0" * 24 + a[2:], "0x" + "0" * 24 + outside[2:]],
            "0x" + format(amount, "064x"))
    add(0, a)
    transfer(0, 2**200 + 7)
    transfer(0, 5)
    add(0, b)
    transfer(1, 999)  # From A but no A-emitter log: it must not select TX1.
    add(2, b)
    return dict(day=day, a=a, b=b, token=token, outside=outside, header=header,
                previous=previous, following=following, transactions=transactions, logs=logs)


def arrow_table(rows, kind, pa):
    mapping = {"blocks": {"block_number": "number", "block_hash": "hash", "event_time_ns": "timestamp"},
               "transactions": {"transaction_hash": "hash", "event_time_ns": "block_timestamp",
                                "dataset_execution_status": "receipt_status"},
               "logs": {"event_time_ns": "block_timestamp"}}[kind]
    columns = {}
    for key in rows[0]:
        if key == "chain_id":
            continue
        values = [r[key] for r in rows]
        typ = pa.timestamp("ns") if key == "event_time_ns" else (
            pa.list_(pa.string()) if key == "topics" else
            pa.int64() if type(values[0]) is int else pa.string())
        columns[mapping.get(key, key)] = pa.array(values, type=typ)
    return pa.table(columns)


class Reader:
    def __init__(self, key, tables):
        self.source = {"key": key}
        self.tables = tables
        self.schema = tables[0].schema
        self.metadata = SimpleNamespace(num_rows=sum(len(t) for t in tables), num_row_groups=len(tables),
            row_group=lambda i: SimpleNamespace(num_rows=len(tables[i])))
        self.calls = []
    def iter_row_groups(self, columns):
        for i, table in enumerate(self.tables):
            self.calls.append((i, tuple(columns)))
            yield i, table.select(columns)
    def read_row_group(self, i, columns):
        self.calls.append((i, tuple(columns)))
        return self.tables[i].select(columns)
    def manifest(self):
        return {"synthetic_source_key": self.source["key"], "rows": self.metadata.num_rows}


def readers_for(f, pa):
    # A selected transaction spans both row groups and source parts. Its opaque
    # A-emitter and B-emitter logs surround external-token logs.
    left = arrow_table(f["logs"][:2], "logs", pa)
    right = arrow_table(f["logs"][2:], "logs", pa)
    tx = arrow_table(f["transactions"], "transactions", pa)
    blocks = arrow_table([f["header"]], "blocks", pa)
    return {"logs": [Reader("log_part_0", [left]), Reader("log_part_1", [right.slice(0, 2), right.slice(2)])],
            "transactions": [Reader("tx_part_0", [tx.slice(0, 2), tx.slice(2)])],
            "blocks": [Reader("block_part_0", [blocks])]}


def pure_expected(f, address):
    tables = {"logs": f["logs"], "transactions": f["transactions"], "blocks": [f["header"]]}
    parts = {kind: [{"object_key": kind, "rows": rows}] for kind, rows in tables.items()}
    inventory = {"schema_version": "fixed_core_day_inventory_v1", "status": "complete", "chain_id": 1,
                 "day_utc": f["day"], "listing_receipts_sha256": ["1" * 64], "objects": [
                     {"table": kind, "object_key": kind, "size": 1, "etag": "synthetic",
                      "rows": len(rows), "source_receipt_sha256": "2" * 64,
                      "normalized_rows_sha256": pure.digest(rows)} for kind, rows in tables.items()]}
    limits = {"max_parts": 3, "max_rows_per_table": 100, "max_source_bytes": 10}
    selection = pure.select_core_day(inventory, parts["logs"], [address],
        expected_inventory_sha256=pure.digest(inventory), limits=limits)
    prepared = pure.prepare_day(inventory, parts, [address], selection,
        expected_inventory_sha256=pure.digest(inventory), expected_selection_sha256=pure.digest(selection),
        predecessor_header=f["previous"], successor_header=f["following"], limits=limits)
    return selection, prepared


def run(dependencies):
    sys.path.insert(0, str(Path(dependencies).resolve()))
    import pyarrow as pa
    import pyarrow.compute as pc
    import numpy as np
    path, pipeline = load_pipeline()
    start_sha = sha(path)
    passed = []
    def checked(name, function):
        function()
        passed.append(name)
    def rejects(name, function, text):
        try:
            function()
        except ValueError as exc:
            assert text in str(exc), (name, str(exc))
        else:
            raise AssertionError(name + " was accepted")
        passed.append(name)
    f = fixture(pa)
    h = pipeline.check_headers(arrow_table([f["header"]], "blocks", pa), f["day"], pa, pc, np)
    limits = {"max_transaction_rows_per_day": 100, "max_log_rows_per_day": 100,
              "max_selected_transactions_per_case_day": 100, "max_selected_logs_per_day": 100}
    with tempfile.TemporaryDirectory(prefix="phase16_review_synthetic_") as directory:
        root = Path(directory)
        readers = readers_for(f, pa)
        configs = {"case_a": {"population_addresses": [f["a"]]}, "case_b": {"population_addresses": [f["b"]]}}
        prep = pipeline.prepare_day(f["day"], readers, h, f["previous"], f["following"], configs,
                                    root / "normal", pa, pc, np, limits)
        for case, address in (("case_a", f["a"]), ("case_b", f["b"])):
            selection, baseline = pure_expected(f, address)
            assert prep["cases"][case]["selected_transactions"] == selection["transactions"]
            assert canon(prep["cases"][case]["bundles"]) == canon(baseline["normalized_transactions"])
        passed.append("all_parts_address_selection_and_full_bundle_match_unchanged_pure_adapter")
        assert len(prep["cases"]["case_a"]["bundles"]) == 1
        assert len(prep["cases"]["case_a"]["bundles"][0]["logs"]) == 4
        assert len(prep["cases"]["case_b"]["bundles"]) == 2
        passed.append("from_core_transfer_without_core_emitter_does_not_select_transaction")
        bundle = prep["cases"]["case_a"]["bundles"][0]
        observation = pure.observe(bundle["transaction"], bundle["logs"], [f["a"]], 1, "3" * 64, "4" * 64,
                                   dataset_execution_status=1)
        assert observation["token_flows"][0]["external_out_raw"] == str(2**200 + 12)
        assert observation["counts"]["logs"] == 4
        passed.append("opaque_core_logs_select_and_selected_token_amount_stays_exact_above_float_range")
        assert all(any(cols == ("address",) for _, cols in r.calls) and
                   any(cols == ("transaction_hash",) for _, cols in r.calls) for r in readers["logs"])
        assert prep["transfer_decoding_performed"] is False and prep["labels_used"] is False
        assert (root / "normal" / "core_selection.json").is_file()
        passed.append("all_source_parts_receive_address_and_hash_scans_before_audit")
        empty = {"case_none": {"population_addresses": ["0x" + "e" * 40]}}
        empty_prep = pipeline.prepare_day(f["day"], readers_for(f, pa), h, f["previous"], f["following"], empty,
                                          root / "empty", pa, pc, np, limits)
        assert empty_prep["cases"]["case_none"]["bundles"] == []
        assert empty_prep["cases"]["case_none"]["selected_transactions"] == []
        passed.append("genuinely_empty_selection_requires_complete_full_identity_and_address_scans")
        bad_previous = f["previous"] | {"event_time_ns": pure.day_start(f["day"])}
        rejects("predecessor_inside_same_utc_day_rejected", lambda: pipeline.prepare_day(f["day"], readers_for(f, pa),
            h, bad_previous, f["following"], configs, root / "bad_previous", pa, pc, np, limits), "UTC boundary")
        rejects("selected_log_expansion_cap_is_failure_not_truncation", lambda: pipeline.prepare_day(f["day"],
            readers_for(f, pa), h, f["previous"], f["following"], configs, root / "bad_cap", pa, pc, np,
            limits | {"max_selected_logs_per_day": 3}), "cap")
    tx = pipeline.check_transactions(arrow_table(f["transactions"], "transactions", pa), h, f["day"], pa, pc, np)
    bad = copy.deepcopy(f["transactions"]); bad[1]["dataset_execution_status"] = 0
    bad_tx = pipeline.check_transactions(arrow_table(bad, "transactions", pa), h, f["day"], pa, pc, np)
    rejects("failed_unselected_transaction_with_log_rejected", lambda: pipeline.check_log_identities(
        arrow_table(f["logs"], "logs", pa), h, bad_tx, f["day"], pa, pc, np), "failed transaction")
    bad = copy.deepcopy(f["transactions"]); bad[2]["transaction_index"] = 1
    rejects("duplicate_transaction_position_rejected", lambda: pipeline.check_transactions(
        arrow_table(bad, "transactions", pa), h, f["day"], pa, pc, np), "duplicate transaction position")
    bad_header = pipeline.check_headers(arrow_table([f["header"] | {"transaction_count": 5}], "blocks", pa),
                                        f["day"], pa, pc, np)
    rejects("missing_transaction_from_header_count_rejected", lambda: pipeline.check_transactions(
        arrow_table(f["transactions"], "transactions", pa), bad_header, f["day"], pa, pc, np), "counts differ")
    bad = copy.deepcopy(f["logs"]); bad[4]["block_hash"] = "0x" + "f" * 64
    rejects("unselected_log_header_identity_mismatch_rejected", lambda: pipeline.check_log_identities(
        arrow_table(bad, "logs", pa), h, tx, f["day"], pa, pc, np), "log/transaction mismatch")
    bad = copy.deepcopy(f["logs"]); bad[4]["log_index"] = 3
    rejects("cross_transaction_duplicate_global_log_index_rejected", lambda: pipeline.check_log_identities(
        arrow_table(bad, "logs", pa), h, tx, f["day"], pa, pc, np), "block log position")
    bad = copy.deepcopy(f["logs"]); bad[1]["log_index"] = 10
    rejects("gapped_selected_transaction_log_sequence_rejected", lambda: pipeline.check_log_identities(
        arrow_table(bad, "logs", pa), h, tx, f["day"], pa, pc, np), "block log position")
    bool_tx = arrow_table(f["transactions"], "transactions", pa)
    bool_tx = bool_tx.set_column(bool_tx.column_names.index("receipt_status"), "receipt_status", pa.array([True] * 4))
    rejects("boolean_execution_status_rejected", lambda: pipeline.normalize_table(bool_tx, "transactions", pa, pc), "integer type")
    assert sha(path) == start_sha, "pipeline changed while test ran"
    return {"schema_version": "phase16_independent_streaming_fault_review_v1", "status": "PASS_SYNTHETIC_CHECKS_ONLY",
            "pipeline_sha256": start_sha, "review_script_sha256": sha(__file__), "checks": passed, "checks_passed": len(passed),
            "pyarrow_version": pa.__version__, "numpy_version": np.__version__, "network_requests": 0,
            "real_source_rows_read": 0, "detector_scores_computed": 0, "old_suites_rerun": False,
            "limitation": "This is implementation preflight, not actual source, selection, acceptance or decision audit."}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dependencies", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.dependencies)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "checks_passed": report["checks_passed"]}))
