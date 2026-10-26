"""Pure, source-bound Ethereum day preparation; no acquisition or detector replay.

Inputs contain complete normalized rows for each declared source part. This module
checks their identities, hashes, row counts and internal consistency. An independent
source audit must establish that the declared parts/rows faithfully represent the
accepted archive. Receipt roots and historical source completeness are not proved.
"""
from __future__ import annotations

import copy
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import sys

PAPER = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PAPER))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from retained_observation_core import (  # exact frozen pure-function extraction
    LOG_FIELDS, TX_FIELDS, normalize_log, observe, validate_transaction,
)

DAY_NS = 86_400_000_000_000
HEX = re.compile(r"0x[0-9a-f]+\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
TABLES = {"logs", "transactions", "blocks"}
HEADER_FIELDS = {"block_number", "block_hash", "parent_hash", "event_time_ns", "transaction_count"}
OBJECT_FIELDS = {"table", "object_key", "size", "etag", "rows", "source_receipt_sha256", "normalized_rows_sha256"}
INVENTORY_FIELDS = {"schema_version", "status", "chain_id", "day_utc", "listing_receipts_sha256", "objects"}
SELECTION_FIELDS = {"schema_version", "chain_id", "day_utc", "population_addresses", "source_inventory_sha256", "transactions", "core_log_count"}
DEPENDENCIES = {
    "phase15/adapter/retained_observation_core.py": "63119a14c1f3fb5a2cf74f24f918181679611633e6e75df63b5dc6b7180ef662",
    "transfer_observation.py": "eb905fdbdc44033424066e4baebbbc1f6724bd68bd9e0573676f39e4908f429c",
}


def check_dependencies():
    for name, expected in DEPENDENCIES.items():
        if hashlib.sha256((PAPER / name).read_bytes()).hexdigest() != expected:
            raise ValueError("frozen dependency changed: " + name)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(value):
    """Hash exact canonical JSON bytes, without a trailing newline."""
    return hashlib.sha256(canonical(value)).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, name, minimum=0):
    require(type(value) is int and value >= minimum, "invalid integer: " + name)
    return value


def hex_value(value, size, name):
    require(type(value) is str and len(value) == 2 + 2 * size and HEX.fullmatch(value),
            "invalid canonical hex: " + name)
    return value


def sha(value, name):
    require(type(value) is str and SHA.fullmatch(value), "invalid SHA256: " + name)
    return value


def day_start(day):
    require(type(day) is str and date.fromisoformat(day).isoformat() == day,
            "invalid canonical UTC date")
    return (date.fromisoformat(day) - date(1970, 1, 1)).days * DAY_NS


def population(addresses):
    require(type(addresses) is list and bool(addresses), "empty population")
    for address in addresses:
        hex_value(address, 20, "population")
        require(address != "0x" + "0" * 40, "zero population address")
    require(addresses == sorted(set(addresses)), "population must be sorted and unique")
    return addresses


def _inventory(inventory, expected_sha256, limits):
    check_dependencies()
    require(type(inventory) is dict and set(inventory) == INVENTORY_FIELDS, "inventory fields")
    require(digest(inventory) == sha(expected_sha256, "inventory"), "inventory hash mismatch")
    require(inventory["schema_version"] == "fixed_core_day_inventory_v1", "inventory schema")
    require(inventory["status"] == "complete", "source unavailable or incomplete")
    require(type(inventory["chain_id"]) is int and inventory["chain_id"] == 1, "Ethereum chain1 required")
    day_start(inventory["day_utc"])
    refs = inventory["listing_receipts_sha256"]
    require(type(refs) is list and bool(refs) and len(set(refs)) == len(refs), "listing receipts")
    for ref in refs:
        sha(ref, "listing receipt")
    require(type(limits) is dict and set(limits) == {"max_parts", "max_rows_per_table", "max_source_bytes"}, "limit fields")
    for key, value in limits.items():
        integer(value, key, 1)
    objects = inventory["objects"]
    require(type(objects) is list and 0 < len(objects) <= limits["max_parts"], "source part cap")
    keys, table_rows, total_bytes = [], {table: 0 for table in TABLES}, 0
    for obj in objects:
        require(type(obj) is dict and set(obj) == OBJECT_FIELDS, "source object fields")
        require(obj["table"] in TABLES, "unknown source table")
        require(type(obj["object_key"]) is str and bool(obj["object_key"]), "object key")
        keys.append(obj["object_key"])
        require(type(obj["etag"]) is str and bool(obj["etag"]), "opaque object ETag required")
        total_bytes += integer(obj["size"], "object size", 1)
        table_rows[obj["table"]] += integer(obj["rows"], "object rows")
        sha(obj["source_receipt_sha256"], "source receipt")
        sha(obj["normalized_rows_sha256"], "normalized rows")
    require(len(set(keys)) == len(keys), "duplicate source object")
    require({obj["table"] for obj in objects} == TABLES, "missing source table")
    require(total_bytes <= limits["max_source_bytes"], "source byte cap")
    require(all(n <= limits["max_rows_per_table"] for n in table_rows.values()), "source row cap")
    return objects


def _table_rows(inventory, parts, table):
    expected = {obj["object_key"]: obj for obj in inventory["objects"] if obj["table"] == table}
    require(type(parts) is list, "source parts must be a list")
    supplied, result = {}, []
    for part in parts:
        require(type(part) is dict and set(part) == {"object_key", "rows"}, "part fields")
        key = part["object_key"]
        require(key in expected and key not in supplied, "unknown or duplicate part")
        rows = part["rows"]
        require(type(rows) is list and len(rows) == expected[key]["rows"], "part row count")
        require(digest(rows) == expected[key]["normalized_rows_sha256"], "part row hash")
        supplied[key] = True
        result.extend(copy.deepcopy(rows))
    require(set(supplied) == set(expected), "missing source part")
    return result


def _identity(row):
    require(type(row["chain_id"]) is int and row["chain_id"] == 1, "Ethereum chain1 required")
    for key in ("block_number", "transaction_index", "event_time_ns"):
        integer(row[key], key)
    for key in ("block_hash", "transaction_hash"):
        hex_value(row[key], 32, key)
    return {key: row[key] for key in TX_FIELDS}


def _logs(rows, day):
    start = day_start(day)
    keys, log_ids, tx_positions, hash_positions = set(), set(), {}, {}
    for row in rows:
        require(type(row) is dict and set(row) == {"chain_id", *LOG_FIELDS}, "log fields")
        _identity(row)
        require(start <= row["event_time_ns"] < start + DAY_NS, "log outside day")
        normalized = {"chain_id": 1, **normalize_log(row, row["event_time_ns"])}
        require(normalized == row, "log is not canonical normalized input")
        key = row["block_number"], row["transaction_index"], row["log_index"]
        log_id = row["block_number"], row["log_index"]
        require(key not in keys and log_id not in log_ids, "duplicate block-log position")
        keys.add(key); log_ids.add(log_id)
        position = row["block_number"], row["transaction_index"]
        identity = _identity(row)
        require(position not in tx_positions or tx_positions[position] == identity, "conflicting transaction position")
        require(row["transaction_hash"] not in hash_positions or hash_positions[row["transaction_hash"]] == identity, "conflicting transaction hash")
        tx_positions[position] = identity
        hash_positions[row["transaction_hash"]] = identity
    ordered = sorted(rows, key=lambda row: (row["block_number"], row["transaction_index"], row["log_index"]))
    for left, right in zip(ordered, ordered[1:]):
        if left["block_number"] == right["block_number"]:
            require(right["log_index"] > left["log_index"], "block log index reverses transaction order")
    return ordered


def select_core_day(inventory, log_parts, addresses, *, expected_inventory_sha256, limits):
    """Scan all declared raw log rows; returns a selection to be externally sealed.

    No transfer-shape decoding, execution labels or detector output are consumed.
    Empty core selections are allowed only with complete declared part coverage.
    """
    _inventory(inventory, expected_inventory_sha256, limits)
    population(addresses)
    logs = _logs(_table_rows(inventory, log_parts, "logs"), inventory["day_utc"])
    groups = {}
    for row in logs:
        if row["address"] in addresses:
            groups.setdefault(row["transaction_hash"], []).append(row)
    selected = []
    for rows in groups.values():
        selected.append({**_identity(rows[0]), "archived_core_log_count": len(rows),
                         "archived_core_payload_sha256": digest([{key: row[key] for key in LOG_FIELDS} for row in rows])})
    return {"schema_version": "fixed_core_day_selection_v1", "chain_id": 1,
            "day_utc": inventory["day_utc"], "population_addresses": copy.deepcopy(addresses),
            "source_inventory_sha256": expected_inventory_sha256, "transactions": selected,
            "core_log_count": sum(item["archived_core_log_count"] for item in selected)}


def _header(row):
    require(type(row) is dict and set(row) == HEADER_FIELDS, "header fields")
    for key in ("block_number", "event_time_ns", "transaction_count"):
        integer(row[key], key)
    for key in ("block_hash", "parent_hash"):
        hex_value(row[key], 32, key)
    return row


def _linked(left, right):
    require(right["block_number"] == left["block_number"] + 1 and
            right["parent_hash"] == left["block_hash"] and
            right["event_time_ns"] > left["event_time_ns"], "header chain or timestamp mismatch")


def prepare_day(inventory, parts_by_table, addresses, selection, *,
                expected_inventory_sha256, expected_selection_sha256,
                predecessor_header, successor_header, limits):
    """Validate full source rows and externally sealed selection, then form bundles.

    The predecessor must be the immediately previous block before UTC midnight;
    successor must be the immediate next block at/after the next UTC midnight.
    Independently accepted source/header anchors remain an external prerequisite.
    """
    _inventory(inventory, expected_inventory_sha256, limits)
    population(addresses)
    require(type(parts_by_table) is dict and set(parts_by_table) == TABLES, "all table parts required")
    require(type(selection) is dict and set(selection) == SELECTION_FIELDS, "selection fields")
    require(digest(selection) == sha(expected_selection_sha256, "selection"), "selection hash mismatch")
    actual = select_core_day(inventory, parts_by_table["logs"], addresses,
                             expected_inventory_sha256=expected_inventory_sha256, limits=limits)
    require(canonical(selection) == canonical(actual), "sealed selection differs from full core-emitter scan")
    day = inventory["day_utc"]; start = day_start(day)
    headers = sorted(_table_rows(inventory, parts_by_table["blocks"], "blocks"), key=lambda row: row["block_number"])
    require(bool(headers), "empty daily headers")
    for header in headers:
        _header(header)
        require(start <= header["event_time_ns"] < start + DAY_NS, "header outside day")
    require(len({row["block_hash"] for row in headers}) == len(headers), "duplicate header hash")
    predecessor = _header(predecessor_header); successor = _header(successor_header)
    require(predecessor["event_time_ns"] < start <= headers[0]["event_time_ns"], "wrong start UTC anchor")
    require(headers[-1]["event_time_ns"] < start + DAY_NS <= successor["event_time_ns"], "wrong end UTC anchor")
    for left, right in zip([predecessor, *headers], [*headers, successor]):
        _linked(left, right)
    header_map = {row["block_number"]: row for row in headers}
    metadata = _table_rows(inventory, parts_by_table["transactions"], "transactions")
    tx_map, positions = {}, set()
    for row in metadata:
        require(type(row) is dict and set(row) == {*TX_FIELDS, "dataset_execution_status"}, "transaction metadata fields")
        identity = _identity(row)
        require(type(row["dataset_execution_status"]) is int and row["dataset_execution_status"] in (0, 1), "unknown transaction status")
        require(row["block_number"] in header_map, "transaction header missing")
        header = header_map[row["block_number"]]
        require(row["block_hash"] == header["block_hash"] and row["event_time_ns"] == header["event_time_ns"], "transaction/header identity mismatch")
        require(row["transaction_index"] < header["transaction_count"], "transaction position outside header")
        position = row["block_number"], row["transaction_index"]
        require(position not in positions and row["transaction_hash"] not in tx_map, "duplicate transaction metadata")
        positions.add(position); tx_map[row["transaction_hash"]] = row
    require(len(metadata) == sum(row["transaction_count"] for row in headers), "full transaction/header count mismatch")
    logs = _logs(_table_rows(inventory, parts_by_table["logs"], "logs"), day)
    all_groups = {}
    for row in logs:
        tx = row["transaction_hash"]
        require(tx in tx_map and _identity(row) == _identity(tx_map[tx]), "log missing/conflicting transaction metadata")
        require(tx_map[tx]["dataset_execution_status"] == 1, "failed transaction with committed logs")
        all_groups.setdefault(tx, []).append(row)
    # This is a source-structural check: missing leading/trailing logs remain unproved.
    for rows in all_groups.values():
        require(all(b["log_index"] == a["log_index"] + 1 for a, b in zip(rows, rows[1:])), "gapped transaction logs")
    normalized = []
    for item in selection["transactions"]:
        tx = item["transaction_hash"]; group = all_groups.get(tx, [])
        core = [row for row in group if row["address"] in addresses]
        identity = validate_transaction(item, tx_map[tx], group, header_map[item["block_number"]], core, addresses)
        normalized.append({"transaction": identity, "dataset_execution_status": tx_map[tx]["dataset_execution_status"],
                           "archived_core_log_count": item["archived_core_log_count"],
                           "logs": [{key: row[key] for key in LOG_FIELDS} for row in group]})
    return {"schema_version": "fixed_core_prepared_day_v1", "chain_id": 1, "day_utc": day,
            "population_addresses": copy.deepcopy(addresses), "source_inventory_sha256": expected_inventory_sha256,
            "selection_sha256": expected_selection_sha256, "normalized_transactions": normalized,
            "coverage": {"status": "declared_parts_structurally_validated", "part_count": len(inventory["objects"]),
                         "header_count": len(headers), "all_transactions_count": len(metadata),
                         "all_logs_count": len(logs), "core_log_count": selection["core_log_count"],
                         "selected_transactions": len(normalized),
                         "first_header": headers[0], "last_header": headers[-1],
                         "predecessor_header": predecessor, "successor_header": successor,
                         "source_authentication_independently_verified_here": False,
                         "receipt_root_verified": False, "full_chain_completeness_verified": False}}


def validate_adjacent_days(left, right):
    require(day_start(right["day_utc"]) == day_start(left["day_utc"]) + DAY_NS, "days are not consecutive")
    require(left["population_addresses"] == right["population_addresses"], "cross-day population mismatch")
    require(left["coverage"]["successor_header"] == right["coverage"]["first_header"], "cross-day successor mismatch")
    require(right["coverage"]["predecessor_header"] == left["coverage"]["last_header"], "cross-day predecessor mismatch")
    _linked(left["coverage"]["last_header"], right["coverage"]["first_header"])
    return True


def observations(prepared, *, expected_prepared_sha256, source_audit_sha256, selection_manifest_sha256):
    """Reuse unchanged integer decoder/aggregator only after separate source audit.

    Caller must supply the actual independently accepted source-audit digest and
    full-window selection-file digest. The latter differs from the day selection
    seal; the window assembler and replay driver verify global membership.
    Digest syntax is not a substitute for that audit; this function performs no
    admission decision, detector scoring or source-authentication work.
    """
    check_dependencies()
    require(digest(prepared) == sha(expected_prepared_sha256, "prepared day"), "prepared day hash mismatch")
    sha(source_audit_sha256, "source audit")
    sha(selection_manifest_sha256, "full-window selection manifest")
    return [observe(row["transaction"], row["logs"], prepared["population_addresses"],
                    row["archived_core_log_count"], source_audit_sha256,
                    selection_manifest_sha256, dataset_execution_status=row["dataset_execution_status"])
            for row in prepared["normalized_transactions"]]
