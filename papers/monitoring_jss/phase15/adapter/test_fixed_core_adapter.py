"""Focused synthetic adapter checks only; no case payloads or old-suite imports."""
import copy
import unittest

import fixed_core_adapter as adapter
from transfer_observation import TRANSFER_TOPIC

DAY = "2022-02-19"
START = adapter.day_start(DAY)
CORE = "0x" + "11" * 20
TOKEN = "0x" + "22" * 20
RECIPIENT = "0x" + "33" * 20
OTHER = "0x" + "44" * 20
LIMITS = {"max_parts": 20, "max_rows_per_table": 100, "max_source_bytes": 10_000}


def hx(number):
    return "0x" + f"{number:064x}"


def fixture(empty=False, amount=2**200 + 3):
    headers = [{"block_number": 10, "block_hash": hx(10), "parent_hash": hx(9),
                "event_time_ns": START + 1, "transaction_count": 1},
               {"block_number": 11, "block_hash": hx(11), "parent_hash": hx(10),
                "event_time_ns": START + 2, "transaction_count": 1}]
    predecessor = {"block_number": 9, "block_hash": hx(9), "parent_hash": hx(8),
                   "event_time_ns": START - 1, "transaction_count": 0}
    successor = {"block_number": 12, "block_hash": hx(12), "parent_hash": hx(11),
                 "event_time_ns": START + adapter.DAY_NS, "transaction_count": 0}
    txs = [{"chain_id": 1, "block_number": header["block_number"], "block_hash": header["block_hash"],
            "transaction_hash": hx(100 + index), "transaction_index": 0,
            "event_time_ns": header["event_time_ns"], "dataset_execution_status": 1}
           for index, header in enumerate(headers)]
    tx = {k: v for k, v in txs[0].items() if k != "dataset_execution_status"}
    logs = [{**tx, "address": OTHER if empty else CORE, "topics": [], "data": "0x", "log_index": 3},
            {**tx, "address": TOKEN, "topics": [TRANSFER_TOPIC, "0x" + "00" * 12 + CORE[2:],
                                                    "0x" + "00" * 12 + RECIPIENT[2:]],
             "data": hx(amount), "log_index": 4}]
    parts = {"logs": [{"object_key": "logs/a", "rows": logs[:1]}, {"object_key": "logs/b", "rows": logs[1:]}],
             "blocks": [{"object_key": "blocks/a", "rows": headers[:1]}, {"object_key": "blocks/b", "rows": headers[1:]}],
             "transactions": [{"object_key": "transactions/a", "rows": txs}]}
    inventory = {"schema_version": "fixed_core_day_inventory_v1", "status": "complete", "chain_id": 1,
                 "day_utc": DAY, "listing_receipts_sha256": ["a" * 64], "objects": []}
    for table, records in parts.items():
        for part in records:
            inventory["objects"].append({"table": table, "object_key": part["object_key"], "size": 100,
                                         "etag": '"opaque-etag"', "rows": len(part["rows"]),
                                         "source_receipt_sha256": "b" * 64,
                                         "normalized_rows_sha256": adapter.digest(part["rows"])})
    return inventory, parts, predecessor, successor


def rebind(inventory, parts):
    for table_parts in parts.values():
        for part in table_parts:
            obj = next(obj for obj in inventory["objects"] if obj["object_key"] == part["object_key"])
            obj["rows"] = len(part["rows"])
            obj["normalized_rows_sha256"] = adapter.digest(part["rows"])


def prepare(data):
    inventory, parts, predecessor, successor = data
    inv_sha = adapter.digest(inventory)
    selection = adapter.select_core_day(inventory, parts["logs"], [CORE], expected_inventory_sha256=inv_sha, limits=LIMITS)
    return adapter.prepare_day(inventory, parts, [CORE], selection, expected_inventory_sha256=inv_sha,
                               expected_selection_sha256=adapter.digest(selection), predecessor_header=predecessor,
                               successor_header=successor, limits=LIMITS)


class AdapterChecks(unittest.TestCase):
    def test_multipart_expands_only_selected_transaction_and_exact_integer(self):
        day = prepare(fixture())
        self.assertEqual(day["coverage"]["part_count"], 5)
        self.assertEqual(day["coverage"]["all_transactions_count"], 2)
        self.assertEqual(day["coverage"]["selected_transactions"], 1)
        self.assertEqual(len(day["normalized_transactions"][0]["logs"]), 2)
        observed = adapter.observations(day, expected_prepared_sha256=adapter.digest(day), source_audit_sha256="c" * 64, selection_manifest_sha256="d" * 64)
        self.assertEqual(observed[0]["token_flows"][0]["external_out_raw"], str(2**200 + 3))
        self.assertEqual(observed[0]["archived_core_log_count"], 1)

    def test_covered_empty_day_not_selected_by_external_transfer(self):
        day = prepare(fixture(empty=True))
        self.assertEqual(day["normalized_transactions"], [])
        self.assertEqual(day["coverage"]["all_logs_count"], 2)
        self.assertEqual(adapter.observations(day, expected_prepared_sha256=adapter.digest(day), source_audit_sha256="c" * 64, selection_manifest_sha256="d" * 64), [])

    def test_unavailable_never_becomes_empty(self):
        data = fixture(empty=True); data[0]["status"] = "unavailable"
        with self.assertRaisesRegex(ValueError, "unavailable"):
            prepare(data)

    def test_missing_source_part_rejected(self):
        data = fixture(); data[1]["logs"].pop()
        with self.assertRaisesRegex(ValueError, "missing source part"):
            prepare(data)

    def test_stale_part_digest_rejected(self):
        data = fixture(); data[1]["logs"][0]["rows"][0]["data"] = "0x00"
        with self.assertRaisesRegex(ValueError, "part row hash"):
            prepare(data)

    def test_unknown_status_rejected(self):
        data = fixture(); data[1]["transactions"][0]["rows"][0]["dataset_execution_status"] = None
        rebind(data[0], data[1])
        with self.assertRaisesRegex(ValueError, "unknown transaction status"):
            prepare(data)

    def test_failed_transaction_with_logs_rejected(self):
        data = fixture(); data[1]["transactions"][0]["rows"][0]["dataset_execution_status"] = 0
        rebind(data[0], data[1])
        with self.assertRaisesRegex(ValueError, "failed transaction"):
            prepare(data)

    def test_gapped_transaction_logs_rejected(self):
        data = fixture(); data[1]["logs"][1]["rows"][0]["log_index"] = 6
        rebind(data[0], data[1])
        with self.assertRaisesRegex(ValueError, "gapped transaction logs"):
            prepare(data)

    def test_duplicate_global_log_position_rejected(self):
        data = fixture(); data[1]["logs"][1]["rows"][0]["log_index"] = 3
        rebind(data[0], data[1])
        with self.assertRaisesRegex(ValueError, "duplicate block-log"):
            prepare(data)

    def test_global_log_order_cannot_reverse_transaction_order(self):
        data = fixture(); inventory, parts, *_ = data
        second = copy.deepcopy(parts["logs"][1]["rows"][0])
        second["transaction_index"] = 1
        second["transaction_hash"] = hx(999)
        second["log_index"] = 2
        parts["logs"][1]["rows"] = [second]
        rebind(inventory, parts)
        with self.assertRaisesRegex(ValueError, "block log index reverses"):
            adapter.select_core_day(inventory, parts["logs"], [CORE],
                                    expected_inventory_sha256=adapter.digest(inventory), limits=LIMITS)

    def test_header_gap_rejected(self):
        data = fixture(); data[1]["blocks"][1]["rows"][0]["block_number"] = 12
        rebind(data[0], data[1])
        with self.assertRaisesRegex(ValueError, "header chain"):
            prepare(data)

    def test_wrong_utc_boundary_rejected(self):
        data = fixture(); data[3]["event_time_ns"] = START + 3
        with self.assertRaisesRegex(ValueError, "wrong end UTC"):
            prepare(data)

    def test_full_transaction_count_must_match_headers(self):
        data = fixture(); data[1]["transactions"][0]["rows"].pop()
        rebind(data[0], data[1])
        with self.assertRaisesRegex(ValueError, "transaction/header count"):
            prepare(data)

    def test_selection_cannot_expand_from_transfer_or_label(self):
        data = fixture(); inventory, parts, predecessor, successor = data
        inv_sha = adapter.digest(inventory)
        selection = adapter.select_core_day(inventory, parts["logs"], [CORE], expected_inventory_sha256=inv_sha, limits=LIMITS)
        selection["transactions"].append(copy.deepcopy(selection["transactions"][0]))
        with self.assertRaisesRegex(ValueError, "sealed selection differs"):
            adapter.prepare_day(inventory, parts, [CORE], selection, expected_inventory_sha256=inv_sha,
                                expected_selection_sha256=adapter.digest(selection), predecessor_header=predecessor,
                                successor_header=successor, limits=LIMITS)

    def test_selection_membership_rejects_boolean_integer_alias(self):
        inventory, parts, predecessor, successor = fixture()
        inv_sha = adapter.digest(inventory)
        selection = adapter.select_core_day(inventory, parts["logs"], [CORE], expected_inventory_sha256=inv_sha, limits=LIMITS)
        selection["transactions"][0]["chain_id"] = True
        with self.assertRaisesRegex(ValueError, "sealed selection differs"):
            adapter.prepare_day(inventory, parts, [CORE], selection, expected_inventory_sha256=inv_sha,
                                expected_selection_sha256=adapter.digest(selection), predecessor_header=predecessor,
                                successor_header=successor, limits=LIMITS)

    def test_malformed_transfer_does_not_return_partial_observation(self):
        data = fixture(); data[1]["logs"][1]["rows"][0]["data"] = "0x01"
        rebind(data[0], data[1]); day = prepare(data)
        with self.assertRaises(ValueError):
            adapter.observations(day, expected_prepared_sha256=adapter.digest(day), source_audit_sha256="c" * 64, selection_manifest_sha256="d" * 64)

    def test_population_and_limits_fail_closed(self):
        data = fixture(); inventory, parts, *_ = data
        for addresses, limits in [([CORE, CORE], LIMITS), ([CORE], {**LIMITS, "max_parts": 1})]:
            with self.assertRaises(ValueError):
                adapter.select_core_day(inventory, parts["logs"], addresses,
                                        expected_inventory_sha256=adapter.digest(inventory), limits=limits)

    def test_cross_day_header_equality_required(self):
        left = prepare(fixture())
        right = copy.deepcopy(left); right["day_utc"] = "2022-02-20"
        right["coverage"]["first_header"] = copy.deepcopy(left["coverage"]["successor_header"])
        right["coverage"]["predecessor_header"] = copy.deepcopy(left["coverage"]["last_header"])
        self.assertTrue(adapter.validate_adjacent_days(left, right))
        right["coverage"]["predecessor_header"]["transaction_count"] += 1
        with self.assertRaisesRegex(ValueError, "cross-day predecessor"):
            adapter.validate_adjacent_days(left, right)


if __name__ == "__main__":
    unittest.main(verbosity=2)
