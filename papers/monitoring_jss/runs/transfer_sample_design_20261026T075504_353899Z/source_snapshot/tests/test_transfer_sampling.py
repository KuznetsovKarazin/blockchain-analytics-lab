"""Offline fixed-sample selection, provider normalization and acquisition gates."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

PAPER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PAPER))
import sample_transfer_observations as sample
from transfer_observation import observe_transaction_log_bundle

BASE_NS = 1677628800 * 1_000_000_000
TX = "0x" + "12" * 32
BLOCK = "0x" + "34" * 32
TOKEN = "0x" + "56" * 20
OTHER = "0x" + "78" * 20
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
LIMITS = {"workers": 2, "timeout_seconds": 30, "max_response_bytes": 1048576,
          "max_log_pages_per_transaction": 10, "max_requests_total": 110,
          "retries": 0, "redirects": False}


def address_topic(address):
    return "0x" + "00" * 12 + address[2:]


def fixture():
    metadata = {"hash": TX, "block_number": 16730074, "position": 13,
                "timestamp": "2023-03-01T00:00:35.000000Z", "status": "ok"}
    def log(index, address, topics, data):
        return {"index": index, "address": {"hash": address},
                "smart_contract": {"hash": OTHER}, "topics": topics, "data": data,
                "transaction_hash": TX, "block_number": 16730074, "block_hash": BLOCK}
    logs = [log(43, sample.CORE, ["0x" + "ab" * 32, None, None, None], "0x01"),
            log(44, TOKEN, [TRANSFER, address_topic(OTHER), address_topic(sample.CORE), None],
                "0x" + f"{2**200 + 17:064x}"),
            log(45, TOKEN, [TRANSFER, address_topic(sample.CORE), address_topic(OTHER), "0x" + f"{9:064x}"], "0x")]
    selected = {"selection_index": 0, "transaction_hash": TX,
                "expected_block": {"block_number": 16730074, "block_hash": BLOCK,
                                   "transaction_index": 13, "event_time_ns": BASE_NS + 35_000_000_000},
                "first_log_index": 43, "archived_core_logs": 1}
    bundle = sample.normalize_bundle(selected, metadata, logs)
    archive = [sample.payload(bundle["logs"][0], bundle)]
    selected["archived_core_payload_sha256"] = sample.digest(archive)
    return metadata, logs, selected, archive


class FakeFetcher:
    def __init__(self, metadata, pages):
        self.metadata, self.pages, self.calls = metadata, list(pages), []

    def fetch(self, path, params, folder, key):
        self.calls.append((path, params, key))
        value = self.pages.pop(0) if path.endswith("/logs") else self.metadata
        raw = sample.canonical(value)
        url = sample.BASE + path + ("?" + urlencode(sorted(params.items())) if params else "")
        receipt = {"key": key, "url": url, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "status": 200}
        with (folder / key).open("xb") as handle:
            handle.write(raw)
        sample.put_json(folder / (key + ".receipt.json"), receipt)
        return value, raw, receipt


class SamplingTests(unittest.TestCase):
    def test_selection_is_first_ten_unique_and_full_day_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "synthetic.jsonl"
            rows = []
            for tx in range(218):
                for index in range(6 if tx < 157 else 5):
                    rows.append({"chain_id": 1, "address": sample.CORE,
                                 "block_number": 1000 + tx, "block_hash": "0x" + f"{tx + 1:064x}",
                                 "transaction_index": 0, "transaction_hash": "0x" + f"{tx + 9:064x}",
                                 "log_index": index, "event_time_ns": BASE_NS + tx * 12_000_000_000,
                                 "topics": [], "data": "0x"})
            path.write_bytes(b"".join(sample.canonical(row) + b"\n" for row in rows))
            selected, archive = sample.select_transactions(path, sample.file_hash(path))
            self.assertEqual(len(selected), 10)
            self.assertEqual([row["transaction_hash"] for row in selected], ["0x" + f"{i + 9:064x}" for i in range(10)])
            self.assertEqual(sum(map(len, archive.values())), 60)
            with self.assertRaises(ValueError):
                sample.select_transactions(path, "0" * 64)
            path.write_bytes(b"".join(sample.canonical(row) + b"\n" for row in reversed(rows)))
            with self.assertRaises(ValueError):
                sample.select_transactions(path, sample.file_hash(path))

    def test_normalizer_preserves_padding_semantics_and_recipient_distinction(self):
        metadata, logs, selected, _ = fixture()
        bundle = sample.normalize_bundle(selected, metadata, list(reversed(logs)))
        self.assertEqual([row["log_index"] for row in bundle["logs"]], [43, 44, 45])
        self.assertEqual([len(row["topics"]) for row in bundle["logs"]], [1, 3, 4])
        self.assertEqual(bundle["logs"][0]["address"], sample.CORE)
        self.assertNotEqual(logs[0]["smart_contract"]["hash"], bundle["logs"][0]["address"])
        self.assertNotIn("chain_id", bundle["logs"][0])
        self.assertNotIn("event_time_ns", bundle["logs"][0])
        logs[0]["address_hash"] = {"hash": OTHER}
        with self.assertRaises(ValueError):
            sample.normalize_bundle(selected, metadata, logs)

    def test_exact_nanoseconds_no_timezone_guess_or_truncation(self):
        self.assertEqual(sample.timestamp_ns("2023-03-01T00:00:00.000000001Z"), BASE_NS + 1)
        self.assertEqual(sample.timestamp_ns("2023-03-01T00:00:00.123456789+00:00"), BASE_NS + 123456789)
        for value in ("2023-03-01T00:00:00", "2023-03-01T00:00:00+01:00", "2023-03-01T00:00:00.1234567890Z"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                sample.timestamp_ns(value)

    def test_fail_closed_identity_duplicates_missing_position_and_topic_holes(self):
        for failure in ("transaction", "block", "index", "position", "timestamp", "log_timestamp", "topics", "removed"):
            with self.subTest(failure=failure):
                metadata, logs, selected, _ = fixture()
                if failure == "transaction":
                    logs[0]["transaction_hash"] = "0x" + "ff" * 32
                elif failure == "block":
                    logs[0]["block_hash"] = "0x" + "ff" * 32
                elif failure == "index":
                    logs[1]["index"] = logs[0]["index"]
                elif failure == "position":
                    del metadata["position"]
                elif failure == "timestamp":
                    metadata["timestamp"] = "2023-03-01T00:00:35.000000001Z"
                elif failure == "log_timestamp":
                    logs[0]["block_timestamp"] = "2023-03-01T00:00:34Z"
                elif failure == "topics":
                    logs[0]["topics"] = [None, "0x" + "11" * 32]
                else:
                    logs[0]["removed"] = True
                with self.assertRaises(ValueError):
                    sample.normalize_bundle(selected, metadata, logs)

    def test_full_paginated_collection_joins_archive_and_real_observer(self):
        metadata, logs, selected, archive = fixture()
        cursor = {"index": 44, "items_count": 50, "block_number": 16730074}
        fake = FakeFetcher(metadata, [{"items": list(reversed(logs[1:])), "next_page_params": cursor},
                                      {"items": logs[:1], "next_page_params": None}])
        with tempfile.TemporaryDirectory() as temp:
            result = sample.acquire_one(selected, {"limits": LIMITS}, "1" * 64, archive,
                                        Path(temp), fake, observe_transaction_log_bundle)
            self.assertEqual(result["status"], "accepted_development_observation", result)
            self.assertTrue(result["provider_pagination_exhausted"])
            self.assertTrue(result["archived_core_payloads_match"])
            self.assertEqual(result["observation_counts"]["erc20_shaped"], 1)
            self.assertEqual(result["observation_counts"]["erc721_shaped"], 1)
            observation = json.loads((Path(temp) / "tx_00/transfer_observation.json").read_bytes())
            self.assertEqual(observation["token_flows"][0]["external_in_raw"], str(2**200 + 17))
            self.assertFalse(observation["evidence"]["raw_receipt_acquired"])
            self.assertEqual(fake.calls[-1][1], cursor)

    def test_no_partial_observation_after_cursor_loop_cap_or_core_mismatch(self):
        for failure in ("loop", "cap", "core", "missing_terminal"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                metadata, logs, selected, archive = fixture()
                cursor = {"index": 44, "items_count": 50}
                config = {"limits": dict(LIMITS)}
                if failure == "loop":
                    pages = [{"items": logs, "next_page_params": cursor}, {"items": [], "next_page_params": cursor}]
                elif failure == "cap":
                    config["limits"]["max_log_pages_per_transaction"] = 1
                    pages = [{"items": logs, "next_page_params": cursor}]
                elif failure == "missing_terminal":
                    pages = [{"items": logs}]
                else:
                    logs[0]["data"] = "0x02"
                    pages = [{"items": logs, "next_page_params": None}]
                result = sample.acquire_one(selected, config, "1" * 64, archive,
                                            Path(temp), FakeFetcher(metadata, pages), observe_transaction_log_bundle)
                self.assertEqual(result["status"], "not_accepted")
                self.assertIsNone(result["provider_logs"])
                self.assertFalse((Path(temp) / "tx_00/transfer_observation.json").exists())

    def test_unknown_status_is_unavailable_not_zero_flow(self):
        metadata, logs, selected, archive = fixture()
        metadata["status"] = None
        with tempfile.TemporaryDirectory() as temp:
            result = sample.acquire_one(selected, {"limits": LIMITS}, "1" * 64, archive,
                                        Path(temp), FakeFetcher(metadata, [{"items": logs, "next_page_params": None}]),
                                        observe_transaction_log_bundle)
            self.assertEqual(result["status"], "not_accepted")
            self.assertIn("ObservationUnavailable", result["reason"])
            self.assertNotIn("observation_counts", result)

    def test_pagination_rejects_url_injection_and_noninteger_params(self):
        for params in ({"url": "https://example.org"}, {}, {"index": True}, {"index": "0"}):
            with self.subTest(params=params), self.assertRaises(ValueError):
                sample.validate_page({"items": [], "next_page_params": params})
        self.assertEqual(sample.validate_page({"items": [], "next_page_params": None}), ([], None))

    def test_response_cap_and_global_cancellation_do_not_retry(self):
        class Response(io.BytesIO):
            status = 200
            headers = {"Content-Length": "1048577"}
            def geturl(self):
                return sample.BASE + "transactions/" + TX
        class Opener:
            calls = 0
            def open(self, request, timeout):
                self.calls += 1
                return Response(b"not read")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake = Opener()
            fetcher = sample.BoundedFetcher(LIMITS, root)
            with patch.object(sample.urllib.request, "build_opener", return_value=fake):
                with self.assertRaises(sample.AcquisitionFailure):
                    fetcher.fetch("transactions/" + TX, {}, root, "oversize.json")
                with self.assertRaises(sample.AcquisitionFailure):
                    fetcher.fetch("transactions/" + TX, {}, root, "cancelled.json")
            self.assertEqual(fake.calls, 1)
            self.assertEqual(fetcher.calls, 1)
            self.assertFalse((root / "cancelled.json").exists())
            self.assertEqual((root / "oversize.json").read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
