"""Adversarial synthetic tests: no provider, chain or incident payloads."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import transfer_observation as obs

A = "0x" + "11" * 20
B = "0x" + "22" * 20
C = "0x" + "33" * 20
TOKEN = "0x" + "44" * 20
TOKEN2 = "0x" + "55" * 20
TX = "0x" + "66" * 32
BLOCK = "0x" + "77" * 32
TIME_NS = 1709510400000000000
BASE = "https://example.test/api/v2/transactions/" + TX


def topic_address(address):
    return "0x" + "0" * 24 + address[2:]


def transfer(sender=C, recipient=A, amount=9, token=TOKEN, index=101):
    return {"address": {"hash": token}, "smart_contract": {"hash": B},
            "topics": [obs.TRANSFER_TOPIC, topic_address(sender), topic_address(recipient), None],
            "data": "0x" + format(amount, "064x"), "index": index,
            "transaction_hash": TX, "block_hash": BLOCK, "block_number": 100}


def fixture(logs=None, status="ok", page_size=2):
    """Create independent declared source records, provider bytes and bundle."""
    logs = copy.deepcopy([transfer()] if logs is None else logs)
    metadata = {"hash": TX, "block_number": 100, "position": 7,
                "status": status, "timestamp": "2024-03-04T00:00:00Z"}
    raw_sources = {}
    def capture(key, body, url):
        raw = obs.canonical_json_bytes(body)
        raw_sources[key] = raw
        return {"key": key, "url": url, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    record = {"schema_version": "transfer_source_record_v1",
              "source_kind": "blockscout_v2_paginated_transaction_logs",
              "chain_id": 1, "requested_transaction_hash": TX,
              "acquired_at_utc": "2026-10-26T09:00:00+00:00",
              "normalizer_source_sha256": "a" * 64,
              "selection_manifest_sha256": "b" * 64,
              "expected_block": {"block_hash": BLOCK, "block_number": 100,
                  "transaction_index": 7, "event_time_ns": TIME_NS},
              "metadata": capture("metadata.json", metadata, BASE),
              "raw_receipt_acquired": False, "pages": []}
    chunks = [logs[i:i + page_size] for i in range(0, len(logs), page_size)] or [[]]
    params = {}
    for i, chunk in enumerate(chunks):
        next_params = {"index": i + 1} if i < len(chunks) - 1 else None
        url = BASE + "/logs" + ("?" + urlencode(params) if params else "")
        entry = capture(f"logs_{i}.json", {"items": chunk, "next_page_params": next_params}, url)
        entry.update(request_params=params, next_page_params=next_params, item_count=len(chunk))
        record["pages"].append(entry)
        params = next_params
    normalized = []
    for item in logs:
        topics = list(item["topics"])
        while topics and topics[-1] is None:
            topics.pop()
        normalized.append({"address": item["address"]["hash"].lower(),
            "topics": topics, "data": item["data"], "log_index": item["index"],
            "block_number": item["block_number"], "block_hash": item["block_hash"],
            "transaction_hash": item["transaction_hash"], "transaction_index": 7,
            "removed": item.get("removed")})
    normalized.sort(key=lambda row: row["log_index"])
    bundle = {"schema_version": "transaction_log_bundle_v1", "chain_id": 1,
              "block_number": 100, "block_hash": BLOCK, "transaction_hash": TX,
              "transaction_index": 7, "event_time_ns": TIME_NS,
              "receipt_status": {"ok": 1, "error": 0}.get(status), "logs": normalized}
    bind_bundle(bundle, record)
    return bundle, record, raw_sources


def bind_bundle(bundle, record):
    encoded = obs.canonical_json_bytes(bundle)
    record["normalized_bundle_sha256"] = hashlib.sha256(encoded).hexdigest()
    record["normalized_bundle_bytes"] = len(encoded)
    return encoded


def bind_raw(record, sources, item_record, body):
    data = obs.canonical_json_bytes(body)
    sources[item_record["key"]] = data
    item_record["sha256"] = hashlib.sha256(data).hexdigest()
    item_record["bytes"] = len(data)


def observe(f, population=None):
    bundle, record, sources = f
    return obs.observe_transaction_log_bundle(obs.canonical_json_bytes(bundle), record,
        expected_source_record_sha256=obs.canonical_sha256(record),
        monitored_addresses=[A] if population is None else population, raw_sources=sources)


class TestTransferObservation(unittest.TestCase):
    def test_evidence_and_nonzero_global_log_index(self):
        result = observe(fixture())
        self.assertEqual(result["status"], "observed_success")
        self.assertEqual(result["counts"], {"logs": 1, "erc20_shaped": 1, "erc721_shaped": 0,
            "opaque": 0, "monitored_erc20_shaped": 1, "zero_value_transfers": 0})
        self.assertEqual(result["token_flows"][0]["external_in_raw"], "9")
        self.assertFalse(result["evidence"]["raw_receipt_acquired"])
        self.assertFalse(result["evidence"]["token_erc20_compliance_verified"])
        self.assertIsNone(result["evidence"]["observed_time"])

    def test_all_flow_categories_and_self_net(self):
        rows = [transfer(C, A, 11, index=101), transfer(A, C, 17, index=102),
                transfer(A, B, 5, index=103), transfer(A, A, 7, index=104),
                transfer(obs.ZERO_ADDRESS, A, 13, index=105),
                transfer(A, obs.ZERO_ADDRESS, 3, index=106), transfer(C, A, 0, index=107)]
        result = observe(fixture(rows), [A, B])
        flow = result["token_flows"][0]
        self.assertEqual([flow[k] for k in ("external_in_raw", "external_out_raw", "internal_raw",
            "mint_from_zero_raw", "burn_to_zero_raw", "net_external_in_raw", "net_event_in_raw")],
            ["11", "17", "12", "13", "3", "-6", "4"])
        self.assertEqual(flow["internal_count"], 2)
        self.assertEqual(flow["transfer_log_count"], 7)
        self.assertEqual(result["counts"]["zero_value_transfers"], 1)
        self.assertEqual(observe(fixture([transfer(A, A, 99)]))["token_flows"][0]["net_event_in_raw"], "0")

    def test_uint256_and_larger_sums_are_decimal_strings(self):
        maximum = 2**256 - 1
        rows = [transfer(C, A, maximum, index=101), transfer(C, A, maximum, index=102),
                transfer(A, C, maximum, token=TOKEN2, index=103)]
        result = observe(fixture(rows))
        first, second = result["token_flows"]
        self.assertEqual(first["external_in_raw"], str(2 * maximum))
        self.assertEqual(second["net_external_in_raw"], str(-maximum))
        self.assertEqual(result["raw_amount_encoding"], "base10_integer_string")
        restored = json.loads(obs.canonical_json_bytes(result))
        self.assertEqual(restored["token_flows"], result["token_flows"])
        self.assertTrue(all(isinstance(v, str) for row in restored["token_flows"]
                            for k, v in row.items() if k.endswith("_raw")))

    def test_two_tokens_never_added_together(self):
        result = observe(fixture([transfer(amount=5, index=101), transfer(amount=90, token=TOKEN2, index=102)]))
        self.assertEqual([(r["token_address"], r["external_in_raw"]) for r in result["token_flows"]],
                         [(TOKEN, "5"), (TOKEN2, "90")])

    def test_nft_topic_collision_and_opaque_logs(self):
        nft = transfer(index=102)
        nft["topics"][3] = "0x" + format(123, "064x")
        nft["data"] = "0x"
        opaque = transfer(index=103)
        opaque["topics"] = ["0x" + "99" * 32, None, None, None]
        result = observe(fixture([transfer(), nft, opaque]))
        self.assertEqual(result["counts"]["erc721_shaped"], 1)
        self.assertEqual(result["counts"]["opaque"], 1)
        self.assertEqual(result["token_flows"][0]["external_in_raw"], "9")

    def test_matching_malformed_event_rejects_entire_bundle(self):
        modifications = [lambda r: r.update(data="0x"),
            lambda r: r.update(data="0x" + "01" * 33),
            lambda r: r.update(topics=r["topics"][:2]),
            lambda r: r["topics"].__setitem__(1, "0x01" + "00" * 31),
            lambda r: r["topics"].__setitem__(3, "0x" + "01" * 32),
            lambda r: r["topics"].__setitem__(1, None)]
        for modify in modifications:
            with self.subTest(modify=modify):
                bad = transfer(index=102)
                modify(bad)
                with self.assertRaises(obs.ObservationError):
                    observe(fixture([transfer(), bad]))

    def test_zero_empty_unknown_and_failed_are_distinct(self):
        success = observe(fixture([]))
        failed = observe(fixture([], status="error"))
        self.assertEqual(success["status"], "observed_success")
        self.assertEqual(failed["status"], "observed_failed_transaction")
        self.assertEqual(success["token_flows"], [])
        with self.assertRaises(obs.ObservationUnavailable):
            observe(fixture([], status="pending"))
        with self.assertRaises(obs.ObservationError):
            observe(fixture([transfer()], status="error"))

    def test_null_missing_metadata_is_not_empty_success(self):
        for body in [None, {"hash": TX, "block_number": None, "position": None, "timestamp": None}]:
            f = fixture([])
            bind_raw(f[1], f[2], f[1]["metadata"], body)
            with self.assertRaises(obs.ObservationUnavailable):
                observe(f)

    def test_complete_provider_presentation_order_does_not_change_features(self):
        rows = [transfer(index=101), transfer(A, C, 3, index=102), transfer(index=103)]
        ascending = observe(fixture(rows))
        descending = observe(fixture(rows[::-1], page_size=1))
        self.assertEqual(ascending["token_flows"], descending["token_flows"])
        self.assertEqual(ascending["counts"], descending["counts"])

    def test_normalized_order_duplicates_and_gaps_rejected(self):
        f = fixture([transfer(index=101), transfer(index=102)])
        f[0]["logs"].reverse()
        bind_bundle(f[0], f[1])
        with self.assertRaises(obs.ObservationError):
            observe(f)
        for indices in [(101, 101), (101, 103)]:
            with self.subTest(indices=indices), self.assertRaises(obs.ObservationError):
                observe(fixture([transfer(index=indices[0]), transfer(index=indices[1])]))

    def test_mixed_transaction_or_block_identity_rejected(self):
        for key, value in [("transaction_hash", "0x" + "88" * 32),
                           ("block_hash", "0x" + "88" * 32), ("block_number", 101)]:
            bad = transfer(index=102)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(obs.ObservationError):
                observe(fixture([transfer(), bad]))

    def test_emitter_is_address_not_transaction_smart_contract(self):
        result = observe(fixture())  # smart_contract B differs from emitter TOKEN
        self.assertEqual(result["token_flows"][0]["token_address"], TOKEN)
        bad = transfer()
        bad["address_hash"] = {"hash": TOKEN2}
        with self.assertRaises(obs.ObservationError):
            observe(fixture([bad]))
        f = fixture()
        page = json.loads(f[2]["logs_0.json"])
        del page["items"][0]["address"]
        bind_raw(f[1], f[2], f[1]["pages"][0], page)
        with self.assertRaises(obs.ObservationError):
            observe(f)

    def test_removed_true_and_bool_indices_rejected(self):
        for key, value in [("removed", True), ("index", True)]:
            bad = transfer()
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(obs.ObservationError):
                observe(fixture([bad]))
        f = fixture([transfer(index=1)])
        f[0]["logs"][0]["log_index"] = True
        bind_bundle(f[0], f[1])
        with self.assertRaises(obs.ObservationError):
            observe(f)

    def test_optional_provider_log_timestamp_must_agree(self):
        row = transfer()
        row["block_timestamp"] = "2024-03-04T00:00:00Z"
        self.assertEqual(observe(fixture([row]))["counts"]["logs"], 1)
        row["block_timestamp"] = "2024-03-04T00:00:01Z"
        with self.assertRaises(obs.ObservationError):
            observe(fixture([row]))

    def test_manifest_and_raw_bytes_bound_independently(self):
        f = fixture()
        expected = obs.canonical_sha256(f[1])
        f[1]["selection_manifest_sha256"] = "c" * 64
        with self.assertRaises(obs.ObservationError):
            obs.observe_transaction_log_bundle(obs.canonical_json_bytes(f[0]), f[1],
                expected_source_record_sha256=expected, monitored_addresses=[A], raw_sources=f[2])
        f = fixture()
        f[2]["logs_0.json"] += b" "
        with self.assertRaises(obs.ObservationError):
            observe(f)
        f = fixture()
        f[0]["logs"][0]["data"] = "0x" + "00" * 32
        with self.assertRaises(obs.ObservationError):
            observe(f)
        bind_bundle(f[0], f[1])
        with self.assertRaises(obs.ObservationError):  # bound but contradicts raw provider
            observe(f)

    def test_terminal_pagination_required_and_cursor_bound(self):
        f = fixture([transfer(index=101), transfer(index=102), transfer(index=103)])
        f[1]["pages"].pop()
        del f[2]["logs_1.json"]
        with self.assertRaises(obs.ObservationError):
            observe(f)
        f = fixture([transfer(index=101), transfer(index=102), transfer(index=103)])
        f[1]["pages"][1]["request_params"] = {"index": 42}
        with self.assertRaises(obs.ObservationError):
            observe(f)
        f = fixture()
        f[1]["pages"][0]["url"] += "?topic=filtered"
        with self.assertRaises(obs.ObservationError):
            observe(f)

    def test_extra_raw_sources_and_false_receipt_claim_rejected(self):
        f = fixture()
        f[2]["untracked.json"] = b"{}"
        with self.assertRaises(obs.ObservationError):
            observe(f)
        f = fixture()
        f[1]["raw_receipt_acquired"] = True
        with self.assertRaises(obs.ObservationError):
            observe(f)

    def test_duplicates_and_nonfinite_json_rejected(self):
        f = fixture()
        raw = b'{"items":[],"items":[],"next_page_params":null}'
        entry = f[1]["pages"][0]
        f[2][entry["key"]] = raw
        entry.update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
        with self.assertRaises(obs.ObservationError):
            observe(f)
        for value in ["NaN", "Infinity", "-Infinity"]:
            f = fixture()
            raw = ('{"items":[],"next_page_params":null,"extra":' + value + '}').encode()
            entry = f[1]["pages"][0]
            f[2][entry["key"]] = raw
            entry.update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
            with self.subTest(value=value), self.assertRaises(obs.ObservationError):
                observe(f)

    def test_explicit_population_and_nanosecond_time(self):
        for population in [[], [A, A], [obs.ZERO_ADDRESS]]:
            with self.subTest(population=population), self.assertRaises(obs.ObservationError):
                observe(fixture(), population)
        self.assertEqual(obs.utc_timestamp_ns("2024-03-04T00:00:00.123456789Z"), TIME_NS + 123456789)
        for timestamp in ["2024-03-04T00:00:00", "2024-03-04T00:00:00+01:00", "2024-03-04T00:00:60Z"]:
            with self.subTest(timestamp=timestamp), self.assertRaises(obs.ObservationError):
                obs.utc_timestamp_ns(timestamp)

    def test_future_bundle_changes_cannot_mutate_prior_observation(self):
        initial = fixture()
        result = observe(initial)
        retained = obs.canonical_json_bytes(result)
        unrelated = fixture([transfer(amount=2**200)])
        observe(unrelated)
        initial[0]["logs"].clear()
        self.assertEqual(obs.canonical_json_bytes(result), retained)
        self.assertEqual(observe(fixture()), result)  # deterministic complete-bundle operation

    def test_nonmonitored_transfer_is_counted_but_not_attributed(self):
        result = observe(fixture([transfer(B, C, 10)]))
        self.assertEqual(result["counts"]["erc20_shaped"], 1)
        self.assertEqual(result["counts"]["monitored_erc20_shaped"], 0)
        self.assertEqual(result["token_flows"], [])


if __name__ == "__main__":
    unittest.main()
