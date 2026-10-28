"""Focused synthetic checks for the offline post-decision reference auditor.

All hashes, source documents, rows and assertions constructed here are invented.
This module runs no historical experiment, HTTP call or previous test suite.
"""
from __future__ import annotations

import argparse
import copy
from datetime import date, datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
PAPER = HERE.parents[1]
TARGET = HERE / "archive_reference_audit.py"
DAY_NS = 86_400_000_000_000


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def h(number):
    return "0x" + format(number, "064x")


def invented_day():
    day = "2022-03-20"
    start = (date.fromisoformat(day) - date(1970, 1, 1)).days * DAY_NS
    stamp = start + 123_000_000_000
    core_a, core_b, token = ("0x" + x * 40 for x in "abc")
    header = {"block_number": 100, "block_hash": h(100), "parent_hash": h(99),
              "event_time_ns": stamp, "transaction_count": 4}
    txs = [{"chain_id": 1, "block_number": 100, "block_hash": h(100),
            "transaction_hash": h(1000 + index), "transaction_index": index,
            "event_time_ns": stamp, "dataset_execution_status": 0 if index == 3 else 1}
           for index in range(4)]
    logs = []
    def add(index, address):
        tx = {k: v for k, v in txs[index].items() if k != "dataset_execution_status"}
        logs.append({**tx, "address": address, "log_index": len(logs)})
    add(0, core_a)
    add(0, token)
    add(0, core_b)
    add(1, token)  # No core emitter, regardless of a Transfer's sender/topic.
    add(2, core_b)
    return {"day": day, "start": start, "core_a": core_a, "core_b": core_b,
            "token": token, "headers": [header], "transactions": txs, "logs": logs}


def raw_table(rows, kind, pa):
    rename = {"blocks": {"block_number": "number", "block_hash": "hash", "event_time_ns": "timestamp"},
              "transactions": {"transaction_hash": "hash", "event_time_ns": "block_timestamp",
                               "dataset_execution_status": "receipt_status"},
              "logs": {"event_time_ns": "block_timestamp"}}[kind]
    columns = {}
    for key in rows[0]:
        if key == "chain_id":
            continue
        values = [row[key] for row in rows]
        typ = pa.timestamp("ns") if key == "event_time_ns" else pa.int64() if type(values[0]) is int else pa.string()
        columns[rename.get(key, key)] = pa.array(values, type=typ)
    return pa.table(columns)


def load_target():
    spec = importlib.util.spec_from_file_location("phase16_archive_reference_under_test", TARGET)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def normalized_table(rows, pa):
    columns = {}
    for key in rows[0]:
        if key == "chain_id":
            continue
        values = [row[key] for row in rows]
        columns[key] = pa.array(values, type=pa.int64() if type(values[0]) is int else pa.string())
    return pa.table(columns)


class ArchiveReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_target()
        import pyarrow as pa
        import pyarrow.compute as pc
        import pyarrow.parquet as pq
        import numpy as np
        cls.pa, cls.pc, cls.pq, cls.np = pa, pc, pq, np

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="phase16_reference_audit_synthetic_")
        self.root = Path(self.temp.name)
        self.f = invented_day()

    def tearDown(self):
        self.temp.cleanup()

    def candidates(self, count=2):
        return {"schema_version": "article2_phase16_primary_candidate_inventory_v1",
                "status": "PRIMARY_CANDIDATES_EXTRACTED_NOT_ADJUDICATED",
                "decision_study_sha256": "a" * 64, "created_utc": "2026-01-03T00:00:00+00:00",
                "cases": [{"case_id": case, "candidates": [{"chain_id": 1, "transaction_hash": h(1000 + i),
                             "reported_role": "UNKNOWN", "synthetic_only": True} for i in reversed(range(count))]}
                          for case in ("lifi_20220320", "revest_20220327")]}

    def active(self):
        result = {}
        for case, address, selected in (("lifi_20220320", self.f["core_a"], (0,)),
                                        ("revest_20220327", self.f["core_b"], (0, 2))):
            observations = {}
            for index in selected:
                identity = {k: v for k, v in self.f["transactions"][index].items() if k != "dataset_execution_status"}
                observations[(1, identity["transaction_hash"])] = {"transaction": identity, "archived_core_log_count": 1}
            result[case] = {"config": {"case_id": case, "population_addresses": [address],
                           "window": {"start_date_utc": "2022-02-19", "end_date_utc_exclusive": "2022-03-28"}},
                           "observations": observations}
        return result

    def inspect(self, *, tx=None, logs=None, headers=None, active=None, keys=None, counts=None):
        return self.module.inspect_day(self.f["day"],
            normalized_table(tx or self.f["transactions"], self.pa),
            normalized_table(logs or self.f["logs"], self.pa),
            normalized_table(headers or self.f["headers"], self.pa),
            active if active is not None else self.active(),
            keys if keys is not None else {(1, r["transaction_hash"]) for r in self.f["transactions"]} | {(1, h(99999))},
            counts if counts is not None else {"all_transaction_rows": 4, "all_log_identity_rows": 5},
            self.pa, self.pc, self.np)

    def test_candidate_cap_is_canonical_and_overflow_retained(self):
        result = self.module.select_candidates(self.candidates(66), "a" * 64, "2026-01-02T00:00:00+00:00")
        self.assertEqual([case["case_id"] for case in result], ["lifi_20220320", "revest_20220327"])
        for case in result:
            rows = case["candidates"]
            self.assertEqual(len(rows), 66)
            self.assertEqual([r["transaction_hash"] for r in rows], sorted(r["transaction_hash"] for r in rows))
            self.assertEqual([r["audit_rank"] for r in rows], list(range(1, 67)))
            self.assertEqual(sum(r["within_cap"] for r in rows), 64)
            self.assertTrue(all(r["reported_role"] == "UNKNOWN" for r in rows))

    def test_candidate_stage_identity_duplicates_and_case_population_rejected(self):
        mutations = [lambda x: x.update(decision_study_sha256="b" * 64),
                     lambda x: x.update(created_utc="2026-01-01T00:00:00+00:00"),
                     lambda x: x["cases"].pop(),
                     lambda x: x["cases"][0]["candidates"].append(copy.deepcopy(x["cases"][0]["candidates"][0])),
                     lambda x: x["cases"][0]["candidates"][0].update(chain_id=56),
                     lambda x: x["cases"][0]["candidates"][0].update(transaction_hash="0x" + "G" * 64)]
        for mutation in mutations:
            candidate = self.candidates()
            mutation(candidate)
            with self.subTest(mutation=mutations.index(mutation)), self.assertRaises(ValueError):
                self.module.select_candidates(candidate, "a" * 64, "2026-01-02T00:00:00+00:00")

    def test_archive_code_missing_or_mismatched_in_pre_reference_seal_rejected(self):
        args = SimpleNamespace(study_manifest=self.root / "not_read_study.json", expected_study_sha256="a" * 64)
        for study in ({}, {"reference_archive_auditor_sha256": "0" * 64}):
            with self.subTest(study=study), \
                 patch.object(self.module.join, "load_study", return_value=(study, [])), \
                 patch.object(self.module.join, "pinned") as source_read:
                with self.assertRaisesRegex(ValueError, "archive auditor differs from pre-reference study seal"):
                    self.module.load_context(args)
                source_read.assert_not_called()

    def test_exact_hash_selection_and_no_core_counts_from_complete_logs(self):
        found = self.inspect()
        self.assertEqual(set(found), {h(1000 + i) for i in range(4)})
        self.assertEqual(found[h(1000)]["core_counts"], {"lifi_20220320": 1, "revest_20220327": 1})
        self.assertEqual(found[h(1001)]["core_counts"], {"lifi_20220320": 0, "revest_20220327": 0})
        self.assertEqual(found[h(1002)]["core_counts"], {"lifi_20220320": 0, "revest_20220327": 1})
        self.assertEqual(found[h(1003)]["dataset_execution_status"], 0)
        self.assertEqual(found[h(1003)]["core_counts"], {"lifi_20220320": 0, "revest_20220327": 0})
        self.assertNotIn(h(99999), found)
        for row in found.values():
            self.assertEqual(row["day_utc"], self.f["day"])
            self.assertEqual(set(row["transaction"]), {"chain_id", "transaction_hash", "block_hash",
                             "block_number", "transaction_index", "event_time_ns"})
            self.assertNotIn("adjudication_status", row)
            self.assertNotIn("attack_label", row)

    def test_independent_review_row_counts_cannot_be_replaced_by_subset(self):
        with self.assertRaises(ValueError):
            self.inspect(logs=self.f["logs"][:-1])
        with self.assertRaises(ValueError):
            self.inspect(tx=self.f["transactions"][:-1])

    def test_selected_input_core_count_or_identity_mismatch_rejected(self):
        for field, value in (("archived_core_log_count", 2), ("transaction", self.f["transactions"][1])):
            active = self.active()
            active["lifi_20220320"]["observations"][(1, h(1000))][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.inspect(active=active)

    def test_missing_selected_membership_cannot_be_called_no_core(self):
        active = self.active()
        active["lifi_20220320"]["observations"].clear()
        with self.assertRaises(ValueError):
            self.inspect(active=active)

    def test_candidate_status_and_header_identity_must_agree_with_complete_tables(self):
        bad = copy.deepcopy(self.f["transactions"])
        bad[0]["dataset_execution_status"] = 0
        with self.assertRaises(ValueError):
            self.inspect(tx=bad)
        bad = copy.deepcopy(self.f["transactions"])
        bad[1]["block_hash"] = h(88888)
        with self.assertRaises(ValueError):
            self.inspect(tx=bad)

    def test_absent_outside_window_and_overcap_candidates_preserve_unknowns(self):
        case = "lifi_20220320"
        run = self.active()[case]
        candidate = {"chain_id": 1, "transaction_hash": h(1001), "audit_rank": 1, "within_cap": True}
        evidence = {"path": "synthetic_evidence.json", "sha256": "1" * 64}
        audit, facts = self.module.make_record(case, candidate, None, run, evidence, [])
        self.assertEqual(facts["archive_disposition"], "UNAVAILABLE_NOT_LOCATED_IN_DECLARED_SOURCE_UNION")
        self.assertIsNone(facts["actual_identity_or_unavailable"])
        self.assertIsNone(facts["in_fixed_window"])
        self.assertEqual(audit["core_selection_status"], "UNAVAILABLE")
        self.assertIsNone(audit["core_log_count"])
        self.assertFalse(audit["full_core_scan_or_terminal_logs_complete"])
        outside = copy.deepcopy(run)
        outside["config"]["window"]["end_date_utc_exclusive"] = self.f["day"]
        match = self.inspect()[h(1001)]
        audit, facts = self.module.make_record(case, candidate, match, outside, evidence, [])
        self.assertEqual(facts["archive_disposition"], "VERIFIED_OUTSIDE_FIXED_WINDOW")
        self.assertFalse(facts["in_fixed_window"])
        self.assertEqual(audit["identity_status"], "VERIFIED")
        self.assertEqual(audit["core_selection_status"], "UNAVAILABLE")
        self.assertIsNone(audit["core_log_count"])
        audit, facts = self.module.make_record(case, candidate | {"within_cap": False, "audit_rank": 65},
                                               match, run, evidence, [])
        self.assertEqual(facts["archive_disposition"], "UNVERIFIED_DUE_TO_CAP")
        self.assertIsNone(facts["actual_identity_or_unavailable"])
        self.assertEqual(audit["identity_status"], "UNAVAILABLE")

    def test_generated_source_records_do_not_adjudicate_attack_role(self):
        matches = self.inspect()
        run = self.active()["lifi_20220320"]
        for index in (0, 1, 3):
            candidate = {"chain_id": 1, "transaction_hash": h(1000 + index), "audit_rank": index + 1, "within_cap": True}
            audit, facts = self.module.make_record("lifi_20220320", candidate, matches[candidate["transaction_hash"]],
                run, {"path": "synthetic_evidence.json", "sha256": "1" * 64}, [])
            self.assertFalse(facts["attack_role_adjudicated"])
            self.assertEqual(audit["schema_version"], "article2_phase16_reference_source_audit_v1")
            self.assertEqual(audit["core_selection_status"], "SELECTED" if index == 0 else "OBSERVED_NO_CORE_EMITTER")
            self.assertEqual(audit["success_status"], "FAILED" if index == 3 else "SUCCESS")
            self.assertTrue(audit["full_core_scan_or_terminal_logs_complete"])
            self.assertNotIn("adjudication_status", facts)

    def test_partial_union_scan_cannot_promote_an_already_found_match(self):
        case = "lifi_20220320"
        match = self.inspect()[h(1000)]
        candidate = {"chain_id": 1, "transaction_hash": h(1000), "audit_rank": 1, "within_cap": True}
        audit, facts = self.module.make_record(case, candidate, match, self.active()[case],
            {"path": "synthetic_evidence.json", "sha256": "1" * 64}, [], scan_complete=False)
        self.assertEqual(facts["archive_disposition"], "UNVERIFIED_DUE_TO_CAP")
        self.assertIsNone(facts["actual_identity_or_unavailable"])
        self.assertIsNone(facts["in_fixed_window"])
        self.assertEqual(facts["success_status_or_unavailable"], "UNAVAILABLE")
        self.assertEqual(audit["identity_status"], "UNAVAILABLE")
        self.assertEqual(audit["core_selection_status"], "UNAVAILABLE")
        self.assertIsNone(audit["core_log_count"])
        self.assertEqual(audit["identity_evidence"], [])
        self.assertEqual(audit["selection_evidence"], [])

    def test_timeout_run_closes_all_facts_unavailable_before_source_decode(self):
        # This tests the run controller's timeout path with a mocked, already
        # validated context. It does not claim to validate the 113-source gate.
        bindings = {}
        for name in ("study", "transport", "review"):
            path = self.root / (name + ".json")
            path.write_text('{"synthetic_only":true}\n')
            bindings[name] = path
        args = SimpleNamespace(study_manifest=bindings["study"], transport_audit=bindings["transport"],
            source_review=bindings["review"], expected_study_sha256=sha(bindings["study"]),
            expected_candidates_sha256="a" * 64,
            dependencies=Path(self.pa.__file__).resolve().parents[1], output=self.root / "timeout_output")
        runs = [{"case_id": case, **value} for case, value in self.active().items()]
        candidates = self.module.select_candidates(self.candidates(1), "a" * 64, "2026-01-02T00:00:00+00:00")
        context = ({}, runs, candidates, {"pyarrow_version": self.pa.__version__, "numpy_version": self.np.__version__},
                   {"synthetic": {"key": "synthetic", "day_utc": self.f["day"], "table": "blocks"}}, {}, {}, {}, {})
        with patch.object(self.module, "load_context", return_value=context), \
             patch.object(self.module.time, "monotonic", side_effect=[0, 1201, 1201]), \
             patch.object(self.module, "verify_current_source") as authenticate, \
             patch.object(self.module.independent, "OfflineSource") as decode:
            result = self.module.run(args)
            authenticate.assert_not_called()
            decode.assert_not_called()
        self.assertTrue(result["time_cap_reached"])
        self.assertEqual(result["status"], "CLOSED_UNAVAILABLE_TIME_CAP")
        self.assertEqual(result["shared_execution_wall_cap_seconds"], 1200)
        evidence = json.loads((args.output / "projection_evidence.json").read_bytes())
        self.assertEqual(evidence["status"], "CLOSED_UNAVAILABLE_TIME_CAP")
        self.assertFalse(evidence["complete_declared_union_scan"])
        for case in result["cases"]:
            self.assertEqual(len(case["candidates"]), 1)
            self.assertEqual(case["candidates"][0]["archive_disposition"], "UNVERIFIED_DUE_TO_CAP")
            self.assertIsNone(case["candidates"][0]["actual_identity_or_unavailable"])

    def byte_fixture(self, whole=True, spans=None):
        path = self.root / "source.parquet"
        self.pq.write_table(raw_table(self.f["logs"], "logs", self.pa), path, row_group_size=2)
        raw = path.read_bytes()
        size = len(raw)
        key = "v1.0/eth/logs/date=" + self.f["day"] + "/synthetic.parquet"
        source = {"table": "logs", "day_utc": self.f["day"], "key": key, "size_bytes": size,
                  "etag_opaque": '"invented"', "url": "https://aws-public-blockchain.s3.us-east-2.amazonaws.com/" + key}
        metadata = self.pq.ParquetFile(path).metadata
        footer_length = int.from_bytes(raw[-8:-4], "little")
        footer_start = size - footer_length - 8
        footer = {"leading_magic_sha256": hashlib.sha256(raw[:4]).hexdigest(),
                  "footer_start": footer_start, "footer_length": footer_length,
                  "footer_and_trailer_sha256": hashlib.sha256(raw[footer_start:]).hexdigest()}
        ranges = [[0, size]] if spans is None else spans(footer_start, size)
        records = []
        if not whole:
            for ordinal, (start, end) in enumerate(ranges, 1):
                length = end - start
                records.append({"ordinal": ordinal, "source": source, "start": start, "length": length,
                    "transport_ok": True, "method": "GET", "http_status": 206, "response_url": source["url"],
                    "etag": source["etag_opaque"], "content_range": f"bytes {start}-{end-1}/{size}",
                    "content_length": str(length), "content_encoding": None,
                    "request_headers": {"Range": f"bytes={start}-{end-1}", "If-Match": source["etag_opaque"],
                                        "Accept-Encoding": "identity"}, "response_bytes": length,
                    "stored_file_name": path.name, "stored_offset": start, "invalid_header_body_read": False,
                    "started_utc": "2026-01-01T00:00:00+00:00", "completed_utc": "2026-01-01T00:00:00+00:00",
                    "response_sha256": hashlib.sha256(raw[start:end]).hexdigest()})
        manifest = {"source": source, "source_id": hashlib.sha256(canon(source)).hexdigest(),
                    "row_count_metadata": metadata.num_rows, "row_group_count": metadata.num_row_groups,
                    "row_group_rows": [metadata.row_group(i).num_rows for i in range(metadata.num_row_groups)],
                    "whole_source_sha256_verified": whole, "whole_source_sha256": sha(path) if whole else None,
                    "successful_original_ranges": records, "available_ranges": ranges,
                    "available_original_bytes": sum(hi-lo for lo, hi in ranges),
                    "holes_are_original_bytes": False, "statistics_values_exported_or_used": False}
        transport = {"source_key": key, "source": source, "source_id": hashlib.sha256(canon(source)).hexdigest(),
                     "path": str(path), "available_ranges": ranges, "whole_source_sha256_verified": whole,
                     "whole_source_sha256": sha(path) if whole else None, "successful_range_count": len(records),
                     "range_receipts_canonical_sha256": hashlib.sha256(canon(records)).hexdigest(),
                     "original_footer_evidence": footer}
        return path, source, manifest, transport, records

    def test_current_whole_source_bytes_reverified_before_parquet_decode(self):
        path, source, manifest, proof, records = self.byte_fixture()
        self.assertIsNone(self.module.verify_current_source(source, manifest, proof, records))
        raw = bytearray(path.read_bytes())
        raw[10] ^= 1
        path.write_bytes(raw)
        with self.assertRaises(ValueError):
            self.module.verify_current_source(source, manifest, proof, records)

    def test_expired_deadline_prevents_hashing_any_source_chunk(self):
        _, source, manifest, proof, records = self.byte_fixture()
        hasher = Mock(wraps=hashlib.sha256())
        with patch.object(self.module.time, "monotonic", return_value=2), \
             patch.object(self.module.hashlib, "sha256", return_value=hasher):
            with self.assertRaises(self.module.AuditDeadlineExceeded):
                self.module.verify_current_source(source, manifest, proof, records, deadline=1)
        hasher.update.assert_not_called()

    def test_current_sparse_range_bytes_reverified_before_decode(self):
        path, source, manifest, proof, records = self.byte_fixture(whole=False)
        self.assertIsNone(self.module.verify_current_source(source, manifest, proof, records))
        raw = bytearray(path.read_bytes())
        raw[12] ^= 1
        path.write_bytes(raw)
        with self.assertRaises(ValueError):
            self.module.verify_current_source(source, manifest, proof, records)

    def test_projection_hole_rejected_even_when_unacquired_file_bytes_look_valid(self):
        path, source, manifest, proof, records = self.byte_fixture(
            whole=False, spans=lambda footer_start, size: [[0, 4], [footer_start, size]])
        self.module.verify_current_source(source, manifest, proof, records)
        sys.path.insert(0, str(PAPER / "phase16" / "qa"))
        import audit_prepared_sources as offline
        reader = offline.OfflineSource(source, manifest, proof, self.pa, self.pq)
        with self.assertRaisesRegex(ValueError, "unacquired column chunk"):
            reader.read(0, ["address", "transaction_hash"])
        self.assertEqual(reader.reads, [])

    def test_full_generated_log_projection_needs_no_topics_or_data(self):
        _, source, manifest, proof, records = self.byte_fixture()
        self.module.verify_current_source(source, manifest, proof, records)
        sys.path.insert(0, str(PAPER / "phase16" / "qa"))
        import audit_prepared_sources as offline
        reader = offline.OfflineSource(source, manifest, proof, self.pa, self.pq)
        table, row_groups = offline.full_projection([reader], "logs", self.pa, self.pc)
        self.assertEqual(len(table), 5)
        self.assertEqual(sum(group["rows"] for group in row_groups), 5)
        self.assertTrue(all("topics" not in item["columns"] and "data" not in item["columns"] for item in reader.reads))

    def test_transport_source_identity_cannot_be_swapped_for_another_key(self):
        _, source, manifest, proof, records = self.byte_fixture()
        proof["source_key"] = proof["source_key"].replace("synthetic", "other")
        with self.assertRaises(ValueError):
            self.module.verify_current_source(source, manifest, proof, records)


def run(dependencies):
    sys.path.insert(0, str(Path(dependencies).resolve()))
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ArchiveReferenceTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"schema_version": "article2_phase16_archive_reference_synthetic_checks_v1",
              "status": "PASS_SYNTHETIC_ONLY" if result.wasSuccessful() else "FAIL_SYNTHETIC_ONLY",
              "recorded_utc": datetime.now(timezone.utc).isoformat(), "tests_run": result.testsRun,
              "failures": len(result.failures), "errors": len(result.errors),
              "checks": sorted(name for name in dir(ArchiveReferenceTests) if name.startswith("test_")),
              "auditor_sha256": sha(TARGET), "test_sha256": sha(__file__),
              "real_source_rows_read": 0, "network_requests": 0, "old_suites_run": False,
              "detector_scores_computed": 0, "reference_labels_adjudicated": 0}
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dependencies", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.dependencies)
    args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: result[key] for key in ("status", "tests_run", "failures", "errors")}))
    raise SystemExit(0 if result["status"] == "PASS_SYNTHETIC_ONLY" else 1)
