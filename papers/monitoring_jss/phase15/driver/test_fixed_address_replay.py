"""Focused synthetic driver checks; no historical payloads or old test suite."""
import copy
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixed_address_replay as driver

frozen = driver.frozen
CORE = "0x" + "12" * 20
TOKEN = "0x" + "34" * 20


def config():
    old = frozen.strict_json((driver.PAPER / "semantic_flow_study_config.json").read_bytes())
    return {"schema_version": "fixed_address_replay_config_v1", "case_id": "synthetic-only",
            "chain_id": 1, "population_addresses": [CORE],
            "window": {"execution_date_utc": "2022-03-20", "start_date_utc": "2022-02-19",
                       "end_date_utc_exclusive": "2022-03-21"},
            "state_initialization": "independent_utc_day_reset", "source_scope": driver.SOURCE_SCOPE,
            "source_tier": driver.EVIDENCE_TIER, **{key: old[key] for key in driver.METHOD_KEYS}}


def observation(day, index, *, amount=1, core_count=1, elapsed_seconds=None):
    """An invented transaction containing core opaque logs and one token event."""
    row = {"chain_id": 1, "token_address": TOKEN, "transfer_log_count": 1,
           "net_external_in_raw": str(-amount), "net_event_in_raw": str(-amount)}
    for category in ("external_in", "external_out", "internal", "mint_from_zero", "burn_to_zero"):
        row[category + "_count"] = int(category == "external_out")
        row[category + "_raw"] = str(amount if category == "external_out" else 0)
    return {"schema_version": "archive_transfer_observation_v1", "status": "observed_success",
            "dataset_execution_status": 1,
            "transaction": {"chain_id": 1, "block_number": 1000 + index, "block_hash": "0x" + format(2000 + index, "064x"),
                            "transaction_hash": "0x" + format(3000 + index, "064x"), "transaction_index": 0,
                            "event_time_ns": frozen.day_start(day) + (index if elapsed_seconds is None else elapsed_seconds) * frozen.NS},
            "population_addresses": [CORE], "archived_core_log_count": core_count,
            "raw_amount_encoding": "base10_integer_string", "token_flows": [row],
            "counts": {"logs": core_count + 1, "erc20_shaped": 1, "erc721_shaped": 0,
                       "opaque": core_count, "monitored_erc20_shaped": 1, "zero_value_transfers": int(amount == 0)},
            "evidence": {"tier": driver.EVIDENCE_TIER, "source_kind": driver.SOURCE_SCOPE,
                         "source_audit_manifest_sha256": "a" * 64, "selection_manifest_sha256": "b" * 64,
                         "observed_time": None, "raw_receipt_acquired": False, "receipt_root_verified": False,
                         "historical_deployed_abi_verified": False, "token_erc20_compliance_verified": False,
                         "full_chain_completeness_verified": False},
            "unavailable_fields": driver.UNAVAILABLE_FIELDS.copy()}


def put(path, value):
    path.write_bytes(frozen.canonical(value) + b"\n")
    return frozen.file_digest(path)


class Fixture:
    """Synthetic coverage attestations exercise bindings; they prove no real data."""
    def __init__(self, folder, rows=None, *, audit_mutation=None, selection_mutation=None, manifest_mutation=None):
        self.folder = Path(folder)
        self.config = config()
        self.config_path = self.folder / "config.json"
        self.config_sha = put(self.config_path, self.config)
        self.days = driver.expected_days(self.config)
        self.rows = {day: copy.deepcopy((rows or {}).get(day, [])) for day in self.days}
        selection = {"schema_version": "fixed_address_transaction_selection_v1", "status": "SEALED_BEFORE_SCORING",
                     "config_sha256": self.config_sha, "rule": "at_least_one_core_emitter_log_no_topic_filter", "days": []}
        for day, values in self.rows.items():
            selection["days"].append({"day_utc": day, "transactions": [
                {**r["transaction"], "archived_core_log_count": r["archived_core_log_count"],
                 "archived_core_payload_sha256": "c" * 64} for r in values]})
        if selection_mutation:
            selection_mutation(selection)
        selection_sha = put(self.folder / "selection.json", selection)
        audit = {"schema_version": "fixed_address_source_audit_v1", "status": "PASS", "config_sha256": self.config_sha,
                 "selection_manifest_sha256": selection_sha, "tier": driver.EVIDENCE_TIER,
                 "cross_day_header_links_checked": True, "endpoint_anchors_checked": True, "days": []}
        for day, values in self.rows.items():
            audit["days"].append({"day_utc": day, "status": "COVERED", "selected_transactions": len(values),
                                  "core_log_count": sum(r["archived_core_log_count"] for r in values),
                                  **{key: "d" * 64 for key in driver.COVERAGE_HASHES},
                                  **{key: True for key in driver.COVERAGE_CHECKS}})
        if audit_mutation:
            audit_mutation(audit)
        audit_sha = put(self.folder / "audit.json", audit)
        manifest = {"schema_version": "fixed_address_observation_manifest_v1", "status": "COMPLETE",
                    "config_sha256": self.config_sha,
                    **{key: self.config[key] for key in ("case_id", "chain_id", "population_addresses", "source_scope", "source_tier")},
                    "selection": {"path": "selection.json", "sha256": selection_sha},
                    "source_audit": {"path": "audit.json", "sha256": audit_sha}, "days": []}
        for day, values in self.rows.items():
            for value in values:
                value["evidence"].update(source_audit_manifest_sha256=audit_sha, selection_manifest_sha256=selection_sha)
            path = self.folder / (day + ".jsonl")
            path.write_bytes(b"".join(frozen.canonical(value) + b"\n" for value in values))
            manifest["days"].append({"day_utc": day, "coverage_status": "COVERED",
                "observation_file": {"path": path.name, "sha256": frozen.file_digest(path)},
                "bytes": path.stat().st_size, "transaction_count": len(values),
                "core_log_count": sum(r["archived_core_log_count"] for r in values),
                "observation_sha256": [frozen.digest(r) for r in values]})
        if manifest_mutation:
            manifest_mutation(manifest)
        self.manifest_path = self.folder / "manifest.json"
        self.manifest_sha = put(self.manifest_path, manifest)

    def load(self):
        return driver.load_inputs(self.config, self.manifest_path, expected_manifest_sha256=self.manifest_sha,
                                  expected_config_sha256=self.config_sha)


class FocusedDriverTests(unittest.TestCase):
    def test_covered_empty_window_has_810_zero_cells(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Fixture(folder)
            manifest, days = f.load()
            runs = dict(driver.replay_loaded(f.config, manifest, days))
            cells = [cell for run in runs.values() for cell in run["cell_summaries"]]
            self.assertEqual((len(days), len(cells)), (30, 810))
            self.assertTrue(all(x["transactions"] == x["notifications"] == 0 for x in cells))

    def test_unavailable_empty_day_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Fixture(folder, audit_mutation=lambda a: a["days"][5].update(status="UNAVAILABLE"))
            with self.assertRaisesRegex(ValueError, "unavailable/partial"):
                f.load()

    def test_empty_day_still_requires_full_address_scan(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Fixture(folder, audit_mutation=lambda a: a["days"][5].update(all_address_row_groups_scanned=False))
            with self.assertRaisesRegex(ValueError, "coverage check missing"):
                f.load()

    def test_coverage_boolean_cannot_be_integer(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Fixture(folder, audit_mutation=lambda a: a.update(cross_day_header_links_checked=1))
            with self.assertRaisesRegex(ValueError, "header checks missing"):
                f.load()

    def test_missing_day_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Fixture(folder, manifest_mutation=lambda m: m["days"].pop(5))
            with self.assertRaisesRegex(ValueError, "missing, repeated or extra"):
                f.load()

    def test_window_and_core_and_chain_cannot_be_relaxed(self):
        mutations = [lambda c: c["window"].update(start_date_utc="2022-02-20"),
                     lambda c: c.update(population_addresses=[CORE, CORE]),
                     lambda c: c.update(population_addresses=["0x" + "0" * 40]),
                     lambda c: c.update(chain_id=56),
                     lambda c: c.update(grouping_ns=0),
                     lambda c: c.update(attack_labels=[])]
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                c = config()
                mutate(c)
                with self.assertRaises(ValueError):
                    driver.validate_config(c)

    def test_daily_feature_grouping_and_budget_resets(self):
        days = driver.expected_days(config())
        first = [observation(days[0], i, amount=1 if i < 19 else 20, core_count=10,
                             elapsed_seconds=86370 + i) for i in range(20)]
        second = [observation(days[1], 20, amount=100, core_count=10, elapsed_seconds=0)]
        with tempfile.TemporaryDirectory() as folder:
            f = Fixture(folder, {days[0]: first, days[1]: second})
            manifest, loaded = f.load()
            runs = dict(driver.replay_loaded(f.config, manifest, loaded))
            semantic_first = runs[days[0]]["methods"]["outflow_rank_1_20"]
            semantic_second = runs[days[1]]["methods"]["outflow_rank_1_20"]
            self.assertEqual(semantic_first[-1]["eligible_token_count"], 1)
            self.assertTrue(semantic_first[-1]["raw_trigger"])
            self.assertEqual(semantic_second[0]["eligible_token_count"], 0)
            self.assertFalse(semantic_second[0]["raw_trigger"])
            for day in days[:2]:
                count_rows = runs[day]["decisions"][("core_count_60s_10", "greedy", 1)]
                self.assertTrue(count_rows[0]["group_candidate"])
                self.assertTrue(count_rows[0]["notification_emitted"])
                self.assertEqual(count_rows[0]["notifications_on_day"], 1)

    def test_exact_frozen_day_outputs_reused(self):
        day = driver.expected_days(config())[0]
        with tempfile.TemporaryDirectory() as folder:
            f = Fixture(folder, {day: [observation(day, i, amount=i + 1) for i in range(21)]})
            manifest, loaded = f.load()
            actual = dict(driver.replay_loaded(f.config, manifest, loaded))[day]
            expected = frozen.replay_day(f.config, day, loaded[day],
                source_audit_sha256=manifest["source_audit"]["sha256"], source_scope=driver.SOURCE_SCOPE)
            self.assertEqual(actual, expected)
            self.assertEqual(actual["method_summaries"]["outflow_rank_1_20"]["eligible_token_scores"], 2)

    def test_selected_membership_cannot_silently_drop_transaction(self):
        day = driver.expected_days(config())[0]
        with tempfile.TemporaryDirectory() as folder:
            f = Fixture(folder, {day: [observation(day, 0)]},
                        selection_mutation=lambda s: s["days"][0]["transactions"].clear())
            with self.assertRaisesRegex(ValueError, "selection count differs"):
                f.load()

    def test_cross_day_transaction_identity_and_order_checked(self):
        days = driver.expected_days(config())
        for mode in ("duplicate_hash", "height_decreases", "block_hash_reused"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                a, b = observation(days[0], 1), observation(days[1], 2)
                if mode == "duplicate_hash":
                    b["transaction"]["transaction_hash"] = a["transaction"]["transaction_hash"]
                elif mode == "height_decreases":
                    b["transaction"]["block_number"] = 999
                else:
                    b["transaction"]["block_hash"] = a["transaction"]["block_hash"]
                f = Fixture(folder, {days[0]: [a], days[1]: [b]})
                with self.assertRaises(ValueError):
                    f.load()

    def test_tampered_empty_file_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Fixture(folder)
            (Path(folder) / (f.days[0] + ".jsonl")).write_bytes(b"\n")
            with self.assertRaisesRegex(ValueError, "bound file digest mismatch"):
                f.load()

    def test_extra_label_field_rejected(self):
        day = driver.expected_days(config())[0]
        with tempfile.TemporaryDirectory() as folder:
            row = observation(day, 0)
            row["attack_label"] = True
            f = Fixture(folder, {day: [row]})
            with self.assertRaisesRegex(ValueError, "invalid observation fields"):
                f.load()

    def test_source_audit_does_not_admit_measurement(self):
        with tempfile.TemporaryDirectory() as folder:
            f = Fixture(folder)
            f.load()  # Synthetic integrity check can pass without scientific acceptance.
            fake = Path(folder) / "not_acceptance.json"
            digest = put(fake, {"status": "PASS"})
            with self.assertRaisesRegex(ValueError, "root acceptance fields"):
                driver.validate_freeze(fake, f.config_path, expected_freeze_sha256=digest)


if __name__ == "__main__":
    parser_args = sys.argv[1:]
    report_path = Path(parser_args[0]) if parser_args else None
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(FocusedDriverTests)
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    print(stream.getvalue(), end="")
    report = {"schema_version": "phase15_driver_focused_test_report_v1", "status": "PASS" if result.wasSuccessful() else "FAIL",
              "completed_utc": datetime.now(timezone.utc).isoformat(), "test_methods": result.testsRun,
              "failures": len(result.failures), "errors": len(result.errors),
              "tests": unittest.defaultTestLoader.getTestCaseNames(FocusedDriverTests),
              "input_kind": "synthetic invented observations and coverage attestations only",
              "network_requests": 0, "historical_payload_rows": 0, "real_case_scores": 0, "old_test_suites_run": 0,
              "driver_sha256": frozen.file_digest(driver.__file__), "test_source_sha256": frozen.file_digest(__file__),
              "dependency_sha256": driver.DEPENDENCIES,
              "scope": "New controller boundary checks. Direct frozen-routine equality is reuse verification, not an independently reimplemented algorithm oracle."}
    if report_path:
        require_parent = report_path.parent
        require_parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
    raise SystemExit(0 if result.wasSuccessful() else 1)
