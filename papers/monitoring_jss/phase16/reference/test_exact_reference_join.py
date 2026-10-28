"""New synthetic-only join checks; importing fixture helpers runs no old suite."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import exact_reference_join as join

sys.path.insert(0, str(join.PAPER / "phase15" / "driver"))
import test_fixed_address_replay as helpers

frozen = join.frozen


def put(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(frozen.canonical(value) + b"\n")
    return {"path": str(path), "sha256": frozen.file_digest(path)}


class SyntheticStudy:
    """Every identity, archive assertion and primary document here is invented."""
    def __init__(self, folder):
        self.base = Path(folder)
        self.entries, self.refs = [], []
        for name in ("lifi", "revest"):
            folder = self.base / name
            folder.mkdir()
            config = join.read(join.PAPER / "phase16" / "protocol" / "configs" / (name + ".json"))
            day = config["window"]["execution_date_utc"]
            values = [helpers.observation(day, i, amount=1 if i < 19 else 20,
                                          core_count=10, elapsed_seconds=i * 400) for i in range(20)]
            for value in values:
                value["population_addresses"] = config["population_addresses"]
            with patch.object(helpers, "config", lambda: copy.deepcopy(config)):
                fixture = helpers.Fixture(folder, {day: values})
            fixture.config = config
            source = put(folder / "synthetic_source.json", {"synthetic_only": True,
                         "notice": "Invented primary report and source evidence; proves no historical execution."})
            gate = put(folder / "synthetic_gate.json", {"synthetic_only": True})
            acceptance = put(folder / "acceptance.json", {
                "schema_version": "fixed_address_measurement_acceptance_v1",
                "status": "ACCEPTED_FOR_DECLARED_FIXED_ADDRESS_MEASUREMENT",
                "accepted_utc": "2026-01-01T00:00:00+00:00", "accepted_before_affected_payload": True,
                "all_frame_dispositions_completed": True, "config_sha256": fixture.config_sha,
                "driver_sha256": frozen.file_digest(join.driver.__file__), "dependency_sha256": join.driver.DEPENDENCIES,
                "gate_bindings": {k: {"path": "synthetic_gate.json", "sha256": gate["sha256"]} for k in join.driver.GATE_NAMES}})
            manifest, rows = fixture.load()
            run_folder = folder / "run"
            run_folder.mkdir()
            summaries = []
            for utc_day, run in join.driver.replay_loaded(config, manifest, rows):
                daily = run_folder / utc_day
                daily.mkdir()
                for method, decisions in run["methods"].items():
                    frozen.write_jsonl_gzip(daily / (method + "__methods.jsonl.gz"), decisions)
                for cell, decisions in run["decisions"].items():
                    frozen.write_jsonl_gzip(daily / ("__".join(map(str, cell)) + "__decisions.jsonl.gz"), decisions)
                for key in ("method_summaries", "cell_summaries", "final_method_states", "final_policy_states"):
                    frozen.write_json(daily / (key + ".json"), run[key])
                summaries.extend(run["cell_summaries"])
            run_manifest = {"schema_version": "fixed_address_replay_run_v1", "status": "COMPLETE",
                "synthetic_only": True, "started_utc": "2026-01-02T00:00:00+00:00",
                "completed_utc": "2026-01-02T00:01:00+00:00",
                **{k: config[k] for k in ("case_id", "chain_id", "window", "state_initialization")},
                "days": 30, "cells": 810, "config_sha256": fixture.config_sha,
                "measurement_acceptance_sha256": acceptance["sha256"], "input_manifest_sha256": fixture.manifest_sha,
                "driver_sha256": frozen.file_digest(join.driver.__file__), "dependency_sha256": join.driver.DEPENDENCIES,
                "decision_rows": sum(s["transactions"] for s in summaries), "summaries": summaries,
                "artifacts": [{"path": str(p.relative_to(run_folder)), "bytes": p.stat().st_size,
                               "sha256": frozen.file_digest(p)} for p in sorted(run_folder.rglob("*")) if p.is_file()],
                "labels_used": False, "label_join_performed": False}
            run_binding = put(run_folder / "run_manifest.json", run_manifest)
            self.entries.append({"case_id": config["case_id"], "status": "COMPLETE",
                "config": {"path": str(fixture.config_path), "sha256": fixture.config_sha},
                "measurement_acceptance": acceptance, "run_manifest": run_binding,
                "input_manifest": {"path": str(fixture.manifest_path), "sha256": fixture.manifest_sha}})
            known = []
            # First selected transaction is cold for semantic arm; last triggers.
            for index, coverage in ((0, "SELECTED"), (19, "SELECTED"), (60, "OBSERVED_NO_CORE_EMITTER"), (61, "UNAVAILABLE")):
                tx = (rows[day][index]["transaction"] if index < 20 else helpers.observation(day, index)["transaction"])
                audit = put(folder / ("refaudit_" + str(index) + ".json"), {
                    "schema_version": "article2_phase16_reference_source_audit_v1", "case_id": config["case_id"],
                    "chain_id": 1, "transaction_hash": tx["transaction_hash"], "identity_status": "VERIFIED",
                    "success_status": "SUCCESS", "core_selection_status": coverage,
                    "core_log_count": 10 if coverage == "SELECTED" else 0 if coverage == "OBSERVED_NO_CORE_EMITTER" else None,
                    "full_core_scan_or_terminal_logs_complete": coverage != "UNAVAILABLE",
                    "identity_evidence": [source], "selection_evidence": [source] if coverage != "UNAVAILABLE" else [],
                    "evidence_tier": "ENUMERATED_SOURCE_ARCHIVE", "rationale": "Synthetic fixture assertion only."})
                known.append({"chain_id": 1, "transaction_hash": tx["transaction_hash"],
                    "primary_source_locations_and_hashes": [{"artifact": source, "url": "https://example.invalid/synthetic", "location": "Synthetic paragraph"}],
                    "reported_role": "SUCCESSFUL_UNAUTHORIZED_EXECUTION", "actual_identity_or_unavailable": tx,
                    "success_status_or_unavailable": "SUCCESS", "in_fixed_window": True,
                    "adjudication_status": "VERIFIED_APPLICABLE_EXECUTION", "reviewer_rationale": "Synthetic fixture only.",
                    "source_coverage_audit_binding": audit})
            self.refs.append({"case_id": config["case_id"], "execution_inventory_status": "KNOWN_SUBSET_ONLY",
                              "completeness_rationale": "No complete inventory established in synthetic fixture.",
                              "completeness_evidence": [], "references": known})
        self.study = {"schema_version": "article2_phase16_decision_study_seal_v1",
                      "status": "BOTH_CASE_DECISION_STAGES_CLOSED", "synthetic_only": True,
                      "reference_join_code_sha256": frozen.file_digest(join.__file__),
                      "sealed_utc": "2026-01-03T00:00:00+00:00", "cases": self.entries}
        self.seal()

    def seal(self):
        self.study_binding = put(self.base / "study.json", self.study)
        review = put(self.base / "review.json", {
            "schema_version": "article2_phase16_reference_review_v1", "status": "APPROVED_FOR_EXACT_REFERENCE_JOIN",
            "decision_study_sha256": self.study_binding["sha256"], "reference_cases_sha256": frozen.digest(self.refs),
            "reviewer": "synthetic-reviewer", "reviewed_utc": "2026-01-04T00:01:00+00:00",
            **{k: True for k in ("primary_roles_checked", "identity_status_window_checked", "source_coverage_checked", "inventory_completeness_checked")}})
        self.inventory = {"schema_version": "article2_phase16_reference_inventory_v1",
                          "status": "SEALED_AFTER_DECISIONS_INDEPENDENTLY_ADJUDICATED", "synthetic_only": True,
                          "decision_study_sha256": self.study_binding["sha256"],
                          "reference_acquisition_started_utc": "2026-01-04T00:00:00+00:00",
                          "sealed_utc": "2026-01-04T00:02:00+00:00", "prepared_by": "synthetic-preparer",
                          "independent_review": review, "cases": self.refs}
        self.inventory_binding = put(self.base / "inventory.json", self.inventory)

    def run(self, output="joined"):
        return join.execute(self.study_binding["path"], self.study_binding["sha256"],
                            self.inventory_binding["path"], self.inventory_binding["sha256"], self.base / output)


class ExactReferenceJoinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.fixture = SyntheticStudy(cls.temp.name)
        cls.original_study = copy.deepcopy(cls.fixture.study)
        cls.original_refs = copy.deepcopy(cls.fixture.refs)
        cls.success = cls.fixture.run()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.fixture.study = copy.deepcopy(self.original_study)
        self.fixture.refs = copy.deepcopy(self.original_refs)
        self.fixture.entries = self.fixture.study["cases"]
        self.fixture.seal()

    def find(self, method, policy="greedy", budget=5):
        return next(x for x in self.success["cases"][0]["cells"]
                    if (x["method"], x["policy"], x["daily_budget"]) == (method, policy, budget))

    def test_full_matrix_and_outer_funnel_unknown_bounds(self):
        self.assertEqual([len(c["cells"]) for c in self.success["cases"]], [27, 27])
        self.assertEqual(len(self.success["across_cases"]), 27)
        cell = self.find("outflow_rank_1_20")
        self.assertEqual((cell["verified_applicable_executions"], cell["exact_notified"], cell["unknown"]), (4, 1, 1))
        self.assertEqual(cell["terminal_categories"]["SELECTED_COLD_START"], 1)
        self.assertEqual(cell["terminal_categories"]["OBSERVED_NOT_SELECTED_NO_CORE_EMITTER_LOG"], 1)
        self.assertIsNone(cell["point_coverage"])
        self.assertEqual(cell["known_set_lower_bound"]["value"], .25)
        self.assertEqual(cell["known_set_upper_bound"]["value"], .5)
        self.assertEqual(cell["incident_status"], "HIT")

    def test_count_skips_outflow_history_and_unknown_alerts_not_fp(self):
        cell = self.find("core_count_60s_10")
        self.assertIsNone(cell["funnel"]["positive_core_outflow_semantic_only"])
        self.assertIsNone(cell["funnel"]["history_eligible_semantic_only"])
        self.assertGreater(cell["load"]["unknown_nonreference_notifications"], 0)
        self.assertEqual(len(cell["load"]["daily"]), 30)
        self.assertEqual(cell["load"]["offered_slots"], 150)
        self.assertTrue(all(x["notifications"] <= 5 for x in cell["load"]["daily"]))

    def test_nearby_unselected_transaction_gets_no_grouped_credit(self):
        cell = self.find("outflow_rank_1_20")
        self.assertEqual(cell["exact_notified"], 1)
        self.assertEqual(cell["known_unnotified"], 2)

    def test_missing_selected_decision_rejected_even_if_artifact_resealed(self):
        entry = self.fixture.entries[0]
        run_path = Path(entry["run_manifest"]["path"])
        original = run_path.read_bytes()
        run = join.read(run_path)
        day = join.read(entry["config"]["path"])["window"]["execution_date_utc"]
        relative = day + "/outflow_rank_1_20__greedy__5__decisions.jsonl.gz"
        path = run_path.parent / relative
        original_decisions = path.read_bytes()
        try:
            decisions = list(join.row_stream(path))[:-1]
            path.unlink()
            frozen.write_jsonl_gzip(path, decisions)
            for artifact in run["artifacts"]:
                if artifact["path"] == relative:
                    artifact.update(sha256=frozen.file_digest(path), bytes=path.stat().st_size)
            entry["run_manifest"] = put(run_path, run)
            self.fixture.seal()
            with self.assertRaisesRegex(ValueError, "missing admission decision"):
                self.fixture.run("invalid_missing")
            self.assertFalse((self.fixture.base / "invalid_missing").exists())
        finally:
            path.write_bytes(original_decisions)
            run_path.write_bytes(original)

    def test_tampered_decision_artifact_rejected(self):
        run_path = Path(self.fixture.entries[0]["run_manifest"]["path"])
        artifact = join.read(run_path)["artifacts"][0]
        path = run_path.parent / artifact["path"]
        original = path.read_bytes()
        try:
            path.write_bytes(original + b"tampered")
            with self.assertRaisesRegex(ValueError, "bound file digest mismatch"):
                self.fixture.run("invalid_tamper")
        finally:
            path.write_bytes(original)

    def test_early_reference_acquisition_rejected(self):
        self.fixture.inventory["reference_acquisition_started_utc"] = "2026-01-01T00:00:00+00:00"
        self.fixture.inventory_binding = put(self.fixture.base / "inventory.json", self.fixture.inventory)
        with self.assertRaisesRegex(ValueError, "must follow both sealed decisions"):
            self.fixture.run("invalid_early")

    def test_incomplete_inventory_no_hit_is_indeterminate_and_empty_undefined(self):
        for case in self.fixture.refs:
            case["references"] = [case["references"][2]]
        self.fixture.seal()
        result = self.fixture.run("no_hits")
        self.assertTrue(all(c["incident_status"] == "INDETERMINATE_INCIDENT_COVERAGE" for c in result["cases"][0]["cells"]))
        for case in self.fixture.refs:
            case["references"] = []
            case["execution_inventory_status"] = "NO_VERIFIED_EXECUTION_UNDER_CAP"
        self.fixture.seal()
        result = self.fixture.run("empty")
        self.assertTrue(all(c["point_coverage"] is None and c["known_set_lower_bound"]["value"] is None
                            for c in result["cases"][0]["cells"]))

    def test_complete_inventory_requires_positive_closure(self):
        self.fixture.refs[0]["execution_inventory_status"] = "COMPLETE_WITH_POSITIVE_CLOSURE_EVIDENCE"
        self.fixture.seal()
        with self.assertRaisesRegex(ValueError, "positive closure evidence"):
            self.fixture.run("invalid_complete")

    def test_complete_observed_no_core_reference_is_complete_incident_miss(self):
        for case in self.fixture.refs:
            case["references"] = [case["references"][2]]
            case["execution_inventory_status"] = "COMPLETE_WITH_POSITIVE_CLOSURE_EVIDENCE"
            case["completeness_evidence"] = [case["references"][0]["primary_source_locations_and_hashes"][0]["artifact"]]
        self.fixture.seal()
        result = self.fixture.run("complete_miss")
        self.assertTrue(all(c["incident_status"] == "VERIFIED_COMPLETE_MISS" and c["point_coverage"]["value"] == 0
                            for c in result["cases"][0]["cells"]))
        self.assertTrue(all(c["point_incident_coverage"]["value"] == 0 for c in result["across_cases"]))

    def test_no_core_without_full_scan_proof_rejected(self):
        ref = self.fixture.refs[0]["references"][2]
        path = Path(ref["source_coverage_audit_binding"]["path"])
        original = path.read_bytes()
        try:
            audit = join.read(path)
            audit["full_core_scan_or_terminal_logs_complete"] = False
            ref["source_coverage_audit_binding"] = put(path, audit)
            self.fixture.seal()
            with self.assertRaisesRegex(ValueError, "complete scan or terminal log evidence"):
                self.fixture.run("invalid_no_core")
        finally:
            path.write_bytes(original)

    def test_unavailable_candidate_metadata_is_retained_without_positive_label(self):
        case = self.fixture.refs[0]
        ref = copy.deepcopy(case["references"][3])
        ref.update(transaction_hash="0x" + format(9999, "064x"), actual_identity_or_unavailable=None,
                   success_status_or_unavailable="UNAVAILABLE", in_fixed_window=None,
                   adjudication_status="UNVERIFIED_DUE_TO_CAP", reported_role="UNKNOWN")
        audit = join.read(ref["source_coverage_audit_binding"]["path"])
        audit.update(transaction_hash=ref["transaction_hash"], identity_status="UNAVAILABLE",
                     success_status="UNAVAILABLE", identity_evidence=[], evidence_tier="UNAVAILABLE")
        ref["source_coverage_audit_binding"] = put(self.fixture.base / "unavailable_candidate_audit.json", audit)
        case["references"].append(ref)
        self.fixture.seal()
        result = self.fixture.run("unknown_candidate")
        self.assertEqual(result["cases"][0]["candidate_count"], 5)
        self.assertEqual(result["cases"][0]["reference_dispositions"]["UNVERIFIED_DUE_TO_CAP"], 1)
        self.assertTrue(all(c["verified_applicable_executions"] == 4 for c in result["cases"][0]["cells"]))

    def test_independent_review_cannot_be_reused_for_changed_reference_records(self):
        self.fixture.inventory["cases"][0]["references"][0]["reported_role"] = "UNKNOWN"
        self.fixture.inventory_binding = put(self.fixture.base / "inventory.json", self.fixture.inventory)
        with self.assertRaisesRegex(ValueError, "independent review seal differs"):
            self.fixture.run("invalid_review")

    def test_unknown_metadata_cannot_be_verified_positive(self):
        ref = self.fixture.refs[0]["references"][0]
        ref["success_status_or_unavailable"] = "UNAVAILABLE"
        self.fixture.seal()
        with self.assertRaisesRegex(ValueError, "audit statuses differ"):
            self.fixture.run("invalid_status")

    def test_unavailable_case_load_is_null_and_incident_not_miss(self):
        entry = self.fixture.entries[1]
        entry.update(status="UNAVAILABLE", run_manifest=None, input_manifest=None,
                     failure_report=put(self.fixture.base / "failure.json", {
                         "schema_version": "article2_phase16_closed_source_failure_v1",
                         "status": "SOURCE_STAGE_CLOSED_UNAVAILABLE", "case_id": entry["case_id"],
                         "config_sha256": entry["config"]["sha256"], "detector_metrics_available": False,
                         "closed_utc": "2026-01-02T00:01:00+00:00", "reason": "Synthetic source failure."}))
        # No selected-observation claims can survive unavailable detector input.
        self.fixture.refs[1]["references"] = [self.fixture.refs[1]["references"][3]]
        self.fixture.seal()
        result = self.fixture.run("unavailable")
        for cell in result["cases"][1]["cells"]:
            self.assertEqual(cell["incident_status"], "UNAVAILABLE")
            self.assertIsNone(cell["load"]["notifications"])
            self.assertIsNone(cell["point_coverage"])
            self.assertEqual((cell["unknown"], cell["known_unnotified"]), (1, 0))


if __name__ == "__main__":
    unittest.main()
