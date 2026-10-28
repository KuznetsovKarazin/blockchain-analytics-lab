"""Independent storage gate checks using tiny, explicitly synthetic metadata.

No acquisition, decoder, detector or actual capture is used. The complete-chain
fixture validates the real frozen driver/config checks, but supplies inert
temporary implementation files and invented forensic attestations. Thus it
tests gate mechanics, not the truth of an actual root attestation or source audit.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("storage_protocol_under_test", HERE / "protocol.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def digest_bytes(value):
    return hashlib.sha256(value).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    return {"path": str(path.resolve()), "sha256": digest_bytes(path.read_bytes())}


def checkpoint():
    """One four-byte success and one unresolved seven-byte request."""
    source = {"key": "synthetic/source.parquet", "size_bytes": 100}
    requests = [
        {"ordinal": 1, "source": deepcopy(source), "start": 0, "length": 4,
         "started_utc": "2030-01-01T00:00:01+00:00", "completed_utc": "2030-01-01T00:00:02+00:00",
         "transport_ok": True, "response_bytes": 4, "response_sha256": digest_bytes(b"abcd")},
        {"ordinal": 2, "source": deepcopy(source), "start": 4, "length": 7,
         "started_utc": "2030-01-01T00:02:00+00:00", "completed_utc": None,
         "transport_ok": False, "response_bytes": 0, "response_sha256": None},
    ]
    session = {"status": "OPEN_REQUEST_PENDING", "retries": 0, "request_count": 2,
               "started_utc": "2030-01-01T00:00:00+00:00", "updated_utc": "2030-01-01T00:02:00+00:00",
               "wall_seconds_elapsed": 120, "retained_response_bytes": 4,
               "attempt_id": "synthetic-unbound-attempt"}
    return session, requests


class PendingGateTests(unittest.TestCase):
    def test_pending_zero_is_unknown_with_full_declared_charge(self):
        session, requests = checkpoint()
        known, pending = gate.validate_pending_checkpoint(session, requests)
        self.assertEqual((known, pending["length"]), (4, 7))
        self.assertIsNone(pending["completed_utc"])
        self.assertIsNone(pending["response_sha256"])
        self.assertEqual(known + pending["length"], 11)

    def test_synthesized_failure_status_is_rejected(self):
        for status in ("FAILED", "COMPLETE", "OPEN"):
            with self.subTest(status=status):
                session, requests = checkpoint()
                session["status"] = status
                with self.assertRaisesRegex(ValueError, "preserved pending checkpoint"):
                    gate.validate_pending_checkpoint(session, requests)

    def test_pending_cannot_be_promoted_to_observed_response(self):
        mutations = {"response_bytes": 1, "completed_utc": "2030-01-01T00:02:01+00:00",
                     "response_sha256": digest_bytes(b"x"), "transport_ok": True}
        for field, value in mutations.items():
            with self.subTest(field=field):
                session, requests = checkpoint()
                requests[-1][field] = value
                with self.assertRaisesRegex(ValueError, "exact unresolved pending GET"):
                    gate.validate_pending_checkpoint(session, requests)

    def test_pending_final_headers_are_not_original_evidence(self):
        session, requests = checkpoint()
        requests[-1]["http_status"] = 206
        with self.assertRaisesRegex(ValueError, "final response evidence"):
            gate.validate_pending_checkpoint(session, requests)

    def test_pending_must_start_strictly_inside_original_wall_deadline(self):
        for second, timestamp in ((7199, "2030-01-01T01:59:59+00:00"),
                                  (7200, "2030-01-01T02:00:00+00:00"),
                                  (7201, "2030-01-01T02:00:01+00:00")):
            with self.subTest(seconds_since_a1_start=second):
                session, requests = checkpoint()
                session["updated_utc"] = timestamp
                session["wall_seconds_elapsed"] = second
                requests[-1]["started_utc"] = timestamp
                if second < 7200:
                    self.assertEqual(gate.validate_pending_checkpoint(session, requests)[0], 4)
                else:
                    with self.assertRaisesRegex(ValueError, "pending GET was not started inside the original wall deadline"):
                        gate.validate_pending_checkpoint(session, requests)

    def test_unaccepted_earlier_request_rejects_prefix(self):
        session, requests = checkpoint()
        requests[0]["transport_ok"] = False
        with self.assertRaisesRegex(ValueError, "successful request prefix"):
            gate.validate_pending_checkpoint(session, requests)

    def test_full_pending_reservation_is_required_by_cap(self):
        session, requests = checkpoint()
        limits = gate.LIMITS | {"cumulative_response_byte_limit": 10}
        with patch.object(gate, "LIMITS", limits):
            with self.assertRaisesRegex(ValueError, "full pending-range charge"):
                gate.validate_pending_checkpoint(session, requests)

    def test_checkpoint_count_and_clocks_are_not_repaired(self):
        for field, value in (("request_count", 1), ("wall_seconds_elapsed", 117), ("retained_response_bytes", 0)):
            with self.subTest(field=field):
                session, requests = checkpoint()
                session[field] = value
                with self.assertRaises(ValueError):
                    gate.validate_pending_checkpoint(session, requests)

    def test_only_exact_final_pending_reacquisition_is_authorized(self):
        _, requests = checkpoint()
        exact = {"parent_request_ordinal": 2, "source_key": "synthetic/source.parquet", "start": 4, "length": 7}
        gate.validate_manual_reacquisition(exact, requests)
        for field, value in (("parent_request_ordinal", 1), ("source_key", "different"), ("start", 3), ("length", 8)):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "exact unresolved final pending range"):
                    gate.validate_manual_reacquisition(exact | {field: value}, requests)
        with self.assertRaisesRegex(ValueError, "invalid pending reacquisition fields"):
            gate.validate_manual_reacquisition(exact | {"retry_count": 2}, requests)


class SyntheticChainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-storage-gate-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"
        self.code = self.repo / "storage_recovery"
        self.code.mkdir(parents=True)
        self.runtime = self.base / "runtime"
        self.root = self.runtime / "attempt1"
        self.root.mkdir(parents=True)
        self.gates = self.base / "synthetic_gates"
        self.gates.mkdir()
        self.code_bindings = []
        for name in sorted(gate.REQUIRED_CODE):
            path = self.code / name
            path.write_text("# Inert synthetic binding fixture; never imported.\n")
            self.code_bindings.append({"path": str(path.relative_to(self.repo)), "sha256": digest_bytes(path.read_bytes())})
        self.addCleanup(patch.stopall)
        patch.object(gate, "REPO", self.repo).start()
        patch.object(gate, "__file__", str(self.code / "protocol.py")).start()
        patch.object(gate, "RUNTIME_ROOT", self.runtime).start()
        configs = []
        for short in ("lifi", "revest"):
            original_config = gate.PAPER / "phase16" / "protocol" / "configs" / (short + ".json")
            path = self.repo / (short + ".json")
            path.write_bytes(original_config.read_bytes())
            configs.append({"path": path.name, "sha256": digest_bytes(path.read_bytes())})
        self.original = {
            "schema_version": "synthetic_original_source_plan_v1",
            "collector": {"caps": {"wall_seconds": 7200, "requests": 5000,
                "total_response_bytes": 17179869184, "request_timeout_seconds": 60,
                "retries": 0, "concurrency": 1}},
            "case_configs": configs,
            "unchanged_science_fixture": {"source_count": 113, "days_per_case": 30, "daily_reset": True},
        }
        self.original_binding = write_json(self.gates / "original_plan.json", self.original)
        dummy_gate = write_json(self.gates / "synthetic_gate.json", {"fixture": "not a real scientific adjudication"})
        wrapper_binding = write_json(self.gates / "source_wrapper.json", {
            "schema_version": "article2_phase16_bound_source_execution_gate_v1",
            "source_plan": {"path": "original_plan.json", "sha256": self.original_binding["sha256"]},
            "execution_source_bindings": [self.code_bindings[0]],
        })
        self.acceptances = {}
        for config_binding in configs:
            config = gate.read(self.repo / config_binding["path"])
            bindings = {name: {"path": "synthetic_gate.json", "sha256": dummy_gate["sha256"]}
                        for name in gate.driver.GATE_NAMES}
            bindings["source_plan"] = {"path": "source_wrapper.json", "sha256": wrapper_binding["sha256"]}
            self.acceptances[config["case_id"]] = write_json(self.gates / (config["case_id"] + "_acceptance.json"), {
                "schema_version": "fixed_address_measurement_acceptance_v1",
                "status": "ACCEPTED_FOR_DECLARED_FIXED_ADDRESS_MEASUREMENT",
                "accepted_utc": "2029-12-31T23:59:59+00:00", "accepted_before_affected_payload": True,
                "all_frame_dispositions_completed": True, "config_sha256": config_binding["sha256"],
                "driver_sha256": gate.DRIVER_SHA256, "dependency_sha256": gate.driver.DEPENDENCIES,
                "gate_bindings": bindings,
            })
        self.session, self.requests = checkpoint()
        self.session["attempt_id"] = gate.frozen.digest({"plan": gate.frozen.digest(self.original["collector"]),
                                                       "started_utc": self.session["started_utc"]})
        for name, value in (("frozen_plan.json", self.original), ("runtime_acceptances.json", self.acceptances),
                            ("transport/plan.json", self.original["collector"]), ("transport/session.json", self.session),
                            ("transport/requests.json", self.requests), ("runtime_source_paths.json", {}),
                            ("days/2022-02-19/prepared.json", {"synthetic": "prepared metadata"}),
                            ("days/2022-02-19/core_selection.json", {"synthetic": "sealed selection 1"}),
                            ("days/2022-02-20/core_selection.json", {"synthetic": "partial selection 2"})):
            write_json(self.root / name, value)
        (self.root / "transport/requests.json.pending").write_bytes(b"")
        self.logical = self.base / "old_logical_attempt1"
        self.logical.symlink_to(self.root, target_is_directory=True)
        self.observer = self.gates / "synthetic_observer.txt"
        self.observer.write_text("Synthetic test only: no real process observation.\n")
        self.observer_binding = {"path": str(self.observer), "sha256": digest_bytes(self.observer.read_bytes())}
        self.documents, self.forensics = self.make_forensics()
        with patch.object(gate, "stamp", return_value="2030-01-01T00:02:07+00:00"):
            self.seal = gate.make_external_closure_seal(self.root, self.original_binding["path"],
                self.original_binding["sha256"], self.forensics, self.gates / "closure_seal.json")
        self.seal_binding = gate.file_binding(self.gates / "closure_seal.json")
        self.exposure = {"schema_version": "article2_phase16_source_only_exposure_report_v1",
            "status": "ROOT_REVIEWED_SOURCE_ONLY_EXPOSURE", "first_attempt_seal_sha256": self.seal_binding["sha256"],
            "source_payload_exposed": True, "detector_scoring_started": False,
            "new_reference_acquisition_started": False, "performance_or_reference_results_examined": False,
            "completed_days": ["2022-02-19"], "partial_core_selection_days": ["2022-02-20"],
            "reviewer": "SYNTHETIC TEST", "exposure_description": "Invented metadata, no actual source imported",
            "reviewed_utc": "2030-01-01T00:02:08+00:00"}
        exposure_binding = write_json(self.gates / "exposure.json", self.exposure)
        self.plan = deepcopy(self.original) | {"schema_version": "article2_phase16_storage_recovery_source_plan_v1",
            "original_plan_binding": self.original_binding, "storage_recovery_transport": deepcopy(gate.LIMITS),
            "storage_recovery_execution_bindings": self.code_bindings}
        plan_binding = write_json(self.gates / "recovery_plan.json", self.plan)
        self.amendment = {"schema_version": "article2_phase16_storage_recovery_acceptance_v1",
            "status": "ACCEPTED_BEFORE_RECOVERY_IMPORT_AND_REQUESTS_ONLY", "accepted_before_recovery_requests": True,
            "accepted_before_recovery_source_import": True, "source_payload_previously_exposed": True,
            "recovery_plan": plan_binding, "first_attempt_seal": self.seal_binding,
            "recovery_output_root": str(self.runtime / "attempt2"),
            "parent_evidence_bindings": self.seal["parent_evidence_bindings"], "forensic_bindings": self.forensics,
            "exposure_report": exposure_binding, "accepted_utc": "2030-01-01T00:02:09+00:00",
            "original_measurement_acceptances": deepcopy(self.acceptances),
            "manual_reacquisition": {"parent_request_ordinal": 2, "source_key": "synthetic/source.parquet", "start": 4, "length": 7}}
        self.now = "2030-01-01T00:02:10+00:00"

    def make_forensics(self):
        files = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file():
                files.append({"path": str(path.relative_to(self.root)), "size_bytes": path.stat().st_size,
                              "sha256": digest_bytes(path.read_bytes()),
                              "checkpoint_kind": "UNCOMMITTED_TEMPORARY" if path.name.endswith(".pending") else "COMMITTED_FILENAME"})
        summary = {"all_files_stable_during_read": True, "session": deepcopy(self.session),
            "committed_request_records": 2, "committed_successful_requests": 1, "committed_response_bytes_sum": 4,
            "committed_incomplete_ordinals": [2], "cache_successful_range_records": 1,
            "cache_accepted_response_bytes_sum": 4, "session_counts_match_committed_requests": True,
            "complete_attempt_costs_established": False, "failure_json_exists": False, "collection_result_json_exists": False,
            "cache_receipt_mismatch_ordinals": [], "cache_non_successful_ordinals": [],
            "duplicate_cache_ordinals": [], "successful_committed_requests_missing_cache": []}
        documents = {"metadata_inventory": {"schema_version": "article2_phase16_readonly_a1_metadata_forensics_v1",
                                             "summary": summary, "files": files}}
        bindings = {"metadata_inventory": write_json(self.gates / "metadata_inventory.json", documents["metadata_inventory"])}
        documents["allocation_review"] = {"schema_version": "phase16_enospc_allocation_review_v1",
            "status": "FORENSIC_METADATA_ONLY_NO_SCIENTIFIC_ADMISSION", "capture_mutations_by_this_reviewer": False,
            "source_payload_read_by_this_report": False, "metadata_inventory": bindings["metadata_inventory"]}
        documents["path_relocation"] = {"schema_version": "article2_phase16_forensic_path_relocation_v1",
            "capture_file_contents_modified": False, "current_physical_root": str(self.root),
            "old_logical_root": str(self.logical), "metadata_sha256_before_and_after": {
                x["path"]: x["sha256"] for x in files if x["checkpoint_kind"] == "COMMITTED_FILENAME"}}
        documents["accepted_range_review"] = {"status": "CANONICAL_ACCEPTED_RANGES_HASH_VERIFIED_AUXILIARY_COPIES_REMOVED",
            "verified_successful_requests": 1, "verified_response_bytes": 4,
            "canonical_capture_files_changed": False, "pending_request_not_promoted": True}
        for name in ("allocation_review", "path_relocation", "accepted_range_review"):
            bindings[name] = write_json(self.gates / (name + ".json"), documents[name])
        documents["external_resource_failure_attestation"] = {
            "schema_version": "article2_phase16_external_resource_failure_attestation_v1",
            "status": "ROOT_OBSERVED_TERMINATED_ENOSPC_ORIGINAL_CHECKPOINT_UNCHANGED",
            "terminal_observation": {"exit_code": 1, "reported_primary_exception": "OSError: [Errno 28] No space left on device",
                "tool_output_chunk_id": "synthetic-only", "source_of_attestation": "synthetic test; no actual observation"},
            "process_observation": {"last_observed_running_utc": "2030-01-01T00:02:01+00:00",
                "first_observed_ended_utc": "2030-01-01T00:02:05+00:00", "exact_failure_time_known": False,
                "runtime_observer_log": self.observer_binding},
            "original_checkpoint": {"status": self.session["status"], "attempt_id": self.session["attempt_id"],
                "started_utc": self.session["started_utc"], "last_updated_utc": self.session["updated_utc"],
                "wall_seconds_elapsed": 120, "request_count": 2, "successful_request_count": 1,
                "committed_successful_response_bytes": 4, "failed_terminal_request": {
                    "ordinal": 2, "source_key": "synthetic/source.parquet", "start": 4, "length": 7,
                    "persisted_response_bytes_placeholder": 0, "actual_terminal_received_bytes": None,
                    "actual_terminal_written_bytes": None, "response_completion_and_identity_headers_persisted": False,
                    "accepted_for_source_use": False, "conservative_charge_bytes": 7}},
            "conservative_parent_response_byte_charge": 11, "producer_failure_json_exists": False,
            "producer_collection_result_exists": False, "committed_metadata_rewritten": False,
            "canonical_source_bytes_changed_by_root": False, "source_payload_decoded_by_original_collection": True,
            "new_detector_scores_computed": 0, "new_reference_requests": 0, "wall_continuation_eligible": False,
            "attested_utc": "2030-01-01T00:02:06+00:00", "supporting_evidence": list(bindings.values())}
        bindings["external_resource_failure_attestation"] = write_json(self.gates / "external_attestation.json",
            documents["external_resource_failure_attestation"])
        return documents, bindings

    def validate(self, *, now=None, for_execution=True):
        binding = write_json(self.gates / "amendment.json", self.amendment)
        return gate.validate_recovery_amendment(binding["path"], binding["sha256"],
            now_utc=now or self.now, for_execution=for_execution)

    def evidence(self, documents):
        return gate.validate_external_evidence(documents, self.forensics, self.root,
                                              self.session, self.requests, self.gates)

    def test_full_metadata_chain_preserves_open_parent_and_unknown_bytes(self):
        result = self.validate()
        self.assertEqual(result["first_attempt_seal"]["producer_status"], "OPEN_REQUEST_PENDING")
        self.assertEqual(result["known_parent_response_bytes"], 4)
        self.assertEqual(result["reserved_parent_pending_response_bytes"], 7)
        self.assertEqual(result["inherited_charged_response_bytes"], 11)
        self.assertFalse(result["first_attempt_seal"]["actual_parent_response_bytes_complete"])
        self.assertIsNone(result["first_attempt_seal"]["pending_received_bytes"])
        self.assertEqual(set(result["original_acceptances"]), set(gate.CASES))
        self.assertEqual(result["absolute_deadline_utc"], "2030-01-01T04:00:00+00:00")
        self.assertEqual(gate.read(self.root / "transport/session.json"), self.session)
        self.assertEqual((self.root / "transport/requests.json.pending").read_bytes(), b"")

    def test_external_terminal_must_be_enospc_with_exit_evidence(self):
        for key, value in (("reported_primary_exception", "TimeoutError: timed out"), ("exit_code", 0), ("tool_output_chunk_id", "")):
            with self.subTest(key=key):
                docs = deepcopy(self.documents)
                docs["external_resource_failure_attestation"]["terminal_observation"][key] = value
                with self.assertRaisesRegex(ValueError, "terminal observation"):
                    self.evidence(docs)

    def test_external_process_end_bracket_must_follow_last_checkpoint(self):
        docs = deepcopy(self.documents)
        docs["external_resource_failure_attestation"]["process_observation"]["first_observed_ended_utc"] = "2030-01-01T00:01:59+00:00"
        with self.assertRaisesRegex(ValueError, "closure bracket/order"):
            self.evidence(docs)

    def test_external_pending_receipt_must_remain_unavailable(self):
        for field, value in (("actual_terminal_received_bytes", 0), ("actual_terminal_written_bytes", 0),
                             ("accepted_for_source_use", True), ("conservative_charge_bytes", 0)):
            with self.subTest(field=field):
                docs = deepcopy(self.documents)
                docs["external_resource_failure_attestation"]["original_checkpoint"]["failed_terminal_request"][field] = value
                with self.assertRaisesRegex(ValueError, "pending exposure"):
                    self.evidence(docs)

    def test_source_only_gate_rejects_scores_labels_and_wall_reclassification(self):
        for field, value in (("new_detector_scores_computed", 1), ("new_reference_requests", 1),
                             ("wall_continuation_eligible", True), ("committed_metadata_rewritten", True)):
            with self.subTest(field=field):
                docs = deepcopy(self.documents)
                docs["external_resource_failure_attestation"][field] = value
                with self.assertRaisesRegex(ValueError, "source-only resource closure"):
                    self.evidence(docs)

    def test_source_acceptance_review_cannot_promote_pending_range(self):
        docs = deepcopy(self.documents)
        docs["accepted_range_review"]["pending_request_not_promoted"] = False
        with self.assertRaisesRegex(ValueError, "accepted original ranges"):
            self.evidence(docs)

    def test_relocation_requires_original_alias_and_exact_metadata_hashes(self):
        for mutation in ("alias", "hash"):
            with self.subTest(mutation=mutation):
                docs = deepcopy(self.documents)
                relocation = docs["path_relocation"]
                if mutation == "alias":
                    relocation["old_logical_root"] = str(self.root)
                else:
                    relocation["metadata_sha256_before_and_after"]["transport/session.json"] = "0" * 64
                with self.assertRaises(ValueError):
                    self.evidence(docs)

    def test_modified_committed_metadata_is_rejected(self):
        write_json(self.root / "transport/session.json", self.session | {"status": "FAILED"})
        with self.assertRaisesRegex(ValueError, "A1 metadata inventory changed"):
            self.validate()

    def test_added_producer_failure_cannot_replace_external_closure(self):
        write_json(self.root / "failure.json", {"status": "FAILED", "synthetic": True})
        with self.assertRaisesRegex(ValueError, "A1 metadata inventory changed"):
            self.validate()

    def test_failed_checkpoint_must_remain_exact_empty_original(self):
        (self.root / "transport/requests.json.pending").write_text("[]")
        self.seal["parent_evidence_bindings"] = gate.evidence_inventory(self.root)
        with self.assertRaisesRegex(ValueError, "empty failed checkpoint changed"):
            gate.validate_external_closure_seal(self.seal, self.original, self.original_binding["sha256"], self.gates)

    def test_exposed_partial_selection_inventory_cannot_be_omitted(self):
        self.seal["partial_core_selection_seals"] = []
        with self.assertRaisesRegex(ValueError, "exposed selection/prepared inventory changed"):
            gate.validate_external_closure_seal(self.seal, self.original, self.original_binding["sha256"], self.gates)

    def test_scientific_scope_and_original_transport_cannot_change(self):
        for mutation in ("scope", "original_cap", "new_cap"):
            with self.subTest(mutation=mutation):
                plan = deepcopy(self.plan)
                if mutation == "scope":
                    plan["unchanged_science_fixture"]["days_per_case"] = 29
                elif mutation == "original_cap":
                    plan["collector"]["caps"]["wall_seconds"] = 14400
                else:
                    plan["storage_recovery_transport"]["cumulative_get_limit"] = 5001
                with self.assertRaises(ValueError):
                    gate.validate_plan(plan, self.original)

    def test_acceptance_cannot_backdate_exposed_payload(self):
        self.amendment["accepted_before_affected_payload"] = True
        with self.assertRaisesRegex(ValueError, "before-payload assertion"):
            self.validate()

    def test_acceptance_must_follow_external_closure_and_exposure_review(self):
        self.amendment["accepted_utc"] = "2030-01-01T00:02:07+00:00"
        with self.assertRaisesRegex(ValueError, "predates original closure/exposure"):
            self.validate()

    def test_future_acceptance_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "timestamp is in the future"):
            self.validate(now="2030-01-01T00:02:08+00:00")

    def test_expired_gate_is_historical_only(self):
        with self.assertRaisesRegex(ValueError, "deadline elapsed"):
            self.validate(now="2030-01-01T04:00:00+00:00")
        result = self.validate(now="2030-01-01T04:00:00+00:00", for_execution=False)
        self.assertEqual(result["amendment"]["status"], "ACCEPTED_BEFORE_RECOVERY_IMPORT_AND_REQUESTS_ONLY")

    def test_fixed_destination_is_fresh_once_and_never_an_alternative(self):
        (self.runtime / "attempt2").mkdir()
        with self.assertRaisesRegex(ValueError, "destination already used"):
            self.validate()
        self.validate(for_execution=False)
        self.amendment["recovery_output_root"] = str(self.runtime / "attempt3")
        with self.assertRaisesRegex(ValueError, "exact fixed A2 destination"):
            self.validate(for_execution=False)

    def test_both_original_case_acceptances_are_required(self):
        self.amendment["original_measurement_acceptances"].pop(gate.CASES[1])
        with self.assertRaisesRegex(ValueError, "both original case acceptances"):
            self.validate()

    def test_original_acceptance_bytes_cannot_change(self):
        path = Path(self.acceptances[gate.CASES[0]]["path"])
        path.write_text(path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "bound recovery file changed"):
            self.validate()

    def test_current_candidate_code_must_match_accepted_binding(self):
        (self.code / "independent_transport_audit.py").write_text("# changed synthetic code\n")
        with self.assertRaisesRegex(ValueError, "bound recovery file changed"):
            self.validate()

    def test_exposure_report_cannot_omit_partial_day(self):
        self.exposure["partial_core_selection_days"] = []
        self.amendment["exposure_report"] = write_json(self.gates / "exposure.json", self.exposure)
        with self.assertRaisesRegex(ValueError, "omits already exposed selection"):
            self.validate()

    def test_exposure_report_cannot_admit_examined_scores(self):
        self.exposure["performance_or_reference_results_examined"] = True
        self.amendment["exposure_report"] = write_json(self.gates / "exposure.json", self.exposure)
        with self.assertRaisesRegex(ValueError, "after scores/new labels"):
            self.validate()


if __name__ == "__main__":
    unittest.main(verbosity=2)
