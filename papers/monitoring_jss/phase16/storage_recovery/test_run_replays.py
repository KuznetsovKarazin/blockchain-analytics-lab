"""Synthetic orchestration checks; never invoke a production detector.

The real launcher and its pinned module imports are used. Pre-replay scientific
admission and full sealed-run validation are explicit stubs; inert driver calls
write only tiny synthetic manifests. Actual source/decision/reference records
are neither read nor created. These checks do not establish run correctness.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("storage_replay_launcher_under_test", HERE / "run_replays.py")
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    return launcher.protocol.file_binding(path)


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-storage-replay-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.code = self.base / "synthetic_code"
        self.code.mkdir()
        # The real protocol remains hash-bound. The two unused archive entry
        # points below are inert fixture bindings, never imported or executed.
        (self.code / "protocol.py").write_bytes((HERE / "protocol.py").read_bytes())
        for name in ("archive_reference_audit.py", "independent_compact_reader.py"):
            (self.code / name).write_text("# Synthetic inert binding fixture.\n")
        self.output = self.base / "fixed_replay_output"
        self.parent = self.base / "immutable_parent"
        self.parent.mkdir()
        self.gates = self.base / "synthetic_admission"
        self.gates.mkdir()
        self.inputs, self.acceptances, self.configs = {}, {}, []
        for case, short in zip(launcher.protocol.CASES, ("lifi", "revest")):
            config_path = launcher.PAPER / "phase16/protocol/configs" / (short + ".json")
            self.configs.append(launcher.protocol.file_binding(config_path))
            self.inputs[case] = write(self.gates / (case + "_inputs.json"), {"synthetic_case": case})
            self.acceptances[case] = write(self.gates / (case + "_original_acceptance.json"), {"synthetic_case": case})
        self.amendment = write(self.gates / "amendment.json", {"synthetic": "storage amendment"})
        self.ledger = write(self.gates / "full_ledger.json", {"synthetic": "full failed/cumulative ledger"})
        self.source = write(self.gates / "source_review.json", {"synthetic": "independent source review"})
        self.transport = write(self.gates / "transport_audit.json", {"synthetic": "transport review"})
        self.auth = {
            "replay_launcher_sha256": launcher.sha(HERE / "run_replays.py"),
            "replay_output_root": str(self.output),
            "reference_archive_auditor": launcher.protocol.file_binding(self.code / "archive_reference_audit.py"),
            "reference_compact_reader": launcher.protocol.file_binding(self.code / "independent_compact_reader.py"),
            "reference_archive_source_engine_sha256": launcher.ENGINE_SHA256,
            "input_manifests": self.inputs,
            "source_review": self.source, "transport_audit": self.transport,
            "accepted_utc": "2030-01-01T00:00:00+00:00",
        }
        self.auth_path = self.gates / "pre_replay_authorization.json"
        self.context = {
            "pre_replay_authorization": self.auth,
            "original_plan": {"case_configs": self.configs},
            "original_acceptances": self.acceptances,
            "parent_root": self.parent,
            "amendment_path": Path(self.amendment["path"]),
            "multiattempt_ledger_path": Path(self.ledger["path"]),
        }
        self.calls, self.validation_calls = [], []
        self.driver_hook = None
        self.validator_hook = None
        self.addCleanup(patch.stopall)
        patch.object(launcher, "HERE", self.code).start()
        patch.object(launcher, "stamp", return_value="2030-01-01T00:00:01+00:00").start()
        self.gate_mock = patch.object(launcher.protocol, "validate_pre_replay_authorization", side_effect=self.stub_admission).start()

    def stub_admission(self, path, expected_sha):
        # Only caller binding checks are reproduced; all admission semantics
        # belong to the independently tested frozen storage protocol.
        self.assertEqual(Path(path), self.auth_path.resolve())
        if launcher.sha(path) != expected_sha:
            raise ValueError("synthetic admission rejected incorrect receipt digest")
        return self.context

    def stub_driver(self, argv):
        flags = dict(zip(argv[::2], argv[1::2]))
        self.assertEqual(len(flags), 6)
        config = launcher.protocol.read(flags["--config"])
        case = config["case_id"]
        destination = Path(flags["--output"])
        self.assertFalse(destination.exists())
        self.calls.append({"case_id": case, "argv": list(argv), "flags": flags})
        destination.mkdir()
        (destination / "synthetic_partial_marker.txt").write_text("Synthetic driver reached this case.\n")
        if self.driver_hook:
            self.driver_hook(case, destination, flags)
        write(destination / "run_manifest.json", {
            "case_id": case, "status": "COMPLETE", "synthetic": True,
            "started_utc": "2030-01-01T00:00:01+00:00", "completed_utc": "2030-01-01T00:00:01+00:00"})

    def stub_validate(self, entry, folder):
        self.validation_calls.append(deepcopy(entry))
        self.assertEqual(folder, self.output)
        manifest_path = launcher.protocol.bound(entry["run_manifest"], folder)
        manifest = launcher.protocol.read(manifest_path)
        if self.validator_hook:
            return self.validator_hook(entry, manifest)
        return {"status": manifest["status"], "case_id": manifest["case_id"]}

    def invoke(self, *, output=None, expected=None):
        binding = write(self.auth_path, self.auth)
        args = argparse.Namespace(pre_replay_authorization=self.auth_path,
            expected_authorization_sha256=expected or binding["sha256"], output=output or self.output)
        return launcher.run(args, driver_main=self.stub_driver, run_validator=self.stub_validate)

    def assert_no_complete_seal(self):
        self.assertFalse((self.output / "decision_study_seal.json").exists())
        self.assertFalse((self.output / "replay_launcher_receipt.json").exists())

    def failure(self):
        return launcher.protocol.read(self.output / "launcher_failure.json")

    def test_exactly_once_per_case_in_fixed_order_and_exact_arguments(self):
        result = self.invoke()
        self.assertEqual(result["status"], "COMPLETE_BOTH_CASES_SEALED")
        self.assertEqual([call["case_id"] for call in self.calls], list(launcher.protocol.CASES))
        self.assertEqual([entry["case_id"] for entry in self.validation_calls], list(launcher.protocol.CASES))
        for call, config in zip(self.calls, self.configs):
            case, flags = call["case_id"], call["flags"]
            self.assertEqual(flags, {
                "--config": config["path"],
                "--measurement-acceptance": self.acceptances[case]["path"],
                "--expected-acceptance-sha256": self.acceptances[case]["sha256"],
                "--input-manifest": self.inputs[case]["path"],
                "--expected-input-manifest-sha256": self.inputs[case]["sha256"],
                "--output": str(self.output / case),
            })
        self.gate_mock.assert_called_once_with(self.auth_path.resolve(), launcher.sha(self.auth_path))

    def test_both_case_receipt_binds_full_lineage_and_reviewed_outputs(self):
        result = self.invoke()
        receipt = launcher.protocol.read(launcher.protocol.bound(result["replay_launcher_receipt"], self.output))
        study = launcher.protocol.read(launcher.protocol.bound(result["study_seal"], self.output))
        self.assertEqual(receipt["driver_invocations"], 2)
        self.assertEqual(receipt["retries"], 0)
        self.assertFalse(receipt["labels_used"])
        self.assertFalse(receipt["reference_acquisition_performed"])
        self.assertEqual(receipt["pre_replay_authorization"], launcher.protocol.file_binding(self.auth_path))
        for key, binding in (("storage_recovery_amendment", self.amendment), ("multiattempt_ledger", self.ledger),
                             ("source_review", self.source), ("transport_audit", self.transport)):
            self.assertEqual(receipt[key], binding)
        self.assertEqual(study["cases"], receipt["cases"])
        self.assertEqual(study["replay_launcher_receipt"], result["replay_launcher_receipt"])
        self.assertEqual(study["reference_archive_auditor_sha256"], self.auth["reference_archive_auditor"]["sha256"])
        self.assertEqual(study["reference_compact_reader_sha256"], self.auth["reference_compact_reader"]["sha256"])
        self.assertFalse(study["reference_acquisition_started"])
        for entry in receipt["cases"]:
            case = entry["case_id"]
            self.assertEqual(entry["measurement_acceptance"], self.acceptances[case])
            self.assertEqual(entry["input_manifest"], self.inputs[case])
            launcher.protocol.bound(entry["run_manifest"], self.output)

    def test_first_driver_failure_preserves_partial_and_never_starts_second(self):
        def fail(case, destination, flags):
            raise RuntimeError("synthetic first-case driver failure")
        self.driver_hook = fail
        with self.assertRaisesRegex(RuntimeError, "first-case driver failure"):
            self.invoke()
        self.assertEqual([call["case_id"] for call in self.calls], [launcher.protocol.CASES[0]])
        self.assertEqual(self.validation_calls, [])
        self.assertTrue((self.output / launcher.protocol.CASES[0] / "synthetic_partial_marker.txt").exists())
        self.assertFalse((self.output / launcher.protocol.CASES[1]).exists())
        self.assert_no_complete_seal()
        failure = self.failure()
        self.assertEqual(failure["started_cases"], [launcher.protocol.CASES[0]])
        self.assertEqual(failure["verified_completed_cases"], [])
        self.assertFalse(failure["automatic_retry_performed"])

    def test_second_driver_failure_keeps_first_seal_without_both_case_receipt(self):
        def fail_second(case, destination, flags):
            if case == launcher.protocol.CASES[1]:
                raise RuntimeError("synthetic second-case failure")
        self.driver_hook = fail_second
        with self.assertRaisesRegex(RuntimeError, "second-case failure"):
            self.invoke()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(self.validation_calls), 1)
        self.assert_no_complete_seal()
        failure = self.failure()
        self.assertEqual(failure["started_cases"], list(launcher.protocol.CASES))
        self.assertEqual([e["case_id"] for e in failure["verified_completed_cases"]], [launcher.protocol.CASES[0]])
        self.assertTrue((self.output / launcher.protocol.CASES[0] / "run_manifest.json").exists())
        self.assertTrue((self.output / launcher.protocol.CASES[1] / "synthetic_partial_marker.txt").exists())

    def test_interruption_is_preserved_without_retry_or_second_case(self):
        self.driver_hook = lambda *unused: (_ for _ in ()).throw(KeyboardInterrupt("synthetic interruption"))
        with self.assertRaises(KeyboardInterrupt):
            self.invoke()
        self.assertEqual(len(self.calls), 1)
        self.assert_no_complete_seal()
        self.assertEqual(self.failure()["error_type"], "KeyboardInterrupt")

    def test_validator_rejects_case_output_before_next_driver(self):
        self.validator_hook = lambda *unused: (_ for _ in ()).throw(ValueError("synthetic corrupted decision seal"))
        with self.assertRaisesRegex(ValueError, "corrupted decision seal"):
            self.invoke()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(self.validation_calls), 1)
        self.assert_no_complete_seal()
        self.assertEqual(self.failure()["verified_completed_cases"], [])

    def test_unavailable_case_is_not_counted_as_zero_or_complete(self):
        self.validator_hook = lambda entry, manifest: {"status": "UNAVAILABLE", "case_id": entry["case_id"]}
        with self.assertRaisesRegex(ValueError, "valid complete sealed case"):
            self.invoke()
        self.assertEqual(len(self.calls), 1)
        self.assert_no_complete_seal()

    def test_reused_output_rejects_before_driver_and_preserves_contents(self):
        self.output.mkdir()
        marker = self.output / "previous_failure.txt"
        marker.write_text("existing attempt must remain")
        with self.assertRaisesRegex(ValueError, "fresh replay output"):
            self.invoke()
        self.assertEqual(self.calls, [])
        self.assertEqual(marker.read_text(), "existing attempt must remain")
        self.assertFalse((self.output / "launcher_failure.json").exists())

    def test_different_cli_destination_rejects_before_output_creation(self):
        other = self.base / "unauthorized_output"
        with self.assertRaisesRegex(ValueError, "exact authorized destination"):
            self.invoke(output=other)
        self.assertEqual(self.calls, [])
        self.assertFalse(other.exists())
        self.assertFalse(self.output.exists())

    def test_output_inside_original_capture_is_never_permitted(self):
        self.output = self.parent / "replays"
        self.auth["replay_output_root"] = str(self.output)
        with self.assertRaisesRegex(ValueError, "outside immutable A1"):
            self.invoke()
        self.assertEqual(self.calls, [])
        self.assertFalse(self.output.exists())

    def test_launcher_hash_mismatch_rejects_before_driver(self):
        self.auth["replay_launcher_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "launcher is not pinned"):
            self.invoke()
        self.assertEqual(self.calls, [])
        self.assertFalse(self.output.exists())

    def test_receipt_hash_and_gate_rejection_precede_driver(self):
        with self.assertRaisesRegex(ValueError, "incorrect receipt digest"):
            self.invoke(expected="0" * 64)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.output.exists())

    def test_both_cases_must_be_available_before_first_call(self):
        self.auth["input_manifests"] = {launcher.protocol.CASES[0]: self.inputs[launcher.protocol.CASES[0]]}
        with self.assertRaisesRegex(ValueError, "both exact frozen cases"):
            self.invoke()
        self.assertEqual(self.calls, [])
        self.assertFalse(self.output.exists())

    def test_archive_identity_is_pinned_before_any_driver(self):
        other = self.code / "another_archive_auditor.py"
        other.write_text("# synthetic wrong archive entry point\n")
        self.auth["reference_archive_auditor"] = launcher.protocol.file_binding(other)
        with self.assertRaisesRegex(ValueError, "wrong storage archive auditor"):
            self.invoke()
        self.assertEqual(self.calls, [])
        self.assertFalse(self.output.exists())

    def test_changed_bound_input_during_calls_never_gets_both_case_seal(self):
        def mutate_after_case_two(case, destination, flags):
            if case == launcher.protocol.CASES[1]:
                Path(self.inputs[launcher.protocol.CASES[0]]["path"]).write_text("synthetic mutation after first replay")
        self.driver_hook = mutate_after_case_two
        with self.assertRaisesRegex(ValueError, "bound recovery file changed"):
            self.invoke()
        self.assertEqual(len(self.calls), 2)
        self.assert_no_complete_seal()

    def test_authorization_cannot_be_later_than_launcher_start(self):
        self.auth["accepted_utc"] = "2030-01-01T00:00:02+00:00"
        with self.assertRaisesRegex(ValueError, "replay cannot predate authorization"):
            self.invoke()
        self.assertEqual(self.calls, [])
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
