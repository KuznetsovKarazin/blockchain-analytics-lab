"""Synthetic policy/invariant tests only; no historical attack evaluation."""
import copy
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

PAPER = Path(__file__).resolve().parents[1]
if str(PAPER) not in sys.path:
    sys.path.insert(0, str(PAPER))
SPEC = importlib.util.spec_from_file_location("monitoring_budget_policy_replay", PAPER / "budget_policy_replay.py")
core = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = core
SPEC.loader.exec_module(core)

NS = 1_000_000_000
DAY_NS = 86400 * NS
BASE_NS = 1677628800 * NS  # 2023-03-01 UTC midnight
ADDRESS = "0x27182842e098f60e3d576794a5bffb0777e025d3"
POLICIES = ("greedy", "paced_cumulative", "token_bucket")


def raw(block=1, offset_ns=0, *, tx_index=0, log_index=0, tx_id=None, **extra):
    tx_id = block * 1000 + tx_index if tx_id is None else tx_id
    return {"chain_id": 1, "address": ADDRESS, "block_number": block,
            "block_hash": "0x" + f"{block:064x}", "transaction_index": tx_index,
            "transaction_hash": "0x" + f"{tx_id:064x}", "log_index": log_index,
            "topics": ["0x" + "11" * 32], "data": "0x1234",
            "event_time_ns": BASE_NS + offset_ns, "observed_time": None,
            "label_available_time": None, **extra}


def config(policy="greedy", **extra):
    return core.BudgetConfig(**{
        "policy": policy, "daily_budget": 5, "window_start_ns": BASE_NS,
        "window_end_ns": BASE_NS + 3 * DAY_NS, "address": ADDRESS,
        "chain_id": 1, "window_seconds": 60, "threshold_count": 10,
        "cooldown_seconds": 300, **extra})


def apply(state, source):
    return state.process(core.decode_event(source))


def input_fixture(root):
    """Only a temporary empty fixture; no acquisition or real-data replay."""
    source = root / "empty.jsonl"
    source.write_bytes(b"")
    checksum = hashlib.sha256(b"").hexdigest()
    start = datetime(2023, 3, 1, tzinfo=timezone.utc)
    days = [(start + timedelta(days=i)).date().isoformat() for i in range(30)]
    study = {
        "schema_version": "budget_policy_study_config_v1",
        "window": {"start_utc": "2023-03-01T00:00:00Z", "end_utc": "2023-03-31T00:00:00Z",
                   "start_ns": BASE_NS, "end_ns": BASE_NS + 30 * DAY_NS,
                   "end_exclusive": True, "days": 30},
        "policies": list(POLICIES), "budgets": [1, 5, 20], "primary_budget": 5,
        "detector": {"window_seconds": 60, "threshold_count": 10, "cooldown_seconds": 300},
        "emitters": [{"id": "fixture_a", "address": ADDRESS, "chain_id": 1},
                     {"id": "fixture_b", "address": "0x" + "22" * 20, "chain_id": 1}],
        "execution": {"cells": 18, "repetitions": 1},
    }
    manifest = {"status": "complete", "populations": []}
    for emitter in study["emitters"]:
        manifest["populations"].append({
            "population_id": emitter["id"], "address": emitter["address"], "chain_id": 1,
            "inputs": [{"day_utc": day, "status": "complete", "rows": 0,
                        "path": "empty.jsonl", "sha256": checksum} for day in days],
        })
    return study, manifest


class BudgetPolicyReplayTests(unittest.TestCase):
    def test_integer_constants_and_tenth_same_timestamp_log(self):
        self.assertEqual(core.NS, NS)
        self.assertEqual(core.DAY_NS, DAY_NS)
        for policy in POLICIES:
            with self.subTest(policy=policy):
                state = core.PolicyReplayState(config(policy))
                rows = [apply(state, raw(log_index=i)) for i in range(10)]
                self.assertEqual([r["score"] for r in rows], list(range(1, 11)))
                self.assertTrue(all(r["accepted"] for r in rows))
                self.assertFalse(any(r["raw_trigger"] for r in rows[:9]))
                self.assertTrue(rows[-1]["notification_emitted"])
                self.assertEqual(rows[-1]["notification_time_ns"], BASE_NS)

    def test_rolling_window_left_boundary_is_exact_in_nanoseconds(self):
        state = core.PolicyReplayState(config())
        for i in range(9):
            apply(state, raw(log_index=i))
        before = apply(state, raw(2, 60 * NS - 1))
        at = apply(state, raw(3, 60 * NS))
        self.assertEqual(before["score"], 10)
        self.assertEqual(at["score"], 2)
        self.assertTrue(before["raw_trigger"])
        self.assertFalse(at["raw_trigger"])

    def test_paced_quota_changes_at_exact_half_day_boundary(self):
        state = core.PolicyReplayState(config("paced_cumulative", daily_budget=2,
                                              threshold_count=1, cooldown_seconds=0))
        first = apply(state, raw(1, 0))
        before = apply(state, raw(2, DAY_NS // 2 - 1))
        at = apply(state, raw(3, DAY_NS // 2))
        self.assertEqual((first["daily_quota"], before["daily_quota"], at["daily_quota"]), (1, 1, 2))
        self.assertTrue(first["notification_emitted"])
        self.assertEqual(before["suppression_reason"], "quota")
        self.assertTrue(at["notification_emitted"])
        self.assertEqual(at["notification_time_ns"], BASE_NS + DAY_NS // 2)

    def test_paced_quota_uses_midnight_not_window_start(self):
        start = BASE_NS + DAY_NS // 2
        state = core.PolicyReplayState(config("paced_cumulative", daily_budget=4,
                                              threshold_count=1, cooldown_seconds=0,
                                              window_start_ns=start))
        row = apply(state, raw(1, DAY_NS // 2))
        self.assertEqual(row["daily_quota"], 3)
        self.assertTrue(row["notification_emitted"])

    def test_nondivisor_budget_uses_exact_ceil_boundary(self):
        # Seven is a utility-test budget, not a change to the study grid.
        boundary = (DAY_NS + 6) // 7
        self.assertNotEqual(DAY_NS % 7, 0)
        for policy, reason in (("paced_cumulative", "quota"), ("token_bucket", "token")):
            with self.subTest(policy=policy):
                state = core.PolicyReplayState(config(policy, daily_budget=7,
                                                      threshold_count=1, cooldown_seconds=0))
                first = apply(state, raw(1, 0))
                before = apply(state, raw(2, boundary - 1))
                at = apply(state, raw(3, boundary))
                self.assertTrue(first["notification_emitted"])
                self.assertEqual(before["suppression_reason"], reason)
                self.assertTrue(at["notification_emitted"])
                self.assertEqual(at["notification_time_ns"], BASE_NS + boundary)
                if policy == "paced_cumulative":
                    self.assertEqual((before["daily_quota"], at["daily_quota"]), (1, 2))
                else:
                    self.assertEqual(before["token_credit_units"], 7 * (boundary - 1))
                    self.assertLess(before["token_credit_units"], DAY_NS)
                    self.assertEqual(at["token_credit_units"], 0)

    def test_token_exact_fractional_refill_and_single_token_cap(self):
        state = core.PolicyReplayState(config("token_bucket", daily_budget=2,
                                              threshold_count=1, cooldown_seconds=0))
        first = apply(state, raw(1, 0))
        before = apply(state, raw(2, DAY_NS // 2 - 1))
        at = apply(state, raw(3, DAY_NS // 2))
        self.assertTrue(first["notification_emitted"])
        self.assertEqual(first["token_credit_units"], 0)
        self.assertEqual(before["suppression_reason"], "token")
        self.assertEqual(before["token_credit_units"], DAY_NS - 2)
        self.assertTrue(at["notification_emitted"])
        self.assertEqual(at["token_credit_units"], 0)
        # A long gap refills at most one token, even though multiple credits accrued.
        later = apply(state, raw(4, 2 * DAY_NS))
        immediate = apply(state, raw(4, 2 * DAY_NS, log_index=1))
        self.assertTrue(later["notification_emitted"])
        self.assertEqual(later["token_credit_units"], 0)
        self.assertEqual(immediate["suppression_reason"], "token")

    def test_token_does_not_reset_at_midnight(self):
        state = core.PolicyReplayState(config("token_bucket", daily_budget=1,
                                              threshold_count=1, cooldown_seconds=0))
        first = apply(state, raw(1, 23 * 3600 * NS))
        midnight = apply(state, raw(2, DAY_NS))
        refilled = apply(state, raw(3, DAY_NS + 23 * 3600 * NS))
        self.assertTrue(first["notification_emitted"])
        self.assertEqual(midnight["notifications_on_day"], 0)
        self.assertEqual(midnight["token_credit_units"], 3600 * NS)
        self.assertEqual(midnight["suppression_reason"], "token")
        self.assertTrue(refilled["notification_emitted"])

    def test_zero_budget_never_emits_and_hard_cap_has_priority(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                state = core.PolicyReplayState(config(policy, daily_budget=0,
                                                      threshold_count=1, cooldown_seconds=0))
                for i, t in enumerate((0, 300 * NS, DAY_NS, 2 * DAY_NS), 1):
                    row = apply(state, raw(i, t))
                    self.assertTrue(row["raw_trigger"])
                    self.assertTrue(row["group_candidate"])
                    self.assertFalse(row["notification_emitted"])
                    self.assertEqual(row["suppression_reason"], "budget")
                    self.assertEqual(row["daily_quota"], 0)
                    self.assertIsNone(row["notification_time_ns"])

    def test_hard_daily_cap_resets_for_all_policies(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                state = core.PolicyReplayState(config(policy, daily_budget=1,
                                                      threshold_count=1, cooldown_seconds=0))
                first = apply(state, raw(1, 0))
                rejected = apply(state, raw(2, 10 * NS))
                tomorrow = apply(state, raw(3, DAY_NS))
                self.assertTrue(first["notification_emitted"])
                self.assertEqual(rejected["suppression_reason"], "budget")
                self.assertTrue(tomorrow["notification_emitted"])
                self.assertEqual(tomorrow["notifications_on_day"], 1)
                self.assertNotEqual(first["budget_day_utc"], tomorrow["budget_day_utc"])

    def test_grouping_precedes_budget_and_never_slides_on_rejection(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                # B=288 yields token refill every300s and paced quota growth every300s.
                state = core.PolicyReplayState(config(policy, daily_budget=288, threshold_count=1))
                first = apply(state, raw(1, 0))
                grouped = apply(state, raw(2, 300 * NS - 1))
                boundary = apply(state, raw(3, 300 * NS))
                self.assertTrue(first["notification_emitted"])
                self.assertEqual(grouped["suppression_reason"], "grouped")
                self.assertTrue(boundary["notification_emitted"])

    def test_quota_and_token_rejections_do_not_extend_cooldown(self):
        for policy, reason in (("paced_cumulative", "quota"), ("token_bucket", "token")):
            with self.subTest(policy=policy):
                state = core.PolicyReplayState(config(policy, daily_budget=2, threshold_count=1))
                apply(state, raw(1, 0))
                rejected = apply(state, raw(2, DAY_NS // 2 - NS))
                admitted = apply(state, raw(3, DAY_NS // 2))
                self.assertEqual(rejected["suppression_reason"], reason)
                self.assertTrue(admitted["notification_emitted"])

    def test_hard_budget_rejection_does_not_extend_group_into_next_day(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                state = core.PolicyReplayState(config(policy, daily_budget=1, threshold_count=1))
                first = apply(state, raw(1, DAY_NS - 400 * NS))
                rejected = apply(state, raw(2, DAY_NS - 100 * NS))
                tomorrow = apply(state, raw(3, DAY_NS))
                self.assertTrue(first["notification_emitted"])
                self.assertEqual(rejected["suppression_reason"], "budget")
                self.assertTrue(tomorrow["group_candidate"])
                if policy == "token_bucket":
                    self.assertEqual(tomorrow["suppression_reason"], "token")
                else:
                    self.assertTrue(tomorrow["notification_emitted"])

    def test_duplicate_and_late_do_not_change_count_or_policy_clock(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                state = core.PolicyReplayState(config(policy))
                first = apply(state, raw(1, 0))
                third = apply(state, raw(3, 12 * NS))
                duplicate = apply(state, raw(1, 0))
                late = apply(state, raw(2, 6 * NS))
                fourth = apply(state, raw(4, 18 * NS))
                self.assertTrue(first["accepted"])
                for row, reason in ((duplicate, "duplicate"), (late, "late")):
                    self.assertFalse(row["accepted"])
                    self.assertEqual(row["suppression_reason"], reason)
                    self.assertIsNone(row["score"])
                    self.assertIsNone(row["raw_trigger"])
                    self.assertEqual(row["policy_clock_ns"], third["policy_clock_ns"])
                    self.assertEqual(row["token_credit_units"], third["token_credit_units"])
                self.assertEqual(fourth["score"], 3)

    def test_raw_trigger_stream_is_identical_across_policies(self):
        sources = [raw(block, seconds * NS, log_index=i)
                   for block, seconds in enumerate((0, 300, 600, 900), 1)
                   for i in range(10)]
        outputs = {}
        for policy in POLICIES:
            state = core.PolicyReplayState(config(policy))
            outputs[policy] = [apply(state, e) for e in sources]
        def raw_signature(rows):
            return [(r["event_id"], r["score"], r["raw_trigger"], r["accepted"]) for r in rows]
        self.assertEqual(raw_signature(outputs["greedy"]), raw_signature(outputs["paced_cumulative"]))
        self.assertEqual(raw_signature(outputs["greedy"]), raw_signature(outputs["token_bucket"]))
        self.assertGreater(sum(r["notification_emitted"] for r in outputs["greedy"]),
                           sum(r["notification_emitted"] for r in outputs["token_bucket"]))

    def test_future_suffix_and_label_changes_do_not_rewrite_prefix(self):
        prefix = [raw(log_index=i) for i in range(12)]
        future = [raw(2, 12 * NS, log_index=i, data="0xabcdef", label=1,
                      label_available_time=1792886400.0) for i in range(25)]
        changed_prefix = [{**e, "label": i % 2,
                           "label_available_time": 1792886400.0 + i}
                          for i, e in enumerate(prefix)]
        alternate_future = [raw(2, 24 * NS, log_index=i, data="0x0102", label=0,
                                label_available_time=1792886500.0) for i in range(3)]
        alternate_future += [raw(3, 360 * NS, log_index=i, data="0xdeadbeef", label=1,
                                 label_available_time=None) for i in range(18)]
        for policy in POLICIES:
            with self.subTest(policy=policy):
                short, long = core.PolicyReplayState(config(policy)), core.PolicyReplayState(config(policy))
                expected = [apply(short, e) for e in prefix]
                expected_checkpoint = copy.deepcopy(short.to_dict())
                actual_prefix = [apply(long, e) for e in prefix]
                self.assertEqual(expected_checkpoint, long.to_dict())
                for e in future:
                    apply(long, e)
                self.assertEqual(expected, actual_prefix)
                altered = core.PolicyReplayState(config(policy))
                altered_prefix = [apply(altered, e) for e in changed_prefix]
                # Labels and their release metadata must not influence this
                # fixed detector, its policy decisions or its saved state.
                self.assertEqual(expected, altered_prefix)
                self.assertEqual(expected_checkpoint, altered.to_dict())
                for e in alternate_future:
                    apply(altered, e)
                self.assertEqual(expected, altered_prefix)

    def test_snapshot_restores_all_policy_and_rolling_state(self):
        sources = [raw(block, seconds * NS, log_index=i)
                   for block, seconds in enumerate((0, 12, 300, 43200, 86400, 129600), 1)
                   for i in range(10)]
        for policy in POLICIES:
            with self.subTest(policy=policy):
                uninterrupted = core.PolicyReplayState(config(policy, daily_budget=2))
                expected = [apply(uninterrupted, e) for e in sources]
                state = core.PolicyReplayState(config(policy, daily_budget=2))
                actual = [apply(state, e) for e in sources[:17]]
                restored = core.PolicyReplayState.from_dict(json.loads(json.dumps(state.to_dict())))
                actual += [apply(restored, e) for e in sources[17:]]
                self.assertEqual(actual, expected)
                self.assertEqual(restored.to_dict(), uninterrupted.to_dict())

    def test_exclusive_window_end_and_outside_start_fail_before_mutation(self):
        state = core.PolicyReplayState(config(window_end_ns=BASE_NS + DAY_NS))
        before = copy.deepcopy(state.to_dict())
        for source in (raw(1, -1), raw(2, DAY_NS)):
            with self.assertRaises(ValueError):
                apply(state, source)
            self.assertEqual(before, state.to_dict())
        accepted = apply(state, raw(1, 0))
        self.assertTrue(accepted["accepted"])

    def test_identity_conflict_and_same_order_key_fail_closed(self):
        state = core.PolicyReplayState(config())
        apply(state, raw())
        before = copy.deepcopy(state.to_dict())
        for source in (raw(data="0xdeadbeef"), raw(tx_id=999999)):
            with self.assertRaises(ValueError):
                apply(state, source)
            self.assertEqual(before, state.to_dict())

    def test_manifest_requires_every_day_in_complete_thirty_day_window(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            study, manifest = input_fixture(root)
            accepted = core.validate_inputs(study, manifest, root)
            self.assertEqual({k: len(v) for k, v in accepted.items()}, {"fixture_a": 30, "fixture_b": 30})
            missing = copy.deepcopy(manifest)
            missing["populations"][0]["inputs"].pop(14)
            with self.assertRaisesRegex(ValueError, "missing|days"):
                core.validate_inputs(study, missing, root)

    def test_zero_row_day_still_requires_completed_acquisition(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            study, manifest = input_fixture(root)
            for status, complete in (("incomplete", False), ("failed", True), ("complete", False)):
                with self.subTest(status=status, complete=complete):
                    invalid = copy.deepcopy(manifest)
                    item = invalid["populations"][1]["inputs"][7]
                    self.assertEqual(item["rows"], 0)
                    item["status"], item["complete"] = status, complete
                    with self.assertRaises(ValueError):
                        core.validate_inputs(study, invalid, root)

    def test_config_and_manifest_population_mismatches_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            study, manifest = input_fixture(root)
            wrong_detector = copy.deepcopy(study)
            wrong_detector["detector"]["window_seconds"] = 59
            wrong_budgets = copy.deepcopy(study)
            wrong_budgets["budgets"] = [1, 5, 21]
            for wrong in (wrong_detector, wrong_budgets):
                with self.assertRaises(ValueError):
                    core.validate_inputs(wrong, manifest, root)
            wrong_population = copy.deepcopy(manifest)
            wrong_population["populations"][0]["chain_id"] = 56
            with self.assertRaisesRegex(ValueError, "identity|population"):
                core.validate_inputs(study, wrong_population, root)

    def test_past_accepted_order_key_conflict_is_rejected_after_checkpoint(self):
        state = core.PolicyReplayState(config())
        apply(state, raw(1, 0))
        apply(state, raw(3, 12 * NS))
        restored = core.PolicyReplayState.from_dict(json.loads(json.dumps(state.to_dict())))
        before = copy.deepcopy(restored.to_dict())
        # The identity changes at a previously accepted exact order key that is
        # now behind the watermark. This is a conflict, not an ordinary late row.
        with self.assertRaises(ValueError):
            apply(restored, raw(1, 0, tx_id=999999))
        self.assertEqual(before, restored.to_dict())
        self.assertEqual(apply(restored, raw(1, 0))["suppression_reason"], "duplicate")

    def test_past_late_order_key_conflict_and_unknown_old_key_after_checkpoint(self):
        state = core.PolicyReplayState(config())
        apply(state, raw(3, 12 * NS))
        self.assertEqual(apply(state, raw(1, 0))["suppression_reason"], "late")
        restored = core.PolicyReplayState.from_dict(json.loads(json.dumps(state.to_dict())))
        before = copy.deepcopy(restored.to_dict())
        with self.assertRaises(ValueError):
            apply(restored, raw(1, 0, tx_id=999999))
        self.assertEqual(before, restored.to_dict())
        self.assertEqual(apply(restored, raw(1, 0))["suppression_reason"], "duplicate")
        self.assertEqual(apply(restored, raw(2, 6 * NS))["suppression_reason"], "late")

    def test_execute_cell_keeps_state_across_days_and_hashes_all_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            study, manifest = input_fixture(root)
            population = manifest["populations"][0]
            for day_index, item in enumerate(population["inputs"]):
                if day_index == 0:
                    events = [raw(1, DAY_NS - 60 * NS, log_index=i) for i in range(10)]
                elif day_index == 1:
                    events = [raw(2, DAY_NS + 60 * NS, log_index=i) for i in range(10)]
                    events += [raw(3, DAY_NS + 300 * NS, log_index=i) for i in range(10)]
                else:
                    events = []
                path = root / (item["day_utc"] + ".jsonl")
                content = "".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in events)
                path.write_text(content)
                item.update(path=path.name, rows=len(events), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            inputs = core.validate_inputs(study, manifest, root)["fixture_a"]
            out = root / "synthetic_run"
            out.mkdir()
            accepted_digests = set()
            summaries = []
            for policy in POLICIES:
                with self.subTest(policy=policy):
                    summary, notified_ids = core.execute_cell(study, study["emitters"][0], policy, 1, inputs, out)
                    cell = out / "cells" / summary["cell_id"]
                    with gzip.open(cell / "decisions.jsonl.gz", "rt") as handle:
                        decisions = [json.loads(line) for line in handle]
                    daily = json.loads((cell / "daily.json").read_text())
                    hourly = json.loads((cell / "hourly.json").read_text())
                    with gzip.open(cell / "final_state.json.gz", "rt") as handle:
                        snapshot = json.load(handle)
                    restored = core.PolicyReplayState.from_dict(snapshot)
                    self.assertEqual(restored.policy_clock_ns, BASE_NS + DAY_NS + 300 * NS)
                    self.assertEqual(len(restored.seen), 30)
                    self.assertEqual(list(restored.window), [BASE_NS + DAY_NS + 300 * NS] * 10)
                    self.assertEqual(len(decisions), 30)
                    self.assertEqual([r["score"] for r in decisions], list(range(1, 11)) * 3)
                    self.assertEqual(summary["records"], 30)
                    self.assertEqual(summary["raw_triggers"], 3)
                    self.assertEqual(summary["suppression_counts"]["grouped"], 1)
                    self.assertEqual(decisions[19]["suppression_reason"], "grouped")
                    expected = 1 if policy == "token_bucket" else 2
                    self.assertEqual(summary["notifications"], expected)
                    self.assertEqual(len(notified_ids), expected)
                    self.assertEqual(sum(r["notification_emitted"] for r in decisions), expected)
                    self.assertEqual(set(restored.alert_ids), {r["alert_id"] for r in decisions if r["notification_emitted"]})
                    self.assertEqual(len(daily), 30)
                    self.assertEqual(len(hourly), 720)
                    self.assertEqual([r["records"] for r in daily[:2]], [10, 20])
                    self.assertTrue(all(r["records"] == 0 and r["notifications"] == 0 for r in daily[2:]))
                    self.assertEqual(sum(r["records"] > 0 for r in hourly), 2)
                    self.assertTrue(all(r["notifications"] <= 1 for r in daily))
                    self.assertEqual(summary["hard_cap_exceedances"], 0)
                    self.assertEqual(restored.daily_counts, {r["day_utc"]: r["notifications"] for r in daily if r["notifications"]})
                    feature_digest = hashlib.sha256()
                    for row in decisions:
                        feature_digest.update(json.dumps([row["event_id"], row["score"], row["raw_trigger"]],
                                                         separators=(",", ":")).encode() + b"\n")
                    self.assertEqual(summary["accepted_feature_stream_sha256"], feature_digest.hexdigest())
                    accepted_digests.add(feature_digest.hexdigest())
                    self.assertEqual(summary["decision_log"]["sha256"], hashlib.sha256((cell / "decisions.jsonl.gz").read_bytes()).hexdigest())
                    for name, checksum in summary["artifacts"].items():
                        self.assertEqual(checksum, hashlib.sha256((cell / name).read_bytes()).hexdigest())
                    summaries.append(summary)
            self.assertEqual(len(accepted_digests), 1)
            integrity = core.verify_written_artifacts(out, {"cells": summaries})
            self.assertEqual(integrity["status"], "pass")
            self.assertEqual(integrity["gzip_files_read_to_eof"], 6)
            self.assertEqual(integrity["decision_rows_read_back"], 90)
            self.assertTrue(integrity["all_recorded_artifact_hashes_match"])


if __name__ == "__main__":
    unittest.main()
