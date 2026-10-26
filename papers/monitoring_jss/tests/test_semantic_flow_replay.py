"""Offline causal grouping/admission and complete-input tests; no network or labels."""
import copy
import json
from pathlib import Path
import random
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import semantic_flow_replay as replay

AUDIT = "a" * 64
SELECTION = "b" * 64
TOKEN = "0x" + "12" * 20
DAY = "2023-03-01"
START = replay.day_start(DAY)


def transaction(index, elapsed_ns=0, day=DAY):
    return {"chain_id": 1, "block_number": 1000 + index,
            "block_hash": "0x" + format(2000 + index, "064x"),
            "transaction_hash": "0x" + format(3000 + index, "064x"),
            "transaction_index": 0,
            "event_time_ns": replay.day_start(day) + elapsed_ns}


def observation(index, elapsed_ns=0, amount=1, core_count=1, day=DAY):
    transfer = amount is not None
    flows = []
    if transfer:
        row = {"chain_id": 1, "token_address": TOKEN, "transfer_log_count": 1,
               "net_external_in_raw": str(-amount), "net_event_in_raw": str(-amount)}
        for category in ("external_in", "external_out", "internal", "mint_from_zero", "burn_to_zero"):
            row[category + "_count"] = int(category == "external_out")
            row[category + "_raw"] = str(amount if category == "external_out" else 0)
        flows.append(row)
    return {"schema_version": "archive_transfer_observation_v1", "status": "observed_success",
            "dataset_execution_status": 1, "transaction": transaction(index, elapsed_ns, day),
            "population_addresses": [replay.ADDRESS], "archived_core_log_count": core_count,
            "raw_amount_encoding": "base10_integer_string", "token_flows": flows,
            "counts": {"logs": core_count + int(transfer), "erc20_shaped": int(transfer),
                       "erc721_shaped": 0, "opaque": core_count,
                       "monitored_erc20_shaped": int(transfer), "zero_value_transfers": int(transfer and amount == 0)},
            "evidence": {"tier": replay.EVIDENCE_TIER, "source_audit_manifest_sha256": AUDIT,
                         "selection_manifest_sha256": SELECTION, "observed_time": None,
                         "raw_receipt_acquired": False, "receipt_root_verified": False,
                         "full_chain_completeness_verified": False,
                         "historical_deployed_abi_verified": False,
                         "token_erc20_compliance_verified": False}}


def config():
    return json.loads((Path(__file__).resolve().parents[1] / "semantic_flow_study_config.json").read_text())


def input_fixture(folder):
    """Complete synthetic source envelope with production-sized fixed counts."""
    folder = Path(folder)
    cfg, selected_days, by_day = config(), [], {}
    for spec in cfg["days"]:
        day, count, core_total = spec["day_utc"], spec["transaction_count"], spec["core_log_count"]
        rows = [observation(i, i * replay.NS, None,
                            core_count=core_total - count + 1 if i == 0 else 1, day=day) for i in range(count)]
        by_day[day] = rows
        selected_days.append({"day_utc": day, "archived_core_input_sha256": "d" * 64,
            "transactions": [{**r["transaction"], "archived_core_log_count": r["archived_core_log_count"],
                              "archived_core_payload_sha256": "e" * 64} for r in rows]})
    selection = {"schema_version": "semantic_flow_transaction_selection_v1", "days": selected_days}
    replay.write_json(folder / "selection.json", selection)
    selection_sha = replay.file_digest(folder / "selection.json")
    audit = {"schema_version": "semantic_flow_source_audit_v1", "status": "PASS", "selection_manifest_sha256": selection_sha}
    replay.write_json(folder / "source_audit_manifest.json", audit)
    audit_sha = replay.file_digest(folder / "source_audit_manifest.json")
    manifest = {"schema_version": "semantic_flow_observation_manifest_v1", "status": "complete", "source_scope": replay.SOURCE_SCOPE,
                "source_audit_manifest_path": "source_audit_manifest.json", "source_audit_manifest_sha256": audit_sha,
                "selection_manifest_path": "selection.json", "selection_manifest_sha256": selection_sha, "days": []}
    for spec in cfg["days"]:
        day, rows = spec["day_utc"], by_day[spec["day_utc"]]
        for row in rows:
            row["evidence"].update(source_audit_manifest_sha256=audit_sha, selection_manifest_sha256=selection_sha)
        path = folder / (day + ".jsonl")
        path.write_bytes(b"".join(replay.canonical(row) + b"\n" for row in rows))
        manifest["days"].append({**spec, "path": path.name, "bytes": path.stat().st_size,
                                 "sha256": replay.file_digest(path), "observation_sha256": [replay.digest(row) for row in rows]})
    path = folder / "observation_manifest.json"
    replay.write_json(path, manifest)
    return cfg, path, selection_sha, manifest


def rewrite_manifest(path, manifest):
    Path(path).write_bytes(replay.canonical(manifest) + b"\n")
    return replay.file_digest(path)


class CountTests(unittest.TestCase):
    def new(self):
        return replay.CountMonitor(start_ns=START, end_ns=START + replay.DAY_NS)

    def test_current_transaction_counts_all_core_logs_before_one_decision(self):
        monitor = self.new()
        result = monitor.observe(transaction(0), 12)
        self.assertEqual(result["rolling_core_log_count"], 12)
        self.assertTrue(result["raw_trigger"])
        self.assertTrue(result["group_candidate"])

    def test_open_left_window_boundary(self):
        monitor = self.new()
        monitor.observe(transaction(0), 10)
        before = monitor.observe(transaction(1, 60 * replay.NS - 1), 1)
        boundary = monitor.observe(transaction(2, 60 * replay.NS), 1)
        self.assertEqual(before["rolling_core_log_count"], 11)
        self.assertEqual(boundary["rolling_core_log_count"], 2)
        self.assertFalse(boundary["raw_trigger"])

    def test_grouping_anchor_does_not_follow_suppressed_raw_triggers(self):
        monitor = self.new()
        first = monitor.observe(transaction(0), 10)
        middle = monitor.observe(transaction(1, 299 * replay.NS), 10)
        boundary = monitor.observe(transaction(2, 300 * replay.NS), 10)
        self.assertTrue(first["group_candidate"])
        self.assertFalse(middle["group_candidate"])
        self.assertTrue(boundary["group_candidate"])

    def test_invalid_order_time_count_do_not_mutate(self):
        monitor = self.new()
        monitor.observe(transaction(0, 10 * replay.NS), 10)
        saved = replay.canonical(monitor.snapshot())
        for tx, count in [(transaction(0, 10 * replay.NS), 1),
                          (transaction(1, 9 * replay.NS), 1),
                          (transaction(1, 11 * replay.NS), True),
                          (transaction(1, replay.DAY_NS), 1)]:
            with self.assertRaises(ValueError):
                monitor.observe(tx, count)
            self.assertEqual(replay.canonical(monitor.snapshot()), saved)


class AdmissionTests(unittest.TestCase):
    def new(self, policy, budget=5):
        return replay.AdmissionState(replay.AdmissionConfig(policy, budget, START,
                                                            START + replay.DAY_NS, replay.METHODS[0]))

    def test_paced_exact_release_boundary(self):
        state = self.new("paced_cumulative")
        self.assertTrue(state.process(transaction(0), True)["notification_emitted"])
        before = state.process(transaction(1, replay.DAY_NS // 5 - 1), True)
        at = state.process(transaction(2, replay.DAY_NS // 5), True)
        self.assertEqual(before["suppression_reason"], "paced_quota")
        self.assertTrue(at["notification_emitted"])
        self.assertEqual(at["daily_quota"], 2)

    def test_token_exact_refill_and_rejected_candidate_does_not_spend(self):
        state = self.new("token_bucket")
        state.process(transaction(0), True)
        before = state.process(transaction(1, replay.DAY_NS // 5 - 1), True)
        at = state.process(transaction(2, replay.DAY_NS // 5), True)
        self.assertEqual(before["suppression_reason"], "token_shortage")
        self.assertEqual(before["token_credit_units"], replay.DAY_NS - 5)
        self.assertTrue(at["notification_emitted"])
        self.assertEqual(at["token_credit_units"], 0)

    def test_non_candidates_do_not_consume_budget(self):
        for policy in replay.POLICIES:
            state = self.new(policy, 1)
            self.assertEqual(state.process(transaction(0), False)["suppression_reason"], "not_candidate")
            self.assertTrue(state.process(transaction(1, 1), True)["notification_emitted"])
            self.assertEqual(state.process(transaction(2, 2), True)["suppression_reason"], "hard_daily_cap")

    def test_zero_budget_never_emits(self):
        for policy in replay.POLICIES:
            state = self.new(policy, 0)
            self.assertEqual(state.process(transaction(0), True)["suppression_reason"], "hard_daily_cap")

    def test_invalid_input_leaves_admission_state_unchanged(self):
        state = self.new("token_bucket")
        state.process(transaction(0, 5), True)
        saved = replay.canonical(state.snapshot())
        for tx, candidate in [(transaction(0, 5), True), (transaction(1, 4), True),
                              (transaction(1, 6), 1), (transaction(1, replay.DAY_NS), True)]:
            with self.assertRaises(ValueError):
                state.process(tx, candidate)
            self.assertEqual(replay.canonical(state.snapshot()), saved)

    def test_independent_prefix_oracle_all_policies_caps(self):
        rng = random.Random(20261026)
        times = sorted(rng.randrange(replay.DAY_NS) for _ in range(250))
        candidates = [rng.randrange(4) != 0 for _ in times]
        for policy in replay.POLICIES:
            for budget in (0, 1, 5, 20):
                state, accepted = self.new(policy, budget), []
                for i, (t, candidate) in enumerate(zip(times, candidates)):
                    allowed = candidate and len(accepted) < budget
                    if policy == "paced_cumulative":
                        # The next permission's release condition, rather than
                        # computing the production quota expression.
                        allowed = allowed and (len(accepted) == 0 or t * budget >= len(accepted) * replay.DAY_NS)
                    elif policy == "token_bucket":
                        allowed = allowed and (not accepted or (t - accepted[-1]) * budget >= replay.DAY_NS)
                    row = state.process(transaction(i, t), candidate)
                    self.assertEqual(row["notification_emitted"], allowed, (policy, budget, i))
                    if allowed:
                        accepted.append(t)
                    self.assertEqual(row["notifications_on_day"], len(accepted))
                self.assertLessEqual(len(accepted), budget)


class IntegrationTests(unittest.TestCase):
    def test_fixed_configuration_and_boolean_budget_rejection(self):
        self.assertEqual(replay.validate_config(config())["execution"]["cells"], 54)
        malformed = config()
        malformed["budgets"][0] = True
        with self.assertRaises(ValueError):
            replay.validate_config(malformed)

    def test_semantic_and_count_common_candidates_and_cold_start_metrics(self):
        observations = [observation(i, i * replay.NS, i + 1) for i in range(24)]
        result = replay.replay_day(config(), DAY, observations,
                                 source_audit_sha256=AUDIT, source_scope=replay.SOURCE_SCOPE)
        for method in replay.METHODS:
            expected = [row["transaction"]["transaction_hash"] for row in result["methods"][method] if row["group_candidate"]]
            for policy in replay.POLICIES:
                for budget in (1, 5, 20):
                    rows = result["decisions"][(method, policy, budget)]
                    actual = [row["transaction"]["transaction_hash"] for row in rows if row["group_candidate"]]
                    self.assertEqual(actual, expected)
                    self.assertEqual(sum(row["notification_emitted"] for row in rows), 1)
        semantic = result["method_summaries"][replay.METHODS[1]]
        self.assertEqual(semantic["positive_token_observations"], 24)
        self.assertEqual(semantic["eligible_token_scores"], 5)
        self.assertEqual(semantic["cold_start_token_scores"], 19)
        self.assertEqual(semantic["raw_triggers"], 5)
        self.assertEqual(semantic["group_candidates"], 1)
        self.assertEqual(result["method_summaries"][replay.METHODS[0]]["raw_triggers"], 15)

    def test_no_outflows_not_confused_with_cold_start(self):
        observations = [observation(i, i * replay.NS, None) for i in range(5)]
        result = replay.replay_day(config(), DAY, observations,
                                 source_audit_sha256=AUDIT, source_scope=replay.SOURCE_SCOPE)
        summary = result["method_summaries"][replay.METHODS[1]]
        for field in ("positive_token_observations", "eligible_token_scores", "cold_start_token_scores", "raw_triggers"):
            self.assertEqual(summary[field], 0)

    def test_day_histories_and_budget_are_reset(self):
        day1 = [observation(i, i * replay.NS, i + 1) for i in range(20)]
        day2 = [observation(i, i * replay.NS, i + 100, day="2023-03-13") for i in range(10)]
        first = replay.replay_day(config(), DAY, day1, source_audit_sha256=AUDIT, source_scope=replay.SOURCE_SCOPE)
        second = replay.replay_day(config(), "2023-03-13", day2,
                                  source_audit_sha256=AUDIT, source_scope=replay.SOURCE_SCOPE)
        self.assertEqual(first["method_summaries"][replay.METHODS[1]]["eligible_token_scores"], 1)
        self.assertEqual(second["method_summaries"][replay.METHODS[1]]["eligible_token_scores"], 0)
        self.assertEqual(second["method_summaries"][replay.METHODS[0]]["group_candidates"], 1)
        self.assertEqual(next(x for x in second["cell_summaries"] if x["method"] == replay.METHODS[0] and x["policy"] == "greedy" and x["daily_budget"] == 1)["notifications"], 1)

    def test_invalid_semantic_observation_halts_all_method_results(self):
        observations = [observation(i, i * replay.NS, i + 1) for i in range(21)]
        observations[20]["token_flows"][0]["net_external_in_raw"] = "999"
        with self.assertRaises(ValueError):
            replay.replay_day(config(), DAY, observations,
                              source_audit_sha256=AUDIT, source_scope=replay.SOURCE_SCOPE)

    def test_manifest_integrity_precedes_content(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "manifest.json"
            path.write_text("{}\n")
            with self.assertRaisesRegex(ValueError, "input manifest digest mismatch"):
                replay.load_inputs(config(), path, "0" * 64, expected_selection_manifest_sha256=SELECTION)

    def test_complete_source_envelope_loads_all_fixed_observations(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg, path, selected_sha, manifest = input_fixture(temp)
            loaded, days = replay.load_inputs(cfg, path, replay.file_digest(path),
                                              expected_selection_manifest_sha256=selected_sha)
            self.assertEqual([len(v) for v in days.values()], [218, 676])
            self.assertEqual(loaded, manifest)

    def test_rehashed_observation_cannot_substitute_frozen_transaction(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg, path, selected_sha, manifest = input_fixture(temp)
            item = manifest["days"][0]
            data_path = Path(temp) / item["path"]
            rows = [replay.strict_json(raw) for raw in data_path.read_bytes().splitlines()]
            rows[0]["transaction"]["transaction_hash"] = "0x" + "ff" * 32
            data_path.write_bytes(b"".join(replay.canonical(row) + b"\n" for row in rows))
            item.update(bytes=data_path.stat().st_size, sha256=replay.file_digest(data_path),
                        observation_sha256=[replay.digest(row) for row in rows])
            manifest_sha = rewrite_manifest(path, manifest)
            with self.assertRaisesRegex(ValueError, "differs from frozen selection"):
                replay.load_inputs(cfg, path, manifest_sha, expected_selection_manifest_sha256=selected_sha)

    def test_source_audit_failure_is_not_an_accepted_input(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg, path, selected_sha, manifest = input_fixture(temp)
            audit_path = Path(temp) / "source_audit_manifest.json"
            audit_path.write_bytes(replay.canonical({"schema_version": "semantic_flow_source_audit_v1", "status": "FAILED", "selection_manifest_sha256": selected_sha}) + b"\n")
            manifest["source_audit_manifest_sha256"] = replay.file_digest(audit_path)
            manifest_sha = rewrite_manifest(path, manifest)
            with self.assertRaisesRegex(ValueError, "source audit or selection"):
                replay.load_inputs(cfg, path, manifest_sha, expected_selection_manifest_sha256=selected_sha)

    def test_missing_transaction_is_not_skipped(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg, path, selected_sha, manifest = input_fixture(temp)
            item = manifest["days"][0]
            data_path = Path(temp) / item["path"]
            raw = data_path.read_bytes().splitlines(keepends=True)
            data_path.write_bytes(b"".join(raw[:-1]))
            item.update(bytes=data_path.stat().st_size, sha256=replay.file_digest(data_path))
            manifest_sha = rewrite_manifest(path, manifest)
            with self.assertRaisesRegex(ValueError, "actual day population"):
                replay.load_inputs(cfg, path, manifest_sha, expected_selection_manifest_sha256=selected_sha)

    def test_json_duplicate_keys_and_nonfinite_values_rejected(self):
        for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(ValueError):
                replay.strict_json(raw)


if __name__ == "__main__":
    unittest.main()
