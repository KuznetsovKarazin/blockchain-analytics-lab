"""Offline adversarial tests for causal flow ranks and fixed candidate grouping."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from semantic_flow_monitor import (SemanticFlowError, SemanticFlowMonitor,
                                   canonical_sha256, validate_observation)

A = "0x" + "11" * 20
TOKEN = "0x" + "22" * 20
TOKEN2 = "0x" + "33" * 20
AUDIT = "a" * 64
NS = 1_000_000_000


def config(**changes):
    value = {"schema_version": "semantic_flow_monitor_config_v1", "chain_id": 1,
             "population_addresses": [A], "history_size": 128, "min_history": 19,
             "threshold_numerator": 1, "threshold_denominator": 20,
             "grouping_ns": 300 * NS, "max_tokens": 4096}
    value.update(changes)
    return value


def observation(i, amounts=None, *, time_ns=None, incoming=None):
    amounts = {TOKEN: 10} if amounts is None else amounts
    incoming = {} if incoming is None else incoming
    flows = []
    total = 0
    for token in sorted(set(amounts) | set(incoming)):
        out = amounts.get(token, 0)
        inc = incoming.get(token, 0)
        row = {"chain_id": 1, "token_address": token,
               "external_out_raw": str(out), "external_in_raw": str(inc),
               "internal_raw": "0", "mint_from_zero_raw": "0", "burn_to_zero_raw": "0",
               "external_out_count": int(token in amounts), "external_in_count": int(token in incoming),
               "internal_count": 0, "mint_from_zero_count": 0, "burn_to_zero_count": 0,
               "transfer_log_count": int(token in amounts) + int(token in incoming),
               "net_external_in_raw": str(inc - out), "net_event_in_raw": str(inc - out)}
        total += row["transfer_log_count"]
        flows.append(row)
    return {"schema_version": "archive_transfer_observation_v1", "status": "observed_success",
            "dataset_execution_status": 1,
            "transaction": {"chain_id": 1, "block_number": 100 + i,
                "block_hash": "0x" + format(100 + i, "064x"), "transaction_index": 0,
                "transaction_hash": "0x" + format(i + 1, "064x"),
                "event_time_ns": i * NS if time_ns is None else time_ns},
            "population_addresses": [A], "raw_amount_encoding": "base10_integer_string",
            "counts": {"logs": total, "erc20_shaped": total, "erc721_shaped": 0, "opaque": 0,
                       "monitored_erc20_shaped": total, "zero_value_transfers": sum(x == 0 for x in amounts.values())},
            "token_flows": flows, "archived_core_log_count": int(total > 0),
            "evidence": {"tier": "enumerated_daily_partition_and_transaction_metadata_checked",
                "source_audit_manifest_sha256": AUDIT, "selection_manifest_sha256": "b" * 64,
                "raw_receipt_acquired": False, "receipt_root_verified": False,
                "historical_deployed_abi_verified": False, "token_erc20_compliance_verified": False,
                "observed_time": None, "full_chain_completeness_verified": False}}


def monitor(**changes):
    return SemanticFlowMonitor(config(**changes), source_audit_sha256=AUDIT,
                               source_scope="synthetic complete transaction observations")


def feed(obj, item):
    return obj.observe(item, expected_observation_sha256=canonical_sha256(item))


def history(obj, amounts, token=TOKEN):
    for i, amount in enumerate(amounts):
        feed(obj, observation(i, {token: amount}))


class TestSemanticFlowMonitor(unittest.TestCase):
    def assert_rejected_without_mutation(self, obj, item, digest=None):
        before = obj.snapshot()
        with self.assertRaises(SemanticFlowError):
            obj.observe(item, expected_observation_sha256=canonical_sha256(item) if digest is None else digest)
        self.assertEqual(before, obj.snapshot())

    def test_first_nineteen_positive_outflows_are_cold_start(self):
        obj = monitor()
        for i in range(19):
            d = feed(obj, observation(i, {TOKEN: i + 1}))
            self.assertEqual(d["eligible_token_count"], 0)
            self.assertFalse(d["raw_trigger"])
            self.assertEqual(d["token_scores"][0]["history_count"], i)
        d = feed(obj, observation(19, {TOKEN: 20}))
        self.assertEqual(d["token_scores"][0]["tail_rank"], {"numerator": 1, "denominator": 20})
        self.assertTrue(d["raw_trigger"])
        self.assertTrue(d["group_candidate"])

    def test_ties_are_conservative(self):
        obj = monitor()
        history(obj, [100] * 19)
        d = feed(obj, observation(19, {TOKEN: 100}))
        self.assertEqual(d["token_scores"][0]["tail_rank"], {"numerator": 20, "denominator": 20})
        self.assertFalse(d["raw_trigger"])

    def test_exact_threshold_boundaries(self):
        for n, ge, expected in [(19, 0, True), (20, 0, True), (38, 1, False),
                                (39, 1, True), (40, 1, True), (128, 5, True), (128, 6, False)]:
            with self.subTest(n=n, ge=ge):
                obj = monitor()
                history(obj, [100] * ge + [1] * (n - ge))
                d = feed(obj, observation(n, {TOKEN: 50}))
                self.assertEqual(d["raw_trigger"], expected)
                self.assertEqual(d["token_scores"][0]["tail_rank"], {"numerator": ge + 1, "denominator": n + 1})

    def test_sensitivity_is_a_separate_fixed_configuration(self):
        strict, sensitive = monitor(), monitor(threshold_denominator=10)
        for obj in (strict, sensitive):
            history(obj, [100] + [1] * 18)
        a, b = [feed(o, observation(19, {TOKEN: 50})) for o in (strict, sensitive)]
        self.assertFalse(a["raw_trigger"])
        self.assertTrue(b["raw_trigger"])
        self.assertNotEqual(a["config_sha256"], b["config_sha256"])

    def test_sliding_window_contains_only_preceding_positive_values(self):
        obj = monitor(history_size=4, min_history=3, threshold_denominator=4)
        history(obj, [100, 1, 2, 3, 4])
        d = feed(obj, observation(5, {TOKEN: 5}))
        self.assertEqual(d["token_scores"][0]["tail_rank"], {"numerator": 1, "denominator": 5})
        self.assertTrue(d["raw_trigger"])
        self.assertEqual([r["amount_raw"] for r in obj.snapshot()["histories"][TOKEN]], ["2", "3", "4", "5"])
        self.assertEqual(d["token_scores"][0]["reference_oldest_event_time_ns"], NS)
        self.assertEqual(d["token_scores"][0]["reference_newest_event_time_ns"], 4 * NS)

    def test_grouping_does_not_change_reference_updates(self):
        obj = monitor()
        history(obj, list(range(1, 20)))
        first = feed(obj, observation(19, {TOKEN: 20}, time_ns=19 * NS))
        grouped = feed(obj, observation(20, {TOKEN: 21}, time_ns=20 * NS))
        boundary = feed(obj, observation(21, {TOKEN: 22}, time_ns=319 * NS))
        self.assertTrue(first["group_candidate"])
        self.assertTrue(grouped["raw_trigger"])
        self.assertFalse(grouped["group_candidate"])
        self.assertEqual(grouped["grouping_reason"], "grouped")
        self.assertTrue(boundary["group_candidate"])
        self.assertEqual(boundary["last_candidate_time_ns_before"], 19 * NS)
        self.assertEqual(boundary["token_scores"][0]["history_count"], 21)
        self.assertEqual(obj.snapshot()["histories"][TOKEN][-2]["amount_raw"], "21")

    def test_token_scores_are_separate_and_merge_once(self):
        obj = monitor()
        for i in range(19):
            feed(obj, observation(i, {TOKEN: 10, TOKEN2: 1000}))
        d = feed(obj, observation(19, {TOKEN: 11, TOKEN2: 1000}))
        self.assertEqual(d["eligible_token_count"], 2)
        self.assertEqual(d["triggering_token_addresses"], [TOKEN])
        self.assertEqual([x["trigger"] for x in d["token_scores"]], [True, False])
        self.assertTrue(d["group_candidate"])

    def test_gross_outflow_can_trigger_with_zero_net_event_flow(self):
        obj = monitor()
        history(obj, [1] * 19)
        d = feed(obj, observation(19, {TOKEN: 500}, incoming={TOKEN: 500}))
        self.assertTrue(d["raw_trigger"])
        self.assertEqual(d["token_scores"][0]["external_in_raw"], "500")
        self.assertEqual(d["token_scores"][0]["net_external_in_raw"], "0")
        self.assertFalse(d["rank_is_calibrated_p_value"])

    def test_zero_incoming_mint_burn_internal_do_not_enter_reference(self):
        obj = monitor()
        items = [observation(0, {}), observation(1, {TOKEN: 0}), observation(2, {}, incoming={TOKEN: 11})]
        for i, category in enumerate(("internal", "mint_from_zero", "burn_to_zero"), 3):
            item = observation(i, {TOKEN: 0})
            row = item["token_flows"][0]
            row["external_out_count"] = 0
            row[category + "_raw"], row[category + "_count"] = "11", 1
            row["net_event_in_raw"] = "11" if category == "mint_from_zero" else "-11" if category == "burn_to_zero" else "0"
            item["counts"]["zero_value_transfers"] = 0
            items.append(item)
        for item in items:
            d = feed(obj, item)
            self.assertEqual(d["grouping_reason"], "no_positive_external_outflow")
        self.assertEqual(obj.snapshot()["histories"], {})
        self.assertEqual(obj.snapshot()["processed_observations"], 6)

    def test_large_raw_integers_remain_exact_strings(self):
        obj = monitor()
        x = 2 ** 256 - 1
        history(obj, [x] * 19)
        item = observation(19, {TOKEN: 2 * x})
        item["token_flows"][0]["external_out_count"] = 2
        item["token_flows"][0]["transfer_log_count"] = 2
        item["counts"].update(logs=2, erc20_shaped=2, monitored_erc20_shaped=2)
        d = feed(obj, item)
        self.assertTrue(d["raw_trigger"])
        self.assertEqual(d["token_scores"][0]["external_out_raw"], str(2 * x))
        self.assertEqual(obj.snapshot()["histories"][TOKEN][-1]["amount_raw"], str(2 * x))

    def test_future_suffix_does_not_change_prefix(self):
        data = [observation(i, {TOKEN: i + 1}) for i in range(25)]
        a, b = monitor(), monitor()
        prefix = [feed(a, x) for x in data[:20]]
        full = [feed(b, x) for x in data]
        self.assertEqual(prefix, full[:20])

    def test_restart_matches_uninterrupted_decisions_and_state(self):
        data = [observation(i, {TOKEN: i + 1, TOKEN2: 100}, time_ns=i * 100 * NS) for i in range(150)]
        whole = monitor()
        expected = [feed(whole, x) for x in data]
        split = monitor()
        actual = [feed(split, x) for x in data[:73]]
        checkpoint = split.snapshot()
        split = SemanticFlowMonitor.from_snapshot(checkpoint, expected_snapshot_sha256=canonical_sha256(checkpoint))
        actual.extend(feed(split, x) for x in data[73:])
        self.assertEqual(actual, expected)
        self.assertEqual(split.snapshot(), whole.snapshot())

    def test_snapshot_and_decision_are_detached_from_mutable_input(self):
        obj = monitor()
        item = observation(0)
        decision = feed(obj, item)
        snapshot = obj.snapshot()
        snapshot["histories"][TOKEN][0]["amount_raw"] = "999"
        item["transaction"]["event_time_ns"] = 999
        decision["transaction"]["event_time_ns"] = 999
        self.assertEqual(obj.snapshot()["histories"][TOKEN][0]["amount_raw"], "10")
        self.assertEqual(obj.snapshot()["last_transaction"]["event_time_ns"], 0)
        detached = obj.config
        detached["threshold_denominator"] = 1
        self.assertEqual(obj.config["threshold_denominator"], 20)

    def test_source_digest_and_unknown_status_fail_atomically(self):
        obj = monitor()
        feed(obj, observation(0))
        self.assert_rejected_without_mutation(obj, observation(1), "0" * 64)
        for mutation in [lambda x: x.update(dataset_execution_status=None),
                         lambda x: x.update(dataset_execution_status=True),
                         lambda x: x.update(dataset_execution_status=0),
                         lambda x: x.update(status="unavailable"),
                         lambda x: x["evidence"].update(source_audit_manifest_sha256="c" * 64),
                         lambda x: x["evidence"].update(tier="complete"),
                         lambda x: x["evidence"].update(raw_receipt_acquired=True),
                         lambda x: x["evidence"].update(token_erc20_compliance_verified=True),
                         lambda x: x["evidence"].update(observed_time=0)]:
            item = observation(1)
            mutation(item)
            self.assert_rejected_without_mutation(obj, item)
        self.assert_rejected_without_mutation(obj, None)

    def test_invalid_second_token_cannot_update_first(self):
        obj = monitor()
        feed(obj, observation(0))
        item = observation(1, {TOKEN: 20, TOKEN2: 30})
        item["token_flows"][1]["external_out_raw"] = "03"
        self.assert_rejected_without_mutation(obj, item)

    def test_capacity_failure_is_atomic_without_eviction(self):
        obj = monitor(max_tokens=1)
        feed(obj, observation(0))
        self.assert_rejected_without_mutation(obj, observation(1, {TOKEN: 20, TOKEN2: 30}))
        self.assertEqual(list(obj.snapshot()["histories"]), [TOKEN])

    def test_duplicate_late_and_decreasing_time_fail(self):
        obj = monitor()
        feed(obj, observation(2))
        self.assert_rejected_without_mutation(obj, observation(2))
        self.assert_rejected_without_mutation(obj, observation(1))
        self.assert_rejected_without_mutation(obj, observation(3, time_ns=NS))

    def test_same_block_requires_same_time_and_hash(self):
        a = observation(0)
        obj = monitor()
        feed(obj, a)
        b = observation(1, time_ns=0)
        b["transaction"].update(block_number=100, block_hash=a["transaction"]["block_hash"], transaction_index=1)
        feed(obj, b)
        for field, val in [("event_time_ns", NS), ("block_hash", "0x" + "f" * 64)]:
            c = observation(2, time_ns=0)
            c["transaction"].update(block_number=100, block_hash=a["transaction"]["block_hash"], transaction_index=2)
            c["transaction"][field] = val
            self.assert_rejected_without_mutation(obj, c)

    def test_config_identity_and_strict_types(self):
        for change in [{"history_size": True}, {"min_history": 129}, {"threshold_denominator": 0},
                       {"threshold_numerator": 21}, {"max_tokens": 0}, {"grouping_ns": -1},
                       {"population_addresses": [A, A]}, {"chain_id": "1"}]:
            with self.subTest(change=change), self.assertRaises(SemanticFlowError):
                monitor(**change)

    def test_counts_raw_values_and_population_are_checked(self):
        obj = monitor()
        mutators = [lambda x: x["counts"].update(logs=True), lambda x: x["counts"].update(logs=1.0),
                    lambda x: x["counts"].update(logs=2), lambda x: x.update(archived_core_log_count=2),
                    lambda x: x.update(population_addresses=[TOKEN]),
                    lambda x: x["transaction"].update(chain_id=2),
                    lambda x: x["token_flows"][0].update(external_out_raw="-1"),
                    lambda x: x["token_flows"][0].update(external_out_raw=10),
                    lambda x: x["token_flows"][0].update(net_event_in_raw="0"),
                    lambda x: x["token_flows"][0].update(transfer_log_count=2)]
        for mutate in mutators:
            item = observation(0)
            mutate(item)
            self.assert_rejected_without_mutation(obj, item)

    def test_checkpoint_digest_and_internal_invariants(self):
        obj = monitor()
        history(obj, [1, 2, 3])
        original = obj.snapshot()
        with self.assertRaises(SemanticFlowError):
            SemanticFlowMonitor.from_snapshot(original, expected_snapshot_sha256="0" * 64)
        for mutation in [lambda x: x.update(config_sha256="0" * 64),
                         lambda x: x.update(last_candidate_time_ns=999 * NS),
                         lambda x: x.update(last_candidate_time_ns=NS),
                         lambda x: x.update(processed_observations=True),
                         lambda x: x["histories"][TOKEN][0].update(amount_raw="0"),
                         lambda x: x["histories"][TOKEN][0].update(block_number=999),
                         lambda x: x["histories"][TOKEN].reverse()]:
            state = copy.deepcopy(original)
            mutation(state)
            with self.assertRaises(SemanticFlowError):
                SemanticFlowMonitor.from_snapshot(state, expected_snapshot_sha256=canonical_sha256(state))

    def test_checkpoint_rejects_cross_token_context_conflict(self):
        obj = monitor()
        feed(obj, observation(0, {TOKEN: 10, TOKEN2: 20}))
        state = obj.snapshot()
        state["histories"][TOKEN2][0]["observation_sha256"] = "f" * 64
        with self.assertRaises(SemanticFlowError):
            SemanticFlowMonitor.from_snapshot(state, expected_snapshot_sha256=canonical_sha256(state))

    def test_shared_validator_and_legacy_compatibility(self):
        item = observation(0)
        result = validate_observation(item, expected_observation_sha256=canonical_sha256(item),
            config=config(), source_audit_sha256=AUDIT, source_scope="test")
        self.assertEqual(result["archived_core_log_count"], 1)
        legacy = copy.deepcopy(item)
        legacy.update(schema_version="transfer_observation_v1", provider_execution_status=1)
        legacy.pop("dataset_execution_status")
        legacy.pop("archived_core_log_count")
        legacy["evidence"].update(tier="provider_pagination_exhausted_structure_checked",
            source_record_sha256="d" * 64, normalizer_source_sha256="e" * 64)
        d = feed(monitor(), legacy)
        self.assertEqual(d["positive_token_count"], 1)
        mixed = monitor()
        feed(mixed, item)
        legacy["transaction"] = observation(1)["transaction"]
        self.assert_rejected_without_mutation(mixed, legacy)


if __name__ == "__main__":
    unittest.main()
