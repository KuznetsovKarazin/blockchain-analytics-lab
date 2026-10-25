"""Contract/invariant tests, not attack-detection performance evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

PATH = Path(__file__).resolve().parents[1] / "replay_core.py"
SPEC = importlib.util.spec_from_file_location("monitoring_replay_core", PATH)
core = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = core
SPEC.loader.exec_module(core)

BASE = 1675209600.0  # 2023-02-01 00:00:00 UTC


def event(number, seconds=0, count=301, **extra):
    return {"chain_id": 1, "block_number": number,
            "block_hash": "0x" + f"{number:064x}", "event_time": BASE + seconds,
            "transaction_count": count, **extra}


def process(state, e, delay=0, **kwargs):
    available = e["event_time"] + delay
    return state.process(e, replay_available_time=available,
                         decision_time=available + 0.001, **kwargs)


class ReplayTests(unittest.TestCase):
    def test_prefix_and_future_labels_do_not_change_decisions(self):
        prefix = [event(1), event(2, 12), event(3, 360)]
        s = core.ReplayState()
        expected = [process(s, e) for e in prefix]
        full = core.ReplayState()
        actual = [process(full, e) for e in prefix + [event(4, 720, label=1,
                   label_available_time=BASE + 900000), event(5, 732, count=99999)]]
        self.assertEqual(expected, actual[:len(prefix)])
        labelled = core.ReplayState()
        for e, target in zip(prefix, expected):
            row = process(labelled, {**e, "label": 1, "label_available_time": BASE + 900000})
            row["label_available_time"] = None
            self.assertEqual(target, row)

    def test_duplicate_does_not_emit_or_spend_budget(self):
        s = core.ReplayState()
        first = process(s, event(1))
        duplicate = process(s, event(1), delay=1)
        self.assertTrue(first["notification_emitted"])
        self.assertEqual(duplicate["suppression_reason"], "duplicate")
        self.assertIsNone(duplicate["raw_trigger"])
        self.assertIsNone(duplicate["alert_id"])
        self.assertEqual(len(s.emitted_alert_ids), 1)

    def test_checkpoint_restart_matches_uninterrupted(self):
        events = [event(i + 1, i * 120) for i in range(20)]
        uninterrupted = core.ReplayState()
        expected = [process(uninterrupted, e) for e in events]
        first = core.ReplayState()
        actual = [process(first, e) for e in events[:7]]
        restored = core.ReplayState.from_dict(json.loads(json.dumps(first.to_dict())))
        actual += [process(restored, e) for e in events[7:]]
        self.assertEqual(actual, expected)
        self.assertEqual(restored.to_dict(), uninterrupted.to_dict())
        duplicate = process(restored, events[0], delay=3000)
        self.assertEqual(duplicate["suppression_reason"], "duplicate")

    def test_late_event_is_dropped_without_rewriting_watermark(self):
        s = core.ReplayState()
        process(s, event(3, 360))
        row = process(s, event(1), delay=400)
        self.assertEqual(row["suppression_reason"], "late")
        self.assertEqual(s.high_water_block, 3)
        self.assertEqual(len(s.emitted_alert_ids), 1)

    def test_budget_uses_decision_day_and_rejected_trigger_does_not_extend_group(self):
        s = core.ReplayState(core.ReplayConfig(daily_budget=1))
        # First event/decision before midnight, second event before but decision after.
        a = process(s, event(1, 86400 - 1000))
        b = process(s, event(2, 86400 - 200), delay=10)
        c = process(s, event(3, 86400 - 100), delay=120)
        self.assertTrue(a["notification_emitted"])
        self.assertEqual(b["suppression_reason"], "budget")
        self.assertTrue(c["notification_emitted"])
        self.assertNotEqual(a["budget_day_utc"], c["budget_day_utc"])
        self.assertTrue(all(v <= 1 for v in s.daily_counts.values()))

    def test_grouping_is_fixed_anchor_not_sliding_raw_trigger(self):
        s = core.ReplayState()
        self.assertTrue(process(s, event(1))["notification_emitted"])
        self.assertEqual(process(s, event(2, 299))["suppression_reason"], "grouped")
        self.assertTrue(process(s, event(3, 300))["notification_emitted"])

    def test_threshold_is_strict_and_unknown_observation_stays_null(self):
        s = core.ReplayState()
        row = process(s, event(1, count=300))
        self.assertFalse(row["raw_trigger"])
        self.assertIsNone(row["observed_time"])
        self.assertIsNone(row["label_available_time"])

    def test_invalid_and_backdated_clocks_do_not_change_state(self):
        s = core.ReplayState()
        process(s, event(1), delay=100)
        before = copy.deepcopy(s.to_dict())
        for kwargs in ({"replay_available_time": BASE + 12, "decision_time": BASE + 13},
                       {"replay_available_time": BASE + 130, "decision_time": BASE + 129},
                       {"replay_available_time": BASE + 10, "decision_time": BASE + 120},
                       {"replay_available_time": BASE + 120, "feature_ready_time": BASE + 119,
                        "decision_time": BASE + 121}):
            with self.assertRaises(ValueError):
                s.process(event(2, 12), **kwargs)
            self.assertEqual(before, s.to_dict())

    def test_conflicting_duplicate_fails_closed(self):
        s = core.ReplayState()
        process(s, event(1))
        before = s.to_dict()
        with self.assertRaisesRegex(ValueError, "conflicting payload"):
            process(s, event(1, count=999), delay=12)
        self.assertEqual(before, s.to_dict())

    def test_config_and_id_are_stable_and_namespaced(self):
        a = process(core.ReplayState(), event(1))
        b = process(core.ReplayState(), event(1))
        c = process(core.ReplayState(core.ReplayConfig(daily_budget=20)), event(1))
        self.assertEqual(a, b)
        self.assertEqual(a["event_id"], c["event_id"])
        self.assertNotEqual(a["alert_id"], c["alert_id"])

    def test_zero_budget_and_disabled_cooldown(self):
        s = core.ReplayState(core.ReplayConfig(daily_budget=0, cooldown_seconds=0))
        for i in range(5):
            row = process(s, event(i + 1, i * 12))
            self.assertTrue(row["raw_trigger"])
            self.assertTrue(row["group_candidate"])
            self.assertEqual(row["suppression_reason"], "budget")
        self.assertFalse(s.emitted_alert_ids)

    def test_callback_samples_decision_after_grouping_and_obeys_budget_day(self):
        s = core.ReplayState()
        calls = []
        def clock():
            calls.append(True)
            return BASE + 86400.5
        row = s.process(event(1, 86399), replay_available_time=BASE + 86399,
                        feature_ready_time=BASE + 86400, decision_time=clock)
        self.assertEqual(calls, [True])
        self.assertEqual(row["budget_day_utc"], "2023-02-02")
        self.assertEqual(row["decision_time"], BASE + 86400.5)
        self.assertTrue(row["notification_emitted"])

    def test_playback_calendar_is_separate_from_historical_event_date(self):
        playback_origin = 1792886400.0  # 2026-10-25 UTC
        s = core.ReplayState()
        row = s.process(event(1), replay_available_time=playback_origin,
                        feature_ready_time=playback_origin + 0.01,
                        decision_time=playback_origin + 0.02)
        self.assertEqual(row["event_time"], BASE)
        self.assertIsNone(row["observed_time"])
        self.assertEqual(row["budget_day_utc"], "2026-10-25")

    def test_wrong_chain_and_non_header_rejected(self):
        s = core.ReplayState()
        for e in (event(1, chain_id=56), event(1, tx_index=0), event(1, count=-1)):
            with self.assertRaises(ValueError):
                process(s, e)
        self.assertEqual(s.high_water_block, -1)


if __name__ == "__main__":
    unittest.main()
