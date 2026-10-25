"""Synthetic fixtures check log-replay invariants; they are not attack evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

PATH = Path(__file__).resolve().parents[1] / "event_log_replay.py"
SPEC = importlib.util.spec_from_file_location("monitoring_event_log_replay", PATH)
core = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = core
SPEC.loader.exec_module(core)

BASE = 1677628800  # historical 2023-03-01 UTC
BASE_NS = BASE * 1_000_000_000
PLAYBACK = 1792886400  # declared 2026-10-25 UTC playback
ADDRESS = "0x27182842e098f60e3d576794a5bffb0777e025d3"


def raw(block=1, seconds=0, *, tx_index=0, log_index=0, tx_id=None, **extra):
    tx_id = block * 1000 + tx_index if tx_id is None else tx_id
    return {
        "chain_id": 1, "address": ADDRESS,
        "block_number": block, "block_hash": "0x" + f"{block:064x}",
        "transaction_index": tx_index, "transaction_hash": "0x" + f"{tx_id:064x}",
        "log_index": log_index, "topics": ["0x" + "11" * 32],
        "data": "0x1234", "event_time_ns": BASE_NS + int(seconds * 1_000_000_000),
        "observed_time": None, "label_available_time": None, **extra,
    }


def apply(state, source, *, extra_delay=0, decision_time=None):
    event = core.decode_event(source)
    arrival = PLAYBACK + (event["event_time_ns"] - BASE_NS) / 1_000_000_000 + extra_delay
    return state.process(event, replay_available_time=arrival,
                         feature_ready_time=arrival + .0005,
                         decision_time=arrival + .001 if decision_time is None else decision_time)


class EventLogReplayTests(unittest.TestCase):
    def test_window_includes_current_and_tenth_log_triggers(self):
        state = core.LogReplayState(core.LogConfig())
        rows = [apply(state, raw(log_index=i)) for i in range(10)]
        self.assertEqual([r["score"] for r in rows], list(range(1, 11)))
        self.assertTrue(all(r["raw_trigger"] is False for r in rows[:9]))
        self.assertTrue(rows[9]["raw_trigger"])
        self.assertTrue(rows[9]["notification_emitted"])

    def test_open_left_window_boundary_expires_exactly_sixty_seconds(self):
        state = core.LogReplayState(core.LogConfig())
        for i in range(9):
            apply(state, raw(log_index=i))
        row_before = apply(state, raw(2, 59, log_index=0))
        self.assertEqual(row_before["score"], 10)
        row_at = apply(state, raw(3, 60, log_index=0))
        self.assertEqual(row_at["score"], 2)  # time zero excluded, current included
        self.assertFalse(row_at["raw_trigger"])

    def test_duplicate_does_not_enter_count_or_create_notification(self):
        state = core.LogReplayState(core.LogConfig())
        for i in range(9):
            apply(state, raw(log_index=i))
        duplicate = apply(state, raw(log_index=8))
        self.assertEqual(duplicate["suppression_reason"], "duplicate")
        self.assertIsNone(duplicate["score"])
        self.assertIsNone(duplicate["raw_trigger"])
        self.assertFalse(duplicate["notification_emitted"])
        tenth = apply(state, raw(log_index=9))
        self.assertEqual(tenth["score"], 10)
        self.assertTrue(tenth["notification_emitted"])
        duplicate_notification = apply(state, raw(log_index=9))
        self.assertEqual(duplicate_notification["suppression_reason"], "duplicate")
        self.assertFalse(duplicate_notification["notification_emitted"])

    def test_late_does_not_enter_count_or_rewrite_old_decisions(self):
        state = core.LogReplayState(core.LogConfig())
        earlier = [apply(state, raw(1, 0)), apply(state, raw(3, 12))]
        saved = copy.deepcopy(earlier)
        late = apply(state, raw(2, 6), extra_delay=7)
        self.assertEqual(late["suppression_reason"], "late")
        self.assertIsNone(late["score"])
        self.assertFalse(late["notification_emitted"])
        next_row = apply(state, raw(4, 18))
        self.assertEqual(next_row["score"], 3)
        self.assertEqual(earlier, saved)

    def test_ordered_logs_with_same_block_timestamp_are_all_accepted(self):
        state = core.LogReplayState(core.LogConfig())
        a = apply(state, raw(tx_index=0, log_index=0))
        b = apply(state, raw(tx_index=0, log_index=1))
        c = apply(state, raw(tx_index=1, log_index=2))
        self.assertEqual([a["score"], b["score"], c["score"]], [1, 2, 3])
        self.assertEqual(len({r["event_id"] for r in (a, b, c)}), 3)

    def test_late_order_is_transaction_then_log_within_block(self):
        state = core.LogReplayState(core.LogConfig())
        apply(state, raw(tx_index=1, log_index=2))
        dropped = apply(state, raw(tx_index=0, log_index=1))
        self.assertEqual(dropped["suppression_reason"], "late")
        next_row = apply(state, raw(tx_index=1, log_index=3))
        self.assertEqual(next_row["score"], 2)

    def test_grouped_raw_trigger_does_not_slide_cooldown_anchor(self):
        state = core.LogReplayState(core.LogConfig(threshold_count=1))
        first = apply(state, raw(1, 0))
        grouped = apply(state, raw(2, 299))
        at_boundary = apply(state, raw(3, 300))
        self.assertTrue(first["notification_emitted"])
        self.assertEqual(grouped["suppression_reason"], "grouped")
        self.assertTrue(grouped["raw_trigger"])
        self.assertTrue(at_boundary["notification_emitted"])

    def test_budget_is_after_grouping_and_rejected_trigger_does_not_slide(self):
        state = core.LogReplayState(core.LogConfig(threshold_count=1, daily_budget=1))
        first = apply(state, raw(1, 85400))
        grouped = apply(state, raw(2, 85401))
        rejected = apply(state, raw(3, 86200))
        next_day = apply(state, raw(4, 86300), extra_delay=120)
        self.assertTrue(first["notification_emitted"])
        self.assertEqual(grouped["suppression_reason"], "grouped")
        self.assertEqual(rejected["suppression_reason"], "budget")
        self.assertTrue(next_day["notification_emitted"])
        self.assertNotEqual(first["budget_day_utc"], next_day["budget_day_utc"])

    def test_hard_budget_and_duplicate_delivery(self):
        state = core.LogReplayState(core.LogConfig(threshold_count=1, cooldown_seconds=0, daily_budget=5))
        originals, duplicates = [], []
        for i in range(8):
            source = raw(i + 1, i * 12)
            originals.append(apply(state, source))
            duplicates.append(apply(state, source))
        self.assertEqual(sum(r["notification_emitted"] for r in originals), 5)
        self.assertFalse(any(r["notification_emitted"] for r in duplicates))
        self.assertEqual([r["suppression_reason"] for r in originals[5:]], ["budget"] * 3)

    def test_prefix_invariant_to_appended_future_data_and_labels(self):
        prefix = [raw(1, 0, log_index=i) for i in range(12)]
        baseline = core.LogReplayState(core.LogConfig())
        expected = [apply(baseline, e) for e in prefix]
        full = core.LogReplayState(core.LogConfig())
        altered_future = [raw(2, 12, log_index=i, data="0xdeadbeef", label=1,
                              label_available_time=PLAYBACK + 999999) for i in range(50)]
        actual = [apply(full, e) for e in prefix + altered_future]
        self.assertEqual(expected, actual[:len(prefix)])

    def test_snapshot_restoration_preserves_rolling_group_and_budget(self):
        events = [raw(block, seconds, log_index=i)
                  for block, seconds in enumerate((0, 12, 300, 312, 600, 900, 1200, 1500), 1)
                  for i in range(10)]
        uninterrupted = core.LogReplayState(core.LogConfig())
        expected = [apply(uninterrupted, e) for e in events]
        state = core.LogReplayState(core.LogConfig())
        actual = [apply(state, e) for e in events[:17]]
        restored = core.LogReplayState.from_dict(json.loads(json.dumps(state.to_dict())))
        actual += [apply(restored, e) for e in events[17:]]
        self.assertEqual(actual, expected)
        self.assertEqual(restored.to_dict(), uninterrupted.to_dict())
        duplicate = apply(restored, events[0], extra_delay=1600)
        self.assertEqual(duplicate["suppression_reason"], "duplicate")
        self.assertFalse(duplicate["notification_emitted"])

    def test_unknown_observed_and_removed_are_preserved(self):
        event = core.decode_event(raw())
        self.assertIsNone(event["removed"])
        self.assertIsNone(event["observed_time"])
        self.assertEqual(event["event_time_ns"], BASE_NS)
        state = core.LogReplayState(core.LogConfig())
        row = apply(state, raw())
        self.assertIsNone(row["observed_time"])
        self.assertIsNone(row["removed"])
        self.assertEqual(row["event_time_ns"], BASE_NS)

    def test_invalid_hex_and_removed_events_rejected(self):
        invalid = [raw(data="0x1"), raw(data="0xzz"), raw(block_hash="0x1234"),
                   raw(transaction_hash="0x" + "gg" * 32), raw(topics=["0x1234"]),
                   raw(removed=True)]
        for source in invalid:
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    event = core.decode_event(source)
                    core.LogReplayState(core.LogConfig()).process(
                        event, replay_available_time=PLAYBACK,
                        feature_ready_time=PLAYBACK + .0005, decision_time=PLAYBACK + .001)

    def test_foreign_emitter_and_chain_fail_without_mutating_state(self):
        state = core.LogReplayState(core.LogConfig())
        before = copy.deepcopy(state.to_dict())
        for source in (raw(address="0x" + "22" * 20), raw(chain_id=56)):
            with self.assertRaises(ValueError):
                apply(state, source)
            self.assertEqual(before, state.to_dict())

    def test_decision_callback_and_backwards_clock(self):
        state = core.LogReplayState(core.LogConfig(threshold_count=1))
        calls = []
        def clock():
            calls.append(1)
            return PLAYBACK + .002
        row = apply(state, raw(), decision_time=clock)
        self.assertEqual(calls, [1])
        self.assertEqual(row["decision_time"], PLAYBACK + .002)
        before = copy.deepcopy(state.to_dict())
        with self.assertRaises(ValueError):
            apply(state, raw(log_index=1), decision_time=PLAYBACK + .001)
        self.assertEqual(before, state.to_dict())


if __name__ == "__main__":
    unittest.main()
