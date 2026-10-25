"""Phase/partition/fallback tests; no training or detection-performance claims."""
import dataclasses
import importlib.util
from pathlib import Path
import sys
import unittest

PATH = Path(__file__).resolve().parents[1] / "delayed_feedback.py"
SPEC = importlib.util.spec_from_file_location("monitoring_delayed_feedback", PATH)
d = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = d
SPEC.loader.exec_module(d)


def history(steps=8):
    return [d.LabelRecord(f"{s}-{label}", s, label) for s in range(1, steps + 1) for label in (0, 1)]


def plan(step=9):
    q = d.DelayedLabelQueue(2, start_step=step, initial_history=history(step - 1))
    return d.plan_retraining(q.begin_step(step), d.CalibrationRequirements(min_positive=4, min_negative=4))


def scores(p, model="m1"):
    return [d.CalibrationScore(r.example_id, model, .9 if r.label else .1) for r in p.calibration]


def registry():
    return d.ModelThresholdRegistry(d.ModelThresholdVersion("m0", "threshold-m0", .5, "declared_initial_calibration"))


class DelayedFeedbackTests(unittest.TestCase):
    def test_zero_delay_predicts_before_reveal(self):
        q = d.DelayedLabelQueue(0, start_step=1)
        q.register_step(1, ["a"], {"a": 1})
        before = q.begin_step(1)
        self.assertEqual(before.records, ())
        released = q.end_step(1)
        self.assertEqual(released.first_usable_prediction_step, 2)
        self.assertEqual(before.records, ())  # prior immutable view never rewritten
        self.assertEqual(q.begin_step(2).known[0].example_id, "a")

    def test_every_declared_delay_releases_after_source_plus_delay(self):
        for delay in (0, 1, 2, 4):
            with self.subTest(delay=delay):
                q = d.DelayedLabelQueue(delay, start_step=1)
                q.register_step(1, ["a"], {"a": 1})
                for t in range(1, delay + 3):
                    view = q.begin_step(t)
                    self.assertEqual(bool(view.known), t >= delay + 2)
                    release = q.end_step(t)
                    self.assertEqual(release.released_known, int(t == 1 + delay))

    def test_preloaded_future_labels_cannot_change_prefix(self):
        def run(future_label):
            q = d.DelayedLabelQueue(1, start_step=1)
            for t in range(1, 8):
                q.register_step(t, [str(t)], {str(t): 0 if t < 5 else future_label})
            views = []
            for t in range(1, 6):
                views.append(q.begin_step(t))
                q.end_step(t)
            return views
        self.assertEqual(run(0), run(1))
        self.assertTrue(all(r.source_step <= 3 for r in run(1)[-1].known))

    def test_unknowns_are_not_negatives_and_missing_stream_is_allowed(self):
        q = d.DelayedLabelQueue(0, start_step=1)
        q.register_step(1, ["positive", "explicit-unknown", "absent"],
                        {"positive": 1, "explicit-unknown": None})
        q.begin_step(1)
        release = q.end_step(1)
        view = q.begin_step(2)
        self.assertEqual((release.released_known, release.released_unknown), (1, 2))
        self.assertEqual({r.label for r in view.known}, {1})
        self.assertTrue(all(r.label is None for r in view.unknown))
        p = d.plan_retraining(view, d.CalibrationRequirements(1, 1))
        self.assertEqual(p.unknown_excluded, 2)
        self.assertIn("insufficient_calibration_negatives", p.skip_reasons)
        empty = d.DelayedLabelQueue(0, start_step=1)
        self.assertEqual(empty.begin_step(1).records, ())
        self.assertEqual(empty.end_step(1).released_known, 0)

    def test_phases_are_consecutive_and_no_early_reveal(self):
        q = d.DelayedLabelQueue(0, start_step=1)
        q.register_step(1, ["a"], {"a": 1})
        with self.assertRaises(RuntimeError):
            q.end_step(1)
        with self.assertRaises(ValueError):
            q.begin_step(2)
        q.begin_step(1)
        with self.assertRaises(RuntimeError):
            q.begin_step(1)
        with self.assertRaises(RuntimeError):
            q.end_step(2)
        q.end_step(1)
        with self.assertRaises(ValueError):
            q.register_step(1, ["b"], {"b": 0})

    def test_initial_history_is_explicit_and_separate(self):
        q = d.DelayedLabelQueue(4, start_step=9, initial_history=history())
        view = q.begin_step(9)
        self.assertEqual(len(view.known), 16)
        self.assertTrue(all(r.availability_origin == "declared_initial_history" for r in view.known))
        self.assertTrue(all(r.released_after_step == 8 for r in view.known))
        with self.assertRaises(ValueError):
            d.DelayedLabelQueue(4, start_step=9, initial_history=[d.LabelRecord("future", 9, 1)])

    def test_calibration_latest_four_available_steps_disjoint_from_training(self):
        p = plan()
        self.assertTrue(p.eligible)
        self.assertEqual(p.calibration_steps, (5, 6, 7, 8))
        self.assertEqual({r.source_step for r in p.train}, {1, 2, 3, 4})
        self.assertFalse({r.example_id for r in p.train} & {r.example_id for r in p.calibration})
        self.assertTrue(max(r.source_step for r in p.train) < min(r.source_step for r in p.calibration))

    def test_unreleased_current_and_future_labels_rejected_by_partitioner(self):
        for row in (d.AvailableLabel("future", 10, 1, 8, "delayed_stream"),
                    d.AvailableLabel("current", 9, 0, 8, "delayed_stream"),
                    d.AvailableLabel("unreleased", 8, 1, 9, "delayed_stream"),
                    d.AvailableLabel("before_source", 8, 1, 7, "delayed_stream")):
            with self.subTest(row=row):
                with self.assertRaises(ValueError):
                    d.plan_retraining(d.PredictionView(9, (row,)), d.CalibrationRequirements(1, 1))

    def test_unknown_only_steps_do_not_fill_labelled_calibration_window(self):
        h = history(7) + [d.LabelRecord("unknown8", 8, None)]
        q = d.DelayedLabelQueue(0, start_step=9, initial_history=h)
        p = d.plan_retraining(q.begin_step(9), d.CalibrationRequirements(4, 4))
        self.assertEqual(p.calibration_steps, (4, 5, 6, 7))
        self.assertEqual(p.unknown_excluded, 1)
        self.assertTrue(p.eligible)

    def test_insufficient_classes_or_calibration_causes_skip(self):
        q = d.DelayedLabelQueue(0, start_step=9,
                                initial_history=[d.LabelRecord(str(s), s, 0) for s in range(1, 9)])
        p = d.plan_retraining(q.begin_step(9), d.CalibrationRequirements(2, 2))
        self.assertFalse(p.eligible)
        self.assertIn("training_requires_two_classes", p.skip_reasons)
        self.assertIn("insufficient_calibration_positives", p.skip_reasons)
        reg = registry()
        old = reg.active
        result = reg.commit_candidate("m1", p, scores(p), threshold_version="threshold-m1", threshold=.4)
        self.assertEqual(result.status, "skip_update")
        self.assertEqual(reg.active, old)

    def test_success_installs_new_model_and_its_threshold_together(self):
        p = plan()
        reg = registry()
        result = reg.commit_candidate("m1", p, scores(p), threshold_version="threshold-m1", threshold=.4)
        self.assertEqual(result.status, "installed")
        self.assertEqual(reg.active.model_version, "m1")
        self.assertEqual(reg.active.threshold_version, "threshold-m1")
        self.assertEqual(reg.active.threshold, .4)
        self.assertEqual(reg.active.calibration_plan_id, p.plan_id)
        self.assertEqual(result.previous.model_version, "m0")

    def test_new_candidate_with_failed_positive_calibration_retains_entire_old_pair(self):
        p = plan()
        reg = registry()
        old = reg.active
        candidate_scores = [d.CalibrationScore(r.example_id, "m1", None if r.label else .1)
                            for r in p.calibration]
        result = reg.commit_candidate("m1", p, candidate_scores,
                                      threshold_version="threshold-m1", threshold=.2)
        self.assertIn("insufficient_usable_calibration_positives", result.reasons)
        self.assertIn("calibration_scoring_failure", result.reasons)
        self.assertEqual(result.status, "skip_update")
        self.assertEqual(reg.active, old)
        self.assertNotEqual(reg.active.model_version, "m1")

    def test_old_model_scores_cannot_calibrate_new_model(self):
        p = plan()
        reg = registry()
        result = reg.commit_candidate("m1", p, scores(p, model="m0"),
                                      threshold_version="threshold-m1", threshold=.4)
        self.assertIn("calibration_score_model_version_mismatch", result.reasons)
        self.assertEqual(result.active, result.previous)

    def test_coverage_duplicates_and_threshold_version_reuse_fail_closed(self):
        p = plan()
        for s, version, reason in ((scores(p)[:-1], "t1", "calibration_score_cohort_mismatch"),
                                   (scores(p) + scores(p)[:1], "t1", "duplicate_calibration_scores"),
                                   (scores(p), "threshold-m0", "threshold_version_already_installed")):
            reg = registry()
            result = reg.commit_candidate("m1", p, s, threshold_version=version, threshold=.4)
            self.assertIn(reason, result.reasons)
            self.assertEqual(result.active, result.previous)

    def test_manual_overlap_cannot_bypass_registry(self):
        p = plan()
        bad = dataclasses.replace(p, train=p.train + p.calibration[:1])
        reg = registry()
        result = reg.commit_candidate("m1", bad, scores(p), threshold_version="t1", threshold=.4)
        self.assertIn("training_calibration_overlap", result.reasons)
        self.assertEqual(result.active, result.previous)

    def test_registration_rejects_bad_labels_and_does_not_mutate(self):
        q = d.DelayedLabelQueue(0, start_step=1)
        for labels in ({"a": -1}, {"b": 0}, {"a": True}):
            with self.assertRaises(ValueError):
                q.register_step(1, ["a"], labels)
        q.register_step(1, ["a"], {"a": None})
        q.begin_step(1)
        self.assertEqual(q.end_step(1).released_unknown, 1)

    def test_model_registry_rejects_forged_plan_identity(self):
        p = dataclasses.replace(plan(), plan_id="unrelated-plan")
        reg = registry()
        result = reg.commit_candidate("m1", p, scores(p), threshold_version="t1", threshold=.4)
        self.assertIn("plan_content_hash_mismatch", result.reasons)
        self.assertEqual(result.active, result.previous)

    def test_valid_older_and_same_step_candidates_cannot_replace_active_pair(self):
        reg = registry()
        self.assertIsNone(reg.last_activation_step)
        p = plan(9)
        self.assertEqual(reg.commit_candidate("m9", p, scores(p, "m9"),
                                              threshold_version="t9", threshold=.4).status, "installed")
        active = reg.active
        for step in (8, 9):
            with self.subTest(step=step):
                p = plan(step)
                self.assertTrue(p.eligible)
                result = reg.commit_candidate(f"late{step}", p, scores(p, f"late{step}"),
                                              threshold_version=f"late-t{step}", threshold=.2)
                self.assertEqual(result.reasons, ("stale_or_duplicate_activation_step",))
                self.assertEqual(result.status, "skip_update")
                self.assertEqual(reg.active, active)
                self.assertEqual(reg.last_activation_step, 9)
        p = plan(10)
        self.assertEqual(reg.commit_candidate("m10", p, scores(p, "m10"),
                                              threshold_version="t10", threshold=.3).status, "installed")
        self.assertEqual(reg.last_activation_step, 10)

    def test_failed_update_does_not_advance_activation_or_consume_versions(self):
        reg = registry()
        p = plan(9)
        result = reg.commit_candidate("m9", p, scores(p, "wrong-model"),
                                      threshold_version="t9", threshold=.2)
        self.assertEqual(result.status, "skip_update")
        self.assertIsNone(reg.last_activation_step)
        result = reg.commit_candidate("m9", p, scores(p, "m9"),
                                      threshold_version="t9", threshold=.2)
        self.assertEqual(result.status, "installed")
        active = reg.active
        p = plan(11)
        result = reg.commit_candidate("m11", p, scores(p, "m11")[:-1],
                                      threshold_version="t11", threshold=.3)
        self.assertEqual(result.status, "skip_update")
        self.assertEqual(reg.active, active)
        self.assertEqual(reg.last_activation_step, 9)
        p = plan(10)
        self.assertEqual(reg.commit_candidate("m10", p, scores(p, "m10"),
                                              threshold_version="t10", threshold=.3).status, "installed")
        self.assertEqual(reg.last_activation_step, 10)

    def test_declared_initial_activation_is_validated_and_enforced(self):
        initial = registry().active
        for invalid in (-1, True, 1.5, "9"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    d.ModelThresholdRegistry(initial, initial_activation_step=invalid)
        reg = d.ModelThresholdRegistry(initial, initial_activation_step=9)
        p = plan(9)
        result = reg.commit_candidate("m9", p, scores(p, "m9"),
                                      threshold_version="t9", threshold=.2)
        self.assertEqual(result.reasons, ("stale_or_duplicate_activation_step",))
        self.assertEqual(reg.active, initial)
        self.assertEqual(reg.last_activation_step, 9)
        p = plan(10)
        self.assertEqual(reg.commit_candidate("m10", p, scores(p, "m10"),
                                              threshold_version="t10", threshold=.3).status, "installed")
        self.assertEqual(reg.last_activation_step, 10)
        self.assertEqual(d.ModelThresholdRegistry(initial, initial_activation_step=0).last_activation_step, 0)


if __name__ == "__main__":
    unittest.main()
