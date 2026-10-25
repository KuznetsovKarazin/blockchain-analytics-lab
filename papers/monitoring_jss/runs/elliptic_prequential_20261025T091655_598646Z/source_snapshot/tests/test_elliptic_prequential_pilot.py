"""Small synthetic utility tests; no estimator fitting or detection claims."""
import dataclasses
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

import numpy as np

PAPER = Path(__file__).resolve().parents[1]
if str(PAPER) not in sys.path:
    sys.path.insert(0, str(PAPER))
import delayed_feedback as feedback

PATH = PAPER / "elliptic_prequential_pilot.py"
SPEC = importlib.util.spec_from_file_location("monitoring_elliptic_prequential_pilot", PATH)
core = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = core
SPEC.loader.exec_module(core)


def fixture_plan():
    history = [feedback.LabelRecord(str(step * 10 + label), step, label)
               for step in range(1, 9) for label in (0, 1)]
    q = feedback.DelayedLabelQueue(0, start_step=9, initial_history=history)
    return feedback.plan_retraining(q.begin_step(9), feedback.CalibrationRequirements(4, 4))


def record(example_id, label, step=1):
    return feedback.AvailableLabel(str(example_id), step, label, step, "delayed_stream")


class EllipticPrequentialUtilityTests(unittest.TestCase):
    def test_f1_threshold_and_confusion_counts(self):
        result = core.select_threshold(np.array([1, 1, 0, 0]), np.array([.9, .8, .7, .1]))
        self.assertEqual(result["threshold"], .8)
        self.assertEqual(result["f1"], 1.0)
        self.assertEqual((result["tp"], result["fp"], result["fn"]), (2, 0, 0))

    def test_exact_objective_tie_chooses_largest_threshold(self):
        # Both .9 and .6 produce F1=2/3; intermediate thresholds do worse.
        result = core.select_threshold(np.array([1, 0, 0, 1]), np.array([.9, .8, .7, .6]))
        self.assertEqual(result["threshold"], .9)
        self.assertAlmostEqual(result["f1"], 2 / 3)
        self.assertEqual((result["tp"], result["fp"], result["fn"]), (1, 0, 1))

    def test_threshold_rejects_unknown_labels_nonfinite_scores_and_length_mismatch(self):
        for labels, scores in (([1, -1], [.8, .2]), ([1, None], [.8, .2]),
                               ([1, 0], [.8, np.nan]), ([1, 0], [.8, np.inf]),
                               ([1, 0], [.8]), ([], [])):
            with self.subTest(labels=labels, scores=scores):
                with self.assertRaises((ValueError, TypeError)):
                    core.select_threshold(np.array(labels), np.array(scores))

    def test_threshold_positive_only_is_defined_but_no_positive_is_rejected(self):
        result = core.select_threshold(np.array([1, 1]), np.array([.7, .2]))
        self.assertEqual(result["threshold"], .2)
        self.assertEqual(result["f1"], 1.0)
        with self.assertRaises(ValueError):
            core.select_threshold(np.array([0, 0]), np.array([.7, .2]))

    def test_budget_floor_has_no_one_alert_minimum(self):
        for n, expected in ((199, 0), (200, 1), (400, 2)):
            with self.subTest(n=n):
                ids = np.arange(n, 0, -1, dtype=np.int64)
                result = core.budget_decisions(ids, np.ones(n), threshold=.5, divisor=200)
                self.assertEqual(result["k"], expected)
                self.assertEqual(int(np.asarray(result["admitted"]).sum()), expected)
                self.assertTrue(np.asarray(result["raw_trigger"]).all())
                self.assertEqual(set(ids[np.asarray(result["admitted"], dtype=bool)]), set(range(1, expected + 1)))

    def test_budget_ties_are_numeric_and_permutation_invariant(self):
        ids = np.arange(1, 401, dtype=np.int64)
        scores = np.ones(400)
        permutation = np.concatenate((np.arange(199, -1, -1), np.arange(399, 199, -1)))
        a = core.budget_decisions(ids, scores, threshold=.5, divisor=200)
        b = core.budget_decisions(ids[permutation], scores[permutation], threshold=.5, divisor=200)
        amap = {int(i): (int(r), bool(v)) for i, r, v in zip(ids, a["rank"], a["admitted"])}
        bmap = {int(i): (int(r), bool(v)) for i, r, v in zip(ids[permutation], b["rank"], b["admitted"])}
        self.assertEqual(amap, bmap)
        self.assertEqual(amap[1], (0, True))
        self.assertEqual(amap[2], (1, True))
        self.assertLess(amap[2][0], amap[10][0])  # numeric, not lexicographic ordering

    def test_budget_admission_requires_threshold_as_well_as_top_k(self):
        ids = np.arange(1, 401, dtype=np.int64)
        scores = np.full(400, .1)
        scores[0], scores[1] = .9, .8
        result = core.budget_decisions(ids, scores, threshold=.85, divisor=200)
        self.assertEqual(result["k"], 2)
        self.assertEqual(int(np.asarray(result["raw_trigger"]).sum()), 1)
        self.assertEqual(int(np.asarray(result["admitted"]).sum()), 1)
        self.assertTrue(result["admitted"][0])
        self.assertFalse(result["admitted"][1])

    def test_cohort_signature_ignores_prediction_phase_and_release_metadata(self):
        p = fixture_plan()
        altered = dataclasses.replace(
            p, prediction_step=10, plan_id="different-scheduling-plan",
            train=tuple(dataclasses.replace(r, released_after_step=9,
                                            availability_origin="delayed_stream") for r in p.train),
            calibration=tuple(dataclasses.replace(r, released_after_step=9,
                                                  availability_origin="delayed_stream") for r in p.calibration))
        self.assertEqual(core.cohort_signature(p), core.cohort_signature(altered))

    def test_cohort_signature_changes_with_labels_ids_steps_or_partition(self):
        p = fixture_plan()
        variants = [
            dataclasses.replace(p, train=(dataclasses.replace(p.train[0], label=1),) + p.train[1:]),
            dataclasses.replace(p, train=(dataclasses.replace(p.train[0], example_id="999999"),) + p.train[1:]),
            dataclasses.replace(p, train=(dataclasses.replace(p.train[0], source_step=2),) + p.train[1:]),
            dataclasses.replace(p, train=p.train[1:], calibration=p.calibration + p.train[:1]),
        ]
        base = core.cohort_signature(p)
        for other in variants:
            with self.subTest(other=other):
                self.assertNotEqual(base, core.cohort_signature(other))

    def test_cohort_arrays_preserves_order_and_never_reads_data_labels(self):
        data = SimpleNamespace(tx_ids=np.array([10, 2, 99, 7]),
                               X=np.array([[10, 11], [20, 21], [30, 31], [40, 41]]),
                               y=np.array([1, 1, 0, 0]))  # deliberately contradictory labels
        rows = (record(99, 1), record(2, 0))
        X, y, indices = core.cohort_arrays(data, rows)
        np.testing.assert_array_equal(indices, [2, 1])
        np.testing.assert_array_equal(X, [[30, 31], [20, 21]])
        np.testing.assert_array_equal(y, [1, 0])

    def test_cohort_arrays_rejects_unknown_and_missing_ids(self):
        data = SimpleNamespace(tx_ids=np.array([10, 2]), X=np.array([[1], [2]]), y=np.array([1, 0]))
        with self.assertRaises(ValueError):
            core.cohort_arrays(data, (record(10, None),))
        with self.assertRaises((ValueError, KeyError)):
            core.cohort_arrays(data, (record(999, 1),))

    def test_budget_rejects_nonfinite_scores(self):
        for invalid in (np.nan, np.inf, -np.inf):
            scores = np.ones(200)
            scores[20] = invalid
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    core.budget_decisions(np.arange(200), scores, threshold=.5, divisor=200)

    def test_queue_partition_and_toy_scores_preserve_prefix_when_future_labels_change(self):
        # Arithmetic only: exercise the same queue -> partition -> cohort-array
        # route as fitting, without constructing or fitting any estimator.
        def replay(change_future):
            history = [feedback.LabelRecord(str(step * 10 + cls), step, cls)
                       for step in range(1, 9) for cls in (0, 1)]
            q = feedback.DelayedLabelQueue(2, start_step=9, initial_history=history)
            all_ids = np.array([step * 10 + cls for step in range(1, 19) for cls in (0, 1)])
            global_labels = np.array([(1 - cls if change_future and step >= 12 else cls)
                                      for step in range(1, 19) for cls in (0, 1)])
            data = SimpleNamespace(tx_ids=all_ids, X=all_ids.astype(float).reshape(-1, 1), y=global_labels)
            for step in range(9, 19):
                ids = [str(step * 10 + cls) for cls in (0, 1)]
                labels = {str(step * 10 + cls): (1 - cls if change_future and step >= 12 else cls)
                          for cls in (0, 1)}
                q.register_step(step, ids, labels)
            outputs = {}
            for step in range(9, 20):
                p = feedback.plan_retraining(q.begin_step(step), feedback.CalibrationRequirements(4, 4))
                self.assertTrue(p.eligible)
                Xtr, ytr, _ = core.cohort_arrays(data, p.train)
                Xcal, ycal, _ = core.cohort_arrays(data, p.calibration)
                coefficient = float(Xtr[:, 0] @ ytr / (1 + Xtr[:, 0] @ Xtr[:, 0]))
                toy_scores = coefficient * Xcal[:, 0]
                outputs[step] = {
                    "signature": core.cohort_signature(p),
                    "train_ids": [r.example_id for r in p.train],
                    "calibration_ids": [r.example_id for r in p.calibration],
                    "train_labels": ytr.tolist(), "calibration_labels": ycal.tolist(),
                    "coefficient": coefficient, "toy_scores": toy_scores.tolist(),
                }
                q.end_step(step)
            return outputs
        ordinary, altered = replay(False), replay(True)
        # Source step12, delay2: released after14, first usable prediction15.
        for step in range(9, 15):
            self.assertEqual(ordinary[step], altered[step])
        self.assertNotEqual(ordinary[15]["signature"], altered[15]["signature"])
        # By prediction19, source12 has moved out of held-out calibration and
        # into training; the toy coefficient must now reflect changed labels.
        self.assertNotEqual(ordinary[19]["coefficient"], altered[19]["coefficient"])


if __name__ == "__main__":
    unittest.main()
