"""Delayed-label phase discipline and retraining bookkeeping (no model fitting).

For a record from step s and delay d, release occurs AFTER prediction at s+d;
the label can first influence prediction s+d+1. A zero-delay label therefore
cannot influence its own prediction. This deliberately differs from historical
M2's ``known_upto=t-DELAY+1`` arithmetic. Steps have no conversion to seconds.

Registering the optional historical label stream may preload future labels, but
only immutable released views are exposed through the prediction API. This is
an API sequencing guarantee, not process-level isolation from Python internals.
Initial history is separately declared available before start_step; it is not
silently assigned the online stream's delay. Unknown labels remain None.

The partitioner chooses the latest four available steps containing known labels
for calibration and excludes them from fitting. Insufficient classes/coverage
skip an update. The registry installs a new model and its threshold atomically
only when calibration scores identify that model and that partition. External
callers still implement fitting, threshold selection, and persisted provenance;
this utility does not verify a trained estimator or a threshold optimizer.
Successful installations must have strictly increasing declared prediction steps.
An optional initial activation step starts that check; when omitted, the initial
pair's timing is unknown and the first successful candidate establishes it.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
from typing import Iterable, Mapping


DELAYS = (0, 1, 2, 4)


def _integer(value, name, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def _label(value):
    if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value not in (0, 1)):
        raise ValueError("label must be 0, 1 or None; unknown is not a negative")
    return value


def _identifier(value, name):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a nonempty string")
    return value


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class LabelRecord:
    example_id: str
    source_step: int
    label: int | None

    def __post_init__(self):
        _identifier(self.example_id, "example_id")
        _integer(self.source_step, "source_step", 1)
        _label(self.label)


@dataclass(frozen=True)
class AvailableLabel:
    example_id: str
    source_step: int
    label: int | None
    released_after_step: int
    availability_origin: str  # declared_initial_history or delayed_stream


@dataclass(frozen=True)
class PredictionView:
    prediction_step: int
    records: tuple[AvailableLabel, ...]
    phase: str = "before_prediction"

    @property
    def known(self):
        return tuple(r for r in self.records if r.label is not None)

    @property
    def unknown(self):
        return tuple(r for r in self.records if r.label is None)


@dataclass(frozen=True)
class ReleaseSummary:
    after_prediction_step: int
    source_steps: tuple[int, ...]
    released_known: int
    released_unknown: int
    first_usable_prediction_step: int


class DelayedLabelQueue:
    """Explicit begin/predict/end phases; end_step attests predictions recorded."""

    def __init__(self, delay: int, start_step: int = 35,
                 initial_history: Iterable[LabelRecord] = ()):
        _integer(delay, "delay")
        if delay not in DELAYS:
            raise ValueError(f"supported delays are {DELAYS}")
        _integer(start_step, "start_step", 1)
        self.delay = delay
        self.start_step = start_step
        self._next_step = start_step
        self._active_step = None
        self._pending: dict[int, tuple[AvailableLabel, ...]] = {}
        self._registered_steps: set[int] = set()
        self._ids: set[str] = set()
        self._released: list[AvailableLabel] = []
        for r in initial_history:
            if not isinstance(r, LabelRecord):
                raise TypeError("initial_history entries must be LabelRecord")
            if r.source_step >= start_step:
                raise ValueError("initial history must precede start_step")
            if r.example_id in self._ids:
                raise ValueError("duplicate example_id in initial history")
            self._ids.add(r.example_id)
            self._released.append(AvailableLabel(r.example_id, r.source_step, r.label,
                                                 start_step - 1, "declared_initial_history"))

    def register_step(self, step: int, example_ids: Iterable[str],
                      labels: Mapping[str, int | None] | None = None) -> None:
        """Schedule one complete batch; absent labels remain explicitly unknown.

        Registration may precede prediction, including preloading future batches.
        Past-step updates and later corrections are outside this minimal protocol.
        """
        _integer(step, "step", 1)
        if step < self._next_step:
            raise ValueError("cannot register an already completed step")
        if step in self._registered_steps:
            raise ValueError("step already registered")
        ids = tuple(example_ids)
        for example_id in ids:
            _identifier(example_id, "example_id")
        if len(ids) != len(set(ids)) or set(ids) & self._ids:
            raise ValueError("example_id must be unique across all batches/history")
        labels = dict(labels or {})
        if set(labels) - set(ids):
            raise ValueError("label map contains IDs outside this batch")
        rows = tuple(AvailableLabel(i, step, _label(labels.get(i)), step + self.delay,
                                    "delayed_stream") for i in ids)
        self._pending[step + self.delay] = rows
        self._registered_steps.add(step)
        self._ids.update(ids)

    def begin_step(self, step: int) -> PredictionView:
        _integer(step, "step", 1)
        if self._active_step is not None:
            raise RuntimeError("record current predictions and call end_step first")
        if step != self._next_step:
            raise ValueError("prediction steps must be consecutive from start_step")
        self._active_step = step
        return PredictionView(step, tuple(sorted(self._released, key=lambda r: (r.source_step, r.example_id))))

    def end_step(self, step: int) -> ReleaseSummary:
        """Call only after the step's predictions/decisions have been recorded."""
        _integer(step, "step", 1)
        if self._active_step != step:
            raise RuntimeError("end_step must follow begin_step for the same step")
        rows = self._pending.pop(step, ())
        self._released.extend(rows)
        self._active_step = None
        self._next_step = step + 1
        return ReleaseSummary(step, tuple(sorted({r.source_step for r in rows})),
                              sum(r.label is not None for r in rows),
                              sum(r.label is None for r in rows), step + 1)


@dataclass(frozen=True)
class CalibrationRequirements:
    # Minimum class counts must be declared by the caller before experiments.
    min_positive: int
    min_negative: int
    recent_steps: int = 4

    def __post_init__(self):
        _integer(self.min_positive, "min_positive", 1)
        _integer(self.min_negative, "min_negative", 1)
        _integer(self.recent_steps, "recent_steps", 1)


@dataclass(frozen=True)
class RetrainingPlan:
    plan_id: str
    prediction_step: int
    train: tuple[AvailableLabel, ...]
    calibration: tuple[AvailableLabel, ...]
    calibration_steps: tuple[int, ...]
    requirements: CalibrationRequirements
    unknown_excluded: int
    eligible: bool
    skip_reasons: tuple[str, ...]


def plan_retraining(view: PredictionView, requirements: CalibrationRequirements) -> RetrainingPlan:
    """Use only available labels; hold out a separate latest temporal window."""
    _integer(view.prediction_step, "prediction_step", 1)
    if view.phase != "before_prediction":
        raise ValueError("planning requires a before_prediction availability view")
    if len({r.example_id for r in view.records}) != len(view.records):
        raise ValueError("view contains duplicate IDs")
    for r in view.records:
        _label(r.label)
        _identifier(r.example_id, "example_id")
        _integer(r.source_step, "source_step", 1)
        _integer(r.released_after_step, "released_after_step")
        if r.source_step >= view.prediction_step or r.released_after_step >= view.prediction_step:
            raise ValueError("current/future/unreleased labels cannot enter retraining plan")
        if r.released_after_step < r.source_step:
            raise ValueError("labels cannot be released before their source step")
        if r.availability_origin not in ("declared_initial_history", "delayed_stream"):
            raise ValueError("unknown availability provenance")
    known = tuple(sorted(view.known, key=lambda r: (r.source_step, r.example_id)))
    steps = sorted({r.source_step for r in known})
    cal_steps = tuple(steps[-requirements.recent_steps:])
    cal = tuple(r for r in known if r.source_step in cal_steps)
    train = tuple(r for r in known if r.source_step not in cal_steps)
    reasons = []
    if len(cal_steps) < requirements.recent_steps:
        reasons.append("insufficient_available_calibration_steps")
    if {r.label for r in train} != {0, 1}:
        reasons.append("training_requires_two_classes")
    if sum(r.label == 1 for r in cal) < requirements.min_positive:
        reasons.append("insufficient_calibration_positives")
    if sum(r.label == 0 for r in cal) < requirements.min_negative:
        reasons.append("insufficient_calibration_negatives")
    content = {"prediction_step": view.prediction_step, "requirements": asdict(requirements),
               "train": [asdict(r) for r in train], "calibration": [asdict(r) for r in cal],
               "unknown_excluded": len(view.unknown)}
    return RetrainingPlan(_hash(content), view.prediction_step, train, cal, cal_steps,
                          requirements, len(view.unknown), not reasons, tuple(reasons))


@dataclass(frozen=True)
class CalibrationScore:
    example_id: str
    model_version: str
    score: float | None  # None denotes a scoring failure, never a zero score.


@dataclass(frozen=True)
class ModelThresholdVersion:
    model_version: str
    threshold_version: str
    threshold: float
    calibration_plan_id: str

    def __post_init__(self):
        for name in ("model_version", "threshold_version", "calibration_plan_id"):
            _identifier(getattr(self, name), name)
        if isinstance(self.threshold, bool) or not isinstance(self.threshold, (int, float)) or not math.isfinite(self.threshold):
            raise ValueError("threshold must be a finite number")


@dataclass(frozen=True)
class UpdateResult:
    status: str
    reasons: tuple[str, ...]
    attempted_model_version: str
    plan_id: str
    previous: ModelThresholdVersion
    active: ModelThresholdVersion


class ModelThresholdRegistry:
    """Atomic in-memory model/threshold pairing; no estimator or disk transaction."""

    def __init__(self, initial: ModelThresholdVersion, *,
                 initial_activation_step: int | None = None):
        if initial_activation_step is not None:
            _integer(initial_activation_step, "initial_activation_step")
        self.active = initial
        self.last_activation_step = initial_activation_step
        self.history: list[UpdateResult] = []
        self._installed_model_versions = {initial.model_version}
        self._installed_threshold_versions = {initial.threshold_version}

    def commit_candidate(self, model_version: str, plan: RetrainingPlan,
                         calibration_scores: Iterable[CalibrationScore], *,
                         threshold_version: str, threshold: float) -> UpdateResult:
        """Retain the entire old pair on any validation/calibration failure.

        Every planned calibration ID must have one candidate-model score.
        Missing/failed predictions cannot silently change the calibration cohort.
        The threshold is supplied by an external calibration procedure. Its
        optimality is not inferred from the existence of this bookkeeping entry.
        Plan steps must advance past the last successful activation; a skipped
        candidate leaves both the active pair and its activation step unchanged.
        This validates declared ordering, not actual fitting or wall-clock time.
        """
        previous = self.active
        reasons = list(plan.skip_reasons) if not plan.eligible else []
        if not isinstance(model_version, str) or not model_version:
            reasons.append("invalid_model_version")
        elif model_version in self._installed_model_versions:
            reasons.append("model_version_already_installed")
        if not isinstance(threshold_version, str) or not threshold_version:
            reasons.append("invalid_threshold_version")
        elif threshold_version in self._installed_threshold_versions:
            reasons.append("threshold_version_already_installed")
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not math.isfinite(threshold):
            reasons.append("invalid_threshold")
        train_ids = {r.example_id for r in plan.train}
        calibration = {r.example_id: r for r in plan.calibration}
        if train_ids & set(calibration):
            reasons.append("training_calibration_overlap")
        scores = tuple(calibration_scores)
        score_ids = [r.example_id for r in scores]
        if len(score_ids) != len(set(score_ids)):
            reasons.append("duplicate_calibration_scores")
        if set(score_ids) != set(calibration):
            reasons.append("calibration_score_cohort_mismatch")
        if any(r.model_version != model_version for r in scores):
            reasons.append("calibration_score_model_version_mismatch")
        usable = []
        failed = 0
        for score in scores:
            value = score.score
            if value is None or isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                failed += 1
            elif score.example_id in calibration:
                usable.append(calibration[score.example_id])
        if sum(r.label == 1 for r in usable) < plan.requirements.min_positive:
            reasons.append("insufficient_usable_calibration_positives")
        if sum(r.label == 0 for r in usable) < plan.requirements.min_negative:
            reasons.append("insufficient_usable_calibration_negatives")
        if failed:
            reasons.append("calibration_scoring_failure")
        # Revalidate actual class/timing constraints instead of trusting a manually
        # constructed eligible flag on an external plan object.
        try:
            verified = plan_retraining(PredictionView(plan.prediction_step, plan.train + plan.calibration), plan.requirements)
            if self.last_activation_step is not None and plan.prediction_step <= self.last_activation_step:
                reasons.append("stale_or_duplicate_activation_step")
            if not verified.eligible:
                reasons.extend(verified.skip_reasons)
            if (verified.train != plan.train or verified.calibration != plan.calibration or
                    verified.calibration_steps != plan.calibration_steps):
                reasons.append("invalid_temporal_partition")
            _integer(plan.unknown_excluded, "unknown_excluded")
            content = {"prediction_step": plan.prediction_step, "requirements": asdict(plan.requirements),
                       "train": [asdict(r) for r in plan.train],
                       "calibration": [asdict(r) for r in plan.calibration],
                       "unknown_excluded": plan.unknown_excluded}
            if _hash(content) != plan.plan_id:
                reasons.append("plan_content_hash_mismatch")
        except ValueError:
            reasons.append("invalid_label_availability")
        reasons = tuple(dict.fromkeys(reasons))
        if not reasons:
            self.active = ModelThresholdVersion(model_version, threshold_version, float(threshold), plan.plan_id)
            self.last_activation_step = plan.prediction_step
            self._installed_model_versions.add(model_version)
            self._installed_threshold_versions.add(threshold_version)
        result = UpdateResult("skip_update" if reasons else "installed", reasons,
                              model_version, plan.plan_id, previous, self.active)
        self.history.append(result)
        return result
