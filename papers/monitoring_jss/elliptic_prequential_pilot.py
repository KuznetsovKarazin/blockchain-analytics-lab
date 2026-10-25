"""Bounded retrospective Elliptic direct18 benchmark with causal label release.

No claim of raw online feature availability or untouched external evaluation is
made: the original features are publisher-normalized and steps35..49 were already
studied. Labels from source step s are exposed only after prediction at s+d. The
latest four AVAILABLE labelled steps are excluded from candidate-model fitting
and used to calibrate that candidate's own scores. A failed update retains both
old model and old threshold. All decisions wait for the completed step batch.

Raw IDs/labels/features, exact cohorts, serialized models and individual scores
remain private. Public JSON contains aggregate counts, configuration and hashes.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import sys
import time
import warnings

PAPER = Path(__file__).resolve().parent
ROOT = PAPER.parents[1]


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


def dump(value, path):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def jsonline(handle, row):
    handle.write(json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")


def select_threshold(y_known, scores):
    """Exact F1 comparisons at complete tied-score groups; largest threshold wins."""
    import numpy as np
    y, s = np.asarray(y_known), np.asarray(scores, dtype=float)
    if y.ndim != 1 or s.shape != y.shape or not len(y) or not np.isfinite(s).all():
        raise ValueError("invalid calibration score vector")
    if not np.isin(y, [0, 1]).all() or not (y == 1).any():
        raise ValueError("calibration requires known binary labels and positives")
    order = np.argsort(-s, kind="stable")
    ys, ss = y[order], s[order]
    total_positive = int(y.sum())
    best_tp, best_den, best_count = 0, total_positive, 0
    best_threshold = float(np.nextafter(ss[0], np.inf))
    cumulative_tp = np.cumsum(ys, dtype=np.int64)
    ends = np.flatnonzero(np.r_[ss[:-1] != ss[1:], True])
    for index in ends:
        count, tp = int(index) + 1, int(cumulative_tp[index])
        denominator = total_positive + count
        if tp * best_den > best_tp * denominator:
            best_tp, best_den, best_count = tp, denominator, count
            best_threshold = float(ss[index])
    return {"threshold": best_threshold, "f1": 2 * best_tp / best_den,
            "tp": best_tp, "fp": best_count - best_tp, "fn": total_positive - best_tp,
            "calibration_rows": len(y), "positive": total_positive, "negative": int((y == 0).sum())}


def budget_decisions(tx_ids, scores, threshold, divisor=200):
    import numpy as np
    ids, s = np.asarray(tx_ids), np.asarray(scores, dtype=float)
    if ids.ndim != 1 or s.shape != ids.shape or not np.isfinite(s).all() or not np.isfinite(threshold):
        raise ValueError("invalid batch scores/threshold")
    if not np.issubdtype(ids.dtype, np.integer) or len(np.unique(ids)) != len(ids):
        raise ValueError("unique integer txIDs required for stable ties")
    if isinstance(divisor, bool) or not isinstance(divisor, int) or divisor <= 0:
        raise ValueError("positive integer budget divisor required")
    order = np.lexsort((ids, -s))
    rank = np.empty(len(ids), dtype=np.int64)
    rank[order] = np.arange(len(ids))
    k = len(ids) // divisor
    raw = s >= threshold
    return {"raw_trigger": raw, "admitted": raw & (rank < k), "rank": rank, "k": k}


def cohort_signature(plan):
    return digest({"train": [(r.example_id, r.source_step, r.label) for r in plan.train],
                   "calibration": [(r.example_id, r.source_step, r.label) for r in plan.calibration]})


def cohort_arrays(data, records):
    """Labels come only from available records, never the global label array."""
    import numpy as np
    index = getattr(data, "_id_index", None)
    if index is None:
        index = {str(int(tx)): i for i, tx in enumerate(data.tx_ids)}
        data._id_index = index
    if any(r.label not in (0, 1) or r.label is None for r in records):
        raise ValueError("unknown labels excluded from fitting/calibration")
    rows = np.array([index[r.example_id] for r in records], dtype=np.int64)
    if len(np.unique(rows)) != len(rows):
        raise ValueError("duplicate cohort IDs")
    return data.X[rows], np.array([r.label for r in records], dtype=np.int8), rows


def make_model(family, config):
    if family == "lightgbm":
        from lightgbm import LGBMClassifier
        return LGBMClassifier(**config["model_configs"][family])
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    params = {k: v for k, v in config["model_configs"][family].items() if k != "scaler"}
    return make_pipeline(StandardScaler(), LogisticRegression(**params))


def score_model(model, X):
    import numpy as np
    if list(model.classes_) != [0, 1]:
        raise ValueError("model class order is not binary [0,1]")
    scores = np.asarray(model.predict_proba(X)[:, 1], dtype=float)
    if scores.shape != (len(X),) or not np.isfinite(scores).all():
        raise ValueError("model returned invalid scores")
    return scores


def fit_candidate(data, plan, family, config, version, cell):
    import joblib
    from sklearn.exceptions import ConvergenceWarning
    Xtr, ytr, train_rows = cohort_arrays(data, plan.train)
    Xcal, ycal, cal_rows = cohort_arrays(data, plan.calibration)
    if set(train_rows) & set(cal_rows):
        raise RuntimeError("fit/calibration overlap")
    prefix = cell / "artifacts" / version
    prefix.parent.mkdir(exist_ok=True)
    model = make_model(family, config)
    before = time.perf_counter()
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            model.fit(Xtr, ytr)
    except Exception as error:
        metadata = {"model_version": version, "plan_id": plan.plan_id, "prediction_step": plan.prediction_step,
                    "status": "skip_update_fit_exception", "fit_seconds": time.perf_counter() - before,
                    "fit_converged": False, "error": f"{type(error).__name__}: {error}",
                    "fit_rows": len(train_rows), "calibration_rows": len(cal_rows),
                    "cohort_signature": cohort_signature(plan)}
        dump(metadata, Path(str(prefix) + "_metadata.json"))
        return None, None, None, metadata
    fit_seconds = time.perf_counter() - before
    warning_records = [{"category": type(w.message).__name__, "message": str(w.message)} for w in caught]
    converged = not any(issubclass(w.category, ConvergenceWarning) for w in caught)
    model_path = prefix.with_suffix(".joblib")
    joblib.dump(model, model_path, compress=("gzip", 3))
    cohorts_path = Path(str(prefix) + "_cohorts.jsonl.gz")
    with gzip.open(cohorts_path, "wt") as target:
        for role, records in (("fit", plan.train), ("calibration", plan.calibration)):
            for r in records:
                jsonline(target, {"role": role, **asdict(r)})
    metadata = {"model_version": version, "plan_id": plan.plan_id, "prediction_step": plan.prediction_step,
                "cohort_signature": cohort_signature(plan), "fit_rows": len(train_rows), "calibration_rows": len(cal_rows),
                "fit_positive": int(ytr.sum()), "calibration_positive": int(ycal.sum()),
                "fit_steps": sorted({r.source_step for r in plan.train}), "calibration_steps": list(plan.calibration_steps),
                "max_label_released_after_step": max(r.released_after_step for r in plan.train + plan.calibration),
                "disjoint_fit_calibration": True, "all_labels_available_before_prediction": all(r.released_after_step < plan.prediction_step for r in plan.train + plan.calibration),
                "fit_seconds": fit_seconds, "fit_converged": converged, "warnings": warning_records,
                "model_file": model_path.name, "model_sha256": sha256(model_path),
                "cohort_file": cohorts_path.name, "cohort_file_sha256": sha256(cohorts_path),
                "fit_X_sha256": hashlib.sha256(Xtr.tobytes()).hexdigest(), "fit_y_sha256": hashlib.sha256(ytr.tobytes()).hexdigest(),
                "calibration_X_sha256": hashlib.sha256(Xcal.tobytes()).hexdigest(), "calibration_y_sha256": hashlib.sha256(ycal.tobytes()).hexdigest(),
                "matrix_dtype": str(Xtr.dtype), "feature_columns": list(data.feature_columns)}
    if not converged:
        metadata["status"] = "skip_update_convergence_warning"
        dump(metadata, Path(str(prefix) + "_metadata.json"))
        return None, None, None, metadata
    before = time.perf_counter()
    try:
        cal_scores = score_model(model, Xcal)
    except Exception as error:
        metadata.update(status="skip_update_calibration_prediction_failure",
                        calibration_prediction_seconds=time.perf_counter() - before,
                        error=f"{type(error).__name__}: {error}")
        dump(metadata, Path(str(prefix) + "_metadata.json"))
        return None, None, None, metadata
    metadata["calibration_prediction_seconds"] = time.perf_counter() - before
    before = time.perf_counter()
    threshold_result = select_threshold(ycal, cal_scores)
    metadata["threshold_selection_seconds"] = time.perf_counter() - before
    scores_path = Path(str(prefix) + "_calibration_scores.jsonl.gz")
    with gzip.open(scores_path, "wt") as target:
        for r, score in zip(plan.calibration, cal_scores):
            jsonline(target, {"tx_id": int(r.example_id), "source_step": r.source_step,
                              "model_version": version, "score": float(score), "label": r.label})
    metadata.update(status="fitted_and_calibrated_candidate", threshold_result=threshold_result,
                    calibration_score_file=scores_path.name, calibration_score_file_sha256=sha256(scores_path))
    dump(metadata, Path(str(prefix) + "_metadata.json"))
    return model, cal_scores, threshold_result["threshold"], metadata


def batch_predictions(data, indices, model, version, threshold_version, threshold, step, config, target):
    import numpy as np
    before = time.perf_counter()
    scores = score_model(model, data.X[indices])
    prediction_seconds = time.perf_counter() - before
    before = time.perf_counter()
    decisions = budget_decisions(data.tx_ids[indices], scores, threshold, config["budget"]["integer_divisor"])
    budget_seconds = time.perf_counter() - before
    for local in np.argsort(data.tx_ids[indices], kind="stable"):
        jsonline(target, {"tx_id": int(data.tx_ids[indices[local]]), "step": step,
                          "model_version": version, "threshold_version": threshold_version,
                          "threshold": float(threshold), "score": float(scores[local]),
                          "raw_trigger": bool(decisions["raw_trigger"][local]),
                          "admitted": bool(decisions["admitted"][local]), "rank_zero_based": int(decisions["rank"][local]),
                          "batch_n_all": len(indices), "budget_k": decisions["k"],
                          "decision_phase": "completed_batch_before_current_step_label_release"})
    target.flush()  # logical record-before-label-release ordering; not fsync/outbox
    return {"step": step, "batch_n_all": len(indices), "budget_k": decisions["k"],
            "raw_alerts": int(decisions["raw_trigger"].sum()), "admitted": int(decisions["admitted"].sum()),
            "prediction_seconds": prediction_seconds, "budget_seconds": budget_seconds,
            "model_version": version, "threshold_version": threshold_version, "threshold": float(threshold)}


def evaluate_written_decisions(data, path):
    """Offline evaluation only AFTER the complete decision log has been closed."""
    import numpy as np
    from sklearn.metrics import average_precision_score
    index = {int(tx): i for i, tx in enumerate(data.tx_ids)}
    grouped = {}
    with gzip.open(path, "rt") as handle:
        for line in handle:
            row = json.loads(line)
            grouped.setdefault(row["step"], []).append(row)
    rows = []
    def metrics(step, batch):
        y = np.array([data.y[index[r["tx_id"]]] for r in batch], dtype=np.int8)
        pred = np.array([r["admitted"] for r in batch], dtype=bool)
        known = y >= 0
        known_alert = known & pred
        tp = int(((y == 1) & pred).sum())
        fp = int(((y == 0) & pred).sum())
        positive = int((y == 1).sum())
        threshold_alerts = sum(r["raw_trigger"] for r in batch)
        capacity = batch[0]["budget_k"] if step != "all" else sum(grouped[s][0]["budget_k"] for s in grouped)
        return {"step": step, "n_all": len(batch), "n_known": int(known.sum()), "n_unknown": int((~known).sum()),
                "positive_known": positive, "raw_threshold_alerts": threshold_alerts, "alerts_all": int(pred.sum()),
                "alerts_known": int(known_alert.sum()), "alerts_unknown": int((pred & ~known).sum()),
                "true_positive_known": tp, "false_positive_known": fp, "false_negative_known": positive - tp,
                "known_alert_precision": tp / (tp + fp) if tp + fp else None,
                "known_positive_recall": tp / positive if positive else None,
                "known_label_f1": 2 * tp / (positive + tp + fp) if positive + tp + fp else None,
                "known_label_AP": float(average_precision_score(y[known], np.array([r["score"] for r in batch])[known])) if positive else None,
                "known_label_coverage": float(known.mean()), "known_alert_coverage": float(known_alert.sum() / pred.sum()) if pred.sum() else None,
                "budget_capacity": capacity, "unused_capacity": capacity - int(pred.sum()),
                "actual_alert_fraction": float(pred.mean()),
                "AP_scope": "known labels only; pooled adaptive scores may differ in calibration across model versions"}
    for step, batch in sorted(grouped.items()):
        rows.append(metrics(step, batch))
    rows.append(metrics("all", [r for batch in grouped.values() for r in batch]))
    return rows


def worker(args):
    import joblib
    import numpy as np
    from threadpoolctl import threadpool_limits
    from delayed_feedback import (CalibrationRequirements, CalibrationScore, DelayedLabelQueue,
                                  LabelRecord, ModelThresholdRegistry, ModelThresholdVersion, plan_retraining)
    from elliptic_data import load_tabular
    args.cell.mkdir(parents=True, exist_ok=False)
    config = json.loads(args.config.read_text())
    ingest_start = time.perf_counter()
    data = load_tabular(args.data, feature_columns=config["features"]["csv_zero_based_positions"])
    ingestion_seconds = time.perf_counter() - ingest_start
    if str(data.X.dtype) != config["model_input_dtype"]:
        raise RuntimeError("loaded matrix dtype differs from frozen model_input_dtype")
    if importlib.metadata.version("lightgbm") != config["required_lightgbm_version"]:
        raise RuntimeError("LightGBM version differs from frozen configuration")
    requirements = CalibrationRequirements(config["calibration"]["min_positive"],
                                          config["calibration"]["min_negative"],
                                          config["calibration"]["recent_labelled_steps"])
    history = [LabelRecord(str(int(data.tx_ids[i])), int(data.step[i]), int(data.y[i]) if data.y[i] >= 0 else None)
               for i in np.flatnonzero(data.step <= 34)]
    seed_queue = DelayedLabelQueue(0, start_step=35, initial_history=history)
    initial_plan = plan_retraining(seed_queue.begin_step(35), requirements)
    if not initial_plan.eligible or {r.source_step for r in initial_plan.train} != set(range(1, 31)) or initial_plan.calibration_steps != (31, 32, 33, 34):
        raise RuntimeError("initial declared fit/calibration contract infeasible")
    started = datetime.now(timezone.utc).isoformat()
    start = time.perf_counter()
    fits, prediction_costs, releases, updates = [], [], [], []
    decisions_path = args.cell / "decisions.jsonl.gz"
    with threadpool_limits(limits=config["threads"]):
        if args.delay == -1:
            version = f"{args.family}_seed{config['seed']}_initial"
            model, _, threshold, meta = fit_candidate(data, initial_plan, args.family, config, version, args.cell)
            fits.append(meta)
            if model is None:
                raise RuntimeError("initial model failed convergence; no baseline or adaptive results valid")
            threshold_version = version + "_threshold"
            base = {"model_version": version, "threshold_version": threshold_version, "threshold": threshold,
                    "plan_id": initial_plan.plan_id, "cohort_signature": cohort_signature(initial_plan),
                    "model_file": "artifacts/" + meta["model_file"], "model_sha256": meta["model_sha256"]}
            dump(base, args.cell / "base_pair.json")
            with gzip.open(decisions_path, "wt") as target:
                for step in range(35, 50):
                    prediction_costs.append(batch_predictions(data, np.flatnonzero(data.step == step), model,
                                            version, threshold_version, threshold, step, config, target))
        else:
            base = json.loads((args.base / "base_pair.json").read_text())
            if sha256(args.base / base["model_file"]) != base["model_sha256"] or base["cohort_signature"] != cohort_signature(initial_plan):
                raise RuntimeError("base model or initial cohort differs")
            model = joblib.load(args.base / base["model_file"])
            registry = ModelThresholdRegistry(ModelThresholdVersion(base["model_version"], base["threshold_version"], base["threshold"], base["plan_id"]), initial_activation_step=35)
            queue = DelayedLabelQueue(args.delay, start_step=35, initial_history=history)
            previous_signature = base["cohort_signature"]
            with gzip.open(decisions_path, "wt") as target, gzip.open(args.cell / "updates.jsonl.gz", "wt") as update_log:
                for step in range(35, 50):
                    indices = np.flatnonzero(data.step == step)
                    ids = [str(int(data.tx_ids[i])) for i in indices]
                    labels = {str(int(data.tx_ids[i])): int(data.y[i]) if data.y[i] >= 0 else None for i in indices}
                    queue.register_step(step, ids, labels)
                    view = queue.begin_step(step)
                    plan = plan_retraining(view, requirements)
                    signature = cohort_signature(plan)
                    record = {"step": step, "delay": args.delay, "plan_id": plan.plan_id,
                              "cohort_signature": signature, "calibration_steps": list(plan.calibration_steps),
                              "fit_steps": sorted({r.source_step for r in plan.train}),
                              "fit_rows": len(plan.train), "calibration_rows": len(plan.calibration),
                              "max_label_released_after_step": max((r.released_after_step for r in plan.train + plan.calibration), default=None),
                              "pair_before": asdict(registry.active)}
                    if signature == previous_signature:
                        record.update(status="no_new_known_label_cohort", reasons=[])
                    elif not plan.eligible:
                        record.update(status="skip_update", reasons=list(plan.skip_reasons))
                    else:
                        version = f"{args.family}_seed{config['seed']}_delay{args.delay}_step{step}"
                        candidate, cal_scores, threshold, meta = fit_candidate(data, plan, args.family, config, version, args.cell)
                        fits.append(meta)
                        if candidate is None:
                            record.update(status="skip_update", reasons=[meta["status"]])
                        else:
                            commit = registry.commit_candidate(version, plan,
                                [CalibrationScore(r.example_id, version, float(s)) for r, s in zip(plan.calibration, cal_scores)],
                                threshold_version=version + "_threshold", threshold=threshold)
                            record.update(status=commit.status, reasons=list(commit.reasons))
                            if commit.status == "installed":
                                model = candidate
                    previous_signature = signature
                    record["pair_after"] = asdict(registry.active)
                    updates.append(record)
                    jsonline(update_log, record)
                    active = registry.active
                    prediction_costs.append(batch_predictions(data, indices, model, active.model_version,
                                            active.threshold_version, active.threshold, step, config, target))
                    releases.append(asdict(queue.end_step(step)))
                    jsonline(update_log, {"event": "after_prediction_label_release", **releases[-1]})
                    update_log.flush()
    training_end = time.perf_counter()
    metrics = evaluate_written_decisions(data, decisions_path)
    private_files = sorted(p for p in args.cell.rglob("*") if p.is_file() and (p.suffix in (".gz", ".joblib")))
    summary = {"schema_version": "elliptic_prequential_cell_v1", "family": args.family, "delay": None if args.delay == -1 else args.delay,
               "policy": "fixed_pair_with_batch_cap" if args.delay == -1 else "retrained_pair_with_batch_cap",
               "evidence_role": config["purpose"], "seed": config["seed"], "feature_columns": list(data.feature_columns),
               "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
               "fit_records": fits, "prediction_costs": prediction_costs, "label_releases": releases,
               "updates": updates, "metrics": metrics, "decision_sha256": sha256(decisions_path),
               "private_artifacts": [{"path": str(p.relative_to(args.cell)), "sha256": sha256(p), "bytes": p.stat().st_size} for p in private_files],
               "modeling_loop_seconds": training_end - start, "evaluation_seconds": time.perf_counter() - training_end,
               "ingestion_seconds": ingestion_seconds,
               "modeling_loop_scope": "excludes data ingestion and initial history/queue/plan construction; includes fitting, recalibration, per-step adaptation bookkeeping, predictions and artifact writes",
               "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
               "rss_scope": "whole worker high-water including ingestion, initial history, model fitting, predictions and offline evaluation buffers",
               "command": sys.argv,
               "limitations": ["original global corpus normalization", "prepared-feature retrospective benchmark", "shared-address dependence", "historical steps35–49 already studied", "labels not all transactions known", "one seed only", "batch waiting not seconds", "not independent attack evidence"]}
    dump(summary, args.cell / "summary.json")
    print(json.dumps({"cell": args.cell.name, "fits": len(fits), "status": "complete"}), flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--config", type=Path, default=PAPER / "elliptic_pilot_config.json")
    ap.add_argument("--run-id")
    ap.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--family", help=argparse.SUPPRESS)
    ap.add_argument("--delay", type=int, help=argparse.SUPPRESS)
    ap.add_argument("--cell", type=Path, help=argparse.SUPPRESS)
    ap.add_argument("--base", type=Path, help=argparse.SUPPRESS)
    args = ap.parse_args()
    args.data, args.config = args.data.resolve(), args.config.resolve()
    if args.worker:
        worker(args)
        return
    config = json.loads(args.config.read_text())
    expected_ranges = {"initial_fit_steps": [1, 30], "initial_calibration_steps": [31, 34], "evaluation_steps": [35, 49]}
    if any(config[key] != value for key, value in expected_ranges.items()):
        raise RuntimeError("declared fit/calibration/evaluation ranges differ from bounded runner contract")
    if config["features"]["csv_zero_based_positions"] != [2,3,5,6,7,9,10,11,12,13,14,15,17,18,19,20,21,22]:
        raise RuntimeError("approved direct18 feature subset changed; protocol re-review required")
    run_id = args.run_id or datetime.now(timezone.utc).strftime("elliptic_prequential_%Y%m%dT%H%M%S_%fZ")
    if Path(run_id).name != run_id:
        raise ValueError("run-id must be a single component")
    out = PAPER / "runs" / run_id
    out.mkdir(parents=True, exist_ok=False)
    source = out / "source_snapshot"
    source.mkdir()
    snapshots = []
    for path in (Path(__file__), PAPER / "delayed_feedback.py", PAPER / "elliptic_data.py", args.config,
                 PAPER / "tests/test_elliptic_prequential_pilot.py"):
        relative = path.relative_to(PAPER) if path.is_relative_to(PAPER) else Path(path.name)
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        snapshots.append({"path": str(relative), "sha256": sha256(target)})
    shutil.copy2(args.config, out / "config.json")
    shutil.copy2(args.data / "acquisition.json", out / "acquisition_manifest.json")
    packages = {p: importlib.metadata.version(p) for p in ("numpy", "pandas", "scipy", "scikit-learn", "lightgbm", "joblib", "threadpoolctl")}
    manifest = {"schema_version": "elliptic_prequential_run_v1", "run_id": run_id, "status": "running",
                "started_utc": datetime.now(timezone.utc).isoformat(), "config_sha256": sha256(args.config),
                "source_snapshot": snapshots, "command": [sys.executable, *sys.argv], "data_root": str(args.data),
                "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "environment": {"python": sys.version, "platform": platform.platform(), "packages": packages,
                                "threads": 1, "cpu_count": os.cpu_count(),
                                "cpu_model": next((x.split(":",1)[1].strip() for x in Path("/proc/cpuinfo").read_text().splitlines() if x.startswith("model name")), "unknown")},
                "evidence_role": config["purpose"], "cells": []}
    dump(manifest, out / "manifest.json")
    for family in ("lightgbm", "logistic"):
        base = out / f"{family}_fixed"
        for delay in (-1, *config["delays"]):
            cell = base if delay == -1 else out / f"{family}_delay{delay}"
            command = [sys.executable, str(source / "elliptic_prequential_pilot.py"), "--worker", "--data", str(args.data),
                       "--config", str(out / "config.json"), "--family", family, "--delay", str(delay),
                       "--cell", str(cell), "--base", str(base)]
            env = {**os.environ, "OMP_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1", "MKL_NUM_THREADS": "1", "NUMEXPR_NUM_THREADS": "1"}
            with (out / f"{cell.name}.stdout.txt").open("w") as stdout, (out / f"{cell.name}.stderr.txt").open("w") as stderr:
                result = subprocess.run(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr)
            if result.returncode:
                manifest.update(status="failed", failed_cell=cell.name)
                dump(manifest, out / "manifest.json")
                raise RuntimeError(f"worker failed: {cell.name}; inspect stderr")
            manifest["cells"].append(cell.name)
            dump(manifest, out / "manifest.json")
            print(json.dumps({"completed": cell.name, "cells": len(manifest["cells"])}), flush=True)
    source_ok = all(sha256(source / s["path"]) == s["sha256"] for s in snapshots)
    config_ok = sha256(out / "config.json") == manifest["config_sha256"]
    manifest.update(status="complete" if source_ok and config_ok else "failed_integrity",
                    finished_utc=datetime.now(timezone.utc).isoformat(),
                    frozen_sources_unchanged=source_ok, frozen_config_unchanged=config_ok)
    dump(manifest, out / "manifest.json")
    if not source_ok or not config_ok:
        raise RuntimeError("captured source/config changed during execution; results are not accepted")
    summaries = [json.loads((out / name / "summary.json").read_text()) for name in manifest["cells"]]
    dump({"schema_version": "elliptic_prequential_summary_v1", "run_id": run_id,
          "cells": [{"family": s["family"], "policy": s["policy"], "delay": s["delay"],
                     "metrics": s["metrics"], "fit_count": len(s["fit_records"]),
                     "updates": [{"step": u["step"], "status": u["status"], "reasons": u["reasons"]} for u in s["updates"]],
                     "fit_seconds": sum(r["fit_seconds"] for r in s["fit_records"]),
                     "prediction_seconds": sum(r["prediction_seconds"] for r in s["prediction_costs"])} for s in summaries]}, out / "pilot_summary.json")
    print(json.dumps({"status": "complete", "run": str(out.relative_to(ROOT))}), flush=True)


if __name__ == "__main__":
    main()
