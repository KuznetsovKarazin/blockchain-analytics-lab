"""Read-only independent audit of a completed Elliptic pilot; never fits models.

Run with --run papers/monitoring_jss/runs/elliptic_prequential_<id>.
Requires private original CSVs and private model/decision/cohort artifacts.
Production experiment modules are not imported. Public output contains aggregates.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from fractions import Fraction
import gzip
import hashlib
import json
import math
from pathlib import Path
import platform
import sys
import time
import warnings

import joblib
import numpy as np
import pandas as pd
from threadpoolctl import threadpool_limits

DIRECT18 = [2, 3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22]


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def read_gzip(path):
    with gzip.open(path, "rt") as source:
        return [json.loads(line) for line in source]


def close(actual, expected, tolerance=1e-12):
    if expected is None:
        assert actual is None, (actual, expected)
    else:
        assert math.isfinite(actual) and abs(actual - expected) <= tolerance, (actual, expected)


def optimal_f1(labels, scores):
    # Independent value histogram, exact rational objective, largest tied threshold.
    groups = defaultdict(lambda: [0, 0])
    for label, score in zip(labels, scores):
        assert label in (0, 1) and math.isfinite(score)
        groups[float(score)][label] += 1
    positive = sum(label == 1 for label in labels)
    negative = len(labels) - positive
    tp, fp = positive, negative
    candidates = []
    for threshold, (n, p) in sorted(groups.items()):
        candidates.append((Fraction(2 * tp, positive + tp + fp), threshold, tp, fp))
        tp -= p
        fp -= n
    best, threshold, tp, fp = max(candidates)
    return {"threshold": threshold, "f1": float(best), "tp": tp, "fp": fp,
            "fn": positive - tp, "calibration_rows": len(labels), "positive": positive, "negative": negative}


def average_precision(labels, scores):
    groups = defaultdict(lambda: [0, 0])
    for label, score in zip(labels, scores):
        if label >= 0:
            groups[float(score)][int(label)] += 1
    total = sum(p for n, p in groups.values())
    if not total:
        return None
    tp = count = 0
    ap = 0.0
    for score, (n, p) in sorted(groups.items(), reverse=True):
        tp += p
        count += n + p
        ap += p / total * (tp / count)
    return ap


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_suffix(".json"))
    args = parser.parse_args()
    run = args.run.resolve()
    started = time.perf_counter()
    manifest = json.loads((run / "manifest.json").read_text())
    assert manifest["status"] == "complete"
    config = json.loads((run / "config.json").read_text())
    assert sha(run / "config.json") == manifest["config_sha256"]
    assert config["features"]["csv_zero_based_positions"] == DIRECT18
    assert config["model_input_dtype"] == "float32"
    assert config["initial_fit_steps"] == [1, 30] and config["initial_calibration_steps"] == [31, 34]
    assert config["evaluation_steps"] == [35, 49] and config["delays"] == [0, 1, 2, 4]
    assert config["budget"]["integer_divisor"] == 200
    assert config["calibration"]["recent_labelled_steps"] == 4
    for source in manifest["source_snapshot"]:
        assert sha(run / "source_snapshot" / source["path"]) == source["sha256"]
    data_root = Path(manifest["data_root"])
    acquisition = json.loads((run / "acquisition_manifest.json").read_text())
    for item in acquisition["files"]:
        assert sha(data_root / item["name"]) == item["sha256"]
    features = pd.read_csv(data_root / "elliptic_txs_features.csv", header=None, usecols=[0, 1, *DIRECT18],
                           dtype={0: np.int64, 1: np.int16, **{c: np.float32 for c in DIRECT18}})
    classes = pd.read_csv(data_root / "elliptic_txs_classes.csv", dtype={"txId": np.int64, "class": str})
    assert not features[0].duplicated().any() and not classes.txId.duplicated().any()
    assert set(features[0]) == set(classes.txId)
    tx = features[0].to_numpy()
    step = features[1].to_numpy()
    X = features[DIRECT18].to_numpy(dtype=np.float32)
    y = classes.set_index("txId")["class"].reindex(tx).map({"1": 1, "2": 0, "unknown": -1}).to_numpy(dtype=np.int8)
    assert X.shape == (203769, 18) and np.isfinite(X).all()
    lookup = {int(identifier): i for i, identifier in enumerate(tx)}
    indices_by_step = {s: np.flatnonzero(step == s) for s in range(1, 50)}
    expected_cohorts = {}
    requirements = {"min_positive": config["calibration"]["min_positive"],
                    "min_negative": config["calibration"]["min_negative"], "recent_steps": 4}

    def expected_plan(prediction_step, delay):
        key = (prediction_step, delay)
        if key in expected_cohorts:
            return expected_cohorts[key]
        last = max(34, prediction_step - delay - 1)
        available = (step <= last)
        known_steps = sorted(set(int(s) for s in step[available & (y >= 0)]))
        calibration_steps = known_steps[-4:]
        known_indices = sorted(np.flatnonzero(available & (y >= 0)), key=lambda i: (int(step[i]), str(int(tx[i]))))
        train, calibration = [], []
        for i in known_indices:
            record = {"example_id": str(int(tx[i])), "source_step": int(step[i]), "label": int(y[i]),
                      "released_after_step": 34 if step[i] <= 34 else int(step[i]) + delay,
                      "availability_origin": "declared_initial_history" if step[i] <= 34 else "delayed_stream"}
            (calibration if int(step[i]) in calibration_steps else train).append(record)
        content = {"prediction_step": prediction_step, "requirements": requirements, "train": train,
                   "calibration": calibration, "unknown_excluded": int((available & (y < 0)).sum())}
        signature = digest({role: [(r["example_id"], r["source_step"], r["label"]) for r in rows]
                            for role, rows in (("train", train), ("calibration", calibration))})
        result = {**content, "plan_id": digest(content), "cohort_signature": signature,
                  "calibration_steps": calibration_steps, "fit_steps": sorted({r["source_step"] for r in train})}
        if len(expected_cohorts) >= 2:
            expected_cohorts.pop(next(iter(expected_cohorts)))
        expected_cohorts[key] = result
        return result

    expected_cells = {f"{family}_{suffix}" for family in ("lightgbm", "logistic")
                      for suffix in ("fixed", "delay0", "delay1", "delay2", "delay4")}
    assert set(manifest["cells"]) == expected_cells
    aggregate = json.loads((run / "pilot_summary.json").read_text())
    result_rows, selected_models, checked_artifacts, checked_gzip = [], [], 0, 0
    checked_cohort_rows = checked_scores = checked_decisions = fitted_models = 0
    fixed_decisions = {}
    for cell_name in manifest["cells"]:
        cell = run / cell_name
        summary = json.loads((cell / "summary.json").read_text())
        family, delay = summary["family"], summary["delay"]
        policy = "fixed_pair_with_batch_cap" if delay is None else "retrained_pair_with_batch_cap"
        assert summary["policy"] == policy and summary["feature_columns"] == DIRECT18
        for artifact in summary["private_artifacts"]:
            path = cell / artifact["path"]
            assert sha(path) == artifact["sha256"] and path.stat().st_size == artifact["bytes"]
            checked_artifacts += 1
        assert sha(cell / "decisions.jsonl.gz") == summary["decision_sha256"]
        decisions = read_gzip(cell / "decisions.jsonl.gz")
        checked_gzip += 1
        checked_decisions += len(decisions)
        grouped = defaultdict(list)
        for row in decisions:
            assert row["step"] in range(35, 50)
            grouped[row["step"]].append(row)
        assert set(grouped) == set(range(35, 50))
        fits = summary["fit_records"]
        metadata_by_version = {item["model_version"]: item for item in fits}
        selection = {fits[0]["model_version"], fits[-1]["model_version"]} if fits else set()
        for metadata in fits:
            version = metadata["model_version"]
            assert json.loads((cell / "artifacts" / f"{version}_metadata.json").read_text()) == metadata
            plan = expected_plan(metadata["prediction_step"], delay or 0)
            assert metadata["plan_id"] == plan["plan_id"] and metadata["cohort_signature"] == plan["cohort_signature"]
            if metadata["status"] != "fitted_and_calibrated_candidate":
                assert metadata["status"].startswith("skip_update")
                continue
            fitted_models += 1
            assert metadata["fit_converged"]
            assert sha(cell / "artifacts" / metadata["model_file"]) == metadata["model_sha256"]
            assert sha(cell / "artifacts" / metadata["cohort_file"]) == metadata["cohort_file_sha256"]
            assert sha(cell / "artifacts" / metadata["calibration_score_file"]) == metadata["calibration_score_file_sha256"]
            cohorts = read_gzip(cell / "artifacts" / metadata["cohort_file"])
            checked_gzip += 1
            checked_cohort_rows += len(cohorts)
            expected = [{"role": role, **r} for role, rows in (("fit", plan["train"]), ("calibration", plan["calibration"])) for r in rows]
            assert cohorts == expected
            assert metadata["fit_steps"] == plan["fit_steps"] and metadata["calibration_steps"] == plan["calibration_steps"]
            assert metadata["max_label_released_after_step"] == max(r["released_after_step"] for r in cohorts) < metadata["prediction_step"]
            assert metadata["disjoint_fit_calibration"] and metadata["all_labels_available_before_prediction"]
            assert metadata["matrix_dtype"] == "float32" and metadata["feature_columns"] == DIRECT18
            row_indices = {}
            for name, records in (("fit", plan["train"]), ("calibration", plan["calibration"])):
                idx = np.array([lookup[int(r["example_id"])] for r in records])
                row_indices[name] = idx
                assert hashlib.sha256(X[idx].tobytes()).hexdigest() == metadata[name + "_X_sha256"]
                assert hashlib.sha256(y[idx].tobytes()).hexdigest() == metadata[name + "_y_sha256"]
                assert len(idx) == metadata[name + "_rows"]
                assert int(y[idx].sum()) == metadata[name + "_positive"]
            assert not set(row_indices["fit"]) & set(row_indices["calibration"])
            assert set(y[row_indices["fit"]]) == {0, 1}
            assert int((y[row_indices["calibration"]] == 1).sum()) >= requirements["min_positive"]
            assert int((y[row_indices["calibration"]] == 0).sum()) >= requirements["min_negative"]
            calibration_scores = read_gzip(cell / "artifacts" / metadata["calibration_score_file"])
            checked_gzip += 1
            checked_scores += len(calibration_scores)
            assert len(calibration_scores) == len(plan["calibration"])
            for row, record in zip(calibration_scores, plan["calibration"]):
                assert row["tx_id"] == int(record["example_id"]) and row["source_step"] == record["source_step"]
                assert row["label"] == record["label"] and row["model_version"] == version
                assert math.isfinite(row["score"]) and 0 <= row["score"] <= 1
            optimum = optimal_f1([r["label"] for r in calibration_scores], [r["score"] for r in calibration_scores])
            for key, value in optimum.items():
                close(metadata["threshold_result"][key], value)
            if version in selection:
                model = joblib.load(cell / "artifacts" / metadata["model_file"])
                assert list(model.classes_) == [0, 1]
                with threadpool_limits(limits=1), warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    replayed = model.predict_proba(X[row_indices["calibration"]])[:, 1]
                saved = np.array([r["score"] for r in calibration_scores])
                assert np.allclose(replayed, saved, rtol=0, atol=1e-12)
                scaler_checked = False
                if family == "logistic":
                    scaler = model.named_steps["standardscaler"]
                    assert scaler.n_samples_seen_ == len(row_indices["fit"])
                    assert np.allclose(scaler.mean_, X[row_indices["fit"]].astype(np.float64).mean(axis=0), rtol=0, atol=1e-10)
                    assert np.allclose(scaler.var_, X[row_indices["fit"]].astype(np.float64).var(axis=0), rtol=1e-10, atol=1e-10)
                    scaler_checked = True
                # Recompute one full evaluation batch for the same actual installed estimator.
                batch = next((rows for rows in grouped.values() if rows[0]["model_version"] == version), None)
                assert batch is not None
                idx = np.array([lookup[row["tx_id"]] for row in batch])
                with threadpool_limits(limits=1), warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    eval_scores = model.predict_proba(X[idx])[:, 1]
                assert np.allclose(eval_scores, [row["score"] for row in batch], rtol=0, atol=1e-12)
                selected_models.append({"cell": cell_name, "model_version": version, "model_sha256": metadata["model_sha256"],
                                        "calibration_scores_recomputed": len(saved), "evaluation_scores_recomputed": len(batch),
                                        "max_absolute_score_difference": float(np.max(np.abs(replayed - saved))),
                                        "training_only_lr_scaler_moments_checked": scaler_checked})
        base = json.loads((run / f"{family}_fixed/base_pair.json").read_text())
        active = {"model_version": base["model_version"], "threshold_version": base["threshold_version"],
                  "threshold": base["threshold"], "calibration_plan_id": base["plan_id"]}
        active_by_step = {}
        update_counts = Counter()
        if delay is None:
            assert not summary["updates"] and not summary["label_releases"] and len(fits) == 1
            assert active["threshold"] == fits[0]["threshold_result"]["threshold"]
            fixed_decisions[family] = grouped
            active_by_step = {s: active for s in range(35, 50)}
        else:
            journal = read_gzip(cell / "updates.jsonl.gz")
            checked_gzip += 1
            assert len(journal) == 30 and len(summary["updates"]) == len(summary["label_releases"]) == 15
            previous_signature = expected_plan(35, delay)["cohort_signature"]
            last_activation = 35
            for offset, prediction_step in enumerate(range(35, 50)):
                update, release = journal[2*offset:2*offset+2]
                assert update == summary["updates"][offset]
                assert release == {"event": "after_prediction_label_release", **summary["label_releases"][offset]}
                plan = expected_plan(prediction_step, delay)
                assert update["step"] == prediction_step and update["delay"] == delay
                assert update["plan_id"] == plan["plan_id"] and update["cohort_signature"] == plan["cohort_signature"]
                assert update["fit_steps"] == plan["fit_steps"] and update["calibration_steps"] == plan["calibration_steps"]
                assert update["fit_rows"] == len(plan["train"]) and update["calibration_rows"] == len(plan["calibration"])
                assert update["pair_before"] == active
                if plan["cohort_signature"] == previous_signature:
                    assert update["status"] == "no_new_known_label_cohort" and update["pair_after"] == active
                elif update["status"] == "installed":
                    version = update["pair_after"]["model_version"]
                    metadata = metadata_by_version[version]
                    assert metadata["prediction_step"] == prediction_step > last_activation
                    assert update["pair_after"]["threshold"] == metadata["threshold_result"]["threshold"]
                    assert update["pair_after"]["threshold_version"] == version + "_threshold"
                    assert update["pair_after"]["calibration_plan_id"] == plan["plan_id"]
                    active, last_activation = update["pair_after"], prediction_step
                else:
                    assert update["status"] == "skip_update" and update["pair_after"] == active and update["reasons"]
                previous_signature = plan["cohort_signature"]
                active_by_step[prediction_step] = active
                update_counts[update["status"]] += 1
                source_step = prediction_step - delay
                revealed = indices_by_step[source_step] if source_step >= 35 else np.array([], dtype=int)
                assert release["after_prediction_step"] == prediction_step and release["first_usable_prediction_step"] == prediction_step + 1
                assert release["source_steps"] == ([source_step] if len(revealed) else [])
                assert release["released_known"] == int((y[revealed] >= 0).sum()) and release["released_unknown"] == int((y[revealed] < 0).sum())
        verified_metrics = []
        for prediction_step, batch in sorted(grouped.items()):
            expected_ids = sorted(int(tx[i]) for i in indices_by_step[prediction_step])
            assert [row["tx_id"] for row in batch] == expected_ids
            ordered = sorted(batch, key=lambda row: (-row["score"], row["tx_id"]))
            ranks = {row["tx_id"]: i for i, row in enumerate(ordered)}
            cap = len(batch) // 200
            pair = active_by_step[prediction_step]
            for row in batch:
                assert row["model_version"] == pair["model_version"] and row["threshold_version"] == pair["threshold_version"]
                assert row["threshold"] == pair["threshold"] and math.isfinite(row["score"])
                assert row["batch_n_all"] == len(batch) and row["budget_k"] == cap
                assert row["rank_zero_based"] == ranks[row["tx_id"]]
                assert row["raw_trigger"] == (row["score"] >= pair["threshold"])
                assert row["admitted"] == (row["raw_trigger"] and ranks[row["tx_id"]] < cap)
                assert row["decision_phase"] == "completed_batch_before_current_step_label_release"
            assert sum(row["admitted"] for row in batch) <= cap
            if delay is not None and prediction_step <= 35 + delay:
                assert batch == fixed_decisions[family][prediction_step]

        def recompute_metrics(label, batch):
            truth = [int(y[lookup[row["tx_id"]]]) for row in batch]
            n = len(batch)
            known = sum(label >= 0 for label in truth)
            positives = sum(label == 1 for label in truth)
            tp = sum(label == 1 and row["admitted"] for label, row in zip(truth, batch))
            fp = sum(label == 0 and row["admitted"] for label, row in zip(truth, batch))
            alerts = sum(row["admitted"] for row in batch)
            cap = len(batch) // 200 if label != "all" else sum(len(rows) // 200 for rows in grouped.values())
            result = {"step": label, "n_all": n, "n_known": known, "n_unknown": n-known, "positive_known": positives,
                      "raw_threshold_alerts": sum(row["raw_trigger"] for row in batch), "alerts_all": alerts,
                      "alerts_known": tp+fp, "alerts_unknown": alerts-tp-fp, "true_positive_known": tp,
                      "false_positive_known": fp, "false_negative_known": positives-tp,
                      "known_alert_precision": tp/(tp+fp) if tp+fp else None,
                      "known_positive_recall": tp/positives if positives else None,
                      "known_label_f1": 2*tp/(positives+tp+fp) if positives+tp+fp else None,
                      "known_label_AP": average_precision(truth, [row["score"] for row in batch]),
                      "known_label_coverage": known/n, "known_alert_coverage": (tp+fp)/alerts if alerts else None,
                      "budget_capacity": cap, "unused_capacity": cap-alerts, "actual_alert_fraction": alerts/n}
            persisted = next(row for row in summary["metrics"] if row["step"] == label)
            for key, expected in result.items():
                if key == "step":
                    assert persisted[key] == expected
                else:
                    close(persisted[key], expected)
            return result
        for prediction_step, batch in sorted(grouped.items()):
            verified_metrics.append(recompute_metrics(prediction_step, batch))
        totals = recompute_metrics("all", decisions)
        public = next(row for row in aggregate["cells"] if row["family"] == family and row["delay"] == delay)
        assert public["metrics"] == summary["metrics"] and public["fit_count"] == len(fits)
        close(public["fit_seconds"], sum(record["fit_seconds"] for record in fits))
        close(public["prediction_seconds"], sum(record["prediction_seconds"] for record in summary["prediction_costs"]))
        result_rows.append({"cell": cell_name, "family": family, "delay": delay, "policy": policy,
                            "fit_count": len(fits), "update_counts": dict(update_counts), "metrics_all": totals,
                            "per_step_metrics_recomputed": verified_metrics,
                            "fit_seconds": public["fit_seconds"], "prediction_seconds": public["prediction_seconds"],
                            "modeling_loop_seconds": summary["modeling_loop_seconds"],
                            "post_loop_evaluation_and_hash_seconds": summary["evaluation_seconds"], "peak_rss_bytes": summary["peak_rss_bytes"]})
    report = {"schema_version": "elliptic_prequential_independent_review_v1", "run_id": manifest["run_id"],
              "verdict": "PASS_FOR_EXPLORATORY_DIRECT18_RETROSPECTIVE_PILOT", "all_checks_pass": True,
              "created_utc": datetime.now(timezone.utc).isoformat(), "review_script_sha256": sha(Path(__file__)),
              "python": sys.version, "platform": platform.platform(), "config_sha256": manifest["config_sha256"],
              "production_modules_imported": False, "new_training_performed": False,
              "original_source_hashes_verified": acquisition["files"], "frozen_source_snapshot": manifest["source_snapshot"],
              "cells_checked": len(result_rows), "decision_rows_checked": checked_decisions,
              "private_artifact_hashes_checked": checked_artifacts, "gzip_streams_read_to_eof": checked_gzip,
              "fitted_models_with_all_cohort_and_matrix_hash_checks": fitted_models,
              "cohort_records_compared_to_source_and_release_oracle": checked_cohort_rows,
              "saved_calibration_scores_with_exact_f1_optimum_checked": checked_scores,
              "actual_models_reloaded_and_repredicted": selected_models, "cells": result_rows,
              "audit_seconds": time.perf_counter()-started,
              "limitations": [
                  "Source-reconstructed direct18 subset of publisher-normalized CSVs; raw historical feature availability and entity independence are not established.",
                  "All1-34 known labels are declared warm-start history. Later release delays are simulated, not empirical investigation timestamps; hidden final source labels are used only for offline scoring of persisted decisions.",
                  "All decisions and cohort artifacts were checked. Initial and first/last fitted estimator per adaptive cell were actually reloaded and rescored; remaining estimator binaries were hash checked, not retrained or independently refitted.",
                  "Fixed control is shared across delays. Early adaptive prefixes equal the fixed control until the first delayed known-label cohort can arrive; this is expected, not an adaptive failure.",
                  "Known-label metrics exclude unknown truth. Unknown rows remain in total population, cap and workload. Pooled adaptive AP mixes model versions; per-step AP is retained separately.",
                  "Modeling-loop wall time includes fit, calibration, scoring, artifact/decision writing; excludes loader/hash setup. The field evaluation_seconds includes post-loop metric evaluation and private-artifact hash preparation. Peak RSS is worker high-water after evaluation/hash preparation. None establishes live end-to-end latency.",
                  "A local gzip flush establishes program-order recording before release; it is not fsync, external delivery or arbitrary-crash recovery.",
                  "One seed, previously studied35-49 snapshots, no new independent incident/attack test and no hyperparameter search."
              ]}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(args.output), "cells": len(result_rows), "decision_rows": checked_decisions,
                      "fitted_models": fitted_models, "repredicted_models": len(selected_models), "all_checks_pass": True}))


if __name__ == "__main__":
    main()
