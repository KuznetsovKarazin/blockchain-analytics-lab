"""
A1 - Basic questions of supervised and unsupervised detection on Elliptic.

Protocol (the same temporal protocol as the companion evaluation project):
train steps 1-30, validation 31-34 (thresholds only), test 35-49.

Questions
  (a) What does each feature family contribute? local features (LF, 93 columns:
      the transaction itself) vs all features (AF, 165 columns: LF plus 72
      aggregates over one-hop neighbours).
  (b) How far is a detector that never sees a label (Isolation Forest) from
      supervised models, at the same alert budget?
  (c) How do ROC-AUC, average precision and precision at a fixed threshold react
      when only the share of illicit transactions changes? (resampling test
      scores of one model; class-conditional score distributions stay fixed)
  (d) How stable is "the most important feature" across time windows?

AP is sklearn's average_precision_score (non-interpolated step sum).
Outputs: results/fundamentals/a1_<stamp>/ (metrics.csv, prevalence.csv,
importance_overlap.csv, importance_top.csv, summary.json, fig_a1.*)
"""

from __future__ import annotations

import argparse
import itertools
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, precision_score, recall_score, roc_auc_score

from bal.data.elliptic import N_LOCAL, TEST_STEPS, TRAIN_STEPS, VAL_STEPS, load_elliptic
from bal.eval.metrics import threshold_at_val_f1
from bal.models.tabular import lightgbm, logreg, random_forest
from bclab import figures as F
from bclab.repro import atomic_to_csv, dump_json, set_seed, write_manifest

DATA = Path("data/raw/elliptic")
BUDGET = 0.01          # alert budget: share of test transactions an analyst can review
PREVALENCES = (0.5, 0.2, 0.1, 0.05, 0.02, 0.01, 0.005)
WINDOWS = [range(s, s + 7) for s in (1, 8, 15, 22, 29, 36, 43)]   # 7 windows of 7 steps


def topk_metrics(y, s, k):
    idx = np.argsort(-s, kind="stable")[:k]
    tp = int(y[idx].sum())
    return tp / k, tp / max(1, int(y.sum()))


def evaluate(name, feats, seed, y_te, s_te, y_va, s_va, step_te):
    thr = threshold_at_val_f1(y_va, s_va)
    pred = s_te >= thr
    k = int(round(BUDGET * len(s_te)))
    p_k, r_k = topk_metrics(y_te, s_te, k)
    row = {"model": name, "features": feats, "seed": seed,
           "ap": average_precision_score(y_te, s_te), "roc_auc": roc_auc_score(y_te, s_te),
           "precision": precision_score(y_te, pred, zero_division=0),
           "recall": recall_score(y_te, pred, zero_division=0),
           "f1": 0.0, "threshold": thr, f"precision_at_{BUDGET:g}": p_k, f"recall_at_{BUDGET:g}": r_k,
           "k": k}
    if row["precision"] + row["recall"] > 0:
        row["f1"] = 2 * row["precision"] * row["recall"] / (row["precision"] + row["recall"])
    for part, steps in (("pre", range(35, 43)), ("post", range(43, 50))):
        m = np.isin(step_te, list(steps))
        row[f"ap_{part}"] = average_precision_score(y_te[m], s_te[m]) if y_te[m].sum() else np.nan
    return row


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--resamples", type=int, default=200)
    args = ap.parse_args()
    out = Path(args.out or f"results/fundamentals/a1_{time.strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)

    d = load_elliptic(DATA)
    tr, va, te = d.mask(TRAIN_STEPS), d.mask(VAL_STEPS), d.mask(TEST_STEPS)
    feats = {"LF": slice(0, N_LOCAL), "AF": slice(0, d.X.shape[1])}
    rows, keep_scores = [], {}

    for fname, sl in feats.items():
        X = d.X[:, sl]
        for seed in range(args.seeds):
            set_seed(seed)
            for mname, make in (("logreg", logreg), ("rf", random_forest), ("lgbm", lightgbm)):
                if mname == "logreg" and seed > 0:
                    continue                                    # deterministic
                m = make(seed=seed).fit(X[tr], d.y[tr])
                s_va, s_te = m.predict_score(X[va]), m.predict_score(X[te])
                rows.append(evaluate(mname, fname, seed, d.y[te], s_te, d.y[va], s_va, d.step[te]))
                if mname == "rf" and fname == "AF" and seed == 0:
                    keep_scores = {"s_te": s_te, "s_va": s_va}
            # unsupervised: fitted on all training-period transactions, labelled or not
            unl = np.isin(d.step, list(TRAIN_STEPS))
            iso = IsolationForest(n_estimators=300, max_samples=256, random_state=seed, n_jobs=4).fit(X[unl])
            s_va, s_te = -iso.score_samples(X[va]), -iso.score_samples(X[te])
            rows.append(evaluate("iforest", fname, seed, d.y[te], s_te, d.y[va], s_va, d.step[te]))
        print(fname, "done", flush=True)
    met = pd.DataFrame(rows)
    atomic_to_csv(met, out / "metrics.csv", index=False)
    agg = (met.groupby(["model", "features"])
           .agg(n_seeds=("seed", "nunique"),
                ap=("ap", "mean"), ap_sd=("ap", "std"), roc_auc=("roc_auc", "mean"),
                f1=("f1", "mean"), f1_sd=("f1", "std"),
                p_at_budget=(f"precision_at_{BUDGET:g}", "mean"),
                r_at_budget=(f"recall_at_{BUDGET:g}", "mean"),
                ap_pre=("ap_pre", "mean"), ap_post=("ap_post", "mean"))
           .reset_index())
    atomic_to_csv(agg, out / "metrics_summary.csv", index=False)

    # (c) prevalence: resample test scores of RF/AF/seed 0 to a target share of illicit
    y_te = d.y[te]
    s_te, thr = keep_scores["s_te"], threshold_at_val_f1(d.y[va], keep_scores["s_va"])
    pos, neg = np.flatnonzero(y_te == 1), np.flatnonzero(y_te == 0)
    rng = np.random.default_rng(0)
    prev_rows = []
    n_pos = 400
    for pi in PREVALENCES:
        n_neg = int(round(n_pos * (1 - pi) / pi))
        for r in range(args.resamples):
            ip = rng.choice(pos, n_pos, replace=False)
            ineg = rng.choice(neg, n_neg, replace=n_neg > len(neg))
            idx = np.concatenate([ip, ineg])
            y, s = y_te[idx], s_te[idx]
            pred = s >= thr
            prev_rows.append({"prevalence": pi, "resample": r, "n_pos": n_pos, "n_neg": n_neg,
                              "roc_auc": roc_auc_score(y, s), "ap": average_precision_score(y, s),
                              "precision_at_thr": precision_score(y, pred, zero_division=0),
                              "recall_at_thr": recall_score(y, pred, zero_division=0),
                              "false_alarms_per_true": (pred & (y == 0)).sum() / max(1, (pred & (y == 1)).sum())})
    prev = pd.DataFrame(prev_rows)
    atomic_to_csv(prev, out / "prevalence.csv", index=False)
    prev_sum = prev.groupby("prevalence").agg(["mean", "std"]).drop(columns=["resample", "n_pos"], level=0)
    prev_sum.columns = ["_".join(c) for c in prev_sum.columns]
    prev_sum = prev_sum.reset_index()
    atomic_to_csv(prev_sum, out / "prevalence_summary.csv", index=False)

    # (d) importance stability: RF (AF) per 7-step window, top-20 by impurity importance
    top = {}
    for w in WINDOWS:
        m = d.mask(w)
        if d.y[m].sum() < 20:
            continue
        rf = random_forest(seed=0).fit(d.X[m], d.y[m]).est
        order = np.argsort(-rf.feature_importances_)[:20]
        top[f"{w.start}-{w.stop - 1}"] = [d.feature_names[i] for i in order]
    imp_rows = [{"window": k, "rank": i + 1, "feature": f} for k, v in top.items() for i, f in enumerate(v)]
    atomic_to_csv(pd.DataFrame(imp_rows), out / "importance_top.csv", index=False)
    ov = []
    for a, b in itertools.combinations(top, 2):
        A, B = set(top[a]), set(top[b])
        ov.append({"window_a": a, "window_b": b, "jaccard_top20": len(A & B) / len(A | B),
                   "same_top1": top[a][0] == top[b][0]})
    ov = pd.DataFrame(ov)
    atomic_to_csv(ov, out / "importance_overlap.csv", index=False)
    in_all = set.intersection(*[set(v) for v in top.values()])

    F.style()
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(6.5, 2.7))
    ps = prev_sum.sort_values("prevalence")
    x = ps["prevalence"] * 100
    for i, (col, lab) in enumerate((("roc_auc", "ROC-AUC"), ("ap", "average precision"),
                                    ("precision_at_thr", "precision at fixed threshold"))):
        axes[0].errorbar(x, ps[f"{col}_mean"], yerr=ps[f"{col}_std"], color="0", ls=F.LINES[i],
                         marker=F.MARKERS[i], ms=3, capsize=2, label=lab)
    axes[0].set_xscale("log")
    axes[0].set_xticks([0.5, 1, 2, 5, 10, 20, 50], ["0.5", "1", "2", "5", "10", "20", "50"])
    axes[0].set_xlabel("share of illicit transactions, %")
    axes[0].set_ylabel("metric value")
    axes[0].set_title("(a) same scores, different prevalence")
    axes[0].legend(frameon=False, loc="lower right")
    sub = agg[agg.features == "AF"].set_index("model").loc[["logreg", "iforest", "rf", "lgbm"]]
    sub_lf = agg[agg.features == "LF"].set_index("model").loc[["logreg", "iforest", "rf", "lgbm"]]
    xx = np.arange(4)
    axes[1].bar(xx - 0.2, sub_lf["ap"], 0.4, color="white", edgecolor="0", hatch="///", label="LF (93 local)")
    axes[1].bar(xx + 0.2, sub["ap"], 0.4, color="0.35", edgecolor="0", label="AF (165 all)")
    axes[1].set_xticks(xx, ["logistic\nregression", "isolation\nforest", "random\nforest", "Light-\nGBM"], fontsize=6)
    axes[1].set_ylabel("average precision, test 35-49")
    axes[1].set_title("(b) model family and feature set")
    axes[1].legend(frameon=False)
    fig.subplots_adjust(wspace=0.35)
    F.save(fig, out, "fig_a1")

    summary = {"metrics_summary": agg.to_dict(orient="records"),
               "prevalence_summary": prev_sum.to_dict(orient="records"),
               "importance": {"windows": list(top), "mean_jaccard_top20": float(ov.jaccard_top20.mean()),
                              "min_jaccard_top20": float(ov.jaccard_top20.min()),
                              "share_pairs_same_top1": float(ov.same_top1.mean()),
                              "features_in_all_top20": sorted(in_all)},
               "test_size": int(te.sum()), "test_pos": int(d.y[te].sum()), "budget": BUDGET}
    dump_json(summary, out / "summary.json")
    write_manifest(out, script="scripts/a1_elliptic_fundamentals.py",
                   config={"seeds": args.seeds, "resamples": args.resamples, "budget": BUDGET,
                           "prevalences": PREVALENCES, "windows": [f"{w.start}-{w.stop-1}" for w in WINDOWS]},
                   data_files=[DATA / "elliptic_txs_classes.csv", DATA / "elliptic_txs_features.csv",
                               DATA / "elliptic_txs_edgelist.csv"])
    print(agg.to_string())
    print(prev_sum[["prevalence", "roc_auc_mean", "ap_mean", "precision_at_thr_mean"]].to_string())
    print(summary["importance"])


if __name__ == "__main__":
    main()
