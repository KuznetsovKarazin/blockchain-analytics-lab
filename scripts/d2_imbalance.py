"""
D2 - Class-imbalance remedies on Elliptic under the temporal protocol.

Remedies (applied to the training steps 1-30 only)
  none        plain fit
  weights     class weights inversely proportional to class frequency
  undersample licit training transactions randomly dropped to a 1:1 ratio
  smote       SMOTE (Chawla et al. 2002): synthetic illicit points on segments
              to one of the 5 nearest illicit neighbours, up to a 1:1 ratio
Models: logistic regression (standardised inputs) and LightGBM, 3 seeds each.

Reported on test steps 35-49: AP, F1 at the validation-F1 threshold, precision
at a 1% alert budget, and two probability diagnostics: the mean predicted
probability (to compare with the test prevalence) and the Brier score. Threshold
is chosen on validation steps 31-34 for every remedy.

Outputs: results/data/d2_<stamp>/
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, f1_score
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler

from bal.data.elliptic import TEST_STEPS, TRAIN_STEPS, VAL_STEPS, load_elliptic
from bal.eval.metrics import threshold_at_val_f1
from bclab import figures as F
from bclab.repro import atomic_to_csv, dump_json, set_seed, write_manifest

DATA = Path("data/raw/elliptic")
BUDGET = 0.01


def smote(X, y, rng, k=5):
    pos = X[y == 1]
    need = int((y == 0).sum() - (y == 1).sum())
    nn = NearestNeighbors(n_neighbors=k + 1).fit(pos)
    _, nb = nn.kneighbors(pos)
    base = rng.integers(0, len(pos), need)
    mate = nb[base, rng.integers(1, k + 1, need)]
    lam = rng.random((need, 1))
    syn = pos[base] + lam * (pos[mate] - pos[base])
    return np.vstack([X, syn]), np.concatenate([y, np.ones(need, int)])


def undersample(X, y, rng):
    pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
    keep = np.concatenate([pos, rng.choice(neg, len(pos), replace=False)])
    return X[keep], y[keep]


def make(model, remedy, seed):
    cw = "balanced" if remedy == "weights" else None
    if model == "logreg":
        return LogisticRegression(max_iter=3000, class_weight=cw, random_state=seed)
    import lightgbm as lgb
    return lgb.LGBMClassifier(n_estimators=400, learning_rate=0.05, num_leaves=31, subsample=0.8,
                              subsample_freq=1, colsample_bytree=0.8, class_weight=cw,
                              random_state=seed, verbose=-1, n_jobs=4)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("--seeds", type=int, default=3)
    args = ap.parse_args()
    out = Path(args.out or f"results/data/d2_{time.strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)
    d = load_elliptic(DATA)
    tr, va, te = d.mask(TRAIN_STEPS), d.mask(VAL_STEPS), d.mask(TEST_STEPS)
    sc = StandardScaler().fit(d.X[tr])
    X = sc.transform(d.X)
    y_te = d.y[te]
    k = int(round(BUDGET * te.sum()))
    rows = []
    for seed in range(args.seeds):
        set_seed(seed)
        for remedy in ("none", "weights", "undersample", "smote"):
            rng = np.random.default_rng(seed)
            Xtr, ytr = X[tr], d.y[tr]
            if remedy == "undersample":
                Xtr, ytr = undersample(Xtr, ytr, rng)
            elif remedy == "smote":
                Xtr, ytr = smote(Xtr, ytr, rng)
            for model in ("logreg", "lgbm"):
                if model == "logreg" and seed > 0 and remedy in ("none", "weights"):
                    continue                                        # deterministic
                m = make(model, remedy, seed).fit(Xtr, ytr)
                p_va, p_te = m.predict_proba(X[va])[:, 1], m.predict_proba(X[te])[:, 1]
                thr = threshold_at_val_f1(d.y[va], p_va)
                top = np.argsort(-p_te, kind="stable")[:k]
                rows.append({"model": model, "remedy": remedy, "seed": seed, "train_size": len(ytr),
                             "train_pos_share": float(ytr.mean()),
                             "ap": average_precision_score(y_te, p_te),
                             "f1": f1_score(y_te, p_te >= thr, zero_division=0), "threshold": thr,
                             "precision_at_budget": float(y_te[top].mean()),
                             "mean_prob": float(p_te.mean()), "test_prevalence": float(y_te.mean()),
                             "brier": brier_score_loss(y_te, p_te)})
            print(seed, remedy, flush=True)
    res = pd.DataFrame(rows)
    atomic_to_csv(res, out / "metrics.csv", index=False)
    agg = (res.groupby(["model", "remedy"])
           .agg(n=("ap", "size"), ap=("ap", "mean"), ap_sd=("ap", "std"), f1=("f1", "mean"), f1_sd=("f1", "std"),
                p_at_budget=("precision_at_budget", "mean"), threshold=("threshold", "mean"),
                mean_prob=("mean_prob", "mean"), prevalence=("test_prevalence", "first"), brier=("brier", "mean"),
                train_size=("train_size", "first"))
           .reset_index())
    atomic_to_csv(agg, out / "metrics_summary.csv", index=False)

    F.style()
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(6.5, 2.6))
    rem = ["none", "weights", "undersample", "smote"]
    xx = np.arange(len(rem))
    for i, (model, lab) in enumerate((("logreg", "logistic regression"), ("lgbm", "LightGBM"))):
        s = agg[agg.model == model].set_index("remedy").loc[rem]
        kw = dict(color="white", edgecolor="0", hatch="///") if i == 0 else dict(color="0.35", edgecolor="0")
        axes[0].bar(xx + (i - 0.5) * 0.38, s.ap, 0.38, yerr=s.ap_sd.fillna(0), capsize=2, label=lab, **kw)
        axes[1].bar(xx + (i - 0.5) * 0.38, s.mean_prob, 0.38, label=lab, **kw)
    axes[1].axhline(agg.prevalence.iloc[0], color="0", ls=":", lw=1, label="test prevalence")
    for a in axes:
        a.set_xticks(xx, ["none", "class\nweights", "under-\nsampling", "SMOTE"])
    axes[0].set_ylabel("average precision, test")
    axes[0].set_title("(a) ranking quality")
    axes[1].set_ylabel("mean predicted probability")
    axes[1].set_title("(b) probability scale")
    for a_ in axes:      # framed legends: the hatched and grey keys stay readable in print
        a_.legend(frameon=True, framealpha=1, edgecolor="0.6", fontsize=6)
    F.save(fig, out, "fig_d2")
    dump_json({"summary": agg.to_dict(orient="records")}, out / "summary.json")
    write_manifest(out, script="scripts/d2_imbalance.py", config={"seeds": args.seeds, "budget": BUDGET, "smote_k": 5},
                   data_files=[DATA / "elliptic_txs_classes.csv", DATA / "elliptic_txs_features.csv"])
    print(agg.to_string())


if __name__ == "__main__":
    main()
