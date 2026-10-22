"""
M2 - A labelled stream: Elliptic test steps 35-49 replayed one step at a time.

A LightGBM model (the shared configuration) is trained on steps 1-30. Each test
step arrives as a batch; every transaction of the step (labelled or not) is
scored and may raise an alert. Precision and recall are measured on the
labelled transactions of the step. Labels of step t become available only after
a delay of DELAY steps (investigation time).

Alerting policies
  fixed       threshold maximising F1 on validation steps 31-34; never updated
  budget      the top 1% of the step's transactions by score (constant load)
  recal       threshold re-chosen after each step to maximise F1 on the most
              recent four steps whose labels have arrived
  retrain     model retrained after each step on all labelled steps whose
              labels have arrived (expanding window), threshold as in recal

Also: scoring latency of four model families on one CPU thread, for one
transaction at a time and for a batch of 1,000.

Outputs: results/monitoring/m2_<stamp>/
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score

from bal.data.elliptic import TEST_STEPS, TRAIN_STEPS, VAL_STEPS, load_elliptic
from bal.eval.metrics import threshold_at_val_f1
from bal.models.tabular import lightgbm, logreg, random_forest
from bclab import figures as F
from bclab.federated import MLP
from bclab.repro import atomic_to_csv, dump_json, set_seed, write_manifest

DATA = Path("data/raw/elliptic")
DELAY, RECENT, BUDGET = 2, 4, 0.01


def latency(models: dict, X: np.ndarray) -> list[dict]:
    rows = []
    for name, m in models.items():
        one = []
        for i in range(200):
            t0 = time.perf_counter()
            m(X[i:i + 1])
            one.append(time.perf_counter() - t0)
        t0 = time.perf_counter()
        for _ in range(5):
            m(X[:1000])
        batch = (time.perf_counter() - t0) / 5
        rows.append({"model": name, "single_ms_median": float(np.median(one) * 1e3),
                     "single_ms_p99": float(np.quantile(one, 0.99) * 1e3),
                     "batch1000_us_per_tx": float(batch / 1000 * 1e6)})
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    set_seed(0)
    out = Path(args.out or f"results/monitoring/m2_{time.strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)
    d = load_elliptic(DATA)
    X, y, step = d.X, d.y, d.step
    tr, va = d.mask(TRAIN_STEPS), d.mask(VAL_STEPS)
    base = lightgbm(seed=0).fit(X[tr], y[tr])
    thr_fixed = threshold_at_val_f1(y[va], base.predict_score(X[va]))

    scores = {"base": {}, "retrain": {}}
    rows = []
    retrain_model, retrain_thr = base, thr_fixed
    recal_thr = thr_fixed
    for t in TEST_STEPS:
        allm = step == t
        lab = allm & (y >= 0)
        s_all = base.predict_score(X[allm])
        s_lab = base.predict_score(X[lab])
        r_all = retrain_model.predict_score(X[allm])
        r_lab = retrain_model.predict_score(X[lab])
        scores["base"][t], scores["retrain"][t] = s_lab, r_lab
        k = max(1, int(round(BUDGET * allm.sum())))
        thr_budget = np.sort(s_all)[-k]
        for pol, thr, sa, sl in (("fixed", thr_fixed, s_all, s_lab), ("budget", thr_budget, s_all, s_lab),
                                 ("recal", recal_thr, s_all, s_lab), ("retrain", retrain_thr, r_all, r_lab)):
            pred = sl >= thr
            rows.append({"step": t, "policy": pol, "alerts_all": int((sa >= thr).sum()), "n_all": int(allm.sum()),
                         "alerts_labelled": int(pred.sum()), "n_labelled": int(lab.sum()), "pos": int(y[lab].sum()),
                         "tp": int((pred & (y[lab] == 1)).sum()),
                         "precision": precision_score(y[lab], pred, zero_division=0),
                         "recall": recall_score(y[lab], pred, zero_division=0) if y[lab].sum() else np.nan,
                         "threshold": float(thr)})
        # labels that have arrived after step t: steps <= t - DELAY + 1 ... (step t-DELAY+1 becomes known)
        known_upto = t - DELAY + 1
        recent = [s for s in range(max(35, known_upto - RECENT + 1), known_upto + 1) if s >= 35]
        if recent:
            yy = np.concatenate([y[(step == s) & (y >= 0)] for s in recent])
            if yy.sum() > 0:
                recal_thr = threshold_at_val_f1(yy, np.concatenate([scores["base"][s] for s in recent]))
        if known_upto >= 35:
            m_tr = (step <= known_upto) & (y >= 0) & ~np.isin(step, list(VAL_STEPS))
            retrain_model = lightgbm(seed=0).fit(X[m_tr], y[m_tr])
            if recent:
                yy = np.concatenate([y[(step == s) & (y >= 0)] for s in recent])
                ss = np.concatenate([retrain_model.predict_score(X[(step == s) & (y >= 0)]) for s in recent])
                # in-sample for the retrained model: optimistic, kept simple and stated in the text
                retrain_thr = threshold_at_val_f1(yy, ss) if yy.sum() else retrain_thr
        print(t, flush=True)
    st = pd.DataFrame(rows)
    atomic_to_csv(st, out / "per_step.csv", index=False)
    summ = []
    for pol, g in st.groupby("policy"):
        for part, rng_ in (("all", range(35, 50)), ("pre", range(35, 43)), ("post", range(43, 50))):
            h = g[g.step.isin(rng_)]
            tp, al, pos = h.tp.sum(), h.alerts_labelled.sum(), h.pos.sum()
            p_ = tp / al if al else 0.0
            r_ = tp / pos if pos else np.nan
            summ.append({"policy": pol, "part": part, "precision": p_, "recall": r_,
                         "f1": 2 * p_ * r_ / (p_ + r_) if p_ + r_ > 0 else 0.0,
                         "alerts_per_step_mean": float(h.alerts_all.mean()), "alerts_per_step_max": int(h.alerts_all.max())})
    summ = pd.DataFrame(summ)
    atomic_to_csv(summ, out / "policies.csv", index=False)

    # latency on one thread
    os.environ["BAL_N_JOBS"] = "1"
    Xs = X[tr][:5000]
    mods = {"logreg": logreg(seed=0).fit(X[tr], y[tr]), "rf": random_forest(seed=0).fit(X[tr], y[tr]),
            "lgbm": lightgbm(seed=0).fit(X[tr], y[tr])}
    for m in mods.values():
        if hasattr(m.est, "n_jobs"):
            m.est.set_params(n_jobs=1)
    mlp = MLP(X.shape[1], seed=0)
    mu, sd = X[tr].mean(0), X[tr].std(0) + 1e-6
    lat = latency({"logistic regression": mods["logreg"].predict_score, "random forest (500)": mods["rf"].predict_score,
                   "LightGBM (400)": mods["lgbm"].predict_score,
                   "MLP 165-64-1 (numpy)": lambda Z: mlp.score((Z - mu) / sd)}, Xs)
    lat = pd.DataFrame(lat)
    atomic_to_csv(lat, out / "latency.csv", index=False)

    F.style()
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(6.5, 2.7))
    for i, pol in enumerate(("fixed", "budget", "recal", "retrain")):
        g = st[st.policy == pol]
        axes[0].plot(g.step, g.recall, color="0" if i % 2 == 0 else "0.5", ls=F.LINES[i], marker=F.MARKERS[i],
                     ms=2.5, label=pol)
        axes[1].plot(g.step, g.precision, color="0" if i % 2 == 0 else "0.5", ls=F.LINES[i], marker=F.MARKERS[i],
                     ms=2.5, label=pol)
    for a in axes:
        a.axvline(42.5, color="0.6", ls=":", lw=0.8)
        a.set_xlabel("time step")
    axes[0].set_ylabel("recall")
    axes[0].set_title("(a) recall per step")
    axes[1].set_ylabel("precision")
    axes[1].set_title("(b) precision per step")
    axes[0].legend(frameon=False, fontsize=6)
    F.save(fig, out, "fig_m2")
    dump_json({"policies": summ.to_dict(orient="records"), "latency": lat.to_dict(orient="records"),
               "thr_fixed": thr_fixed, "delay": DELAY, "recent": RECENT, "budget": BUDGET}, out / "summary.json")
    write_manifest(out, script="scripts/m2_elliptic_stream.py",
                   config={"delay": DELAY, "recent": RECENT, "budget": BUDGET},
                   data_files=[DATA / "elliptic_txs_classes.csv", DATA / "elliptic_txs_features.csv"])
    print(summ.to_string())
    print(lat.to_string())


if __name__ == "__main__":
    main()
