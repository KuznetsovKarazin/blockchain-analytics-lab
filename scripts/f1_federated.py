"""
F1 - Federated detection on Elliptic: what does pooling, partitioning and privacy cost?

Setting. The labelled training transactions (steps 1-30) are split across K
simulated institutions. Every regime trains the same one-hidden-layer MLP
(64 ReLU units, SGD, lr 0.01, batch 128) for up to 100 passes over the data
(epochs, or rounds of one local epoch), evaluated every 5 passes; the reported
model is the checkpoint with the best validation AP (steps 31-34), and the AP at
a fixed 20 passes is kept as well.
Features are standardised with training-period statistics and clipped to [-10, 10]
(in a real federation these statistics would themselves be aggregated).

Regimes
  central      all training data pooled
  local        each institution trains alone (mean / min / max over institutions)
  fedavg       FedAvg, full participation, 1 local epoch per round
Partitions (K = 10)
  iid          random split
  time         institution k holds time steps 3k+1..3k+3 (different eras)
  label        Dirichlet(0.5) label skew: illicit share differs by institution
Privacy
  dp           client-level DP-FedAvg, 100 rounds: clip each update to C (median
               update norm of a 20-round non-private pilot), Gaussian noise
               z*C on the sum; K = 10 and K = 100 (iid); epsilon by RDP, no
               subsampling amplification, delta = 1e-5
  secagg       pairwise masking: time per client and exactness vs K
Validation-only selection: thresholds (F1) on steps 31-34; test 35-49.

Outputs: results/federated/f1_<stamp>/ (curves.csv, regimes.csv, dp.csv, secagg.csv,
summary.json, fig_f1.*)
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, f1_score

from bal.data.elliptic import POST_SHUTDOWN, PRE_SHUTDOWN, TEST_STEPS, TRAIN_STEPS, VAL_STEPS, load_elliptic
from bal.eval.metrics import threshold_at_val_f1
from bclab import figures as F
from bclab.federated import MLP, fedavg, masked_sum, rdp_epsilon
from bclab.repro import atomic_to_csv, dump_json, set_seed, write_manifest

DATA = Path("data/raw/elliptic")
LR, BATCH, PASSES, K = 0.01, 128, 20, 10
CURVE_LEN, EVERY = 100, 5
DP_ROUNDS = 100


def partition(kind, idx, y, step, k, rng):
    if kind == "iid":
        return np.array_split(rng.permutation(idx), k)
    if kind == "time":
        return [idx[(step[idx] - 1) // 3 == c] for c in range(k)]
    if kind == "label":
        parts = [[] for _ in range(k)]
        for cls in (0, 1):
            ii = rng.permutation(idx[y[idx] == cls])
            share = rng.dirichlet(np.full(k, 0.5))
            cuts = (np.cumsum(share)[:-1] * len(ii)).astype(int)
            for c, chunk in enumerate(np.split(ii, cuts)):
                parts[c].extend(chunk)
        return [np.array(sorted(p)) for p in parts]
    raise ValueError(kind)


class Ctx:
    def __init__(self):
        d = load_elliptic(DATA)
        self.d = d
        self.tr, self.va, self.te = d.mask(TRAIN_STEPS), d.mask(VAL_STEPS), d.mask(TEST_STEPS)
        mu, sd = d.X[self.tr].mean(0), d.X[self.tr].std(0) + 1e-6
        self.X = np.clip((d.X - mu) / sd, -10, 10).astype(np.float64)
        self.pre = np.isin(d.step[self.te], list(PRE_SHUTDOWN))
        self.post = np.isin(d.step[self.te], list(POST_SHUTDOWN))

    def evaluate(self, model):
        d, X = self.d, self.X
        s_va, s_te = model.score(X[self.va]), model.score(X[self.te])
        y_te = d.y[self.te]
        thr = threshold_at_val_f1(d.y[self.va], s_va)
        return {"ap_val": average_precision_score(d.y[self.va], s_va),
                "ap": average_precision_score(y_te, s_te),
                "ap_pre": average_precision_score(y_te[self.pre], s_te[self.pre]),
                "ap_post": average_precision_score(y_te[self.post], s_te[self.post]),
                "f1": f1_score(y_te, s_te >= thr, zero_division=0)}


def select(cur):
    """Best-validation checkpoint, plus the test AP at the fixed budget of PASSES."""
    best = max(cur, key=lambda r: r["ap_val"])
    fixed = next(r for r in cur if r["pass"] == PASSES)
    return [{**best, "best_pass": best["pass"], "ap_fixed": fixed["ap"]}]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("--seeds", type=int, default=3)
    args = ap.parse_args()
    out = Path(args.out or f"results/federated/f1_{time.strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)
    c = Ctx()
    d, X = c.d, c.X
    tr_idx = np.flatnonzero(c.tr)
    curves, regimes, parts_info = [], [], []

    for seed in range(args.seeds):
        set_seed(seed)
        # central, with learning curve (validation and test AP per pass)
        rng = np.random.default_rng(seed)
        m = MLP(X.shape[1], seed=seed)
        cur = []
        for ep in range(CURVE_LEN):
            m.sgd(X[tr_idx], d.y[tr_idx], 1, LR, BATCH, rng)
            if (ep + 1) % EVERY == 0:
                cur.append({"regime": "central", "partition": "-", "seed": seed, "pass": ep + 1, **c.evaluate(m)})
        curves += cur
        regimes += select(cur)

        for kind in ("iid", "time", "label"):
            prng = np.random.default_rng(1000 + seed)
            parts = partition(kind, tr_idx, d.y, d.step, K, prng)
            for i, p in enumerate(parts):
                parts_info.append({"partition": kind, "seed": seed, "client": i, "n": len(p),
                                   "n_illicit": int(d.y[p].sum()),
                                   "illicit_share": float(d.y[p].mean()) if len(p) else np.nan})
            # local only
            for i, p in enumerate(parts):
                if d.y[p].sum() == 0 or len(p) < 50:
                    continue
                rng = np.random.default_rng(seed * 100 + i)
                lm = MLP(X.shape[1], seed=seed)
                cur = []
                for ep in range(CURVE_LEN):
                    lm.sgd(X[p], d.y[p], 1, LR, BATCH, rng)
                    if (ep + 1) % EVERY == 0:
                        cur.append({"regime": "local", "partition": kind, "seed": seed, "client": i,
                                    "pass": ep + 1, **c.evaluate(lm)})
                regimes += select(cur)
            # FedAvg with curve
            clients = [(X[p], d.y[p].astype(float)) for p in parts]

            cur = []

            def cb(t, g, kind=kind, seed=seed, cur=cur):
                if (t + 1) % EVERY == 0:
                    cur.append({"regime": "fedavg", "partition": kind, "seed": seed, "pass": t + 1, **c.evaluate(g)})
            fedavg(clients, X.shape[1], CURVE_LEN, 1, LR, BATCH, seed, callback=cb)
            curves += cur
            regimes += select(cur)
            print(seed, kind, "done", flush=True)

    curves = pd.DataFrame(curves)
    regimes = pd.DataFrame(regimes)
    atomic_to_csv(curves, out / "curves.csv", index=False)
    atomic_to_csv(regimes, out / "regimes.csv", index=False)
    atomic_to_csv(pd.DataFrame(parts_info), out / "partitions.csv", index=False)
    reg_sum = (regimes.groupby(["regime", "partition"])
               .agg(n=("ap", "size"), ap=("ap", "mean"), ap_sd=("ap", "std"), ap_min=("ap", "min"),
                    ap_max=("ap", "max"), ap_pre=("ap_pre", "mean"), ap_post=("ap_post", "mean"),
                    f1=("f1", "mean"), ap_val=("ap_val", "mean"), ap_fixed=("ap_fixed", "mean"),
                    best_pass=("best_pass", "median"))
               .reset_index())
    atomic_to_csv(reg_sum, out / "regimes_summary.csv", index=False)

    # client-level DP on iid partitions; C from a non-private pilot (median update norm)
    dp_rows = []
    for k in (10, 100):
        prng = np.random.default_rng(7)
        parts = partition("iid", tr_idx, d.y, d.step, k, prng)
        clients = [(X[p], d.y[p].astype(float)) for p in parts]
        _, norms = fedavg(clients, X.shape[1], 20, 1, LR, BATCH, 0)
        clip = float(np.median(norms))
        for z in (0.0, 0.5, 1.0, 2.0, 4.0):
            for seed in range(args.seeds):
                cur = []

                def cb(t, g, cur=cur):
                    if (t + 1) % EVERY == 0:
                        cur.append({"pass": t + 1, **c.evaluate(g)})
                fedavg(clients, X.shape[1], DP_ROUNDS, 1, LR, BATCH, seed, clip=clip, noise_mult=z, callback=cb)
                best = max(cur, key=lambda r: r["ap_val"])
                dp_rows.append({"clients": k, "clip": clip, "noise_mult": z, "seed": seed, "rounds": DP_ROUNDS,
                                "epsilon": rdp_epsilon(z, DP_ROUNDS), "noise_sd_on_mean": z * clip / k,
                                "best_pass": best["pass"], **{kk: v for kk, v in best.items() if kk != "pass"}})
            print("dp", k, z, flush=True)
    dp = pd.DataFrame(dp_rows)
    atomic_to_csv(dp, out / "dp.csv", index=False)
    dp_sum = (dp.groupby(["clients", "noise_mult"])
              .agg(epsilon=("epsilon", "first"), clip=("clip", "first"), noise_sd_on_mean=("noise_sd_on_mean", "first"),
                   ap=("ap", "mean"), ap_sd=("ap", "std"), f1=("f1", "mean"))
              .reset_index())
    atomic_to_csv(dp_sum, out / "dp_summary.csv", index=False)

    # secure aggregation by pairwise masking
    dim = MLP(X.shape[1]).theta.size
    sa_rows = []
    rng = np.random.default_rng(0)
    for k in (5, 10, 20, 50, 100):
        v = rng.normal(0, 0.05, (k, dim))
        agg, t_client, ups = masked_sum(v, seed=k)
        err = np.abs(agg - v.sum(0)).max()
        corr = float(np.corrcoef(ups[0].astype(float), v[0])[0, 1])
        t0 = time.perf_counter()
        _ = v.sum(0)
        t_plain = time.perf_counter() - t0
        sa_rows.append({"clients": k, "params": dim, "upload_bytes": dim * 4,
                        "mask_seconds_per_client": t_client, "plain_sum_seconds": t_plain,
                        "max_abs_error": err, "corr_upload_vs_update": corr})
    sa = pd.DataFrame(sa_rows)
    atomic_to_csv(sa, out / "secagg.csv", index=False)

    F.style()
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(6.5, 2.7))
    cm = curves[curves.regime == "central"].groupby("pass")[["ap_val", "ap"]].mean()
    axes[0].plot(cm.index, cm.ap_val, color="0", ls=F.LINES[1], label="central, validation 31-34")
    axes[0].plot(cm.index, cm.ap, color="0", ls=F.LINES[0], label="central, test 35-49")
    for i, kind in enumerate(("iid", "time", "label")):
        fm = curves[(curves.regime == "fedavg") & (curves.partition == kind)].groupby("pass")["ap"].mean()
        axes[0].plot(fm.index, fm, color="0.55", ls=F.LINES[i], label=f"FedAvg {kind}, test")
    axes[0].axvline(PASSES, color="0.7", lw=0.8, ls=":")
    axes[0].set_xlim(0, CURVE_LEN)
    axes[0].set_xlabel("passes over the data (epochs or rounds)")
    axes[0].set_ylabel("average precision")
    axes[0].set_title("(a) learning curves")
    axes[0].legend(frameon=False, fontsize=6)
    for i, k in enumerate((10, 100)):
        s = dp_sum[(dp_sum.clients == k) & (dp_sum.noise_mult > 0)]
        axes[1].errorbar(s.epsilon, s.ap, yerr=s.ap_sd, color="0", ls=F.LINES[i], marker=F.MARKERS[i],
                         ms=3, capsize=2, label=f"{k} institutions")
        base = dp_sum[(dp_sum.clients == k) & (dp_sum.noise_mult == 0)].ap.iloc[0]
        axes[1].axhline(base, color="0.6", ls=F.LINES[i], lw=0.8)
    axes[1].set_xscale("log")
    eps_ticks = sorted(dp_sum.loc[dp_sum.noise_mult > 0, "epsilon"].unique())
    axes[1].set_xticks(eps_ticks, [f"{e:.0f}" for e in eps_ticks])
    axes[1].minorticks_off()
    fig.subplots_adjust(wspace=0.35)
    axes[1].set_xlabel(f"client-level epsilon (delta = 1e-5, {DP_ROUNDS} rounds)")
    axes[1].set_ylabel("average precision, test")
    axes[1].set_title("(b) cost of differential privacy")
    axes[1].legend(frameon=False)
    F.save(fig, out, "fig_f1")

    summary = {"regimes": reg_sum.to_dict(orient="records"), "dp": dp_sum.to_dict(orient="records"),
               "secagg": sa.to_dict(orient="records"),
               "config": {"lr": LR, "batch": BATCH, "passes": PASSES, "K": K, "hidden": 64,
                          "curve_len": CURVE_LEN, "every": EVERY, "dp_rounds": DP_ROUNDS}}
    dump_json(summary, out / "summary.json")
    write_manifest(out, script="scripts/f1_federated.py",
                   config={"seeds": args.seeds, "lr": LR, "batch": BATCH, "passes": PASSES, "K": K,
                           "curve_len": CURVE_LEN, "every": EVERY, "dp_rounds": DP_ROUNDS,
                           "dirichlet_alpha": 0.5, "delta": 1e-5},
                   data_files=[DATA / "elliptic_txs_classes.csv", DATA / "elliptic_txs_features.csv"])
    print(reg_sum.to_string())
    print(dp_sum.to_string())
    print(sa.to_string())


if __name__ == "__main__":
    main()
