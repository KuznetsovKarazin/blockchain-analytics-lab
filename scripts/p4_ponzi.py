"""
P4 - Case study: Ponzi-scheme contracts on Ethereum from bytecode, and how the
evaluation split decides the answer.

Data
  * deployed bytecode of all contracts created 2015-07-30..2017-12-31 (AWS cache)
  * 184 addresses of Ponzi contracts collected by Bartoletti et al. (ethereum-ponzi
    repository, pinned commit; GPL-3.0, used locally and not redistributed)
Unlabelled contracts are treated as negatives: the setting is positive-unlabelled,
so "precision" here is a lower bound if unlisted Ponzi contracts exist.

Features: relative frequency of each opcode family (PUSHn, DUPn, SWAPn, LOGn
collapsed) in the linear disassembly of the deployed code, plus log code length.
Model: random forest (500 trees, balanced subsample weights).

Sample: all Ponzi addresses + 20,000 non-Ponzi addresses drawn at random from
the population of contract addresses (so code duplicates appear as often as they
do on chain). Evaluation by 5-fold cross-validation, three repetitions, with
three ways of forming folds:
  random    stratified by label, ignoring code identity
  exact     grouped by code hash after removing the compiler metadata trailer
  skeleton  grouped by opcode sequence without PUSH operands (near-clones)
plus a temporal split: train on contracts created before 2017-01-01, test on 2017.

Outputs: results/patterns/p4_<stamp>/
"""

from __future__ import annotations

import argparse
import hashlib
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import GroupKFold, StratifiedKFold

from bclab import evm
from bclab import figures as F
from bclab.aws import cache_dir
from bclab.repro import atomic_to_csv, dump_json, set_seed, write_manifest

PONZI = Path("data/raw/ethereum-ponzi/ponzi-addresses.csv")
N_NEG = 20_000
SPLIT_DATE = pd.Timestamp("2017-01-01")


def featurise(code: str) -> np.ndarray:
    ops = [evm.family(o) for o in evm.opcodes(evm.strip_metadata(code))]
    v = np.zeros(len(evm.VOCAB) + 1)
    if ops:
        idx = {k: i for i, k in enumerate(evm.VOCAB)}
        for o in ops:
            v[idx[o]] += 1
        v[:-1] /= len(ops)
    v[-1] = np.log1p(len(ops))
    return v


def rf(seed):
    return RandomForestClassifier(n_estimators=500, class_weight="balanced_subsample", n_jobs=4, random_state=seed)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("--repeats", type=int, default=3)
    args = ap.parse_args()
    set_seed(0)
    out = Path(args.out or f"results/patterns/p4_{time.strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)

    # read day by day and keep one copy of each distinct bytecode (memory: ~4M rows,
    # but only tens of thousands of distinct codes)
    files = sorted(cache_dir("eth", "contracts").glob("*.parquet"))
    parts, code_of = [], {}
    for f in files:
        t = pd.read_parquet(f, columns=["address", "bytecode", "block_timestamp"])
        h = t.bytecode.map(lambda c: hashlib.sha1(c.encode()).hexdigest())
        for hh, c in zip(h, t.bytecode):
            code_of.setdefault(hh, c)
        parts.append(pd.DataFrame({"address": t.address, "code": h, "block_timestamp": t.block_timestamp}))
    df = pd.concat(parts, ignore_index=True)
    del parts
    n_rows = len(df)
    df["address"] = df.address.str.lower()
    df = df.sort_values("block_timestamp").drop_duplicates("address")
    pz = pd.read_csv(PONZI, header=None, names=["address", "name"])
    pz["address"] = pz.address.str.lower()
    df["y"] = df.address.isin(set(pz.address)).astype(int)
    pop = {"rows": n_rows, "addresses": len(df), "duplicate_rows": n_rows - len(df),
           "ponzi_listed": len(pz), "ponzi_unique": pz.address.nunique(), "ponzi_found": int(df.y.sum())}

    rng = np.random.default_rng(0)
    neg = df[df.y == 0].sample(N_NEG, random_state=0)
    smp = pd.concat([df[df.y == 1], neg], ignore_index=True)
    smp["bytecode"] = smp.code.map(code_of)
    codes = smp.bytecode.unique()
    feat = {c: featurise(c) for c in codes}
    exact = {c: hashlib.sha1(evm.strip_metadata(c).encode()).hexdigest() for c in codes}
    skel = {c: evm.skeleton(c) for c in codes}
    X = np.vstack([feat[c] for c in smp.bytecode])
    y = smp.y.to_numpy()
    g_exact = smp.bytecode.map(exact).to_numpy()
    g_skel = smp.bytecode.map(skel).to_numpy()
    pos = smp[smp.y == 1]
    pop.update({"ponzi_distinct_exact_codes": int(pd.Series(g_exact[y == 1]).nunique()),
                "ponzi_distinct_skeletons": int(pd.Series(g_skel[y == 1]).nunique()),
                "sample_distinct_exact_codes": int(pd.Series(g_exact).nunique()),
                "population_distinct_raw_codes": int(df.code.nunique()),
                "ponzi_by_year": pos.block_timestamp.dt.year.value_counts().sort_index().to_dict(),
                "neg_codes_shared_with_ponzi": int(np.isin(g_exact[y == 0], g_exact[y == 1]).sum())})
    print(pop, flush=True)

    rows = []
    for rep in range(args.repeats):
        for scheme in ("random", "exact", "skeleton"):
            if scheme == "random":
                folds = StratifiedKFold(5, shuffle=True, random_state=rep).split(X, y)
            else:
                groups = g_exact if scheme == "exact" else g_skel
                # shuffle group order per repetition so that folds differ across repeats
                uniq = pd.unique(groups)
                perm = {gname: i for i, gname in enumerate(rng.permutation(uniq))}
                folds = GroupKFold(5).split(X, y, groups=np.array([perm[gname] for gname in groups]))
            for k, (tr, te) in enumerate(folds):
                if y[te].sum() == 0:
                    continue
                m = rf(rep).fit(X[tr], y[tr])
                s = m.predict_proba(X[te])[:, 1]
                rows.append({"repeat": rep, "scheme": scheme, "fold": k, "test_pos": int(y[te].sum()),
                             "test_n": len(te), "ap": average_precision_score(y[te], s),
                             "roc_auc": roc_auc_score(y[te], s),
                             "test_pos_with_exact_twin_in_train": int(np.isin(g_exact[te][y[te] == 1],
                                                                             g_exact[tr][y[tr] == 1]).sum())})
            print(rep, scheme, flush=True)
    cv = pd.DataFrame(rows)
    atomic_to_csv(cv, out / "cv_folds.csv", index=False)
    cv_sum = (cv.groupby("scheme").agg(ap=("ap", "mean"), ap_sd=("ap", "std"), roc_auc=("roc_auc", "mean"),
                                       twin_share=("test_pos_with_exact_twin_in_train", "sum"),
                                       test_pos=("test_pos", "sum"))
              .reset_index())
    cv_sum["twin_share"] = cv_sum.twin_share / cv_sum.test_pos
    atomic_to_csv(cv_sum, out / "cv_summary.csv", index=False)

    # temporal split
    t_tr = (smp.block_timestamp < SPLIT_DATE).to_numpy()
    tmp = []
    for rep in range(args.repeats):
        m = rf(rep).fit(X[t_tr], y[t_tr])
        s = m.predict_proba(X[~t_tr])[:, 1]
        k = int(y[~t_tr].sum())
        top = np.argsort(-s)[:k]
        tmp.append({"repeat": rep, "train_pos": int(y[t_tr].sum()), "test_pos": k, "test_n": int((~t_tr).sum()),
                    "ap": average_precision_score(y[~t_tr], s), "roc_auc": roc_auc_score(y[~t_tr], s),
                    "precision_at_k_eq_pos": float(y[~t_tr][top].mean()),
                    "test_pos_with_exact_twin_in_train": int(np.isin(g_exact[~t_tr][y[~t_tr] == 1],
                                                                    g_exact[t_tr][y[t_tr] == 1]).sum())})
    tmp = pd.DataFrame(tmp)
    atomic_to_csv(tmp, out / "temporal.csv", index=False)
    imp = pd.Series(rf(0).fit(X, y).feature_importances_, index=evm.VOCAB + ["log_length"]).sort_values(ascending=False)
    atomic_to_csv(imp.head(15).rename("importance").rename_axis("feature").reset_index(), out / "importance_top.csv",
                  index=False)

    F.style()
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(3.4, 2.6))
    order = ["random", "exact", "skeleton"]
    s_ = cv_sum.set_index("scheme").loc[order]
    xx = np.arange(4)
    vals = list(s_.ap) + [tmp.ap.mean()]
    errs = list(s_.ap_sd) + [tmp.ap.std()]
    ax.bar(xx, vals, yerr=errs, capsize=2, color=["0.85", "0.6", "0.35", "0.1"], edgecolor="0")
    ax.axhline(y.mean(), color="0", ls=":", lw=1)
    ax.set_xticks(xx, ["random\nfolds", "grouped:\nexact code", "grouped:\nnear-clones", "temporal:\n<2017 / 2017"],
                  fontsize=7)
    ax.set_ylabel("average precision")
    ax.set_title("Ponzi detection from bytecode")
    F.save(fig, out, "fig_p4")
    dump_json({"population": pop, "cv": cv_sum.to_dict(orient="records"), "temporal": tmp.to_dict(orient="records"),
               "importance_top": imp.head(10).to_dict(), "sample_prevalence": float(y.mean())}, out / "summary.json")
    write_manifest(out, script="scripts/p4_ponzi.py",
                   config={"n_neg": N_NEG, "repeats": args.repeats, "split_date": str(SPLIT_DATE.date())},
                   data_files=[PONZI])
    print(cv_sum.to_string())
    print(tmp.to_string())
    print(imp.head(10))


if __name__ == "__main__":
    main()
