"""
A1b - Prevalence versus the expected AP of a random score (no training).

The prevalence is the population no-skill reference of the precision-recall curve. On
a finite sample the expected average precision of a random ranking is higher, and the
gap grows as positives get fewer. This script estimates the finite-sample random AP by
averaging AP over random scores, on the labelled Elliptic test steps 35-49 and on
subsamples with few illicit transactions.

Outputs: results/fundamentals/a1b_<stamp>/ (random_ap.csv, summary.json)
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

from bclab.repro import atomic_to_csv, dump_json, set_seed, write_manifest

DATA = Path("data/raw/elliptic")
TEST_STEPS = range(35, 50)
N_PERM = 300


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    set_seed(0)
    out = Path(args.out or f"results/fundamentals/a1b_{time.strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)
    steps = pd.read_csv(DATA / "elliptic_txs_features.csv", header=None, usecols=[0, 1], names=["txId", "step"])
    cls = pd.read_csv(DATA / "elliptic_txs_classes.csv")
    d = steps.merge(cls, on="txId")
    d = d[d.step.isin(TEST_STEPS) & (d["class"].astype(str) != "unknown")]
    y = (d["class"].astype(str) == "1").to_numpy(int)
    rng = np.random.default_rng(0)
    neg = np.flatnonzero(y == 0)
    rows = []
    for n_pos in (int(y.sum()), 100, 20, 5):
        yy = np.r_[np.ones(n_pos), np.zeros(len(neg))]
        aps = [average_precision_score(yy, rng.random(len(yy))) for _ in range(N_PERM)]
        rows.append({"illicit": n_pos, "licit": len(neg), "prevalence": n_pos / len(yy),
                     "random_ap_mean": float(np.mean(aps)), "random_ap_sd": float(np.std(aps)),
                     "n_permutations": N_PERM})
    res = pd.DataFrame(rows)
    atomic_to_csv(res, out / "random_ap.csv", index=False)
    dump_json({"rows": rows, "test_steps": "35-49"}, out / "summary.json")
    write_manifest(out, script="scripts/a1b_random_ap.py", config={"test_steps": "35-49", "n_perm": N_PERM, "seed": 0},
                   data_files=[DATA / "elliptic_txs_features.csv", DATA / "elliptic_txs_classes.csv"])
    print(res.to_string())


if __name__ == "__main__":
    main()
