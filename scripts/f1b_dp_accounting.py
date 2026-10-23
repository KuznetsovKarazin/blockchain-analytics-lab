"""
F1b - What the privacy numbers of F1 do and do not certify (no retraining).

F1 adds Gaussian noise z*C to the sum of client updates clipped to norm C and reports
an RDP epsilon for 100 rounds (delta = 1e-5, no subsampling). That figure is a
conditional accountant value, not an end-to-end guarantee of the implemented pipeline:
  * feature standardisation uses statistics of the pooled training data, and the
    clipping bound C is the median update norm of a non-private 20-round pilot on the
    same clients; neither access is accounted for;
  * the checkpoint is selected on validation steps every 5 rounds;
  * the accountant assumes add/remove-one-client adjacency (sensitivity C). Under
    replace-one-client adjacency the sensitivity of the clipped sum is 2C, so the
    same noise gives the epsilon of noise multiplier z/2.
The unit of privacy is a client (institution); one institution holds many
transactions, so the figures say nothing directly about a single transaction or
customer beyond what client-level protection implies.

This script reads F1's dp_summary.csv and tabulates both adjacency conventions with the
same accountant (bclab.federated.rdp_epsilon); utility numbers are copied unchanged.

Outputs: results/federated/f1b_<stamp>/ (accounting.csv, summary.json)
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
import pandas as pd

from bclab.federated import rdp_epsilon
from bclab.repro import atomic_to_csv, dump_json, write_manifest

F1_DIR = Path("results/federated/f1_v1")
ROUNDS, DELTA = 100, 1e-5


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    out = Path(args.out or f"results/federated/f1b_{time.strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)
    src = F1_DIR / "dp_summary.csv"
    dp = pd.read_csv(src)
    dp["epsilon_add_remove"] = [rdp_epsilon(z, ROUNDS, DELTA) for z in dp.noise_mult]
    dp["epsilon_replace_one"] = [rdp_epsilon(z / 2, ROUNDS, DELTA) for z in dp.noise_mult]
    assert np.allclose(dp.epsilon_add_remove.replace(np.inf, -1), dp.epsilon.replace(np.inf, -1))
    acc = dp[["clients", "noise_mult", "clip", "epsilon_add_remove", "epsilon_replace_one", "ap", "ap_sd", "f1"]]
    atomic_to_csv(acc, out / "accounting.csv", index=False)
    dump_json({"rounds": ROUNDS, "delta": DELTA, "source": str(src),
               "status": "conditional accountant values; not an end-to-end DP guarantee of F1",
               "not_accounted": ["pooled standardisation statistics", "clip bound from a non-private pilot",
                                 "validation-based checkpoint selection"],
               "rows": acc.to_dict(orient="records")}, out / "summary.json")
    write_manifest(out, script="scripts/f1b_dp_accounting.py",
                   config={"f1_dir": str(F1_DIR), "rounds": ROUNDS, "delta": DELTA}, data_files=[src])
    print(acc.to_string())


if __name__ == "__main__":
    main()
