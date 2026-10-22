"""
S1 - Double-spend success probability under three race models.

Question: how much do the textbook confirmation counts depend on two modelling
choices that the Poisson/negative-binomial analysis fixes implicitly?
  (i)  time is continuous, so the attacker and the honest network never find a
       block in the same instant (independent players model with slots);
  (ii) the attacker never gives up (finite patience).

Outputs (results/security/s1_<stamp>/):
  slots.csv        success probability vs slot length relative to the block interval
  patience.csv     success probability vs give-up deficit
  min_conf.csv     smallest z with success probability < 1e-3 per model
  mc_check.csv     Monte Carlo check of the independent players model
  fig_s1.png/.eps/.pdf
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
import pandas as pd

from bclab import doublespend as ds
from bclab import figures as F
from bclab.repro import atomic_to_csv, dump_json, set_seed, write_manifest

QS = (0.1, 0.2, 0.3, 0.4)
ZS = range(1, 41)
SLOT_RATIOS = (0.0, 0.1, 0.5, 1.0, 2.0)     # slot length / mean block interval; 0 = continuous


def per_slot(q: float, r: float) -> tuple[float, float]:
    """Per-slot block probabilities when blocks arrive as Poisson processes and r = slot / interval."""
    return 1 - np.exp(-q * r), 1 - np.exp(-(1 - q) * r)


def prob(model: str, q: float, z: int, r: float = 0.0, give_up: int | None = None) -> float:
    if model == "exact":
        return ds.exact_catch_up(q, z)
    if model == "slots":
        if r == 0:
            return ds.exact_catch_up(q, z)
        a, b = per_slot(q, r)
        return ds.independent_players(a, b, z)
    if model == "patience":
        return ds.finite_patience(q, z, give_up)
    raise ValueError(model)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("--mc", type=int, default=400_000)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    set_seed(args.seed)
    out = Path(args.out or f"results/security/s1_{time.strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)

    rows = []
    for q in QS:
        for r in SLOT_RATIOS:
            for z in ZS:
                rows.append({"q": q, "slot_ratio": r, "z": z, "p_success": prob("slots", q, z, r)})
    slots = pd.DataFrame(rows)
    atomic_to_csv(slots, out / "slots.csv", index=False)

    rows = []
    for q in QS:
        for z in ZS:
            for extra in (1, 3, 10, None):
                g = None if extra is None else z + extra
                p = ds.exact_catch_up(q, z) if g is None else prob("patience", q, z, give_up=g)
                rows.append({"q": q, "z": z, "give_up": "never" if g is None else f"z+{extra}",
                             "p_success": p})
    pat = pd.DataFrame(rows)
    atomic_to_csv(pat, out / "patience.csv", index=False)

    rows = []
    for q in QS:
        for r in SLOT_RATIOS:
            s = slots[(slots.q == q) & (slots.slot_ratio == r)]
            ok = s[s.p_success < 1e-3]
            rows.append({"q": q, "model": "continuous" if r == 0 else f"slots r={r}",
                         "min_z": int(ok.z.min()) if len(ok) else None})
        for g in ("z+1", "z+3", "z+10"):
            s = pat[(pat.q == q) & (pat.give_up == g)]
            ok = s[s.p_success < 1e-3]
            rows.append({"q": q, "model": f"give up at {g}", "min_z": int(ok.z.min()) if len(ok) else None})
    mz = pd.DataFrame(rows)
    atomic_to_csv(mz, out / "min_conf.csv", index=False)

    rows = []
    for q, r, z in ((0.3, 1.0, 3), (0.3, 2.0, 3), (0.2, 1.0, 2), (0.4, 0.5, 6)):
        a, b = per_slot(q, r)
        sims = [ds.simulate_independent(a, b, z, args.mc, seed) for seed in range(3)]
        rows.append({"q": q, "slot_ratio": r, "z": z, "analytic": ds.independent_players(a, b, z),
                     "mc_mean": float(np.mean(sims)), "mc_sd": float(np.std(sims, ddof=1)),
                     "n_per_seed": args.mc, "seeds": 3})
    mc = pd.DataFrame(rows)
    atomic_to_csv(mc, out / "mc_check.csv", index=False)

    F.style()
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(6.5, 2.7))
    q = 0.3
    for i, r in enumerate((0.0, 1.0, 2.0)):
        s = slots[(slots.q == q) & (slots.slot_ratio == r) & (slots.z <= 30)]
        lab = "continuous time" if r == 0 else f"slot = {r:g} x block interval"
        axes[0].semilogy(s.z, s.p_success, color="0.0", ls=F.LINES[i], label=lab)
    axes[0].set_title(f"(a) attacker share q = {q}: slotted races")
    qgrid = np.round(np.arange(0.05, 0.451, 0.025), 3)
    curve = []
    for qq in qgrid:
        for r in (0.0, 1.0, 2.0):
            z = next((z for z in range(1, 400) if prob("slots", qq, z, r) < 1e-3), None)
            curve.append({"q": qq, "slot_ratio": r, "min_z": z})
    curve = pd.DataFrame(curve)
    atomic_to_csv(curve, out / "min_conf_curve.csv", index=False)
    for i, r in enumerate((0.0, 1.0, 2.0)):
        c = curve[curve.slot_ratio == r]
        axes[1].plot(c.q, c.min_z, color="0.0", ls=F.LINES[i], marker=F.MARKERS[i], ms=3,
                     label="continuous time" if r == 0 else f"slot = {r:g} x block interval")
    axes[1].set_yscale("log")
    axes[1].set_xlabel("attacker share q")
    axes[1].set_ylabel("confirmations for P < 0.001")
    axes[1].set_title("(b) confirmations needed vs attacker share")
    axes[1].legend(frameon=False)
    axes[0].axhline(1e-3, color="0.5", lw=0.8, ls=":")
    axes[0].set_xlabel("confirmations z")
    axes[0].legend(frameon=False)
    axes[0].set_ylabel("success probability")
    F.save(fig, out, "fig_s1")

    summary = {"min_conf": mz.to_dict(orient="records"), "mc_check": mc.to_dict(orient="records")}
    dump_json(summary, out / "summary.json")
    write_manifest(out, script="scripts/s1_double_spend.py",
                   config={"qs": QS, "zs": [min(ZS), max(ZS)], "slot_ratios": SLOT_RATIOS,
                           "mc": args.mc, "seed": args.seed})
    print(mz.pivot(index="model", columns="q", values="min_z"))
    print(mc)


if __name__ == "__main__":
    main()
