"""
M1 - Monitoring a block stream without labels: threshold policies and alert load.

Data: Ethereum block headers 2023-01-01..2025-12-31 (AWS cache), replayed in
block order as a monitor would receive them. Monitored signals per block:
  log base fee, gas-used ratio (gas_used / gas_limit), transaction count.

Threshold policies, applied to each signal separately (upper tail; an alert is
raised when any signal crosses):
  fixed      99.9th percentile of January 2023, never updated
  rolling    robust z >= 6 against the trailing 7,200 blocks (about one day):
             median of those blocks and the median absolute deviation from that
             median, both over the same window (bclab.online.rolling_mad_z)
  ewma       z >= 6 against an exponentially weighted mean and variance of past
             blocks (half-life 1,800 blocks, about six hours; bclab.online.ewma_z)
  quantile   value above the 99.9th percentile of the trailing 7,200 blocks
             (a rate-controlling rule: about 7 crossings per signal per day
             if the recent past is representative)
Alert handling: raw alerts, and incidents = alerts merged when they are less than
25 blocks (about five minutes) apart.

January 2023 is calibration (fixed threshold) and warm-up (adaptive statistics);
all policies are evaluated on 2023-02-01..2025-12-31. Adaptive statistics use only
blocks before the scored block. A zero MAD or variance gives no score (no alert).

Reported: alerts and incidents per day, share of days with no alert, worst day,
and the per-block CPU cost of the online update for the ewma policy (O(1)) and
for a sliding-window median (O(window)), measured in a plain Python loop.

Outputs: results/monitoring/m1_<stamp>/
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
import pandas as pd

from bclab import figures as F
from bclab.aws import read_cached, write_input_index
from bclab.online import ewma_z as _ewma_z
from bclab.online import rolling_mad_z
from bclab.repro import atomic_to_csv, dump_json, set_seed, write_manifest

START, END = "2023-01-01", "2025-12-31"
EVAL_START = "2023-02-01"
WINDOW, HALF_LIFE, Z, MERGE = 7200, 1800, 6.0, 25


def signals(b: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame({"log_base_fee": np.log(b.base_fee_per_gas.astype(float).clip(lower=1)),
                         "gas_ratio": b.gas_used / b.gas_limit,
                         "tx_count": b.transaction_count.astype(float)}, index=b.index)


def rolling_z(x: pd.Series) -> pd.Series:
    return pd.Series(rolling_mad_z(x.to_numpy(), WINDOW), index=x.index)


def ewma_z(x: pd.Series) -> pd.Series:
    return pd.Series(_ewma_z(x.to_numpy(), HALF_LIFE), index=x.index)


def rolling_q(x: pd.Series) -> pd.Series:
    return x.rolling(WINDOW, min_periods=WINDOW // 2).quantile(0.999).shift(1)


def incidents(alert_idx: np.ndarray) -> np.ndarray:
    if len(alert_idx) == 0:
        return alert_idx
    starts = np.concatenate([[True], np.diff(alert_idx) >= MERGE])
    return alert_idx[starts]


def bench(x: np.ndarray, n: int = 50_000) -> dict:
    a = 1 - 0.5 ** (1 / HALF_LIFE)
    m, v = x[0], 0.0
    t0 = time.perf_counter()
    for xi in x[1:n]:
        d = xi - m
        z = d / (v ** 0.5 + 1e-12)
        m += a * d
        v = (1 - a) * v + a * d * d      # same recursion as bclab.online.ewma_z
    t_ewma = (time.perf_counter() - t0) / (n - 1)
    buf = x[:WINDOW].copy()
    t0 = time.perf_counter()
    for i, xi in enumerate(x[WINDOW:WINDOW + n // 10]):
        med = np.median(buf)
        mad = np.median(np.abs(buf - med))
        z = (xi - med) / (1.4826 * mad + 1e-12)
        buf[i % WINDOW] = xi
    t_win = (time.perf_counter() - t0) / (n // 10)
    return {"ewma_us_per_block": t_ewma * 1e6, "window_median_us_per_block": t_win * 1e6, "z_last": float(z)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    set_seed(0)
    out = Path(args.out or f"results/monitoring/m1_{time.strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)
    b, bfiles = read_cached("eth", "blocks", START, END,
                       ["number", "timestamp", "transaction_count", "gas_used", "gas_limit", "base_fee_per_gas"])
    b = b.drop_duplicates("number").sort_values("number").reset_index(drop=True)
    S = signals(b)
    day = b.timestamp.dt.normalize()
    jan = (b.timestamp < EVAL_START).to_numpy()

    ev = ~jan                                     # evaluation blocks
    Zr = S.apply(rolling_z)
    Ze = S.apply(ewma_z)
    Q = S.apply(rolling_q)
    fixed_thr = S[jan].quantile(0.999)
    per_col = {"fixed": S > fixed_thr, "rolling": Zr >= Z, "ewma": Ze >= Z, "quantile": S > Q}
    flags = {pol: f.any(axis=1).to_numpy() & ev for pol, f in per_col.items()}
    per_signal = {pol: {c: int((f[c].to_numpy() & ev).sum()) for c in S.columns} for pol, f in per_col.items()}

    days = pd.Index(day[ev].unique())
    daily, summ = [], []
    for pol, f in flags.items():
        idx = np.flatnonzero(f)
        inc = incidents(idx)
        a = pd.Series(1, index=day.iloc[idx]).groupby(level=0).size().reindex(days, fill_value=0)
        i_ = pd.Series(1, index=day.iloc[inc]).groupby(level=0).size().reindex(days, fill_value=0)
        daily.append(pd.DataFrame({"day": days, "policy": pol, "alerts": a.values, "incidents": i_.values}))
        yr = pd.Series(a.values, index=days).groupby(days.year).mean()
        summ.append({"policy": pol, "alerts": int(len(idx)), "incidents": int(len(inc)),
                     "alerts_per_day_mean": float(a.mean()), "alerts_per_day_median": float(a.median()),
                     "incidents_per_day_mean": float(i_.mean()), "incidents_per_day_p99": float(i_.quantile(0.99)),
                     "days_without_alert": float((a == 0).mean()), "worst_day": str(a.idxmax().date()),
                     "worst_day_alerts": int(a.max()), "alerts_per_day_by_year": {int(k): float(v) for k, v in yr.items()},
                     "per_signal_alerts": per_signal[pol]})
    daily = pd.concat(daily, ignore_index=True)
    atomic_to_csv(daily, out / "daily_alerts.csv", index=False)
    summ = pd.DataFrame(summ)
    atomic_to_csv(summ.drop(columns=["alerts_per_day_by_year", "per_signal_alerts"]), out / "policies.csv", index=False)
    cost = bench(S.log_base_fee.to_numpy())

    F.style()
    import matplotlib.dates as mdates
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(6.5, 2.7))
    ax = axes[0]
    bf = pd.Series(np.exp(S.log_base_fee.values) / 1e9, index=b.timestamp).resample("1D").median()
    ax.semilogy(bf.index, bf.values, color="0", lw=0.7)
    ax.axhline(np.exp(fixed_thr.log_base_fee) / 1e9, color="0.5", ls="--", lw=0.8, label="fixed threshold (Jan 2023)")
    ax.set_ylabel("daily median base fee, gwei")
    ax.set_title("(a) the monitored signal drifts")
    ax.legend(frameon=False, fontsize=6)
    ax = axes[1]
    for i, pol in enumerate(flags):
        d_ = daily[daily.policy == pol].set_index("day").incidents.rolling(30).mean()
        ax.semilogy(d_.index, d_.values + 1e-2, color="0" if i % 2 == 0 else "0.5", ls=F.LINES[i % len(F.LINES)], lw=0.8, label=pol)
    ax.set_ylabel("incidents per day (30-day mean)")
    ax.set_title("(b) alert load by threshold policy")
    from matplotlib.ticker import FixedLocator, NullFormatter, NullLocator, ScalarFormatter
    ax.yaxis.set_major_locator(FixedLocator([2, 5, 10, 20, 50, 100]))
    ax.yaxis.set_major_formatter(ScalarFormatter())
    ax.yaxis.set_minor_locator(NullLocator())
    ax.yaxis.set_minor_formatter(NullFormatter())
    fig.subplots_adjust(wspace=0.38)
    ax.legend(frameon=False, fontsize=6)
    for a_ in axes:
        a_.xaxis.set_major_locator(mdates.YearLocator())
        a_.xaxis.set_major_formatter(mdates.DateFormatter("%Y"))
    F.save(fig, out, "fig_m1")
    dump_json({"blocks": len(b), "policies": summ.to_dict(orient="records"), "cost": cost,
               "fixed_thresholds": fixed_thr.to_dict()}, out / "summary.json")
    write_input_index(out, "eth", "blocks", bfiles)
    write_manifest(out, script="scripts/m1_block_stream.py", data_sets={"eth_blocks": bfiles},
                   config={"start": START, "eval_start": EVAL_START, "end": END, "window": WINDOW, "half_life": HALF_LIFE, "z": Z, "merge": MERGE})
    print(summ.to_string())
    print(cost)


if __name__ == "__main__":
    main()
