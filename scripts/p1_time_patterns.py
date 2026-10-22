"""
P1 - Time-based patterns in block-level activity: periodicity, seasonality, bursts.

Data: Ethereum and Bitcoin block headers 2023-01-01..2025-12-31 (AWS cache).
Series: Ethereum transactions per hour; Bitcoin transactions per day (a Bitcoin
hour holds about six blocks, too few for a stable count).

  (a) periodicity: periodogram of the de-trended hourly Ethereum series
      (log counts minus a centred 7-day rolling mean); strongest periods
  (b) seasonality: mean profile by hour of day (UTC) and by weekday
  (c) bursts: robust z-score of log counts against a trailing 28-day median
      and MAD (only past data, as a monitor would see it); bursts are runs with
      z >= 5; the same rule applied to Bitcoin daily counts

Outputs: results/patterns/p1_<stamp>/
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
import pandas as pd

from bclab import figures as F
from bclab.aws import read_cached
from bclab.repro import atomic_to_csv, dump_json, set_seed, write_manifest

START, END = "2023-01-01", "2025-12-31"
Z_BURST = 5.0


def robust_z(x: pd.Series, window: int) -> pd.Series:
    med = x.rolling(window, min_periods=window // 2).median().shift(1)
    mad = (x - med).abs().rolling(window, min_periods=window // 2).median().shift(1)
    return (x - med) / (1.4826 * mad.replace(0, np.nan))


def runs(flag: pd.Series) -> pd.DataFrame:
    f = flag.fillna(False).astype(bool)
    start = f & ~f.shift(1, fill_value=False)
    gid = start.cumsum()[f]
    return pd.DataFrame({"start": gid.index.to_series().groupby(gid.values).min().values,
                         "end": gid.index.to_series().groupby(gid.values).max().values,
                         "length": gid.groupby(gid.values).size().values})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    set_seed(0)
    out = Path(args.out or f"results/patterns/p1_{time.strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)

    eth, efiles = read_cached("eth", "blocks", START, END, ["number", "timestamp", "transaction_count"])
    eth = eth.drop_duplicates("number")
    h = eth.set_index("timestamp").transaction_count.resample("1h").sum()
    btc, bfiles = read_cached("btc", "blocks", START, END, ["number", "timestamp", "transaction_count"])
    btc = btc.drop_duplicates("number")
    dly = btc.set_index("timestamp").transaction_count.resample("1D").sum()

    # (a) periodogram on de-trended log counts
    lh = np.log(h.clip(lower=1))
    resid = (lh - lh.rolling(24 * 7, center=True, min_periods=24).mean()).dropna()
    x = resid.to_numpy() - resid.mean()
    pw = np.abs(np.fft.rfft(x)) ** 2
    fr = np.fft.rfftfreq(len(x), d=1.0)                   # cycles per hour
    per = pd.DataFrame({"period_h": 1 / fr[1:], "power": pw[1:] / pw[1:].sum()})
    per = per[per.period_h <= 24 * 14]
    top = per.sort_values("power", ascending=False).head(8)
    atomic_to_csv(top, out / "periodogram_top.csv", index=False)

    # (b) profiles (share of the overall mean)
    prof_h = (h.groupby(h.index.hour).mean() / h.mean()).rename("relative").rename_axis("hour_utc").reset_index()
    prof_w = (h.groupby(h.index.dayofweek).mean() / h.mean()).rename("relative").rename_axis("weekday").reset_index()
    atomic_to_csv(prof_h, out / "profile_hour.csv", index=False)
    atomic_to_csv(prof_w, out / "profile_weekday.csv", index=False)
    yearly = h.groupby(h.index.year).agg(["mean", "std"]).rename_axis("year").reset_index()
    atomic_to_csv(yearly, out / "eth_hourly_by_year.csv", index=False)

    # (c) bursts with a trailing window
    ze = robust_z(lh, 24 * 28)
    zb = robust_z(np.log(dly.clip(lower=1)), 28)
    be, bb = runs(ze >= Z_BURST), runs(zb >= Z_BURST)
    be["peak_z"] = [ze[s:e].max() for s, e in zip(be.start, be.end)]
    bb["peak_z"] = [zb[s:e].max() for s, e in zip(bb.start, bb.end)]
    be["peak_count"] = [h[s:e].max() for s, e in zip(be.start, be.end)]
    bb["peak_count"] = [dly[s:e].max() for s, e in zip(bb.start, bb.end)]
    atomic_to_csv(be.sort_values("peak_z", ascending=False), out / "bursts_eth_hourly.csv", index=False)
    atomic_to_csv(bb.sort_values("peak_z", ascending=False), out / "bursts_btc_daily.csv", index=False)
    lows = runs(ze <= -Z_BURST)
    atomic_to_csv(zb.sort_values(ascending=False).head(15).rename("z").rename_axis("day").reset_index(),
                  out / "btc_top_z_days.csv", index=False)
    atomic_to_csv(lows, out / "dips_eth_hourly.csv", index=False)

    F.style()
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(2, 2, figsize=(6.5, 4.6))
    ax = axes[0, 0]
    ax.semilogx(per.period_h, per.power, color="0", lw=0.6)
    for p_ in (24, 168):
        ax.axvline(p_, color="0.6", ls=":", lw=0.8)
    ax.set_xlabel("period, hours")
    ax.set_ylabel("share of variance")
    ax.set_title("(a) periodogram, Ethereum tx/hour")
    ax = axes[0, 1]
    ax.plot(prof_h.hour_utc, prof_h.relative, color="0", marker="o", ms=2.5)
    ax.set_xlabel("hour of day, UTC")
    ax.set_ylabel("relative to mean")
    ax.set_title("(b) daily profile, Ethereum")
    wd = ", ".join(f"{d} {v:.2f}" for d, v in zip(["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"], prof_w.relative))
    ax.text(0.33, 0.30, "weekday profile:\n" + wd.replace(", Th", ",\nTh"), transform=ax.transAxes,
            va="top", fontsize=6)
    ax = axes[1, 0]
    ax.plot(h.index, h.values / 1e3, color="0.6", lw=0.3)
    ax.plot(h.rolling(24 * 7).mean().index, h.rolling(24 * 7).mean().values / 1e3, color="0", lw=0.8)
    for s in be.start:
        ax.axvline(s, color="0", lw=0.4, ls=":")
    ax.set_ylabel("thousand tx per hour")
    ax.set_title("(c) Ethereum, bursts with z >= 5 marked")
    ax.tick_params(axis="x", labelsize=6)
    ax = axes[1, 1]
    ax.plot(dly.index, dly.values / 1e3, color="0", lw=0.6)
    for s in bb.start:
        ax.axvline(s, color="0.4", lw=0.5, ls=":")
    ax.set_ylabel("thousand tx per day")
    ax.set_title("(d) Bitcoin tx/day" + (", bursts marked" if len(bb) else f", no day with z >= {Z_BURST:g}"))
    ax.tick_params(axis="x", labelsize=6)
    import matplotlib.dates as mdates
    for ax in axes[1]:
        ax.xaxis.set_major_locator(mdates.YearLocator())
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y"))
    fig.tight_layout()
    F.save(fig, out, "fig_p1")

    summary = {"eth_hours": len(h), "btc_days": len(dly), "periodogram_top": top.to_dict(orient="records"),
               "hour_profile_min_max": [float(prof_h.relative.min()), float(prof_h.relative.max())],
               "weekday_profile": prof_w.relative.round(4).tolist(),
               "eth_bursts": len(be), "btc_bursts": len(bb), "eth_dips": len(lows), "btc_max_z": float(zb.max()),
               "eth_bursts_top": be.sort_values("peak_z", ascending=False).head(10).astype(str).to_dict(orient="records"),
               "btc_bursts_top": bb.sort_values("peak_z", ascending=False).head(10).astype(str).to_dict(orient="records"),
               "eth_tx_per_hour_by_year": yearly.to_dict(orient="records")}
    dump_json(summary, out / "summary.json")
    write_manifest(out, script="scripts/p1_time_patterns.py",
                   config={"start": START, "end": END, "z_burst": Z_BURST, "eth_window_h": 24 * 28, "btc_window_d": 28})
    print(top.to_string())
    print(prof_w.to_string())
    print(be.sort_values("peak_z", ascending=False).head(12).to_string())
    print(bb.sort_values("peak_z", ascending=False).head(12).to_string())
    print(yearly)


if __name__ == "__main__":
    main()
