"""
S2 - What kinds of exploits produce the losses? Incident statistics from DeFiHackLabs.

DeFiHackLabs (SunWeb3Sec, Apache-2.0) lists exploits for which a Foundry
proof-of-concept exists. It is a convenience sample: incidents that could be
reproduced on a fork are over-represented, off-chain key thefts and centralized
exchange hacks are under-represented. Counts are therefore counts of indexed
incidents, not of all incidents.

Outputs (results/security/s2_<stamp>/):
  incidents.csv     one row per incident: date, name, root-cause text, class, parsed USD
  by_year.csv       incidents and parsed USD losses per year
  by_class.csv      incidents and parsed USD losses per stated-cause class (2021 onward)
  by_component.csv  the same per attacked component (bridge / cross-chain or other);
                    component and cause are separate codings (see bclab.incidents)
  class_audit.csv   40 random titles with their class (for a manual consistency check)
  fig_s2.png/.eps/.pdf
"""

from __future__ import annotations

import argparse
import subprocess
import textwrap
import time
from pathlib import Path

import numpy as np
import pandas as pd

from bclab import figures as F
from bclab.incidents import load_all
from bclab.repro import atomic_to_csv, dump_json, write_manifest

ROOT = Path("data/raw/DeFiHackLabs")


def summarise(g: pd.DataFrame) -> pd.Series:
    usd = g["loss_usd"].dropna()
    return pd.Series({
        "incidents": len(g),
        "with_usd": len(usd),
        "usd_total": usd.sum(),
        "usd_median": usd.median() if len(usd) else np.nan,
        "usd_top1_share": usd.max() / usd.sum() if usd.sum() > 0 else np.nan,
        "with_usd_lenient": int(g["loss_usd_lenient"].notna().sum()),
        "usd_total_lenient": g["loss_usd_lenient"].sum(),
    })


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("--from-year", type=int, default=2021)
    args = ap.parse_args()
    out = Path(args.out or f"results/security/s2_{time.strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)

    df = load_all(ROOT)
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    atomic_to_csv(df.drop(columns=["source_file"]), out / "incidents.csv", index=False)

    by_year = df.groupby("year").apply(summarise, include_groups=False).reset_index()
    atomic_to_csv(by_year, out / "by_year.csv", index=False)

    recent = df[df.year >= args.from_year]
    by_class = (recent.groupby("cause_class").apply(summarise, include_groups=False)
                .sort_values("incidents", ascending=False).reset_index())
    by_class["share_incidents"] = by_class["incidents"] / by_class["incidents"].sum()
    by_class["share_usd"] = by_class["usd_total"] / by_class["usd_total"].sum()
    atomic_to_csv(by_class, out / "by_class.csv", index=False)

    by_comp = (recent.groupby("component").apply(summarise, include_groups=False).reset_index())
    by_comp["share_incidents"] = by_comp["incidents"] / by_comp["incidents"].sum()
    by_comp["share_usd"] = by_comp["usd_total"] / by_comp["usd_total"].sum()
    atomic_to_csv(by_comp, out / "by_component.csv", index=False)
    bridge_by_cause = (recent[recent.component == "bridge / cross-chain"]
                       .groupby("cause_class").apply(summarise, include_groups=False).reset_index())
    atomic_to_csv(bridge_by_cause, out / "bridge_by_cause.csv", index=False)

    audit = df.sample(40, random_state=2026)[["date", "name", "cause_text", "cause_class", "component"]]
    audit["cause_text"] = audit["cause_text"].str.slice(0, 200)
    atomic_to_csv(audit, out / "class_audit.csv", index=False)

    # concentration of losses: share of parsed USD in the largest 1 % / 10 incidents
    usd = recent["loss_usd"].dropna().sort_values(ascending=False)
    top10 = usd.head(10).sum() / usd.sum()
    top1pct = usd.head(max(1, int(round(0.01 * len(usd))))).sum() / usd.sum()

    F.style()
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(6.6, 3.6), gridspec_kw={"width_ratios": [1.25, 1]})
    bc = by_class.sort_values("incidents")
    y = np.arange(len(bc))
    axes[0].barh(y - 0.2, bc["share_incidents"] * 100, 0.4, color="0.35", edgecolor="0", label="incidents")
    axes[0].barh(y + 0.2, bc["share_usd"] * 100, 0.4, color="white", edgecolor="0", hatch="///",
                 label="parsed USD loss")
    axes[0].set_yticks(y, [textwrap.fill(c, 30) for c in bc["cause_class"]], fontsize=6)
    axes[0].set_xlabel("share, %")
    axes[0].set_title(f"(a) stated-cause classes, {args.from_year}-{int(df.year.max())}")
    axes[0].legend(frameon=False, loc="lower right")
    yr = by_year[by_year.year >= args.from_year]
    axes[1].bar(yr["year"], yr["incidents"], color="0.75", edgecolor="0")
    axes[1].set_ylabel("indexed incidents")
    ax2 = axes[1].twinx()
    ax2.semilogy(yr["year"], yr["usd_median"] / 1e3, "k-o", ms=3, label="median parsed loss")
    ax2.set_ylabel("median parsed loss, thousand USD (log)")
    ax2.grid(False)
    axes[1].set_title("(b) incidents and median loss per year")
    axes[1].set_xticks(yr["year"], [str(int(v)) for v in yr["year"]], rotation=45)
    fig.subplots_adjust(wspace=0.55)
    F.save(fig, out, "fig_s2")

    summary = {
        "source_commit": commit,
        "n_incidents": len(df), "date_min": str(df.date.min().date()), "date_max": str(df.date.max().date()),
        "parse_counts": df["loss_parse"].value_counts().to_dict(),
        "share_with_usd": float(df["loss_usd"].notna().mean()),
        "share_other_class": float((df["cause_class"] == "other").mean()),
        "recent_from_year": args.from_year,
        "recent_n": len(recent), "recent_with_usd": int(recent["loss_usd"].notna().sum()),
        "recent_usd_total": float(usd.sum()), "recent_usd_median": float(usd.median()),
        "recent_top10_share": float(top10),
        "recent_usd_total_lenient": float(recent["loss_usd_lenient"].sum()),
        "recent_with_usd_lenient": int(recent["loss_usd_lenient"].notna().sum()), "recent_top1pct_share": float(top1pct),
        "by_component": by_comp.to_dict(orient="records"),
        "largest": recent.nlargest(10, "loss_usd")[["date", "name", "cause_class", "component", "loss_usd"]]
                         .astype({"date": str}).to_dict(orient="records"),
    }
    dump_json(summary, out / "summary.json")
    write_manifest(out, script="scripts/s2_incident_statistics.py",
                   config={"from_year": args.from_year, "source": "SunWeb3Sec/DeFiHackLabs",
                           "source_commit": commit},
                   data_files=[ROOT / "README.md", *sorted(ROOT.glob("past/*/README.md"))])
    print(by_year.to_string())
    print(by_class.to_string())
    print({k: v for k, v in summary.items() if k != "largest"})


if __name__ == "__main__":
    main()
