"""Rebuild the Elliptic pilot table and scientific figure from frozen aggregates.

No fitting, threshold selection, or per-transaction data access occurs here.
Initial fitting is charged once on each family's fixed baseline row. Adaptive
rows report only additional fitting; they reference the already-fitted initial
pair. Timings are descriptive measurements from a shared hosted environment.

Run from the repository root:
  python papers/monitoring_jss/make_elliptic_results.py

The SVG and CSV are repository artifacts. The optional PNG is only a local
visual-QA rendering. Original per-transaction outputs/models remain private.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path

PAPER = Path(__file__).resolve().parent
ROOT = PAPER.parents[1]
DEFAULT_RUN = PAPER / "runs/elliptic_prequential_20261025T091655_598646Z"
FAMILIES = ("lightgbm", "logistic")
DELAYS = (None, 0, 1, 2, 4)
LABELS = ("Fixed", "d = 0", "d = 1", "d = 2", "d = 4")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build_rows(run):
    source = run / "pilot_summary.json"
    summary = json.loads(source.read_text())
    config = json.loads((run / "config.json").read_text())
    cells = {(c["family"], c["delay"]): c for c in summary["cells"]}
    if len(cells) != 10 or set(cells) != {(f, d) for f in FAMILIES for d in DELAYS}:
        raise ValueError("expected the frozen two-family, five-policy pilot")
    rows = []
    populations = set()
    for family in FAMILIES:
        for delay, label in zip(DELAYS, LABELS):
            cell = cells[family, delay]
            metrics = next(m for m in cell["metrics"] if m["step"] == "all")
            populations.add((metrics["n_all"], metrics["n_known"], metrics["positive_known"]))
            tp, fp, unknown = (metrics[k] for k in
                               ("true_positive_known", "false_positive_known", "alerts_unknown"))
            if tp + fp != metrics["alerts_known"] or tp + fp + unknown != metrics["alerts_all"]:
                raise ValueError("known/unknown alert count inconsistency")
            if not math.isclose(metrics["known_positive_recall"], tp / metrics["positive_known"], abs_tol=1e-14):
                raise ValueError("recall does not match the known-positive denominator")
            if tp + fp and not math.isclose(metrics["known_alert_precision"], tp / (tp + fp), abs_tol=1e-14):
                raise ValueError("known-alert precision denominator inconsistency")
            fixed = delay is None
            rows.append({
                "model_family": family,
                "policy": cell["policy"],
                "display_policy": label,
                "label_delay_steps": "" if fixed else delay,
                "seed": config["seed"],
                "feature_count": len(config["features"]["csv_zero_based_positions"]),
                "evaluation_steps": "35-49",
                "transactions_all": metrics["n_all"],
                "transactions_known": metrics["n_known"],
                "transactions_unknown": metrics["n_unknown"],
                "positive_known_denominator": metrics["positive_known"],
                "raw_threshold_alerts": metrics["raw_threshold_alerts"],
                "alerts_all": metrics["alerts_all"],
                "alerts_known": metrics["alerts_known"],
                "alerts_unknown": unknown,
                "true_positive_known": tp,
                "false_positive_known": fp,
                "false_negative_known": metrics["false_negative_known"],
                "known_alert_precision": metrics["known_alert_precision"],
                "known_positive_recall": metrics["known_positive_recall"],
                "known_label_f1": metrics["known_label_f1"],
                "known_label_coverage": metrics["known_label_coverage"],
                "known_alert_coverage": metrics["known_alert_coverage"],
                "unknown_alert_fraction": unknown / metrics["alerts_all"],
                "actual_alert_fraction": metrics["actual_alert_fraction"],
                "nominal_batch_budget_fraction": config["budget"]["fraction"],
                "budget_capacity_total": metrics["budget_capacity"],
                "unused_capacity_total": metrics["unused_capacity"],
                "initial_fit_count_charged": cell["fit_count"] if fixed else 0,
                "initial_fit_seconds_charged": cell["fit_seconds"] if fixed else 0.0,
                "additional_fit_count": 0 if fixed else cell["fit_count"],
                "additional_fit_seconds": 0.0 if fixed else cell["fit_seconds"],
                "new_fit_seconds_for_this_row": cell["fit_seconds"],
                "initial_pair_reference": f"{family}_fixed/base_pair.json",
                "prediction_seconds": cell["prediction_seconds"],
                "fit_cost_accounting": "initial fit charged once on fixed row; adaptive rows add retraining only",
                "timing_scope": "descriptive shared-host measurements; not a controlled hardware comparison",
                "evidence_scope": "one-seed retrospective prepared-feature benchmark; unknown labels are not negatives",
                "run_id": summary["run_id"],
                "input_summary_sha256": sha256(source),
                "input_config_sha256": sha256(run / "config.json"),
            })
    if len(populations) != 1:
        raise ValueError("policy rows must use the same evaluation population")
    if sum(r["initial_fit_count_charged"] for r in rows) != 2:
        raise ValueError("initial fitting must be counted once per family")
    return rows, config


def draw(rows, config, svg, png):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 8.5,
        "axes.labelsize": 8.5,
        "axes.titlesize": 9.3,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 7.4,
        "svg.fonttype": "none",
        "svg.hashsalt": "elliptic_direct18_frozen_pilot_v1",
        "axes.spines.top": False,
        "axes.spines.right": False,
    })
    by_family = {family: [r for r in rows if r["model_family"] == family] for family in FAMILIES}
    positive = rows[0]["positive_known_denominator"]
    x = np.arange(len(DELAYS))
    fig, axes = plt.subplots(1, 2, figsize=(8.3, 4.25))
    fig.subplots_adjust(left=.073, right=.985, bottom=.245, top=.70, wspace=.34)
    fig.suptitle("Elliptic direct-feature pilot: recall and alert label coverage", y=.965,
                 fontsize=11.8, fontweight="semibold")
    fig.text(.5, .884,
             f"{len(config['features']['csv_zero_based_positions'])} features | steps 35-49 | completed-batch cap: floor(N / 200)",
             ha="center", fontsize=8.5, color="#333333")
    blue, orange, grey = "#0072B2", "#D55E00", "#D9D9D9"
    ax = axes[0]
    width = .36
    for offset, family, color, hatch, label in (
        (-width / 2, "lightgbm", blue, "", "LightGBM"),
        (width / 2, "logistic", orange, "//", "Logistic regression"),
    ):
        values = [100 * r["known_positive_recall"] for r in by_family[family]]
        bars = ax.bar(x + offset, values, width, label=label, color=color, hatch=hatch,
                      edgecolor="black", linewidth=.5, zorder=3)
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, value + .13, f"{value:.2f}",
                    ha="center", va="bottom", fontsize=7.6)
    ax.set_title(f"A  Known-positive recall ({positive:,} positives)", loc="left", pad=34)
    ax.set_ylabel("Recall of known positives (%)")
    ax.set_ylim(0, 8)
    ax.set_yticks([0, 2, 4, 6, 8])
    ax.set_xticks(x, LABELS)
    ax.set_xlabel("Fixed baseline or retraining delay d (steps)", labelpad=8)
    ax.grid(axis="y", color="#D7D7D7", linewidth=.5, zorder=0)
    ax.legend(loc="upper left", bbox_to_anchor=(-.025, 1.16), ncol=2,
              frameon=False, handlelength=1.5, columnspacing=1.0)

    ax = axes[1]
    lgbm = by_family["lightgbm"]
    total_alerts = {r["alerts_all"] for r in lgbm}
    if len(total_alerts) != 1:
        raise ValueError("this frozen pilot expects equal total LightGBM alert counts")
    total = total_alerts.pop()
    bottom = np.zeros(len(lgbm))
    for key, label, color, hatch, text_color in (
        ("true_positive_known", "Known TP", blue, "", "white"),
        ("false_positive_known", "Known FP", "#E69F00", "//", "black"),
        ("alerts_unknown", "Unknown", grey, "..", "black"),
    ):
        counts = np.array([r[key] for r in lgbm])
        ax.bar(x, counts, .65, bottom=bottom, color=color, label=label,
               edgecolor="black", linewidth=.5, hatch=hatch, zorder=3)
        for i, count in enumerate(counts):
            ax.text(i, bottom[i] + count / 2, str(count), ha="center", va="center",
                    color=text_color, fontsize=8, fontweight="medium",
                    bbox={"facecolor": color, "edgecolor": "none", "pad": .6})
        bottom += counts
    ax.set_title(f"B  LightGBM: composition of {total} alerts", loc="left", pad=34)
    ax.set_ylabel("Number of issued alerts")
    ax.set_ylim(0, 350)
    ax.set_yticks([0, 100, 200, 300])
    ax.set_xticks(x, LABELS)
    ax.set_xlabel("Fixed baseline or retraining delay d (steps)", labelpad=8)
    ax.grid(axis="y", color="#D7D7D7", linewidth=.5, zorder=0)
    ax.legend(loc="upper left", bbox_to_anchor=(-.025, 1.16), ncol=3,
              frameon=False, handlelength=1.25, columnspacing=.8)
    fig.text(.073, .105,
             "Single seed (0), retrospective benchmark; original global normalization and shared-address dependence remain.",
             ha="left", va="center", fontsize=7.5, color="#333333")
    fig.text(.073, .058,
             "Unknown labels are not false positives. Delays use benchmark steps, not wall-clock time.",
             ha="left", va="center", fontsize=7.5, color="#333333")
    description = ("Generated from frozen Elliptic pilot summary. Panel A uses 1083 known positives. "
                   "Panel B separates known true positives, known false positives and unknown labels. "
                   "One seed, retrospective prepared-feature study; no overall-precision or online-validity claim.")
    fig.savefig(svg, format="svg", metadata={"Date": None, "Title": "Elliptic pilot recall and alert label coverage",
                                           "Description": description})
    svg.write_text("\n".join(line.rstrip() for line in svg.read_text().splitlines()) + "\n")
    if png:
        fig.savefig(png, dpi=180, metadata={"Description": description})
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run", type=Path, default=DEFAULT_RUN)
    ap.add_argument("--png", type=Path, default=ROOT.parent / "elliptic_pilot_results.png")
    args = ap.parse_args()
    rows, config = build_rows(args.run.resolve())
    table = PAPER / "tables/elliptic_pilot_results.csv"
    svg = PAPER / "figures/elliptic_pilot_results.svg"
    table.parent.mkdir(exist_ok=True)
    svg.parent.mkdir(exist_ok=True)
    args.png.parent.mkdir(parents=True, exist_ok=True)
    with table.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    draw(rows, config, svg, args.png)
    print(json.dumps({"rows": len(rows), "csv": str(table), "svg": str(svg), "png": str(args.png),
                      "source_summary_sha256": rows[0]["input_summary_sha256"],
                      "initial_fit_count_charged": sum(r["initial_fit_count_charged"] for r in rows),
                      "additional_fit_count": sum(r["additional_fit_count"] for r in rows)}))


if __name__ == "__main__":
    main()
