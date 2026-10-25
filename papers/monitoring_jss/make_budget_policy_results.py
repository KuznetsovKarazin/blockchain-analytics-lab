"""Rebuild the 18-cell allocation table and primary-B5 scientific figure.

Only completed-run aggregate JSON is read: study/run manifests, configuration,
daily counts and hourly counts. No event-level records, labels or trained models
are opened. Counts are checked against independent aggregate decompositions and
recorded hashes before outputs are written. A failed or pending run is rejected.

Example from the repository root (supply the accepted completed run):
  python papers/monitoring_jss/make_budget_policy_results.py --run <run_directory>

CSV/SVG are repository artifacts; the PNG is a local visual-QA rendering.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

PAPER = Path(__file__).resolve().parent
ROOT = PAPER.parents[1]
POLICIES = ("greedy", "paced_cumulative", "token_bucket")
BUDGETS = (1, 5, 20)
EMITTERS = ("euler_core", "beanstalk_diamond")
NAMES = {"euler_core": "Euler core", "beanstalk_diamond": "Beanstalk Diamond"}
REASONS = ("duplicate", "late", "below_threshold", "grouped", "budget", "quota", "token")
COUNT_KEYS = ("records", "accepted_events", "raw_triggers", "group_candidates", "notifications")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def utc_from_ns(value):
    if value is None:
        return ""
    seconds, nanos = divmod(int(value), 1_000_000_000)
    stamp = datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    return stamp + (f".{nanos:09d}" if nanos else "") + "Z"


def check_counts(item):
    for key in COUNT_KEYS:
        require(type(item[key]) is int and item[key] >= 0, f"invalid count: {key}")
    reasons = item["suppression_counts"]
    require(not (set(reasons) - set(REASONS)), "unknown suppression reason")
    require(all(type(v) is int and v >= 0 for v in reasons.values()), "invalid suppression count")
    require(item["records"] == item["accepted_events"] + reasons.get("duplicate", 0) + reasons.get("late", 0),
            "accepted/dropped event count mismatch")
    require(item["accepted_events"] == item["raw_triggers"] + reasons.get("below_threshold", 0),
            "raw-trigger count mismatch")
    require(item["raw_triggers"] == item["group_candidates"] + reasons.get("grouped", 0),
            "group-candidate count mismatch")
    require(item["group_candidates"] == item["notifications"] + sum(reasons.get(k, 0) for k in ("budget", "quota", "token")),
            "admission count mismatch")
    require(item["records"] == item["notifications"] + sum(reasons.values()), "suppression partition mismatch")
    if item["notifications"]:
        require(type(item["first_notification_time_ns"]) is int and
                type(item["last_notification_time_ns"]) is int and
                item["first_notification_time_ns"] <= item["last_notification_time_ns"],
                "invalid first/last notification time")
    else:
        require(item["first_notification_time_ns"] is None and item["last_notification_time_ns"] is None,
                "zero-notification interval has a notification timestamp")


def build_rows(run):
    summary_path = run / "study_summary.json"
    manifest_path = run / "run_manifest.json"
    config_path = run / "config.json"
    summary = json.loads(summary_path.read_text())
    manifest = json.loads(manifest_path.read_text())
    config = json.loads(config_path.read_text())
    require(summary.get("status") == "complete", "study summary is failed or pending; no output generated")
    require(manifest.get("status") == "complete", "run manifest is failed or pending; no output generated")
    require(manifest.get("frozen_sources_config_inputs_unchanged") is True,
            "completed run lacks successful frozen-source/input integrity check")
    require(summary.get("raw_feature_streams_identical") is True and summary.get("labels_used") is False,
            "raw-stream invariance or label separation is unverified")
    require(config["primary_budget"] == 5 and tuple(config["budgets"]) == BUDGETS and
            tuple(config["policies"]) == POLICIES and tuple(e["id"] for e in config["emitters"]) == EMITTERS,
            "expected the frozen two-emitter, three-policy, three-budget design")
    require(config["window"]["days"] == 30, "expected thirty UTC days")
    require(manifest["config_sha256"] == sha256(config_path), "config checksum differs from completed manifest")
    start = datetime.fromisoformat(config["window"]["start_utc"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(config["window"]["end_utc"].replace("Z", "+00:00"))
    require(end - start == timedelta(days=30), "window length differs from thirty days")
    days = [(start + timedelta(days=i)).date().isoformat() for i in range(30)]
    expected_hours = [f"{day}T{hour:02d}:00:00Z" for day in days for hour in range(24)]
    cells = {(c["population_id"], c["daily_budget"], c["policy"]): c for c in summary["cells"]}
    require(len(summary["cells"]) == 18 and set(cells) ==
            {(e, b, p) for e in EMITTERS for b in BUDGETS for p in POLICIES},
            "summary does not contain exactly the declared eighteen unique cells")
    source_summary_sha = sha256(summary_path)
    config_sha = sha256(config_path)
    provenance = {"run_id": run.name, "source_summary_sha256": source_summary_sha,
                  "source_config_sha256": config_sha, "source_run_manifest_sha256": sha256(manifest_path)}
    rows, series = [], {}
    feature_digests = {e: set() for e in EMITTERS}
    for emitter in EMITTERS:
        for budget in BUDGETS:
            for policy in POLICIES:
                cell = cells[emitter, budget, policy]
                require(cell["cell_id"] == f"{emitter}__{policy}__B{budget}", "cell ID does not match its design coordinates")
                check_counts(cell)
                require(cell["days"] == 30 and cell["hard_cap_exceedances"] == 0, "day coverage/cap check failed")
                feature_digests[emitter].add(cell["accepted_feature_stream_sha256"])
                directory = run / "cells" / cell["cell_id"]
                daily_path, hourly_path = directory / "daily.json", directory / "hourly.json"
                require(sha256(daily_path) == cell["artifacts"]["daily.json"], "daily JSON checksum mismatch")
                require(sha256(hourly_path) == cell["artifacts"]["hourly.json"], "hourly JSON checksum mismatch")
                daily, hourly = json.loads(daily_path.read_text()), json.loads(hourly_path.read_text())
                require([r["day_utc"] for r in daily] == days, "missing/repeated/unordered daily interval")
                require([r["hour_utc"] for r in hourly] == expected_hours, "missing/repeated/unordered hourly interval")
                for item in daily + hourly:
                    check_counts(item)
                for key in COUNT_KEYS:
                    require(sum(r[key] for r in daily) == cell[key] == sum(r[key] for r in hourly),
                            f"daily/hourly/total mismatch: {key}")
                for reason in REASONS:
                    require(sum(r["suppression_counts"].get(reason, 0) for r in daily) ==
                            cell["suppression_counts"].get(reason, 0) ==
                            sum(r["suppression_counts"].get(reason, 0) for r in hourly),
                            f"suppression aggregate mismatch: {reason}")
                require(all(r["daily_budget"] == budget and r["notifications"] <= budget for r in daily),
                        "daily cap mismatch")
                require(cell["days_at_cap"] == sum(r["notifications"] == budget for r in daily), "days-at-cap mismatch")
                require(cell["unused_daily_slots"] == sum(budget - r["notifications"] for r in daily),
                        "unused daily slots mismatch")
                require(cell["raw_trigger_active_hours"] == sum(r["raw_triggers"] > 0 for r in hourly),
                        "raw-trigger-active hour count mismatch")
                require(cell["raw_trigger_active_hours_with_notification"] ==
                        sum(r["raw_triggers"] > 0 and r["notifications"] > 0 for r in hourly),
                        "captured active-hour count mismatch")
                emitted_days = [r for r in daily if r["notifications"]]
                require(cell["first_notification_time_ns"] == (emitted_days[0]["first_notification_time_ns"] if emitted_days else None),
                        "first notification timestamp mismatch")
                require(cell["last_notification_time_ns"] == (emitted_days[-1]["last_notification_time_ns"] if emitted_days else None),
                        "last notification timestamp mismatch")
                hour_totals = [sum(r["notifications"] for r in hourly if int(r["hour_utc"][11:13]) == h) for h in range(24)]
                require(sum(hour_totals) == cell["notifications"], "UTC-hour marginal count mismatch")
                series[emitter, budget, policy] = {"daily": daily, "hour_totals": hour_totals}
                rows.append({
                    "population_id": emitter, "emitter_name": NAMES[emitter], "policy": policy,
                    "daily_budget": budget, "primary_B5": budget == 5,
                    "window_start_utc": config["window"]["start_utc"],
                    "window_end_utc_exclusive": config["window"]["end_utc"], "days": 30,
                    **{k: cell[k] for k in COUNT_KEYS},
                    **{f"suppressed_{k}": cell["suppression_counts"].get(k, 0) for k in REASONS},
                    "hard_cap_exceedances": cell["hard_cap_exceedances"],
                    "days_at_cap": cell["days_at_cap"], "unused_daily_slots": cell["unused_daily_slots"],
                    "raw_trigger_active_hours": cell["raw_trigger_active_hours"],
                    "raw_trigger_active_hours_with_notification": cell["raw_trigger_active_hours_with_notification"],
                    "first_notification_time_ns": cell["first_notification_time_ns"],
                    "last_notification_time_ns": cell["last_notification_time_ns"],
                    "first_notification_utc": utc_from_ns(cell["first_notification_time_ns"]),
                    "last_notification_utc": utc_from_ns(cell["last_notification_time_ns"]),
                    "unknown_observed_time": cell["unknown_observed_time"],
                    "unknown_removed": cell["unknown_removed"],
                    "accepted_feature_stream_sha256": cell["accepted_feature_stream_sha256"],
                    "source_daily_sha256": cell["artifacts"]["daily.json"],
                    "source_hourly_sha256": cell["artifacts"]["hourly.json"],
                    **provenance,
                    "clock_domain": "original integer event_time_ns; logical simulation",
                    "evidence_scope": "exploratory workload allocation; no attack-quality or observed-delivery claim",
                })
    require(all(len(values) == 1 for values in feature_digests.values()), "feature streams differ between policy/budget cells")
    return rows, config, series, provenance


def draw(config, series, provenance, svg, png):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.dates as mdates
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MaxNLocator

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9,
                         "axes.labelsize": 9, "axes.titlesize": 10,
                         "xtick.labelsize": 8, "ytick.labelsize": 8,
                         "legend.fontsize": 9, "svg.fonttype": "none",
                         "svg.hashsalt": "budget_policy_primary_B5_v1",
                         "axes.spines.top": False, "axes.spines.right": False})
    start = datetime.fromisoformat(config["window"]["start_utc"].replace("Z", "+00:00"))
    dates = [start + timedelta(days=i) for i in range(30)]
    primary = config["primary_budget"]
    styles = {
        "greedy": {"label": "Greedy", "color": "#0072B2", "marker": "o", "linestyle": "-", "markersize": 5.6},
        "paced_cumulative": {"label": "Paced cumulative", "color": "#D55E00", "marker": "s", "linestyle": "--", "markersize": 4.1},
        "token_bucket": {"label": "Token bucket", "color": "#009E73", "marker": "^", "linestyle": ":", "markersize": 3.6},
    }
    fig, axes = plt.subplots(2, 2, figsize=(11.2, 7.15))
    fig.subplots_adjust(left=.07, right=.985, bottom=.17, top=.79, hspace=.49, wspace=.24)
    fig.suptitle("Notification allocation under a daily cap of five", y=.974,
                 fontsize=14, fontweight="semibold")
    fig.text(.5, .928,
             f"{dates[0]:%d %b}–{dates[-1]:%d %b %Y} | 30 UTC days | fixed count rule and grouping | logical event-time simulation",
             ha="center", va="center", fontsize=9.2, color="#333333")
    hourly_max = max(max(series[e, primary, p]["hour_totals"]) for e in EMITTERS for p in POLICIES)
    hourly_top = max(1, hourly_max * 1.12)
    legend_handles = []
    for row_index, emitter in enumerate(EMITTERS):
        left, right = axes[row_index]
        for policy_index, policy in enumerate(POLICIES):
            values = series[emitter, primary, policy]
            style = styles[policy]
            line, = left.plot(dates, [r["notifications"] for r in values["daily"]],
                              **style, linewidth=1.35, markerfacecolor="white",
                              markeredgewidth=1, zorder=3 + policy_index)
            right.plot(range(24), values["hour_totals"], **style, linewidth=1.35,
                       markerfacecolor="white", markeredgewidth=1, zorder=3 + policy_index)
            if row_index == 0:
                legend_handles.append(line)
        left.set_title(f"{'A' if row_index == 0 else 'C'}  {NAMES[emitter]}: daily notifications", loc="left", pad=11)
        right.set_title(f"{'B' if row_index == 0 else 'D'}  {NAMES[emitter]}: UTC-hour distribution", loc="left", pad=11)
        left.axhline(primary, color="#777777", linestyle=(0, (2, 3)), linewidth=.7, zorder=1)
        left.set_ylim(-.15, primary + .55)
        left.set_yticks(range(primary + 1))
        left.set_ylabel("Notifications per UTC day")
        left.set_xticks([dates[i] for i in (0, 7, 14, 21, 28)])
        left.xaxis.set_major_formatter(mdates.DateFormatter("%d %b", tz=timezone.utc))
        left.set_xlim(dates[0] - timedelta(hours=12), dates[-1] + timedelta(hours=12))
        left.set_xlabel("Date (UTC)", labelpad=5)
        right.set_xlim(-.5, 23.5)
        right.set_xticks([0, 4, 8, 12, 16, 20, 23])
        right.set_xlabel("UTC hour of day", labelpad=5)
        right.set_ylabel("Notifications summed over 30 days")
        right.set_ylim(-.03 * hourly_top, hourly_top)
        right.yaxis.set_major_locator(MaxNLocator(nbins=5, integer=True))
        for ax in (left, right):
            ax.grid(axis="y", color="#D8D8D8", linewidth=.55, zorder=0)
            ax.tick_params(axis="both", length=3, width=.6)
    fig.legend(handles=legend_handles, loc="upper center", bbox_to_anchor=(.5, .892),
               ncol=3, frameon=False, handlelength=3, columnspacing=2.2)
    fig.text(.07, .076,
             "Exploratory workload comparison: counts describe admission and timing, not attack-detection quality.",
             fontsize=8.3, color="#333333", ha="left")
    fig.text(.07, .043,
             "The cap applies separately to each emitter. Event timestamps are simulation time; historical arrival times are unknown.",
             fontsize=8.3, color="#333333", ha="left")
    description = ("Primary daily budget B=5. Rows: Euler core and Beanstalk Diamond. Left: daily notification counts. "
                   "Right: notification counts by UTC hour summed over the thirty-day window. Greedy, paced cumulative and "
                   "single-token policies use identical source events and raw triggers. This is exploratory allocation evidence, "
                   "not a detector-quality or observed-latency claim. " + json.dumps(provenance, sort_keys=True))
    fig.savefig(svg, format="svg", metadata={"Date": None, "Title": "Primary B5 notification allocation",
                                           "Description": description, "Creator": "make_budget_policy_results.py"})
    svg.write_text("\n".join(line.rstrip() for line in svg.read_text().splitlines()) + "\n")
    fig.savefig(png, dpi=200, metadata={"Description": description})
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True, help="Accepted completed eighteen-cell run directory")
    parser.add_argument("--csv", type=Path, default=PAPER / "tables/budget_policy_results.csv")
    parser.add_argument("--svg", type=Path, default=PAPER / "figures/budget_policy_primary_B5.svg")
    parser.add_argument("--png", type=Path, default=ROOT.parent / "budget_policy_primary_B5.png")
    args = parser.parse_args()
    rows, config, series, provenance = build_rows(args.run.resolve())
    for path in (args.csv, args.svg, args.png):
        path.parent.mkdir(parents=True, exist_ok=True)
    with args.csv.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    draw(config, series, provenance, args.svg, args.png)
    print(json.dumps({"rows": len(rows), **provenance,
                      "outputs": {str(p): sha256(p) for p in (args.csv, args.svg, args.png)}}))


if __name__ == "__main__":
    main()
