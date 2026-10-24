# Article 2 status — 25 October 2026

Working title: **Operational Evaluation of Blockchain Monitoring Pipelines under Alert Budgets and Delayed Feedback**.
Target: Journal of Systems and Software, ordinary research article.

## Starting point

Repository `KuznetsovKarazin/blockchain-analytics-lab`, branch `paper/monitoring-jss`.
Baseline commit: `049239566bc5ecadec1691eb64279ce7b204a86d`.
The paper branch initially matched main. The current `pyproject.toml` pins the companion `blockchain-detector-eval` package to `dc1ba8876f3f163c27c48f3a39292fc47f71bf18`; this is not the newer article-1 baseline. The dependency is not changed here.

## Completed now

- Read and checked the M1/M2 implementation, summaries, data instructions and dependency pin.
- Saved this handoff and a machine-readable draft protocol.
- Preserved the established priority: article 1 first; article 2 protocol and small pilot before a larger study.

No new replay, model training, incident evaluation, latency measurement or reliability experiment has been run in this starter package.

## Existing evidence and limits

M1 uses 7,827,863 Ethereum blocks from 2023–2025, with January 2023 used for calibration and evaluation beginning in February. It measures alert workload without attack ground truth. Grouped triggers are not confirmed security incidents.

M2 uses Elliptic steps 1–30 for training, 31–34 for validation and previously studied steps 35–49 for testing. It has a single delay setting of 2 steps. The top-1% budget is a completed-batch policy; batch waiting must be counted. Retrain threshold calibration reuses training predictions and must be replaced by an independent temporal calibration procedure. MLP timing is an untrained forward pass; existing timing excludes data acquisition and feature construction.

Ronin, Nomad and the studied custody case remain development examples. Independent incidents, continuous ordinary periods and explicit event availability are not yet established for the new paper.

## P2.01–P2.06

All six work packages remain planned. `protocol.json` is **draft-not-frozen**. The next step is to implement an event schema and one small replay, followed by a data/volume pilot and candidate-incident registry. The full grid follows feasibility and protocol freeze.

Pipeline ordering must enforce the stated resource unit: score -> raw trigger -> causal grouping/suppression -> hard-budget admission -> emitted notification and decision log. Labels arrive through their own availability queue. Any different grouping/admission ordering must define its state effects explicitly.

Do not run `scripts/run_all.sh` unchanged: it removes and rewrites fixed historical `*_v1` outputs. Use `papers/monitoring_jss/runs/<unique_run_id>/`. Retain `results/monitoring/`, the current package pin and the source manifest.

## First pilot

One ordinary day and one intensive fragment; one detector and two regimes. Verify prefix invariance, no duplicate notifications after replay/restart, explicit unknown historical observation times, and causal hard-budget handling. Measure runtime, RAM, disk/cache and queue size. Report measured local stages separately from hypothetical acquisition/confirmation delays. A successful smoke run is not confirmatory evidence of detection performance.

