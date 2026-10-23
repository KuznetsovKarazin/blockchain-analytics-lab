#!/usr/bin/env bash
# Re-run every study into results/<area>/<code>_v1 from a clean checkout.
# Each fixed run folder is deleted and rewritten; earlier states live only in Git history.
# Usage: bash scripts/run_all.sh [lane]   lane = fed | rest | all (default all)
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -n "$(git status --porcelain -- src scripts pyproject.toml)" ]; then
  echo "working tree has uncommitted changes in src/, scripts/ or pyproject.toml; commit first" >&2
  exit 1
fi
run() {  # run <script> <out dir> [args...]
  local script=$1 out=$2; shift 2
  rm -rf "$out"
  echo "== $(date -u +%FT%TZ) $script -> $out"
  python "scripts/$script" --out "$out" "$@"
}
lane=${1:-all}
if [ "$lane" = fed ] || [ "$lane" = all ]; then
  run f1_federated.py results/federated/f1_v1
  run f1b_dp_accounting.py results/federated/f1b_v1     # reads f1_v1, so only after F1
fi
if [ "$lane" = rest ] || [ "$lane" = all ]; then
  run s1_double_spend.py results/security/s1_v1
  run s2_incident_statistics.py results/security/s2_v1
  run a1_elliptic_fundamentals.py results/fundamentals/a1_v1
  run a1b_random_ap.py results/fundamentals/a1b_v1
  run d1_eth_pipeline.py results/data/d1_v1
  run d2_imbalance.py results/data/d2_v1
  run p1_time_patterns.py results/patterns/p1_v1
  run p2_graph_elliptic.py results/patterns/p2_v1
  run p3_value_flows.py results/patterns/p3_v1
  run p4_ponzi.py results/patterns/p4_v1
  run m1_block_stream.py results/monitoring/m1_v1
  run m2_elliptic_stream.py results/monitoring/m2_v1
  run c1_custody_drain.py results/cases/c1_v1
fi
