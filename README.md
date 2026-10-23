# blockchain-analytics-lab

Reproducible studies of blockchain security data: threat models and incident
statistics (S), AI fundamentals on transaction data (A), data collection and
preprocessing (D), transaction patterns (P), streaming monitoring (M) and
federated, privacy-preserving detection (F), plus one incident case (C).

Every number comes from a numbered script in `scripts/` and is stored with a
manifest (code commit, uncommitted diff hash, input files, package versions,
configuration) under `results/`. The Elliptic loader and evaluation helpers are
reused from the public project
[blockchain-detector-eval](https://github.com/KuznetsovKarazin/blockchain-detector-eval)
(pinned commit in `pyproject.toml`).

## Studies

| Study | Question | Data | Script → results |
|---|---|---|---|
| S1 | How sensitive are double-spend confirmation rules to discretized time and limited attacker patience? | analytical + Monte Carlo | `s1_double_spend.py` → `results/security/s1_v1` |
| S2 | Which stated causes and attacked components (bridge or not) carry the indexed DeFi losses? | DeFiHackLabs | `s2_incident_statistics.py` → `results/security/s2_v1` |
| A1 | How do model families, prevalence and time windows change Elliptic metrics and feature importance? | Elliptic | `a1_elliptic_fundamentals.py` → `results/fundamentals/a1_v1` |
| A1b | Prevalence (population no-skill reference) versus the expected AP of a random score on finite samples | Elliptic labels | `a1b_random_ap.py` → `results/fundamentals/a1b_v1` |
| D1 | What do public Ethereum/Bitcoin tables encode silently; how do normalisation and label versions change results? | AWS public blockchain data, OFAC lists, ethereum-lists | `d1_eth_pipeline.py` → `results/data/d1_v1` |
| D2 | Do imbalance remedies help under a temporal split? | Elliptic | `d2_imbalance.py` → `results/data/d2_v1` |
| P1 | Periodicity and bursts in block-level activity | AWS ETH/BTC blocks 2023–2025 | `p1_time_patterns.py` → `results/patterns/p1_v1` |
| P2 | Do centrality or communities separate illicit transactions? | Elliptic graph | `p2_graph_elliptic.py` → `results/patterns/p2_v1` |
| P3 | Fixed-denomination, round-value and large-transfer rules | AWS ETH transactions, OFAC lists | `p3_value_flows.py` → `results/patterns/p3_v1` |
| P4 | Ponzi contracts from bytecode under random, grouped, distinct-code and temporal evaluation | AWS ETH contracts 2015–2017, ethereum-ponzi | `p4_ponzi.py` → `results/patterns/p4_v1` |
| M1 | Unsupervised threshold policies on a block stream: alert load and cost | AWS ETH blocks 2023–2025 | `m1_block_stream.py` → `results/monitoring/m1_v1` |
| M2 | Supervised stream with delayed labels: fixed, budget, recalibrated, retrained; scoring latency | Elliptic | `m2_elliptic_stream.py` → `results/monitoring/m2_v1` |
| F1 | Central vs local vs FedAvg under three partitions; clipping and Gaussian noise at client level; pairwise-masking cost (simulation) | Elliptic | `f1_federated.py` → `results/federated/f1_v1` |
| F1b | What F1's privacy numbers certify: RDP accountant under add/remove and replace-one adjacency, and what is not accounted | F1 results | `f1b_dp_accounting.py` → `results/federated/f1b_v1` |
| C1 | Exchange cold-wallet drain (2025-02-21): first on-chain signal, its alert cost on ordinary days, dispersion of the stolen ether | AWS ETH traces and token transfers, Feb–Mar 2025 | `c1_custody_drain.py` → `results/cases/c1_v1` |

## Quick start

```bash
pip install -e ".[dev,bal]"
python scripts/00_fetch_data.py          # pinned GitHub sources into data/raw/
# Elliptic: place the three CSV files in data/raw/elliptic/ (see docs/DATA.md)
python scripts/d0_cache_aws.py           # AWS public blockchain cache (tens of GB)
pytest -q
bash scripts/run_all.sh                  # all studies; refuses to run on uncommitted code
```

`run_all.sh fed` and `run_all.sh rest` run the federated study and the others
in two parallel lanes. On a 4-core machine with 16 GB RAM the whole set takes
a few hours; P4 reads about four million contract bytecodes day by day.

## Reproducibility notes

* Results are deterministic given the seeds in each script, the pinned data
  revisions and the package versions recorded in each `manifest.json`.
* Studies that read the AWS cache write `inputs_<chain>_<table>.csv` next to
  their results: one row per day with row count, columns, SHA-256 of the cached
  file and the upstream object keys, sizes and modification times. A study
  refuses to run when a day in its range is missing from the cache, unless the
  day is marked missing upstream. The cached files themselves (tens of GB) are
  not part of the repository.
* F1 reports conditional privacy-accountant values, not an end-to-end
  differential-privacy guarantee of the pipeline (see `f1b_dp_accounting.py`).
* Timing measurements limit numerical thread pools to one thread.
* All online statistics in M1/M2 use only past blocks or steps; thresholds are
  never chosen on test data.
* Labels that are not ours to redistribute (Elliptic, ethereum-ponzi) are never
  written to `results/`; only aggregate metrics are.

## License

Code: MIT. Results and documentation: CC BY 4.0. Data sources keep their own
licences (see `docs/DATA.md`).
