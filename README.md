# blockchain-analytics-lab

Reproducible studies of blockchain security data: threat models and incident
statistics (S), AI fundamentals on transaction data (A), data collection and
preprocessing (D), transaction patterns (P), streaming monitoring (M) and
federated, privacy-preserving detection (F).

Work in progress; this README is completed when all studies are in.

| Study | Question | Data | Scripts |
|---|---|---|---|
| **S · security** | How sensitive are double-spend confirmation rules to the race model? Which exploit classes produce the indexed losses? | analytical; DeFiHackLabs | `s1`, `s2` |

Every number comes from a numbered script in `scripts/` and is stored with a
manifest (code commit, input hashes, package versions, configuration) under
`results/`.

## Quick start

```bash
pip install -e ".[dev,bal]"
python scripts/00_fetch_data.py
python scripts/s1_double_spend.py
python scripts/s2_incident_statistics.py
pytest -q
```

## License

Code: MIT. Results and documentation: CC BY 4.0. Data sources keep their own
licences (see `docs/DATA.md`).
