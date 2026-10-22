"""
D0 - Build the local cache of AWS Public Blockchain Data used by studies D, P and M.

Usage:  python scripts/d0_cache_aws.py <spec> [<spec> ...]   (default: all specs)
Specs and the columns kept are listed in SPECS; downloads are resumable (existing
days are skipped) and every fetched day is logged in cache_index.csv.
"""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor

from bclab.aws import append_index, days, fetch_day, s3

SPECS = {
    # block-level activity, 3 years (periodicity, bursts, stream replay)
    "eth_blocks": ("eth", "blocks", "2023-01-01", "2025-12-31",
                   ["number", "timestamp", "transaction_count", "gas_used", "gas_limit",
                    "base_fee_per_gas", "size", "miner"]),
    "btc_blocks": ("btc", "blocks", "2023-01-01", "2025-12-31",
                   ["number", "timestamp", "mediantime", "transaction_count", "size", "weight"]),
    # transaction-level data for two weeks (pipeline, labels, value flows)
    "eth_tx_2022w30": ("eth", "transactions", "2022-07-25", "2022-07-31",
                       ["hash", "block_number", "block_timestamp", "transaction_index", "from_address",
                        "to_address", "value", "gas", "gas_price", "receipt_gas_used", "receipt_status",
                        "transaction_type", "receipt_contract_address", "nonce"]),
    "eth_tx_2024w10": ("eth", "transactions", "2024-03-04", "2024-03-10",
                       ["hash", "block_number", "block_timestamp", "transaction_index", "from_address",
                        "to_address", "value", "gas", "gas_price", "receipt_gas_used", "receipt_status",
                        "transaction_type", "receipt_contract_address", "nonce"]),
    # contract bytecode of the first two years (Ponzi case study)
    "eth_contracts_2015_2017": ("eth", "contracts", "2015-07-30", "2017-12-31",
                                ["address", "bytecode", "block_number", "block_timestamp"]),
}


def run(name: str, workers: int = 4) -> None:
    chain, table, start, end, cols = SPECS[name]
    fs = s3()
    todo = list(days(start, end))
    done = 0
    with ThreadPoolExecutor(workers) as ex:
        for rec in ex.map(lambda d: fetch_day(fs, chain, table, d, cols), todo):
            if rec:
                append_index(chain, table, rec)
                if not rec["status"].startswith("ok") and rec["status"] != "missing":
                    print(name, rec, flush=True)
            done += 1
            if done % 50 == 0:
                print(f"{name}: {done}/{len(todo)}", flush=True)
    print(f"{name}: finished", flush=True)


if __name__ == "__main__":
    for n in sys.argv[1:] or list(SPECS):
        run(n, workers=2 if "tx" in n else 4)
