"""
D0 - Build the local cache of AWS Public Blockchain Data used by studies D, P and M.

Usage:  python scripts/d0_cache_aws.py <spec> [<spec> ...]   (default: all specs)
Specs and the columns kept are listed in SPECS; downloads are resumable (existing
days are skipped) and every fetched day is logged in cache_index.csv.
"""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor

import pyarrow.compute as pc

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
    # call traces around the Bybit cold-wallet drain of 2025-02-21 (case study C1):
    # only successful delegatecalls and value-carrying calls are kept
    "eth_traces_slim": ("eth", "traces", "2025-02-07", "2025-03-07",
                        ["block_number", "transaction_hash", "transaction_index", "trace_address",
                         "trace_type", "call_type", "from_address", "to_address", "value",
                         "block_timestamp", "status"],
                        (pc.field("status") == 1) & ((pc.field("call_type") == "delegatecall")
                                                     | (pc.field("value") > 0)),
                        "traces_slim"),
    "eth_token_transfers_c1": ("eth", "token_transfers", "2025-02-21", "2025-02-21",
                               ["token_address", "from_address", "to_address", "value",
                                "transaction_hash", "block_number", "block_timestamp"]),
}


def run(name: str, workers: int = 4) -> None:
    chain, table, start, end, cols, *extra = SPECS[name]
    row_filter, alias = extra if extra else (None, None)
    fs = s3()
    todo = list(days(start, end))
    done = 0
    with ThreadPoolExecutor(workers) as ex:
        for rec in ex.map(lambda d: fetch_day(fs, chain, table, d, cols, row_filter=row_filter,
                                              alias=alias), todo):
            if rec:
                append_index(chain, alias or table, rec)
                if not rec["status"].startswith("ok") and rec["status"] != "missing":
                    print(name, rec, flush=True)
            done += 1
            if done % 50 == 0:
                print(f"{name}: {done}/{len(todo)}", flush=True)
    print(f"{name}: finished", flush=True)


if __name__ == "__main__":
    for n in sys.argv[1:] or list(SPECS):
        run(n, workers=2 if "tx" in n or "traces" in n else 4)
