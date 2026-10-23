"""
Causal custody rules and taint tracking on Ethereum call traces (study C1).

Rows are calls (trace rows) in execution order: block, transaction index, then the call
tree in pre-order (a call before the calls it makes, siblings in order). "Earlier" history
always means earlier *transactions*: every call of a transaction is judged against the
same snapshot of history, which is updated only after the transaction.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


def trace_order_key(trace_address: pd.Series) -> pd.Series:
    """Sortable key for the call tree: '' for the root call, '00000,00002' for [0, 2].
    Lexicographic order of the keys is the pre-order (execution start) order."""
    def pad(s):
        if s is None or (isinstance(s, float) and np.isnan(s)) or s == "":
            return ""
        return ",".join(f"{int(p):05d}" for p in str(s).split(","))
    return trace_address.map(pad)


def new_pair_tx(df: pd.DataFrame, a: str, b: str, tx: str = "txpos") -> np.ndarray:
    """True for every row whose (a, b) pair did not occur in any earlier transaction
    (all rows of the pair's first transaction are new)."""
    first = df.groupby([a, b], sort=False)[tx].transform("min").to_numpy()
    return df[tx].to_numpy() == first


def prior_tx_stats(df: pd.DataFrame, who: str, val: str = "eth", tx: str = "txpos") -> tuple[np.ndarray, np.ndarray]:
    """For each row: the largest single value and the number of rows of `who` in
    transactions before the row's own transaction (NaN max and 0 count if none)."""
    per = df.groupby([who, tx], sort=False)[val].agg(["max", "size"]).reset_index().sort_values([who, tx])
    g = per.groupby(who, sort=False)
    per["prev_max"] = g["max"].cummax().groupby(per[who]).shift(1)
    per["prev_n"] = g["size"].cumsum() - per["size"]
    m = df[[who, tx]].merge(per[[who, tx, "prev_max", "prev_n"]], on=[who, tx], how="left")
    return m.prev_max.to_numpy(), m.prev_n.to_numpy()


def taint_replay(frm: np.ndarray, to: np.ndarray, eth: np.ndarray, hours: np.ndarray, start: int,
                 amount: float, hubs: set, min_new: float) -> dict:
    """Tainted-first propagation of `amount` from address `start`, over transfers given in
    execution order (all after the event that put the amount at `start`). An address spends
    traced ether before any other; only the traced part moves on; taint stops at hubs; a
    new address is traced from `min_new`. `hours` are times after the start event.

    Returns held[k] = traced ether held outside hubs at exactly k hours (after all
    transfers with time <= k), and new_by_hour[k, j] = addresses at hop 1, 2, 3+ traced
    by then."""
    n_hour = int(np.ceil(hours.max())) + 1 if len(hours) else 1
    hop = {start: 1}
    held = {start: amount}
    total = amount
    held_h = np.full(n_hour, np.nan)
    cnt = np.zeros((n_hour, 3), int)
    cnt[:, 0] = 1
    to_hubs = 0.0
    cur = 0
    for i in range(len(frm)):
        x = hours[i]
        while cur < x:
            held_h[cur] = total
            cur += 1
        f = frm[i]
        h_f = held.get(f, 0.0)
        if h_f <= 0:
            continue
        e = min(eth[i], h_f)
        held[f] = h_f - e
        total -= e
        d = to[i]
        if d in hubs:
            to_hubs += e
            continue
        if d not in hop:
            if e < min_new:          # dust below the tracing threshold leaves the traced set
                continue
            hop[d] = hop[f] + 1
            cnt[int(np.ceil(x)):, min(hop[d], 3) - 1] += 1
        held[d] = held.get(d, 0.0) + e
        total += e
    while cur < n_hour:
        held_h[cur] = total
        cur += 1
    return {"held": held_h, "counts": cnt, "traced": len(hop), "to_hubs": to_hubs}
