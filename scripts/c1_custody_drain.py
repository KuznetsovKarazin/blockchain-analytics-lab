"""
C1 - Exchange cold-wallet drain (Bybit, 2025-02-21): which on-chain signal comes first,
what it costs in alerts on ordinary days, and how fast the stolen ether disperses.

Data: Ethereum call traces 2025-02-07..2025-03-07 (AWS cache, successful delegatecalls
and value-carrying calls only) and token transfers of 2025-02-21. Addresses of the case
(the exchange's Safe multisig cold wallet and the first receiving address) are public
and appear in the trace data themselves; no third-party labels are used. Ether
transfers are value-carrying calls other than delegatecalls: a delegatecall trace
repeats the value of the call it runs in (for example a deposit into a proxy wallet)
without moving ether.

Part A - custody rules, replayed causally over all addresses of the chain. History
starts 2025-02-07; rules are evaluated 2025-02-14..2025-02-21 (seven ordinary days and
the incident day). "Earlier" means an earlier transaction (block, transaction index).
  R1  new delegate target: a contract executes a delegatecall to a target it has never
      delegatecalled before, and it made at least N earlier delegatecalls (N = 1, 3, 10).
      For a proxy or Safe wallet a new target means new code runs with its storage.
  R2  large transfer to a new counterparty: ether sent >= X (X = 100, 1,000, 10,000 ETH)
      to an address this sender has not paid before.
  R3  outlier transfer: ether sent >= 100 ETH and more than twice the sender's largest
      earlier transfer, sender with at least five earlier transfers.
Each rule is reported for all senders and for high-value senders: addresses that moved
at least 10,000 ETH (in plus out) since 2025-02-07, counted before the alerting
transaction. R1 is also reported for stable proxies, callers whose earlier delegatecalls
all went to one target (a Safe wallet delegatecalls its singleton every time). An alert
is one (address, transaction) pair. Reported: alerts per ordinary day (mean, max),
alerts on the incident day, whether and when the rule fired on the cold wallet and the
ether drained up to and including the alerting block.

Part B - dispersion after the drain. Taint starts at the first receiving address with the
drained ether and follows ether transfers in time order up to 2025-03-07 under a
tainted-first rule: an address spends its traced ether before any other ether, and only
the traced part of a transfer moves on (a new address is traced from 0.01 ETH). Taint does not pass through hubs, defined as addresses with at least H
distinct counterparties (H = 50, 100, 500) in ether transfers of 2025-02-07..2025-02-20;
hubs are typically services (exchanges, routers, bridges, swap contracts). Reported per
hour: tainted non-hub addresses and the ether they still hold (received minus sent along
traced transfers; gas fees ignored), and the times at which that holding falls below
50% and 10% of the drained ether.

Outputs: results/cases/c1_<stamp>/
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

from bclab import figures as F
from bclab.aws import cached_files, read_cached, write_input_index
from bclab.repro import atomic_to_csv, dump_json, set_seed, write_manifest

COLD = "0x1db92e2eebc8e0c075a02bea49a2935bcd2dfcf4"      # Safe multisig cold wallet
FIRST_RECEIVER = "0x47666fab8bd0ac7003bce3f5c3585383f09486e2"
HIST0, EVAL0, INCIDENT, END = "2025-02-07", "2025-02-14", "2025-02-21", "2025-03-07"
HV_VOLUME = 10_000.0
N_PRIOR = (1, 3, 10)
X_ETH = (100.0, 1_000.0, 10_000.0)
R3_MIN, R3_FACTOR, R3_HIST = 100.0, 2.0, 5
TAINT_MIN = 0.01
HUB_H = (50, 100, 500)
WEI = 1e18


COLD_ID = RECV_ID = -1
_NIB = np.full(256, 0, np.uint64)
_NIB[np.frombuffer(b"0123456789abcdef", np.uint8)] = np.arange(16, dtype=np.uint64)


def addr_key(col) -> np.ndarray:
    """64-bit key of a 0x-address: its last 16 hex digits (null -> 0). Tens of millions
    of address strings do not fit in memory; for the ~10^8 distinct addresses of a month
    the chance of any collision is below 10^-3, and the addresses the case reports are
    checked explicitly (`check_keys`)."""
    s = np.asarray(pc.fill_null(pc.utf8_lower(col), "0x0000000000000000").to_numpy(zero_copy_only=False))
    b = np.char.encode(s.astype("U42"), "ascii").astype("S42")
    raw = np.frombuffer(b.tobytes(), np.uint8).reshape(len(b), 42)[:, -16:]
    v = np.zeros(len(b), np.uint64)
    for j in range(16):
        v = (v << np.uint64(4)) | _NIB[raw[:, j]]
    return v.view(np.int64)


def key1(a: str) -> int:
    return int(addr_key(pa.array([a]))[0])


def load(start: str, end: str, value_only: bool = False) -> pd.DataFrame:
    """Call traces, one day at a time, with addresses replaced by 64-bit keys; rows in
    transaction order (days are read in order and sorted one by one)."""
    global COLD_ID, RECV_ID
    COLD_ID, RECV_ID = key1(COLD), key1(FIRST_RECEIVER)
    cols = ["block_number", "transaction_index", "call_type", "from_address", "to_address", "value",
            "block_timestamp"]
    parts = []
    for f in cached_files("eth", "traces_slim", start, end):
        x = pq.read_table(f, columns=cols)
        if value_only:      # ether transfers only: a delegatecall carries its caller's value, it moves none
            x = x.filter(pc.and_(pc.greater(x.column("value"), 0),
                                 pc.invert(pc.equal(x.column("call_type"), "delegatecall").fill_null(False))))
        d = pd.DataFrame({
            "block_number": x.column("block_number").to_numpy(),
            "transaction_index": x.column("transaction_index").to_numpy().astype(np.int32),
            "dc": pc.equal(x.column("call_type"), "delegatecall").fill_null(False).to_numpy(),
            "from_address": addr_key(x.column("from_address")),
            "to_address": addr_key(x.column("to_address")),
            "eth": x.column("value").to_numpy() / WEI,
            "block_timestamp": x.column("block_timestamp").to_pandas()})
        del x
        d = d.sort_values(["block_number", "transaction_index"], kind="stable")
        d["txpos"] = d.block_number.to_numpy() * 10_000 + d.pop("transaction_index").to_numpy()
        d["day"] = d.block_timestamp.dt.normalize()
        parts.append(d)
    t = pd.concat(parts, ignore_index=True)
    del parts
    return t


def cold_rows(start: str, end: str) -> pd.DataFrame:
    """Rows of the cold wallet with address strings (for reporting)."""
    fs = cached_files("eth", "traces_slim", start, end)
    return pd.concat([pq.read_table(f, columns=["block_number", "block_timestamp", "transaction_hash", "call_type",
                                                "from_address", "to_address", "value"],
                                    filters=[("from_address", "=", COLD)]).to_pandas() for f in fs],
                     ignore_index=True)


def check_keys(df: pd.DataFrame) -> bool:
    """The keys of the reported addresses do not collide with any other address seen
    in the cold wallet's own rows."""
    a = pd.unique(pd.concat([df.from_address, df.to_address]).dropna().str.lower())
    k = addr_key(pa.array(a))
    return len(np.unique(k)) == len(a)


def first_in_tx(df: pd.DataFrame, keys: list[str]) -> pd.Series:
    """True where `keys` occur for the first time since the start of the history
    (rows are in transaction order)."""
    return ~df.duplicated(keys, keep="first")


def prior_count(df: pd.DataFrame, key: str) -> np.ndarray:
    """Rows of `key` in earlier transactions (rows of the same transaction excluded)."""
    c = df.groupby(key).cumcount().to_numpy()
    same = df.groupby([key, "txpos"]).cumcount().to_numpy()
    return c - same


def volume_before(val: pd.DataFrame, q: pd.DataFrame, who: str) -> np.ndarray:
    """Ether moved (in plus out) by q[who] since the start of the history, in
    transactions before q's own transaction (causal 'high-value' test)."""
    ev = pd.concat([pd.DataFrame({"addr": val.from_address.to_numpy(), "txpos": val.txpos.to_numpy(),
                                  "eth": val.eth.to_numpy()}),
                    pd.DataFrame({"addr": val.to_address.to_numpy(), "txpos": val.txpos.to_numpy(),
                                  "eth": val.eth.to_numpy()})])
    ev = ev[ev.addr.isin(set(q[who]))]
    ev = ev.groupby(["addr", "txpos"], as_index=False).eth.sum().sort_values("txpos")
    ev["cum"] = ev.groupby("addr").eth.cumsum()
    qq = pd.DataFrame({"addr": q[who].to_numpy(), "txpos": q.txpos.to_numpy(),
                       "i": np.arange(len(q))}).sort_values("txpos")
    m = pd.merge_asof(qq, ev[["addr", "txpos", "cum"]], on="txpos", by="addr", allow_exact_matches=False)
    out = np.zeros(len(q))
    out[m.i.to_numpy()] = m.cum.fillna(0).to_numpy()
    return out


def summarize(name: str, flag, df: pd.DataFrame, who: str, val: pd.DataFrame,
              extra: dict[str, np.ndarray] | None = None) -> list[dict]:
    """Alerts per day for scopes: all senders, high-value senders (>= HV_VOLUME ETH moved
    since the start of the history, before the alert), and any `extra` row masks."""
    rows = []
    sel = np.asarray(flag) & (df.day >= EVAL0).to_numpy()
    ev = df[sel]
    hv = volume_before(val, ev, who) >= HV_VOLUME
    scopes = {"all": np.ones(len(ev), bool), "high-value": hv}
    for k, m in (extra or {}).items():
        scopes[k] = m[sel]
        scopes[k + " & high-value"] = m[sel] & hv
    for scope, m in scopes.items():
        a = ev[m].drop_duplicates([who, "txpos"])
        per_day = a.groupby("day").size().reindex(pd.date_range(EVAL0, INCIDENT), fill_value=0)
        ordinary = per_day.iloc[:-1]
        cw = a[a[who] == COLD_ID]
        rows.append({"rule": name, "scope": scope,
                     "alerts_per_day_mean": float(ordinary.mean()), "alerts_per_day_max": int(ordinary.max()),
                     "alerts_incident_day": int(per_day.iloc[-1]),
                     "cold_wallet_alerts_ordinary": int((cw.day < INCIDENT).sum()),
                     "cold_wallet_first_alert_block_incident_day":
                         int(cw[cw.day == INCIDENT].block_number.min()) if (cw.day == INCIDENT).any() else None})
    return rows


def part_a(t: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    val = t[(t.eth > 0) & ~t.dc]        # a delegatecall reports the value of the call it runs in; no ether moves
    rows = []
    dc = t[t.dc].reset_index(drop=True)
    new_pair = first_in_tx(dc, ["from_address", "to_address"])
    prior = prior_count(dc, "from_address")
    # distinct delegate targets of the caller before this row: a "stable proxy" has
    # used exactly one target so far (a Safe wallet calls its singleton every time)
    targets_before = new_pair.groupby(dc.from_address).cumsum().to_numpy() - new_pair.to_numpy()
    stable = {"stable proxy": targets_before == 1}
    for n in N_PRIOR:
        rows += summarize(f"R1 new delegate target (N>={n})", new_pair & (prior >= n), dc, "from_address", val,
                          extra=stable)

    v = val.reset_index(drop=True)
    new_cp = first_in_tx(v, ["from_address", "to_address"])
    for x in X_ETH:
        rows += summarize(f"R2 >= {x:,.0f} ETH to new counterparty", new_cp & (v.eth >= x), v, "from_address", val)
    g = v.groupby("from_address")
    prev_max = g.eth.cummax().groupby(v.from_address).shift(1)
    nprev = g.cumcount()
    r3 = (v.eth >= R3_MIN) & (nprev >= R3_HIST) & (v.eth > R3_FACTOR * prev_max)
    rows += summarize("R3 outlier transfer (>2x own max)", r3, v, "from_address", val)
    res = pd.DataFrame(rows)

    # the incident on the cold wallet
    inc = t[(t.day == INCIDENT) & ((t.from_address == COLD_ID) | (t.to_address == COLD_ID))]
    drain = inc[(inc.from_address == COLD_ID) & (inc.to_address == RECV_ID) & (inc.eth > 0)]
    drain_block = int(drain.block_number.min())
    drained_eth = float(drain.eth.sum())
    first_bad = dc[(dc.from_address == COLD_ID) & new_pair & (dc.day == INCIDENT)]
    ts = inc.drop_duplicates("block_number").set_index("block_number").block_timestamp
    lost = []
    for _, r in res.iterrows():
        b = r.cold_wallet_first_alert_block_incident_day
        lost.append(None if pd.isna(b) else float(drain[drain.block_number <= b].eth.sum()))
    res["eth_lost_when_first_cold_wallet_alert"] = lost      # an alert on the drain itself comes too late
    cr = cold_rows(HIST0, INCIDENT)
    cdc = cr[cr.call_type == "delegatecall"].sort_values("block_number", kind="stable")
    before = cdc[cdc.block_timestamp < INCIDENT]
    known = set(before.to_address)
    new_t = []
    for r in cdc[cdc.block_timestamp >= INCIDENT].itertuples():
        if r.to_address not in known:
            known.add(r.to_address)
            new_t.append({"block": int(r.block_number), "time": str(r.block_timestamp),
                          "target": r.to_address, "tx": r.transaction_hash})
    first_block = int(first_bad.block_number.min())
    assert new_t and new_t[0]["block"] == first_block, "string and key views of the cold wallet disagree"
    info = {"cold_wallet_volume_before_first_new_target":
                float(volume_before(val, first_bad.iloc[:1], "from_address")[0]),
            "address_keys_unique_in_cold_wallet_rows": check_keys(cr),
            "cold_wallet_delegatecalls_before_incident_day": int(len(before)),
            "cold_wallet_delegate_targets_before": sorted(before.to_address.unique()),
            "new_delegate_targets_incident_day": new_t,
            "drain_block": drain_block, "drain_time": str(ts.get(drain_block)), "drained_eth": drained_eth,
            "first_new_target_block": first_block,
            "lead_blocks": int(drain_block - first_block),
            "lead_seconds": float((ts.get(drain_block) - ts.get(first_block)).total_seconds())}
    return res, info


def tokens_out() -> pd.DataFrame:
    tt, _ = read_cached("eth", "token_transfers", INCIDENT, INCIDENT)
    # addresses in this table are 32-byte words: keep the last 20 bytes
    def norm(s):
        return "0x" + s.str.lower().str[-40:]
    x = tt[(norm(tt.from_address) == COLD) & (norm(tt.to_address) == FIRST_RECEIVER)]
    return (x.groupby("token_address").agg(raw_amount=("value", "sum"), transfers=("value", "size"),
                                           first_block=("block_number", "min"), time=("block_timestamp", "min"))
            .reset_index().sort_values("first_block"))


def part_b(t: pd.DataFrame, drain_block: int, drained_eth: float) -> tuple[pd.DataFrame, list[dict]]:
    base = t[(t.eth > 0) & (t.day < INCIDENT)]
    deg = pd.concat([base[["from_address", "to_address"]].rename(columns={"from_address": "a", "to_address": "b"}),
                     base[["to_address", "from_address"]].rename(columns={"to_address": "a", "from_address": "b"})])
    deg = deg.drop_duplicates().groupby("a").size()
    v = t[(t.eth > 0) & (t.block_number > drain_block)]
    frm, to, eth, ts = v.from_address.to_numpy(), v.to_address.to_numpy(), v.eth.to_numpy(), v.block_timestamp.to_numpy()
    t0 = t[t.block_number == drain_block].block_timestamp.iloc[0]
    hours = ((ts - np.datetime64(t0)) / np.timedelta64(1, "h"))
    series, summ = [], []
    for h in HUB_H:
        hubs = set(deg[deg >= h].index)
        hop = {RECV_ID: 1}
        held = {RECV_ID: drained_eth}
        total_held = drained_eth
        n_hour = int(np.ceil(hours.max())) + 1
        cnt_by_hour = np.zeros((n_hour, 3), int)
        cnt_by_hour[:, 0] = 1
        held_by_hour = np.full(n_hour, np.nan)
        to_hubs = 0.0
        cur = 0
        for i in range(len(frm)):
            hr = int(hours[i])
            while cur < hr:
                held_by_hour[cur] = total_held
                cur += 1
            f = frm[i]
            h_f = held.get(f, 0.0)
            if h_f <= 0:
                continue
            e = min(eth[i], h_f)          # tainted-first: only the traced part moves on
            held[f] = h_f - e
            total_held -= e
            d = to[i]
            if d in hubs:
                to_hubs += e
                continue
            if d not in hop:
                if e < TAINT_MIN:
                    continue
                hop[d] = hop[f] + 1
                cnt_by_hour[hr:, min(hop[d], 3) - 1] += 1
            held[d] = held.get(d, 0.0) + e
            total_held += e
        while cur < n_hour:
            held_by_hour[cur] = total_held
            cur += 1
        frac = held_by_hour / drained_eth
        def first_below(p):
            idx = np.flatnonzero(frac < p)
            return float(idx[0]) if len(idx) else None
        summ.append({"hub_threshold": h, "hubs": len(hubs), "traced_addresses": len(hop),
                     "eth_into_hubs": to_hubs, "hours_to_below_50pct": first_below(0.5),
                     "hours_to_below_10pct": first_below(0.1),
                     "held_share_after_24h": float(frac[min(24, n_hour - 1)]),
                     "held_share_after_7d": float(frac[min(168, n_hour - 1)]),
                     "held_share_end": float(frac[-1])})
        series.append(pd.DataFrame({"hub_threshold": h, "hour": np.arange(n_hour), "held_eth": held_by_hour,
                                    "held_share": frac, "hop1": cnt_by_hour[:, 0], "hop2": cnt_by_hour[:, 1],
                                    "hop3plus": cnt_by_hour[:, 2]}))
    return pd.concat(series, ignore_index=True), summ


def figure(out: Path, inc: pd.DataFrame, info: dict, series: pd.DataFrame) -> None:
    """`inc`: the drain transfers (cold wallet -> first receiver) of the incident day."""
    F.style()
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(6.5, 2.7))
    ax = axes[0]
    t_first = pd.Timestamp(info["new_delegate_targets_incident_day"][0]["time"])
    m = lambda s: (pd.Timestamp(s) - t_first).total_seconds() / 60  # noqa: E731
    x = [-2, 0] + [m(s) for s in inc.block_timestamp] + [6]
    y = [0, 0] + list(np.cumsum(inc.eth) / 1e3) + [inc.eth.sum() / 1e3]
    ax.step(x, y, where="post", color="0", lw=0.9)
    ax.axvline(0, color="0.4", ls="--", lw=0.8)
    ax.text(0.15, y[-1] * 0.55, "R1: new delegate\ntarget", fontsize=6)
    ax.axvline(m(info["drain_time"]), color="0.6", ls=":", lw=0.8)
    ax.text(m(info["drain_time"]) + 0.15, y[-1] * 0.15, "R2: large transfer\nto new counterparty", fontsize=6)
    ax.set_xlabel("minutes after first new delegate target")
    ax.set_ylabel("ether drained, thousand ETH")
    ax.set_title("(a) cold wallet, 21 Feb 2025")
    ax = axes[1]
    for i, h in enumerate(HUB_H):
        s = series[series.hub_threshold == h]
        ax.plot(s.hour / 24, s.held_share * 100, color="0" if i != 1 else "0.5", ls=F.LINES[i % len(F.LINES)],
                lw=0.8, label=f"hubs: >= {h} counterparties")
    ax.set_xlabel("days after the drain")
    ax.set_ylabel("% of drained ETH still held")
    ax.set_title("(b) dispersion of the stolen ether")
    ax.legend(frameon=True, fontsize=6)
    fig.subplots_adjust(wspace=0.45)
    F.save(fig, out, "fig_c1")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    set_seed(0)
    out = Path(args.out or f"results/cases/c1_{time.strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)
    t = load(HIST0, INCIDENT)
    n_a = len(t)
    rules, info = part_a(t)
    inc = t[(t.day == INCIDENT) & (t.from_address == COLD_ID) & (t.to_address == RECV_ID) & (t.eth > 0)].copy()
    del t
    atomic_to_csv(rules, out / "rules.csv", index=False)
    tok = tokens_out()
    atomic_to_csv(tok, out / "tokens_drained.csv", index=False)
    tv = load(HIST0, END, value_only=True)
    series, disp = part_b(tv, info["drain_block"], info["drained_eth"])
    n_b = len(tv)
    del tv
    atomic_to_csv(series, out / "dispersion_hourly.csv", index=False)
    figure(out, inc, info, series)
    dump_json({"rows_part_a": n_a, "value_rows_part_b": n_b, "incident": info, "dispersion": disp},
              out / "summary.json")
    tr_files = cached_files("eth", "traces_slim", HIST0, END)
    tt_files = cached_files("eth", "token_transfers", INCIDENT, INCIDENT)
    write_input_index(out, "eth", "traces_slim", tr_files)
    write_input_index(out, "eth", "token_transfers", tt_files)
    write_manifest(out, script="scripts/c1_custody_drain.py",
                   data_sets={"eth_traces_slim": tr_files, "eth_token_transfers": tt_files},
                   config={"hist0": HIST0, "eval0": EVAL0, "incident": INCIDENT, "end": END, "hv_volume": HV_VOLUME,
                           "n_prior": N_PRIOR, "x_eth": X_ETH, "r3": [R3_MIN, R3_FACTOR, R3_HIST],
                           "taint_min": TAINT_MIN, "hub_h": HUB_H})
    pd.set_option("display.width", 200)
    print(rules.to_string())
    print(tok.to_string())
    print(pd.DataFrame(disp).to_string())
    print(info)


if __name__ == "__main__":
    main()
