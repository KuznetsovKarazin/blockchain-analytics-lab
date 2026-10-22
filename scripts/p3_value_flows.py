"""
P3 - Value-flow patterns in Ethereum transactions: fixed denominations, round
values and large transfers.

Data: Ethereum transactions 2022-07-25..31 and 2024-03-04..10 (AWS cache).
Reference list: OFAC SDN Ethereum addresses at the 2022-09-16 revision of the
0xB10C extracted lists (used ONLY to check what an unsupervised rule finds).

  (a) fixed-denomination recipients: for every recipient with at least 30
      incoming value-bearing transactions in the week, the share of those
      transactions that carry exactly the recipient's most common value, and
      the share at a power of ten between 0.001 and 1000 ETH. Mixing pools of
      the Tornado Cash type accept only fixed amounts. Two candidate rules:
        single: modal share >= 0.99 and modal value = 10^k ETH
        multi:  >= 90% of deposits at 10^k ETH and at least three values of k
                each carrying >= 5% of deposits (a router in front of pools)
      Hits are checked against the reference list.
  (b) round values: share of value-bearing transactions whose ETH value has at
      most two significant digits, by value decile.
  (c) large transfers: a robust threshold on log value (median + 6 MAD) versus
      a fixed 1000 ETH threshold; how many transfers each flags per day.

Outputs: results/patterns/p3_<stamp>/
"""

from __future__ import annotations

import argparse
import subprocess
import time
from pathlib import Path

import numpy as np
import pandas as pd

from bclab import figures as F
from bclab.aws import read_cached
from bclab.repro import atomic_to_csv, dump_json, set_seed, write_manifest

WEEKS = {"2022w30": ("2022-07-25", "2022-07-31"), "2024w10": ("2024-03-04", "2024-03-10")}
OFAC_REPO, OFAC_SHA = Path("data/raw/ofac-addresses"), "96f89d770659edad674fa2ea101a0d79a7f4c768"
WEI = 10 ** 18
MIN_IN = 30


def two_sig(eth: np.ndarray) -> np.ndarray:
    """True where the value has at most two significant digits (e.g. 0.25, 3, 1200)."""
    e = np.floor(np.log10(eth))
    scaled = eth / 10 ** (e - 1)
    return np.abs(scaled - np.round(scaled)) < 1e-6


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    set_seed(0)
    out = Path(args.out or f"results/patterns/p3_{time.strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)
    txt = subprocess.run(["git", "show", f"{OFAC_SHA}:sanctioned_addresses_ETH.txt"], cwd=OFAC_REPO,
                         check=True, capture_output=True, text=True).stdout
    ofac = {a.strip().lower() for a in txt.split() if a.strip()}

    cand_rows, round_rows, large_rows, hits_by_week = [], [], [], {}
    for week, (a, b) in WEEKS.items():
        df, _ = read_cached("eth", "transactions", a, b,
                            ["block_timestamp", "from_address", "to_address", "value", "receipt_status"])
        df = df[(df.receipt_status == 1) & (df.value > 0) & (df.to_address != "None")]
        df = df.assign(eth=df.value / WEI, to=df.to_address.str.lower())
        g = df.groupby("to")
        n_in = g.size()
        keep = n_in[n_in >= MIN_IN].index
        sub = df[df.to.isin(keep)]
        mode = sub.groupby("to").eth.agg(lambda v: v.value_counts().index[0])
        share = sub.assign(m=sub.to.map(mode)).pipe(lambda x: (x.eth == x.m).groupby(x.to).mean())
        cand = pd.DataFrame({"n_in": n_in[keep], "modal_eth": mode, "modal_share": share,
                             "senders": sub.groupby("to").from_address.nunique()})
        lg = np.log10(cand.modal_eth)
        cand["power_of_ten"] = np.isclose(lg, np.round(lg), atol=1e-9) & (lg >= -3) & (lg <= 3)
        # multi-denomination signature: most deposits at 10^k ETH, several k in use
        lv = np.log10(sub.eth)
        p10 = np.isclose(lv, np.round(lv), atol=1e-9) & (lv >= -3) & (lv <= 3)
        sub = sub.assign(p10=p10, k=np.where(p10, np.round(lv), np.nan))
        cand["pow10_share"] = sub.groupby("to").p10.mean()
        kshare = sub[sub.p10].groupby(["to", "k"]).size().div(n_in[keep], level="to")
        cand["n_denoms"] = (kshare >= 0.05).groupby(level="to").sum().reindex(cand.index).fillna(0).astype(int)
        cand["rule_single"] = (cand.modal_share >= 0.99) & cand.power_of_ten
        cand["rule_multi"] = (cand.pow10_share >= 0.9) & (cand.n_denoms >= 3)
        cand["rule_hit"] = cand.rule_single | cand.rule_multi
        cand["in_reference_list"] = cand.index.isin(ofac)
        cand["week"] = week
        cand_rows.append(cand.reset_index())
        hits_by_week[week] = cand[cand.rule_hit]

        # (b) round values by decile
        v = df.eth.to_numpy()
        dec = pd.qcut(v, 10, labels=False, duplicates="drop")
        rs = pd.Series(two_sig(v)).groupby(dec).mean()
        for k_, val in rs.items():
            round_rows.append({"week": week, "decile": int(k_) + 1, "two_sig_share": float(val)})
        # (c) large transfers
        lv = np.log10(v)
        med = np.median(lv)
        mad = np.median(np.abs(lv - med)) * 1.4826
        thr = 10 ** (med + 6 * mad)
        days = df.block_timestamp.dt.normalize().nunique()
        large_rows.append({"week": week, "robust_threshold_eth": float(thr),
                           "robust_flags_per_day": float((v >= thr).sum() / days),
                           "fixed_1000_flags_per_day": float((v >= 1000).sum() / days),
                           "value_bearing_tx": len(v), "median_eth": float(10 ** med)})
        del df
        print(week, flush=True)

    cand = pd.concat(cand_rows, ignore_index=True)
    atomic_to_csv(cand.sort_values(["week", "rule_hit", "n_in"], ascending=[True, False, False]),
                  out / "recipient_candidates.csv", index=False)
    hits = cand[cand.rule_hit]
    atomic_to_csv(hits, out / "rule_hits.csv", index=False)
    rnd = pd.DataFrame(round_rows)
    atomic_to_csv(rnd, out / "round_values.csv", index=False)
    lg_ = pd.DataFrame(large_rows)
    atomic_to_csv(lg_, out / "large_transfers.csv", index=False)
    summ = (cand.groupby("week")
            .agg(recipients_ge30=("n_in", "size"), single_hits=("rule_single", "sum"),
                 single_in_list=("in_reference_list", lambda s: int((s & cand.loc[s.index, "rule_single"]).sum())),
                 multi_hits=("rule_multi", "sum"),
                 multi_in_list=("in_reference_list", lambda s: int((s & cand.loc[s.index, "rule_multi"]).sum())),
                 list_recipients_ge30=("in_reference_list", "sum"))
            .reset_index())
    atomic_to_csv(summ, out / "rule_summary.csv", index=False)

    F.style()
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(6.5, 2.7))
    c = cand[cand.week == "2022w30"]
    for sel, kw, lab in ((~c.in_reference_list, dict(color="0.65", s=3, marker="."), "other recipients"),
                         (c.in_reference_list, dict(color="0", s=18, marker="x"), "on reference list")):
        axes[0].scatter(c.n_in[sel], c.modal_share[sel], label=lab, **kw)
    axes[0].set_xscale("log")
    axes[0].axhline(0.99, color="0", ls=":", lw=0.8)
    axes[0].set_xlabel("incoming value-bearing tx (one week)")
    axes[0].set_ylabel("share at the modal value")
    axes[0].set_title("(a) fixed-denomination recipients, 2022-07-25..31")
    axes[0].legend(frameon=False, fontsize=6, loc="lower right")
    for i, week in enumerate(WEEKS):
        r = rnd[rnd.week == week]
        axes[1].plot(r.decile, r.two_sig_share, color="0", ls=F.LINES[i], marker=F.MARKERS[i], ms=3, label=week)
    axes[1].set_xlabel("value decile (1 = smallest)")
    axes[1].set_ylabel("share with <= 2 significant digits")
    axes[1].set_title("(b) round values")
    axes[1].legend(frameon=False)
    F.save(fig, out, "fig_p3")
    dump_json({"rule_summary": summ.to_dict(orient="records"),
               "hits": hits[["week", "to", "n_in", "modal_eth", "modal_share", "pow10_share", "n_denoms", "senders",
                                     "rule_single", "rule_multi", "in_reference_list"]].to_dict(orient="records"),
               "large": lg_.to_dict(orient="records")}, out / "summary.json")
    write_manifest(out, script="scripts/p3_value_flows.py",
                   config={"weeks": WEEKS, "min_in": MIN_IN, "ofac_sha": OFAC_SHA, "modal_share": 0.99})
    print(summ.to_string())
    print(hits[["week", "to", "n_in", "modal_eth", "modal_share", "pow10_share", "n_denoms", "senders",
                                     "rule_single", "rule_multi", "in_reference_list"]].to_string())
    print(lg_.to_string())
    print(rnd.pivot(index="decile", columns="week", values="two_sig_share"))


if __name__ == "__main__":
    main()
