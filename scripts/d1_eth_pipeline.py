"""
D1 - From raw public blockchain records to a feature table: what goes wrong on the way?

Data: AWS Public Blockchain Data (local cache, see d0_cache_aws.py)
  * Ethereum transactions of two weeks: 2022-07-25..31 and 2024-03-04..10
  * Ethereum and Bitcoin block headers 2023-01-01..2025-12-31
Labels: OFAC SDN Ethereum addresses (0xB10C extracted lists) and the
MyEtherWallet community darklist, both at pinned commits (00_fetch_data.py).

Parts
  (a) audit of the transaction tables: encodings of "missing", failed
      transactions, zero-value share, value precision (value is stored as a
      float64 number of wei, exact only below 2**53 wei), heavy tails;
  (b) time-series hygiene of block headers: Ethereum missed slots (gaps that are
      multiples of 12 s), Bitcoin timestamps that go backwards;
  (c) sender-level features for 2024-03-04..10 (ether sent counts successful
      transactions only; the value of failed attempts is a separate feature) and four
      normalisations
      (z-score, log1p + z-score, robust median/IQR, rank); overlap of the top 1%
      most anomalous senders under a scale-sensitive detector (k-NN distance)
      and under Isolation Forest;
  (d) label coverage: how many transactions and senders touch a listed address.

Outputs: results/data/d1_<stamp>/
"""

from __future__ import annotations

import argparse
import itertools
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import NearestNeighbors

from bclab import figures as F
from bclab.aws import cached_files, read_cached, write_input_index
from bclab.repro import atomic_to_csv, dump_json, set_seed, write_manifest

WEEKS = {"2022w30": ("2022-07-25", "2022-07-31"), "2024w10": ("2024-03-04", "2024-03-10")}
COLS = ["block_number", "block_timestamp", "from_address", "to_address", "value", "gas", "gas_price",
        "receipt_gas_used", "receipt_status", "transaction_type", "receipt_contract_address", "nonce"]
WEI = 1e18
OFAC_REPO = Path("data/raw/ofac-addresses")
OFAC_FILE = "sanctioned_addresses_ETH.txt"
OFAC_SNAPSHOTS = {"ofac_2022-09-16": "96f89d770659edad674fa2ea101a0d79a7f4c768",
                  "ofac_2024-02-21": "0650c71e7a7561dd0f97bdda49110eb56b59a7fa",
                  "ofac_2026-10-01": "6ae2472c439b9bb2788f8df662052ae31854aa97"}
DARK = Path("data/raw/ethereum-lists/src/addresses/addresses-darklist.json")
N_SAMPLE = 100_000
TOP = 0.01


def audit(df: pd.DataFrame, week: str) -> dict:
    v = df["value"].to_numpy()
    gp = df["gas_price"].to_numpy() / 1e9
    # contract creations carry the literal string "None" in to_address
    to_empty = df["to_address"].fillna("").isin(["", "None"])
    create = df["receipt_contract_address"].fillna("") != ""
    return {"week": week, "transactions": len(df), "blocks": df.block_number.nunique(),
            "senders": df.from_address.nunique(),
            "to_none_string_share": float((df.to_address == "None").mean()),
            "to_null_share": float(df.to_address.isna().mean()),
            "contract_address_empty_string_share": float((df.receipt_contract_address == "").mean()),
            "contract_creation_share": float(create.mean()),
            "to_empty_equals_creation": bool((to_empty == create).all()),
            "failed_share": float((df.receipt_status == 0).mean()),
            "zero_value_share": float((v == 0).mean()),
            "value_above_2p53_wei_share": float((v > 2 ** 53).mean()),
            "value_eth_median_nonzero": float(np.median(v[v > 0]) / WEI),
            "value_eth_p99": float(np.quantile(v, 0.99) / WEI), "value_eth_max": float(v.max() / WEI),
            "top1pct_value_share": float(np.sort(v)[-len(v) // 100:].sum() / v.sum()),
            "gas_price_gwei_median": float(np.median(gp)), "gas_price_gwei_p99": float(np.quantile(gp, 0.99)),
            "gas_price_kurtosis": float(stats.kurtosis(gp)),
            "log_gas_price_kurtosis": float(stats.kurtosis(np.log(gp + 1e-9))),
            "type_shares": json.dumps({int(k): round(float(s), 4)
                                       for k, s in df.transaction_type.value_counts(normalize=True).items()})}


def blocks_hygiene() -> tuple[dict, pd.DataFrame]:
    eth, _ = read_cached("eth", "blocks", "2023-01-01", "2025-12-31", ["number", "timestamp"])
    eth = eth.sort_values("number").drop_duplicates("number")
    t = eth.timestamp.astype("int64").to_numpy() // 10 ** 9
    dt = np.diff(t)
    num_gap = np.diff(eth.number.to_numpy())
    btc, _ = read_cached("btc", "blocks", "2023-01-01", "2025-12-31", ["number", "timestamp", "mediantime"])
    btc = btc.sort_values("number").drop_duplicates("number")
    bt = btc.timestamp.astype("int64").to_numpy() // 10 ** 9
    bdt = np.diff(bt)
    res = {"eth_blocks": len(eth), "eth_number_gaps": int((num_gap != 1).sum()),
           "eth_dt_not_multiple_of_12": int((dt % 12 != 0).sum()),
           "eth_missed_slots": int((dt // 12 - 1).sum()),
           "eth_missed_slot_rate": float((dt // 12 - 1).sum() / (dt // 12).sum()),
           "eth_dt_max_s": int(dt.max()),
           "btc_blocks": len(btc), "btc_backwards_timestamps": int((bdt < 0).sum()),
           "btc_backwards_share": float((bdt < 0).mean()), "btc_dt_min_s": int(bdt.min()),
           "btc_dt_mean_s": float(bdt.mean()), "btc_dt_cv": float(bdt.std() / bdt.mean()),
           "btc_mediantime_monotone": bool((np.diff(btc.mediantime.astype("int64").to_numpy()) >= 0).all())}
    gaps = pd.DataFrame({"chain": "eth", "dt_s": dt})
    gaps = pd.concat([gaps, pd.DataFrame({"chain": "btc", "dt_s": bdt})])
    return res, gaps


def sender_features(df: pd.DataFrame) -> pd.DataFrame:
    ts = df.block_timestamp.astype("int64") // 10 ** 9
    ok = df.receipt_status == 1
    df = df.assign(ts=ts, fee=df.receipt_gas_used * df.gas_price / WEI,
                   eth_sent=np.where(ok, df.value / WEI, 0.0),             # value actually transferred
                   eth_failed=np.where(ok, 0.0, df.value / WEI),           # value of failed attempts
                   failed=(~ok).astype(int),
                   create=(df.receipt_contract_address.fillna("") != "").astype(int))
    g = df.groupby("from_address")
    f = pd.DataFrame({"n_tx": g.size(), "n_to": g.to_address.nunique(), "eth_sent": g.eth_sent.sum(),
                      "eth_max_sent": g.eth_sent.max(), "eth_failed_attempts": g.eth_failed.sum(),
                      "fee_eth": g.fee.sum(), "gas_price_gwei": g.gas_price.mean() / 1e9,
                      "failed_share": g.failed.mean(), "creations": g.create.sum(),
                      "span_h": (g.ts.max() - g.ts.min()) / 3600, "nonce_max": g.nonce.max()})
    return f


def normalise(f: pd.DataFrame, how: str) -> np.ndarray:
    X = f.to_numpy(dtype=float)
    if how == "z":
        return (X - X.mean(0)) / (X.std(0) + 1e-12)
    if how == "log_z":
        L = np.log1p(np.maximum(X, 0))
        return (L - L.mean(0)) / (L.std(0) + 1e-12)
    if how == "robust":
        med = np.median(X, 0)
        iqr = np.quantile(X, 0.75, 0) - np.quantile(X, 0.25, 0)
        return (X - med) / np.where(iqr > 0, iqr, X.std(0) + 1e-12)
    if how == "rank":
        return np.column_stack([stats.rankdata(c) / len(c) for c in X.T])
    raise ValueError(how)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    set_seed(0)
    out = Path(args.out or f"results/data/d1_{time.strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)

    import subprocess
    lists = {}
    for name, sha in OFAC_SNAPSHOTS.items():
        txt = subprocess.run(["git", "show", f"{sha}:{OFAC_FILE}"], cwd=OFAC_REPO, check=True,
                             capture_output=True, text=True).stdout
        lists[name] = {a.strip().lower() for a in txt.split() if a.strip()}
    lists["darklist"] = {d["address"].lower() for d in json.loads(DARK.read_text())}
    ofac, dark = lists["ofac_2026-10-01"], lists["darklist"]
    aud, cov, files_used = [], [], []
    feats = None
    for week, (a, b) in WEEKS.items():
        df, files = read_cached("eth", "transactions", a, b, COLS)
        files_used += files
        aud.append(audit(df, week))
        fr, to = df.from_address.str.lower(), df.to_address.fillna("").str.lower()
        for name, lst in lists.items():
            hit = fr.isin(lst) | to.isin(lst)
            seen = set(fr[fr.isin(lst)]) | set(to[to.isin(lst)])
            cov.append({"week": week, "list": name, "list_size": len(lst), "tx_touching": int(hit.sum()),
                        "tx_share": float(hit.mean()), "listed_addresses_seen": len(seen),
                        "senders_touching": int(df.from_address[hit].nunique()),
                        "sender_share": float(df.from_address[hit].nunique() / df.from_address.nunique())})
        if week == "2024w10":
            feats = sender_features(df)
            lab = feats.index.str.lower().isin(set().union(*lists.values()))
        del df
        print(week, "done", flush=True)
    aud = pd.DataFrame(aud)
    atomic_to_csv(aud, out / "audit.csv", index=False)
    cov = pd.DataFrame(cov)
    atomic_to_csv(cov, out / "label_coverage.csv", index=False)

    hyg, gaps = blocks_hygiene()
    dump_json(hyg, out / "blocks_hygiene.json")
    qs = gaps.groupby("chain").dt_s.describe(percentiles=[0.01, 0.5, 0.99])
    atomic_to_csv(qs.reset_index(), out / "block_interval_quantiles.csv", index=False)

    # (c) normalisation and the identity of "the anomalies"
    desc = feats.describe(percentiles=[0.5, 0.99]).T
    desc["skew"] = stats.skew(feats.to_numpy(float), axis=0)
    atomic_to_csv(desc.reset_index(names="feature"), out / "sender_features_describe.csv", index=False)
    rng = np.random.default_rng(0)
    idx = rng.choice(len(feats), min(N_SAMPLE, len(feats)), replace=False)
    fs = feats.iloc[idx]
    k_top = int(TOP * len(fs))
    flagged, dominant = {}, []
    for how in ("z", "log_z", "robust", "rank"):
        Z = normalise(fs, how)
        nn = NearestNeighbors(n_neighbors=11).fit(Z)
        dist, _ = nn.kneighbors(Z)
        s_knn = dist[:, -1]
        iso = IsolationForest(n_estimators=300, random_state=0, n_jobs=4).fit(Z)
        s_iso = -iso.score_samples(Z)
        for det, s in (("knn", s_knn), ("iforest", s_iso)):
            top = np.argsort(-s)[:k_top]
            flagged[(how, det)] = set(top)
            # which feature makes flagged senders extreme: largest |rank deviation| from median
            R = normalise(fs, "rank")[top]
            dom = pd.Series(np.array(fs.columns)[np.abs(R - 0.5).argmax(1)]).value_counts(normalize=True)
            dominant.append({"normalisation": how, "detector": det, "top_features": json.dumps(dom.head(3).round(3).to_dict()),
                             "median_n_tx_flagged": float(fs.n_tx.iloc[top].median()),
                             "labelled_in_top": int(lab[idx][top].sum()), "labelled_in_sample": int(lab[idx].sum())})
        print(how, "done", flush=True)
    jac = []
    for (a, b) in itertools.combinations(flagged, 2):
        A, B = flagged[a], flagged[b]
        jac.append({"a": "/".join(a), "b": "/".join(b), "jaccard": len(A & B) / len(A | B)})
    jac = pd.DataFrame(jac)
    atomic_to_csv(jac, out / "top_overlap.csv", index=False)
    atomic_to_csv(pd.DataFrame(dominant), out / "flagged_profile.csv", index=False)

    F.style()
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(6.5, 2.7))
    for i, (col, lab_) in enumerate((("eth_sent", "ETH sent (successful tx)"), ("n_tx", "transactions sent"),
                                     ("gas_price_gwei", "mean gas price, gwei"))):
        x = np.sort(feats[col].to_numpy(float))
        x = x[x > 0]
        ccdf = 1 - np.arange(len(x)) / len(x)
        axes[0].loglog(x, ccdf, color="0", ls=F.LINES[i], label=lab_)
    axes[0].set_xlim(1e-3, 1e7)
    axes[0].set_xlabel("value per sender (one week)")
    axes[0].set_ylabel("share of senders >= value")
    axes[0].set_title("(a) heavy tails, 2024-03-04..10")
    axes[0].legend(frameon=False)
    keys = [k for k in flagged if k[1] == "knn"] + [k for k in flagged if k[1] == "iforest"]
    M = np.array([[len(flagged[a] & flagged[b]) / len(flagged[a] | flagged[b]) for b in keys] for a in keys])
    im = axes[1].imshow(M, cmap="Greys", vmin=0, vmax=1)
    axes[1].grid(False)
    labs = [f"{h}/{'kNN' if d == 'knn' else 'IF'}" for h, d in keys]
    axes[1].set_xticks(range(len(keys)), labs, rotation=60, ha="right", fontsize=6)
    axes[1].set_yticks(range(len(keys)), labs, fontsize=6)
    for i_ in range(len(keys)):
        for j_ in range(len(keys)):
            axes[1].text(j_, i_, f"{M[i_, j_]:.2f}", ha="center", va="center", fontsize=5,
                         color="white" if M[i_, j_] > 0.5 else "black")
    axes[1].set_title("(b) overlap of top-1% senders")
    fig.colorbar(im, ax=axes[1], fraction=0.046)
    fig.subplots_adjust(wspace=0.6)
    F.save(fig, out, "fig_d1")

    summary = {"audit": aud.to_dict(orient="records"), "blocks": hyg, "coverage": cov.to_dict(orient="records"),
               "overlap": jac.to_dict(orient="records"), "n_senders": len(feats), "sample": len(fs)}
    dump_json(summary, out / "summary.json")
    bl = {c: cached_files(c, "blocks", "2023-01-01", "2025-12-31") for c in ("eth", "btc")}
    write_input_index(out, "eth", "transactions", files_used)
    for c, fl in bl.items():
        write_input_index(out, c, "blocks", fl)
    write_manifest(out, script="scripts/d1_eth_pipeline.py",
                   data_sets={"eth_transactions": files_used, "eth_blocks": bl["eth"], "btc_blocks": bl["btc"]},
                   config={"weeks": WEEKS, "n_sample": N_SAMPLE, "top": TOP, "knn_k": 10,
                           "ofac_snapshots": OFAC_SNAPSHOTS},
                   data_files=[DARK])
    print(aud.T.to_string())
    print(json.dumps(hyg, indent=1))
    print(cov.to_string())
    print(pd.DataFrame(dominant).to_string())
    print(jac.sort_values("jaccard").to_string())


if __name__ == "__main__":
    main()
