"""
P2 - Network-based analysis on the Elliptic transaction graph.

Each Elliptic time step is a separate graph (edges never cross steps). For the
training steps 1-30 we compute, per step:
  in-degree, out-degree and PageRank (alpha 0.85) on the directed graph;
  betweenness (sampled, k = 500 pivots, fixed seed) and the local clustering
  coefficient on its undirected version; and Louvain communities (networkx,
  resolution 1, fixed seed).

Questions
  (a) Are illicit transactions more central? ROC-AUC and AP of each centrality
      used directly as an illicit score, against the prevalence among labelled
      nodes (AUC < 0.5 means illicit nodes are LESS central).
  (b) Do communities group behaviour? Label homophily: share of labelled edges
      joining two illicit or two licit nodes, versus p^2 + (1-p)^2, the share
      expected if labels were independent of the graph (a formula, not a
      shuffle experiment); and a leave-one-out community score (illicit share of the
      other labelled members of a node's community) evaluated by AP.

Outputs: results/patterns/p2_<stamp>/
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import networkx as nx
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from bal.data.elliptic import TRAIN_STEPS, load_elliptic
from bclab import figures as F
from bclab.repro import atomic_to_csv, dump_json, set_seed, write_manifest

DATA = Path("data/raw/elliptic")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    set_seed(0)
    out = Path(args.out or f"results/patterns/p2_{time.strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)
    d = load_elliptic(DATA)
    src, dst = d.edges
    rows, comm_rows, hom_rows = [], [], []
    rng = np.random.default_rng(0)
    for t in TRAIN_STEPS:
        nodes = np.flatnonzero(d.step == t)
        m = d.step[src] == t
        G = nx.DiGraph()
        G.add_nodes_from(nodes.tolist())
        G.add_edges_from(zip(src[m].tolist(), dst[m].tolist()))
        U = G.to_undirected()
        pr = nx.pagerank(G, alpha=0.85)
        bc = nx.betweenness_centrality(U, k=min(500, len(U)), seed=t)
        cc = nx.clustering(U)
        comms = nx.community.louvain_communities(U, resolution=1.0, seed=t)
        cid = {n: i for i, c in enumerate(comms) for n in c}
        for n in nodes:
            rows.append({"node": int(n), "step": t, "y": int(d.y[n]), "in_degree": G.in_degree(n),
                         "out_degree": G.out_degree(n), "pagerank": pr[n], "betweenness": bc[n],
                         "clustering": cc[n], "community": f"{t}_{cid[n]}"})
        # homophily over edges with both ends labelled
        ya, yb = d.y[src[m]], d.y[dst[m]]
        lab = (ya >= 0) & (yb >= 0)
        same = float((ya[lab] == yb[lab]).mean()) if lab.any() else np.nan
        yl = d.y[nodes][d.y[nodes] >= 0]
        p = yl.mean() if len(yl) else np.nan
        hom_rows.append({"step": t, "labelled_edges": int(lab.sum()), "same_label_share": same,
                         "expected_if_random": float(p ** 2 + (1 - p) ** 2),
                         "illicit_illicit_edges": int(((ya == 1) & (yb == 1)).sum()),
                         "communities": len(comms), "modularity": nx.community.modularity(U, comms)})
    df = pd.DataFrame(rows)
    hom = pd.DataFrame(hom_rows)
    atomic_to_csv(hom, out / "homophily_by_step.csv", index=False)

    # leave-one-out community score
    labd = df[df.y >= 0].copy()
    g = labd.groupby("community").y
    s, n = g.transform("sum"), g.transform("size")
    labd["comm_loo"] = np.where(n > 1, (s - labd.y) / (n - 1).clip(lower=1), np.nan)
    prev = labd.y.mean()
    labd["comm_loo"] = labd.comm_loo.fillna(prev)

    res = []
    for col in ("in_degree", "out_degree", "pagerank", "betweenness", "clustering", "comm_loo"):
        res.append({"score": col, "roc_auc": roc_auc_score(labd.y, labd[col]),
                    "ap": average_precision_score(labd.y, labd[col]), "prevalence": prev,
                    "median_illicit": float(labd.loc[labd.y == 1, col].median()),
                    "median_licit": float(labd.loc[labd.y == 0, col].median())})
    res = pd.DataFrame(res)
    atomic_to_csv(res, out / "centrality_scores.csv", index=False)
    cs = labd.groupby("community").agg(n_lab=("y", "size"), illicit=("y", "sum"))
    cs = cs[cs.n_lab >= 10]
    cs["share"] = cs.illicit / cs.n_lab
    conc = {"communities_ge10_labelled": len(cs),
            "share_of_illicit_in_majority_illicit_communities": float(cs.loc[cs.share > 0.5, "illicit"].sum() / labd.y.sum()),
            "share_communities_without_illicit": float((cs.illicit == 0).mean()),
            "mean_same_label_share": float(hom.same_label_share.mean()),
            "mean_expected_if_random": float(hom.expected_if_random.mean())}

    F.style()
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(6.5, 2.7))
    names = {"in_degree": "in-degree", "out_degree": "out-degree", "pagerank": "PageRank",
             "betweenness": "betweenness", "clustering": "clustering", "comm_loo": "community\nlabel share"}
    xx = np.arange(len(res))
    axes[0].bar(xx, res.roc_auc, color=["0.6"] * (len(res) - 1) + ["0.2"], edgecolor="0")
    axes[0].axhline(0.5, color="0", ls=":", lw=1)
    axes[0].set_xticks(xx, [names[c] for c in res.score], rotation=45, ha="right", fontsize=6)
    axes[0].set_ylabel("ROC-AUC as illicit score")
    axes[0].set_ylim(0, 1)
    axes[0].set_title("(a) centrality vs community")
    axes[1].plot(hom.step, hom.same_label_share, color="0", marker="o", ms=2.5, label="observed")
    axes[1].plot(hom.step, hom.expected_if_random, color="0.5", ls="--", marker="s", ms=2.5, label="independent labels")
    axes[1].set_xlabel("time step")
    axes[1].set_ylabel("edges joining equal labels")
    axes[1].set_title("(b) label homophily, steps 1-30")
    axes[1].legend(frameon=False)
    F.save(fig, out, "fig_p2")
    dump_json({"scores": res.to_dict(orient="records"), "concentration": conc,
               "labelled_nodes": len(labd), "prevalence": prev}, out / "summary.json")
    write_manifest(out, script="scripts/p2_graph_elliptic.py",
                   config={"steps": "1-30", "betweenness_k": 500, "louvain_resolution": 1.0},
                   data_files=[DATA / "elliptic_txs_classes.csv", DATA / "elliptic_txs_edgelist.csv"])
    print(res.to_string())
    print(conc)
    print(hom.describe().T[["mean", "min", "max"]])


if __name__ == "__main__":
    main()
