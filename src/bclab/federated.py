"""
Federated learning building blocks in plain numpy (no deep learning framework).

  MLP          one hidden layer (ReLU), sigmoid output, binary cross-entropy,
               minibatch SGD; parameters are a flat float64 vector so that
               averaging, clipping and masking are vector operations.
  fedavg       FedAvg (McMahan et al. 2017) with full participation, optional
               client-level clipping of the model update and Gaussian noise on
               the sum (DP-FedAvg in the style of McMahan et al. 2018).
  rdp_epsilon  (epsilon, delta) of T compositions of the Gaussian mechanism with
               noise multiplier z, via Renyi DP (Mironov 2017). No subsampling
               amplification: every client takes part in every round.
  masked_sum   pairwise additive masking as in secure aggregation (Bonawitz et
               al. 2017), without dropout recovery: fixed-point encoding modulo
               2**32, one PRG stream per client pair.
"""

from __future__ import annotations

import time

import numpy as np


class MLP:
    def __init__(self, d_in: int, hidden: int = 64, seed: int = 0):
        rng = np.random.default_rng(seed)
        self.shapes = [(d_in, hidden), (hidden,), (hidden, 1), (1,)]
        w1 = rng.normal(0, np.sqrt(2 / d_in), (d_in, hidden))
        w2 = rng.normal(0, np.sqrt(1 / hidden), (hidden, 1))
        self.theta = np.concatenate([w1.ravel(), np.zeros(hidden), w2.ravel(), np.zeros(1)])

    def unpack(self, theta=None):
        theta = self.theta if theta is None else theta
        out, i = [], 0
        for s in self.shapes:
            n = int(np.prod(s))
            out.append(theta[i:i + n].reshape(s))
            i += n
        return out

    def score(self, X):
        w1, b1, w2, b2 = self.unpack()
        h = np.maximum(X @ w1 + b1, 0)
        return (h @ w2 + b2).ravel()          # logit; monotone in probability

    def grad(self, X, y):
        w1, b1, w2, b2 = self.unpack()
        z1 = X @ w1 + b1
        h = np.maximum(z1, 0)
        p = 1 / (1 + np.exp(-np.clip((h @ w2 + b2).ravel(), -30, 30)))
        g = (p - y)[:, None] / len(y)
        gw2, gb2 = h.T @ g, g.sum(0)
        gh = (g @ w2.T) * (z1 > 0)
        gw1, gb1 = X.T @ gh, gh.sum(0)
        return np.concatenate([gw1.ravel(), gb1, gw2.ravel(), gb2])

    def sgd(self, X, y, epochs: int, lr: float, batch: int, rng) -> None:
        n = len(y)
        for _ in range(epochs):
            order = rng.permutation(n)
            for s in range(0, n, batch):
                b = order[s:s + batch]
                self.theta -= lr * self.grad(X[b], y[b])


def fedavg(clients, d_in, rounds, local_epochs, lr, batch, seed, clip=None, noise_mult=0.0,
           weighted=True, callback=None):
    """clients: list of (X, y). Returns the global model and per-round update norms."""
    rng = np.random.default_rng(seed)
    glob = MLP(d_in, seed=seed)
    sizes = np.array([len(y) for _, y in clients], float)
    w = sizes / sizes.sum() if weighted else np.full(len(clients), 1 / len(clients))
    norms = []
    for t in range(rounds):
        deltas = []
        for X, y in clients:
            loc = MLP(d_in)
            loc.theta = glob.theta.copy()
            loc.sgd(X, y, local_epochs, lr, batch, rng)
            deltas.append(loc.theta - glob.theta)
        deltas = np.array(deltas)
        nrm = np.linalg.norm(deltas, axis=1)
        norms.append(nrm)
        if clip is not None:
            deltas *= np.minimum(1.0, clip / np.maximum(nrm, 1e-12))[:, None]
            # with clipping, use the unweighted mean so that one client's
            # contribution to the sum is bounded by clip (sensitivity = clip)
            agg = deltas.sum(0)
            if noise_mult > 0:
                agg = agg + rng.normal(0, noise_mult * clip, agg.shape)
            glob.theta += agg / len(clients)
        else:
            glob.theta += (w[:, None] * deltas).sum(0)
        if callback:
            callback(t, glob)
    return glob, np.array(norms)


def rdp_epsilon(noise_mult: float, rounds: int, delta: float = 1e-5) -> float:
    """epsilon after `rounds` Gaussian mechanisms with sensitivity 1 and std noise_mult."""
    if noise_mult <= 0:
        return float("inf")
    alphas = np.concatenate([np.linspace(1.01, 10, 400), np.linspace(10, 1000, 400)])
    eps = rounds * alphas / (2 * noise_mult ** 2) + np.log(1 / delta) / (alphas - 1)
    return float(eps.min())


SCALE = 2 ** 16          # fixed-point scale
MOD = 2 ** 32


def encode(v):
    return np.round(v * SCALE).astype(np.int64) % MOD


def decode(u, n_clients):
    u = u % MOD
    u = np.where(u >= MOD // 2, u - MOD, u)       # back to signed
    return u.astype(np.float64) / SCALE


def masked_sum(vectors, seed: int = 0):
    """Sum of client vectors computed only from masked uploads. Returns (sum, seconds per client)."""
    k, d = vectors.shape
    rng = np.random.default_rng(seed)
    pair_seed = rng.integers(0, 2 ** 63, size=(k, k))          # stands in for pairwise key agreement
    uploads, t_client = [], []
    for i in range(k):
        t0 = time.perf_counter()
        y = encode(vectors[i])
        for j in range(k):
            if j == i:
                continue
            a, b = min(i, j), max(i, j)
            m = np.random.default_rng(pair_seed[a, b]).integers(0, MOD, d, dtype=np.int64)
            y = (y + m) % MOD if i < j else (y - m) % MOD
        uploads.append(y)
        t_client.append(time.perf_counter() - t0)
    total = np.zeros(d, np.int64)
    for y in uploads:
        total = (total + y) % MOD
    return decode(total, k), float(np.mean(t_client)), uploads
