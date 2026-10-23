"""
Success probability of a double-spend race under three models (study S, S1).

All models use the same success event as Nakamoto (2008): after the merchant has seen z honest confirmations, the attacker's
private chain catches up with the honest chain (a tie counts as success).
With strict lead required, replace the deficit d by d + 1.

exact_catch_up        Grunspan and Pérez-Marco (2018): attacker blocks found while
                      the honest network finds z blocks follow a negative binomial
                      law; continuous time, attacker share q = 1 - p.
independent_players   Discrete slots. In each slot the attacker finds a block with
                      probability a and the honest network with probability b,
                      independently (Poluyanenko et al. 2020). Both may succeed in
                      the same slot, which leaves the deficit unchanged.
finite_patience       Continuous-time race in which the attacker gives up once the
                      deficit reaches `give_up` blocks (gambler's ruin with a finite
                      target; Ozisik and Levine 2017 discuss the same restriction).
"""

from __future__ import annotations

import numpy as np
from scipy import stats
from scipy.special import comb


def catch_up(ratio: float, deficit: np.ndarray) -> np.ndarray:
    """P(random walk with up/down odds `ratio` ever closes `deficit` >= 0), unlimited patience."""
    deficit = np.asarray(deficit, dtype=float)
    if ratio >= 1:
        return np.ones_like(deficit)
    return np.where(deficit <= 0, 1.0, ratio ** np.clip(deficit, 0, None))


def catch_up_finite(ratio: float, deficit: np.ndarray, give_up: int) -> np.ndarray:
    """As `catch_up`, but the race stops (attacker fails) when the deficit reaches `give_up`."""
    deficit = np.asarray(deficit, dtype=float)
    out = np.zeros_like(deficit)
    out[deficit <= 0] = 1.0
    mid = (deficit > 0) & (deficit < give_up)
    if ratio == 1:
        out[mid] = 1 - deficit[mid] / give_up
    else:
        r = ratio
        out[mid] = (r ** deficit[mid] - r ** give_up) / (1 - r ** give_up)
    return out


def exact_catch_up(q: float, z: int) -> float:
    """Closed form of the exact race: 1 - sum_{k<z} C(k+z-1,k) (p^z q^k - q^z p^k)."""
    p = 1 - q
    if q >= p:
        return 1.0
    k = np.arange(z)
    return float(1 - np.sum(comb(k + z - 1, k) * (p ** z * q ** k - q ** z * p ** k)))


def attacker_blocks_pmf(q: float, z: int, kmax: int) -> np.ndarray:
    """Negative binomial pmf of attacker blocks found before the honest network's z-th block."""
    k = np.arange(kmax + 1)
    return stats.nbinom.pmf(k, z, 1 - q)


def finite_patience(q: float, z: int, give_up: int, kmax: int = 2000) -> float:
    pk = attacker_blocks_pmf(q, z, kmax)
    k = np.arange(kmax + 1)
    return float(np.sum(pk * catch_up_finite(q / (1 - q), z - k, give_up)) + (1 - pk.sum()))


def independent_players(a: float, b: float, z: int, kmax: int = 4000) -> float:
    """Attacker per-slot success a, honest per-slot success b, independent.

    Slots in which nobody finds a block change nothing and are skipped. Among the
    remaining slots, a slot is honest-only, attacker-only or "both" with
    probabilities proportional to b(1-a), a(1-b) and ab. Until the z-th slot that
    contains an honest block, the attacker gains one block in every "both" slot,
    Binomial(z, a), plus the attacker-only slots, negative binomial with z
    successes of probability b / (a + b - ab). After that, the deficit moves up
    with odds a(1-b) : b(1-a).
    """
    s = a + b - a * b
    k = np.arange(kmax + 1)
    both = stats.binom.pmf(k[: z + 1], z, a)
    only = stats.nbinom.pmf(k, z, b / s)
    pk = np.convolve(both, only)[: kmax + 1]
    ratio = a * (1 - b) / (b * (1 - a))
    return float(np.sum(pk * catch_up(ratio, z - k)) + max(0.0, 1 - pk.sum()))


def simulate_independent(a: float, b: float, z: int, n: int, seed: int,
                         give_up: int = 60, max_slots: int = 20000) -> float:
    """Monte Carlo check of `independent_players` (give_up only bounds the run time)."""
    rng = np.random.default_rng(seed)
    honest = np.zeros(n, dtype=np.int64)
    attack = np.zeros(n, dtype=np.int64)
    # phase 1: until z honest blocks
    active = np.ones(n, bool)
    while active.any():
        idx = np.flatnonzero(active)
        attack[idx] += rng.random(idx.size) < a
        honest[idx] += rng.random(idx.size) < b
        active[idx] = honest[idx] < z
    deficit = z - attack
    done = deficit <= 0
    win = done.copy()
    alive = ~done
    for _ in range(max_slots):
        if not alive.any():
            break
        idx = np.flatnonzero(alive)
        up = rng.random(idx.size) < a
        down = rng.random(idx.size) < b
        deficit[idx] += down.astype(int) - up.astype(int)
        w = deficit[idx] <= 0
        lose = deficit[idx] >= give_up
        win[idx[w]] = True
        alive[idx[w | lose]] = False
    return float(win.mean())
