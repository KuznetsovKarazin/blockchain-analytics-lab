"""
Causal robust scores shared by the burst rule (P1) and the block-stream monitor (M1).

rolling_mad_z(x, W) scores each point against the W points before it:
    med_t = median(x_{t-W}, ..., x_{t-1})
    MAD_t = median(|x_i - med_t|, i = t-W, ..., t-1)
    z_t   = (x_t - med_t) / (1.4826 * MAD_t)
i.e. the usual median absolute deviation of the trailing window, both statistics
taken over the same window. Before W points are available the window holds all past
points (at least `min_periods`); z is NaN when MAD_t = 0 or the window is too short,
so a constant recent past never raises an alert.
"""

from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor

import numpy as np

_X: np.ndarray | None = None
MAD_SCALE = 1.4826


def _init(x: np.ndarray) -> None:
    global _X
    _X = x


def _block(args: tuple[int, int, int]) -> tuple[np.ndarray, np.ndarray]:
    """Median and MAD of the windows ending just before t = lo..hi-1 (all t >= W)."""
    lo, hi, w = args
    v = np.lib.stride_tricks.sliding_window_view(_X[lo - w:hi - 1], w)   # row j: x[lo+j-w .. lo+j-1]
    med = np.median(v, axis=1)
    mad = np.median(np.abs(v - med[:, None]), axis=1)
    return med, mad


def rolling_median_mad(x: np.ndarray, window: int, min_periods: int | None = None,
                       chunk: int = 2000, workers: int | None = None) -> tuple[np.ndarray, np.ndarray]:
    x = np.asarray(x, dtype=float)
    if np.isnan(x).any():
        raise ValueError("rolling_median_mad expects a series without missing values")
    n, w = len(x), window
    mp = window // 2 if min_periods is None else min_periods
    med = np.full(n, np.nan)
    mad = np.full(n, np.nan)
    for t in range(mp, min(w, n)):               # warm-up: all past points
        past = x[:t]
        m = np.median(past)
        med[t], mad[t] = m, np.median(np.abs(past - m))
    if n > w:
        jobs = [(lo, min(lo + chunk, n), w) for lo in range(w, n, chunk)]
        workers = workers or min(4, os.cpu_count() or 1)
        if workers > 1 and len(jobs) > 1:
            with ProcessPoolExecutor(workers, initializer=_init, initargs=(x,)) as ex:
                res = list(ex.map(_block, jobs))
        else:
            _init(x)
            res = [_block(j) for j in jobs]
        for (lo, hi, _), (m, d) in zip(jobs, res):
            med[lo:hi], mad[lo:hi] = m, d
    return med, mad


def rolling_mad_z(x, window: int, min_periods: int | None = None, **kw) -> np.ndarray:
    x = np.asarray(x, dtype=float)
    med, mad = rolling_median_mad(x, window, min_periods, **kw)
    scale = MAD_SCALE * mad
    with np.errstate(divide="ignore", invalid="ignore"):
        return np.where(scale > 0, (x - med) / scale, np.nan)


def ewma_z(x, half_life: float) -> np.ndarray:
    """z_t = (x_t - m_{t-1}) / sqrt(v_{t-1}) with m_t = m_{t-1} + a d_t and
    v_t = (1 - a) v_{t-1} + a d_t^2, d_t = x_t - m_{t-1}; a = 1 - 0.5**(1/half_life),
    so the weight of an observation halves after `half_life` steps. Initial state:
    m_0 = x_0, v_0 = 0 (z undefined until v > 0)."""
    x = np.asarray(x, dtype=float)
    a = 1 - 0.5 ** (1 / half_life)
    import pandas as pd
    s = pd.Series(x)
    m = s.ewm(alpha=a, adjust=False).mean()                  # m_t, includes x_t
    m_prev = m.shift(1)
    d2 = (s - m_prev) ** 2
    v = d2.fillna(0).ewm(alpha=a, adjust=False).mean()       # v_t = (1-a) v_{t-1} + a d_t^2
    v_prev = v.shift(1)
    with np.errstate(divide="ignore", invalid="ignore"):
        return np.where(v_prev > 0, (s - m_prev) / np.sqrt(v_prev), np.nan)
