import numpy as np
import pytest

from bclab import aws
from bclab.online import ewma_z, rolling_mad_z


def test_rolling_mad_is_mad_of_the_trailing_window():
    # x = 0..39, W = 10, t = 30: window 20..29, median 24.5, MAD 2.5
    z = rolling_mad_z(np.arange(40.0), 10, workers=1)
    assert z[30] == pytest.approx(5.5 / (1.4826 * 2.5))


def test_rolling_mad_matches_brute_force_and_chunks():
    x = np.random.default_rng(0).normal(size=3000)
    z = rolling_mad_z(x, 200, chunk=137, workers=1)
    for t in (100, 199, 200, 1234, 2999):
        w = x[max(0, t - 200):t]
        m = np.median(w)
        assert z[t] == pytest.approx((x[t] - m) / (1.4826 * np.median(np.abs(w - m))))
    assert np.isnan(z[:100]).all()           # fewer than min_periods past points


def test_zero_mad_gives_no_score():
    x = np.r_[np.ones(50), 5.0]
    assert np.isnan(rolling_mad_z(x, 20, workers=1)[-1])


def test_ewma_recursion():
    x = np.array([1.0, 2.0, 0.0, 3.0])
    a = 1 - 0.5 ** (1 / 2.0)
    m, v, zs = x[0], 0.0, [np.nan]
    for xi in x[1:]:
        d = xi - m
        zs.append(d / np.sqrt(v) if v > 0 else np.nan)
        m += a * d
        v = (1 - a) * v + a * d * d
    np.testing.assert_allclose(ewma_z(x, 2.0), zs, equal_nan=True)


def test_read_cached_refuses_silent_gaps(tmp_path, monkeypatch):
    import pandas as pd
    monkeypatch.setattr(aws, "CACHE", tmp_path)
    d = tmp_path / "eth_blocks"
    d.mkdir()
    pd.DataFrame({"number": [1]}).to_parquet(d / "2025-01-01.parquet")
    with pytest.raises(FileNotFoundError):
        aws.read_cached("eth", "blocks", "2025-01-01", "2025-01-03")
    aws.append_index("eth", "blocks", {"day": "2025-01-02", "status": "missing"})
    aws.append_index("eth", "blocks", {"day": "2025-01-03", "status": "missing"})
    df, files = aws.read_cached("eth", "blocks", "2025-01-01", "2025-01-03")
    assert len(df) == 1 and len(files) == 1
