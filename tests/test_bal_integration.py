"""Integration with the pinned companion package `bal` (blockchain-detector-eval).

The studies A1, D2, P2, M2 and F1 load Elliptic and fit models through `bal`.
This test runs that path end to end on a tiny file set in the Elliptic CSV
format: `load_elliptic` -> step masks -> the three tabular model factories ->
`threshold_at_val_f1` on validation -> scores on the pre- and post-shutdown
test steps. It is skipped when the `bal` extra is not installed
(`pip install -e ".[dev,bal]"`).
"""

import numpy as np
import pandas as pd
import pytest

bal_elliptic = pytest.importorskip("bal.data.elliptic")
from bal.eval.metrics import threshold_at_val_f1          # noqa: E402
from bal.models.tabular import lightgbm, logreg, random_forest   # noqa: E402

E = bal_elliptic


def _write(root, per_step=12, seed=0):
    rng = np.random.default_rng(seed)
    rows, cls, edges, tx = [], [], [], 0
    for step in range(1, 50):
        for i in range(per_step):
            illicit = i < 2
            x = rng.normal(size=E.N_LOCAL + 72) + (1.5 if illicit else 0.0)
            rows.append([tx, step, *x])
            cls.append((tx, "1" if illicit else ("2" if i < 9 else "unknown")))
            if i:
                edges.append((tx - 1, tx))
            tx += 1
    pd.DataFrame(rows).to_csv(root / "elliptic_txs_features.csv", header=False, index=False)
    pd.DataFrame(cls, columns=["txId", "class"]).to_csv(root / "elliptic_txs_classes.csv", index=False)
    pd.DataFrame(edges, columns=["txId1", "txId2"]).to_csv(root / "elliptic_txs_edgelist.csv", index=False)


def test_elliptic_path_through_bal(tmp_path):
    _write(tmp_path)
    d = E.load_elliptic(tmp_path)
    assert d.X.shape[1] == E.N_LOCAL + 72 and d.features("LF").shape[1] == E.N_LOCAL
    tr, va = d.mask(E.TRAIN_STEPS), d.mask(E.VAL_STEPS)
    pre, post = d.mask(E.PRE_SHUTDOWN), d.mask(E.POST_SHUTDOWN)
    assert tr.sum() and va.sum() and pre.sum() and post.sum()
    for make in (logreg, random_forest, lightgbm):
        m = make(0).fit(d.X[tr], d.y[tr])
        t = threshold_at_val_f1(d.y[va], m.predict_score(d.X[va]))
        s = m.predict_score(d.X[pre | post])
        assert np.isfinite(t) and s.shape == ((pre | post).sum(),)
        # the planted shift is easy: illicit rows score higher on average
        y = d.y[pre | post]
        assert s[y == 1].mean() > s[y == 0].mean()
