import importlib.util
from pathlib import Path

import pandas as pd

spec = importlib.util.spec_from_file_location("p3", Path(__file__).parents[1] / "scripts" / "p3_value_flows.py")
p3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p3)


def test_exact_denominations_only():
    wei = pd.Series([0.1e18, 1e18, 10e18, 100e18, 100.003e18, 0.100001e18, 10.0002e18, 1e15, 1e21, 1e22])
    k = wei.map(p3.POW10_WEI)
    assert k.notna().tolist() == [True, True, True, True, False, False, False, True, True, False]
    assert k.dropna().astype(int).tolist() == [-1, 0, 1, 2, -3, 3]
