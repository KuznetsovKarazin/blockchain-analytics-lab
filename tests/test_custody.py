import numpy as np
import pandas as pd

from bclab.custody import new_pair_tx, prior_tx_stats, taint_replay, trace_order_key


def test_trace_order_is_preorder():
    s = pd.Series([None, "1", "0,1", "0", "10", "0,0", "2"])
    order = s.iloc[np.argsort(trace_order_key(s).to_numpy(), kind="stable")].fillna("root").tolist()
    assert order == ["root", "0", "0,0", "0,1", "1", "2", "10"]


def test_large_call_in_first_tx_of_pair_is_new():
    # two internal calls of one first transaction, 1 ETH then 1000 ETH, same pair
    v = pd.DataFrame({"from_address": [1, 1], "to_address": [2, 2], "eth": [1.0, 1000.0], "txpos": [10, 10]})
    flag = new_pair_tx(v, "from_address", "to_address") & (v.eth.to_numpy() >= 1000)
    assert flag.sum() == 1
    v2 = pd.concat([v, pd.DataFrame({"from_address": [1], "to_address": [2], "eth": [5000.0], "txpos": [11]})])
    assert not new_pair_tx(v2.reset_index(drop=True), "from_address", "to_address")[-1]


def test_outlier_history_excludes_current_tx():
    # five small calls and one large call inside the sender's very first transaction
    v = pd.DataFrame({"from_address": [1] * 6, "eth": [1.0] * 5 + [500.0], "txpos": [7] * 6})
    prev_max, prev_n = prior_tx_stats(v, "from_address")
    assert (prev_n == 0).all() and np.isnan(prev_max).all()
    r3 = (v.eth.to_numpy() >= 100) & (prev_n >= 5) & (v.eth.to_numpy() > 2 * prev_max)
    assert r3.sum() == 0
    # the same pattern spread over earlier transactions does count
    v = pd.DataFrame({"from_address": [1] * 6, "eth": [1.0] * 5 + [500.0], "txpos": [1, 2, 3, 4, 5, 6]})
    prev_max, prev_n = prior_tx_stats(v, "from_address")
    assert prev_n[-1] == 5 and prev_max[-1] == 1.0


def test_taint_same_block_forwarding_and_hour_convention():
    # start address 0 receives 10; in the same block it forwards 6 to 1, which forwards 6 to 2
    frm = np.array([0, 1, 2])
    to = np.array([1, 2, 99])
    eth = np.array([6.0, 6.0, 6.0])
    hours = np.array([0.0, 0.0, 1.5])
    r = taint_replay(frm, to, eth, hours, start=0, amount=10.0, hubs={99}, min_new=0.01)
    assert r["traced"] == 3
    assert r["held"][0] == 10.0           # at exactly 0 h all forwarding stays inside the traced set
    assert r["held"][1] == 10.0           # the transfer at 1.5 h is not yet counted at 1 h
    assert r["held"][2] == 4.0            # ... and is counted at 2 h
    assert r["to_hubs"] == 6.0
