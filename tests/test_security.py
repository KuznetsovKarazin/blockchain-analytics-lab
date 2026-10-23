import numpy as np

from bclab import doublespend as ds
from bclab.incidents import classify, component, parse_usd


def test_exact_matches_known_values():
    # values printed in Nakamoto-style tables (Grunspan and Perez-Marco 2018)
    assert abs(ds.exact_catch_up(0.1, 1) - 0.2) < 1e-12
    assert abs(ds.exact_catch_up(0.1, 6) - 0.00059141216) < 1e-10


def test_finite_patience_converges_to_exact():
    for q, z in ((0.1, 6), (0.3, 4)):
        assert abs(ds.finite_patience(q, z, 10**6) - ds.exact_catch_up(q, z)) < 1e-9


def test_independent_players_continuous_limit():
    eps = 1e-4
    q = 0.2
    a, b = 1 - np.exp(-q * eps), 1 - np.exp(-(1 - q) * eps)
    assert abs(ds.independent_players(a, b, 5) - ds.exact_catch_up(q, 5)) < 2e-3


def test_independent_players_agrees_with_simulation():
    a, b = 0.25, 0.5
    sim = ds.simulate_independent(a, b, 3, 200_000, seed=1)
    assert abs(sim - ds.independent_players(a, b, 3)) < 0.005


def test_parse_usd():
    assert parse_usd("$611 million") == (611e6, "usd")
    assert parse_usd("Multiple ERC-20 Tokens (~152M US$)") == (152e6, "usd")
    assert parse_usd("204,215.57 USDC") == (204215.57, "stablecoin")
    assert parse_usd("~22 ETH") == (None, "other token")
    assert parse_usd("1.5B") == (None, "unit not stated")
    # leading-decimal amounts (SafeDollar, Chainswap in the index)
    assert parse_usd("$.2 million") == (0.2e6, "usd")
    assert parse_usd("$.8 million") == (0.8e6, "usd")


def test_classify_first_match():
    assert classify("Penpie - Reentrancy and Reward Manipulation") == "reentrancy"
    assert classify("Harmony's Horizon Bridge - Private key compromised") == "key compromise / phishing"
    assert classify("X - Lack Slippage Protection") == "slippage / front-running"


def test_component_is_separate_from_cause():
    t = "Harmony's Horizon Bridge - Private key compromised"
    assert component(t) == "bridge / cross-chain"
    assert classify(t) == "key compromise / phishing"
    assert component("Penpie - Reentrancy") == "no bridge keyword in title"
