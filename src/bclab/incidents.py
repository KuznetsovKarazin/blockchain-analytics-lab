"""
Parse the incident index of DeFiHackLabs (SunWeb3Sec) into a table (study S, S2).

Each incident is a markdown section "### YYYYMMDD <name> - <root cause>" followed by
"#### Lost: <free text>". The free text mixes US dollars, stablecoins and native
tokens. We convert to USD only what the text states in dollars or in USD-pegged
stablecoins; amounts in other tokens are left unconverted (no price lookup).

Two separate codings come from keyword rules over the title:
  * cause_class: a coarse class of the stated proximate cause (ordered rules, first
    match wins; the share of titles that fall through to "other" is reported). A
    flash loan is an instrument, not a cause; titles that name nothing but a flash
    loan form their own residual class.
  * component: the attacked component when the title names a bridge or cross-chain
    messaging ("bridge / cross-chain"), else "other or not stated". A bridge is a
    target, not a cause: a bridge incident also has a cause class (key compromise,
    validation, ...).
"""

from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pandas as pd

HEAD = re.compile(r"^###\s+(\d{8})\s*-?\s*(.*)$")
LOST = re.compile(r"^#+\s*Lost\s*:?\s*(.*)$", re.I)

# (class, regex over the lower-cased title); first match wins
CLASSES: list[tuple[str, str]] = [
    ("key compromise / phishing", r"private key|key compromis|compromised key|phishing|social engineer|leaked key|default account|known key"),
    ("reentrancy", r"reentran|re-entran|read-only"),
    ("oracle / price manipulation", r"price manipulation|oracle|manipulat|twap|spot price|share price|donation|inflation attack|first deposit|sync\(|\bk\b value|price"),
    ("slippage / front-running", r"slippage|sandwich|front-?run|mev\b"),
    ("arithmetic / precision", r"overflow|underflow|precision|rounding|unit mismatch|decimal|division|truncat|miscalculat|calculation|precission"),
    ("access control", r"access control|unprotected|onlyowner|permissionless|missing (?:check|modifier|auth)|authori[sz]|anyone can|ungated|initiali[sz]|caller check|owner check|permission|accesscontrol|msg\.sender|privileged|unguarded"),
    ("input / call validation", r"validation|arbitrary (?:external )?call|unchecked|unverified|input|signature|replay|approve|approval|delegatecall|calldata|parameter|check"),
    ("token mechanics (fee, tax, rebase, reflection)", r"\bfee|tax|rebas|reflection|deflationary|burn"),
    ("weak randomness", r"\brng\b|random"),
    ("malicious project / rug pull", r"rug|malicious|backdoor|honeypot|exit scam|scam"),
    ("business logic", r"business logic|logic flaw|logic error|bussiness logic|accounting|reward|incorrect|wrong|flaw|bug|logic|mechanism|verification"),
    ("flash-loan assisted (unspecified)", r"flash ?loan"),
]

_MULT = {"k": 1e3, "thousand": 1e3, "m": 1e6, "mm": 1e6, "million": 1e6, "b": 1e9, "billion": 1e9}
_NUM = r"(\d[\d,]*(?:\.\d+)?|\.\d+)\s*(k|m|mm|b|thousand|million|billion)?\b"
USD_PATTERNS = [
    re.compile(r"\$\s*" + _NUM, re.I),                                   # $1.2M, $ 70k
    re.compile(_NUM + r"\s*(?:us\$|usd\b|us dollars|dollars)", re.I),     # 4.9M USD, 152M US$
    re.compile(_NUM + r"\s*\$", re.I),                                   # 2.4 k$ (rare)
]
STABLE = re.compile(_NUM + r"\s*\$?(usdt|usdc|busd|dai|usde|fdusd|tusd|usdc\.e)\b", re.I)


def _value(num: str, mult: str | None) -> float:
    v = float(num.replace(",", ""))
    return v * _MULT.get((mult or "").lower(), 1.0)


def parse_usd(text: str) -> tuple[float | None, str]:
    """Return (USD, how). Takes the first explicit dollar amount, else the sum of stablecoin amounts."""
    t = text.strip()
    if not t:
        return None, "missing"
    # parenthesised dollar value is usually the USD equivalent of a token amount
    paren = re.search(r"\(([^)]*\$[^)]*)\)", t)
    for src in ([paren.group(1)] if paren else []) + [t]:
        for pat in USD_PATTERNS:
            m = pat.search(src)
            if m:
                return _value(m.group(1), m.group(2)), "usd"
    st = STABLE.findall(t)
    if st:
        return sum(_value(n, k) for n, k, _ in st), "stablecoin"
    m = re.fullmatch(r"~?\s*" + _NUM + r"\s*", t, re.I)
    if m:
        return None, "unit not stated"
    if re.search(r"unclear|unknown|n/a", t, re.I):
        return None, "unknown"
    return None, "other token"


COMPONENT = r"bridge|cross-chain|crosschain"


def component(title: str) -> str:
    return "bridge / cross-chain" if re.search(COMPONENT, title.lower()) else "other or not stated"


def classify(title: str) -> str:
    t = title.lower()
    for name, rx in CLASSES:
        if re.search(rx, t):
            return name
    return "other"


def parse_readme(path: str | Path) -> pd.DataFrame:
    rows, cur = [], None
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        m = HEAD.match(line.strip())
        if m:
            if cur:
                rows.append(cur)
            date, rest = m.groups()
            name, _, cause = rest.partition(" - ")
            cur = {"date": pd.to_datetime(date, format="%Y%m%d", errors="coerce"),
                   "name": name.strip(), "cause_text": cause.strip() or name.strip(), "lost_text": ""}
            continue
        if cur is not None and not cur["lost_text"]:
            m = LOST.match(line.strip())
            if m:
                cur["lost_text"] = m.group(1).strip()
    if cur:
        rows.append(cur)
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    usd = df["lost_text"].map(parse_usd)
    df["loss_usd"] = [u for u, _ in usd]
    df["loss_parse"] = [h for _, h in usd]
    # lenient variant: a bare number without unit is read as US dollars
    bare = df["lost_text"].str.extract(r"^~?\s*" + _NUM + r"\s*$", flags=re.I)
    lenient = [(_value(n, k if isinstance(k, str) else None) if isinstance(n, str) else np.nan) for n, k in zip(bare[0], bare[1])]
    df["loss_usd_lenient"] = df["loss_usd"].where(df["loss_usd"].notna(), lenient)
    df["cause_class"] = (df["name"] + " " + df["cause_text"]).map(classify)
    df["component"] = (df["name"] + " " + df["cause_text"]).map(component)
    df["source_file"] = str(path)
    return df


def load_all(root: str | Path) -> pd.DataFrame:
    root = Path(root)
    files = [root / "README.md"] + sorted(root.glob("past/*/README.md"))
    df = pd.concat([parse_readme(f) for f in files], ignore_index=True)
    df = df.dropna(subset=["date"]).drop_duplicates(subset=["date", "name"]).sort_values("date")
    df["year"] = df["date"].dt.year
    return df.reset_index(drop=True)
