"""Grayscale figure style shared by all studies (print-safe, serif, hatching instead of colour)."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

GRAYS = ["0.15", "0.45", "0.65", "0.85"]
HATCHES = ["", "///", "...", "xx"]
LINES = ["-", "--", "-.", ":"]
MARKERS = ["o", "s", "^", "D", "v"]


def style() -> None:
    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 9,
        "axes.titlesize": 9,
        "axes.labelsize": 9,
        "legend.fontsize": 8,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "axes.grid": True,
        "grid.color": "0.9",
        "grid.linewidth": 0.6,
        "axes.edgecolor": "0.0",
        "axes.linewidth": 0.8,
        "lines.linewidth": 1.2,
        "savefig.bbox": "tight",
    })


def save(fig, out_dir: str | Path, name: str) -> list[Path]:
    """PNG (300 dpi) for viewing, EPS and PDF as vector sources."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for ext, kw in (("png", {"dpi": 300}), ("eps", {}), ("pdf", {})):
        p = out_dir / f"{name}.{ext}"
        fig.savefig(p, **kw)
        paths.append(p)
    plt.close(fig)
    return paths
