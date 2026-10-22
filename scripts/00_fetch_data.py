"""
Fetch public data sources at pinned revisions into data/raw/ (git-ignored).

GitHub sources are cloned and checked out at the pinned commit; an existing
checkout is accepted only if its HEAD equals the pin. Elliptic must be placed in
data/raw/elliptic/ by hand (Kaggle "ellipticco/elliptic-data-set").
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

RAW = Path("data/raw")
SOURCES = {
    "DeFiHackLabs": ("https://github.com/SunWeb3Sec/DeFiHackLabs.git",
                     "23c7bd83ccb4524972a9493617fcc8764ab6269b"),
}


def git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def fetch(name: str, url: str, commit: str) -> None:
    dest = RAW / name
    if (dest / ".git").exists():
        try:
            head = git("rev-parse", "HEAD", cwd=dest)
        except subprocess.CalledProcessError:
            head = None
        if head == commit:
            print(f"{name}: present at {commit[:10]}")
            return
        print(f"{name}: HEAD {head} differs from pin {commit}; fetching the pin")
    else:
        dest.mkdir(parents=True, exist_ok=True)
        git("init", "-q", cwd=dest)
        git("remote", "add", "origin", url, cwd=dest)
    git("fetch", "-q", "--depth", "1", "origin", commit, cwd=dest)
    git("checkout", "-q", "FETCH_HEAD", cwd=dest)
    print(f"{name}: checked out {commit[:10]}")


def main() -> int:
    for name, (url, commit) in SOURCES.items():
        fetch(name, url, commit)
    if not (RAW / "elliptic" / "elliptic_txs_features.csv").exists():
        print("elliptic: not found; download it manually into data/raw/elliptic/ (see docs/DATA.md)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
