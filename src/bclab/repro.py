"""
Reproducibility helpers: seeding, run manifests, file hashing.

Every script writes a manifest next to its results so that a reported number
can be traced to (code commit + uncommitted diff, data hash, package versions,
configuration).
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import subprocess
import sys
import time
from importlib import metadata
from pathlib import Path
from typing import Any, Iterable

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    try:
        import torch

        torch.manual_seed(seed)
        torch.use_deterministic_algorithms(True, warn_only=True)
    except ImportError:
        pass


def sha256_file(path: str | Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


# paths whose state defines the code of a run; results/ and data/ are outputs/inputs
CODE_PATHS = ("src", "scripts", "tests", "requirements.txt", "pyproject.toml")


def _git(*args: str) -> str | None:
    try:
        out = subprocess.run(["git", "-C", str(REPO_ROOT), *args],
                             capture_output=True, text=True, timeout=10)
        return out.stdout if out.returncode == 0 else None
    except Exception:
        return None


def git_commit() -> str | None:
    out = _git("rev-parse", "--verify", "HEAD")
    return out.strip() if out else None


def git_dirty() -> bool | None:
    """True if code files differ from HEAD (results/ and data/ are ignored)."""
    out = _git("status", "--porcelain", "--untracked-files=all", "--", *CODE_PATHS)
    return None if out is None else bool(out.strip())


def git_code_state() -> dict[str, Any]:
    """Commit, changed code files and a SHA-256 of the uncommitted code diff.

    Untracked files are listed one by one (also inside new directories) and
    enter the digest with their relative path and content.
    """
    changed = (_git("status", "--porcelain", "--untracked-files=all", "--", *CODE_PATHS) or "").splitlines()
    diff = _git("diff", "HEAD", "--", *CODE_PATHS) or ""
    for line in sorted(changed):               # untracked files are not in `git diff`
        if line.startswith("??"):
            rel = line[3:].strip()
            f = REPO_ROOT / rel
            if f.is_file():
                diff += f"\n+++ untracked {rel}\n" + f.read_text(errors="replace")
    return {"git_commit": git_commit(), "git_dirty": bool(changed),
            "dirty_files": [c[3:] for c in changed],
            "diff_sha256": hashlib.sha256(diff.encode()).hexdigest() if changed else None}


def package_versions(names: Iterable[str] = (
    "numpy", "pandas", "scikit-learn", "scipy", "torch", "lightgbm", "xgboost",
    "pyarrow", "networkx", "statsmodels",
)) -> dict[str, str | None]:
    out = {}
    for n in names:
        try:
            out[n] = metadata.version(n)
        except metadata.PackageNotFoundError:
            out[n] = None
    return out


_CODE_STATE_AT_IMPORT: dict[str, Any] | None = None


def code_state_at_start() -> dict[str, Any]:
    """Code state captured when the script imported this module (before any long run)."""
    global _CODE_STATE_AT_IMPORT
    if _CODE_STATE_AT_IMPORT is None:
        _CODE_STATE_AT_IMPORT = git_code_state()
    return _CODE_STATE_AT_IMPORT


def corpus_digest(paths: Iterable[str | Path]) -> dict[str, Any]:
    """One digest for a large set of input files: SHA-256 over sorted 'path  sha256' lines."""
    lines = sorted(f"{p}  {sha256_file(p)}" for p in map(str, paths))
    return {"n_files": len(lines), "sha256": hashlib.sha256("\n".join(lines).encode()).hexdigest()}


def write_manifest(out_dir: str | Path, *, script: str, config: dict[str, Any],
                   data_files: Iterable[str | Path] = (), extra: dict | None = None,
                   data_sets: dict[str, Iterable[str | Path]] | None = None,
                   name: str = "manifest.json") -> Path:
    """`data_files` are hashed one by one; each entry of `data_sets` gets one corpus digest."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "script": script,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **code_state_at_start(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "packages": package_versions(),
        "config": config,
        "data": {str(p): sha256_file(p) for p in data_files if Path(p).exists()},
        "data_sets": {k: corpus_digest(v) for k, v in (data_sets or {}).items()},
    }
    missing = [str(p) for p in data_files if not Path(p).exists()]
    if missing:
        manifest["data_missing"] = missing
    if extra:
        manifest.update(extra)
    path = out_dir / name
    atomic_write_text(path, json.dumps(manifest, indent=2, default=str))
    return path


def atomic_write_text(path: str | Path, text: str) -> None:
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def atomic_to_csv(df, path: str | Path, **kw) -> None:
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    df.to_csv(tmp, **kw)
    os.replace(tmp, path)


def dump_json(obj: Any, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=_np_default))


def _np_default(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return str(o)


code_state_at_start()
