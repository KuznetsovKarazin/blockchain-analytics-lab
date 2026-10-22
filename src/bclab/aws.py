"""
Local column-projected cache of the AWS Public Blockchain Data (s3://aws-public-blockchain/v1.0).

The bucket is public (anonymous access, us-east-2). Tables are partitioned by
UTC date: v1.0/<chain>/<table>/date=YYYY-MM-DD/part-*.parquet. We read only the
columns a study needs and store them under data/cache/<chain>_<table>/<date>.parquet.
Each cached file records the source key, size and ETag in cache_index.csv so
that a run can be traced to the exact upstream object.
"""

from __future__ import annotations

import csv
import time
from datetime import date, timedelta
from pathlib import Path

import pyarrow.fs as pafs
import pyarrow.parquet as pq

BUCKET = "aws-public-blockchain"
CACHE = Path("data/cache")


def s3() -> pafs.S3FileSystem:
    return pafs.S3FileSystem(anonymous=True, region="us-east-2", connect_timeout=30, request_timeout=120)


def days(start: str, end: str):
    d0, d1 = date.fromisoformat(start), date.fromisoformat(end)
    while d0 <= d1:
        yield d0.isoformat()
        d0 += timedelta(days=1)


def cache_dir(chain: str, table: str) -> Path:
    return CACHE / f"{chain}_{table}"


def fetch_day(fs, chain: str, table: str, day: str, columns: list[str], retries: int = 4) -> dict | None:
    out = cache_dir(chain, table) / f"{day}.parquet"
    if out.exists():
        return None
    prefix = f"{BUCKET}/v1.0/{chain}/{table}/date={day}"
    for attempt in range(retries):
        try:
            infos = [i for i in fs.get_file_info(pafs.FileSelector(prefix, allow_not_found=True))
                     if i.path.endswith(".parquet")]
            if not infos:
                return {"day": day, "status": "missing"}
            tables = [pq.read_table(i.path, filesystem=fs, columns=columns) for i in infos]
            import pyarrow as pa
            t = pa.concat_tables(tables) if len(tables) > 1 else tables[0]
            out.parent.mkdir(parents=True, exist_ok=True)
            tmp = out.with_suffix(".tmp")
            pq.write_table(t, tmp, compression="zstd")
            tmp.replace(out)
            return {"day": day, "status": "ok", "rows": t.num_rows,
                    "keys": ";".join(i.path.removeprefix(BUCKET + "/") for i in infos),
                    "sizes": ";".join(str(i.size) for i in infos),
                    "mtimes": ";".join(str(i.mtime) for i in infos)}
        except Exception as e:  # network hiccups: back off and retry
            if attempt == retries - 1:
                return {"day": day, "status": f"error: {type(e).__name__}: {e}"[:300]}
            time.sleep(2 ** (attempt + 1))
    return None


def append_index(chain: str, table: str, rec: dict) -> None:
    idx = cache_dir(chain, table) / "cache_index.csv"
    idx.parent.mkdir(parents=True, exist_ok=True)
    new = not idx.exists()
    with open(idx, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["day", "status", "rows", "keys", "sizes", "mtimes"])
        if new:
            w.writeheader()
        w.writerow({k: rec.get(k, "") for k in w.fieldnames})


def read_cached(chain: str, table: str, start: str, end: str, columns: list[str] | None = None):
    import pandas as pd
    files = [cache_dir(chain, table) / f"{d}.parquet" for d in days(start, end)]
    files = [f for f in files if f.exists()]
    if not files:
        raise FileNotFoundError(f"no cached {chain}/{table} between {start} and {end}")
    return pd.concat([pd.read_parquet(f, columns=columns) for f in files], ignore_index=True), files
