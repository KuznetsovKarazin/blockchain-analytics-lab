"""Fetch and normalize one immutable-key AWS header day for a feasibility pilot.

Raw Parquet and JSONL remain in git-ignored data/raw/monitoring_jss. This does not
grant redistribution rights; only the manifest and original derived results are
intended for the paper branch. Network acquisition and Parquet normalization are
measured separately from local JSONL replay.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
PAPER = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def dump(value, path: Path) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=PAPER / "pilot_config.json")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    day = config["source_day"]
    out = args.out or ROOT / "data/raw/monitoring_jss" / day
    out.mkdir(parents=True, exist_ok=True)
    # Refuse to silently replace a previously normalized input.
    if (out / "input_manifest.json").exists():
        saved = json.loads((out / "input_manifest.json").read_text())
        for item in saved["files"]:
            path = out / item["name"]
            if not path.exists() or sha256(path) != item["sha256"]:
                raise RuntimeError(f"existing input hash mismatch: {path}")
        print(json.dumps({"status": "verified_existing", "manifest": str(out / "input_manifest.json")}))
        return
    index = ROOT / "results/monitoring/m1_v1/inputs_eth_blocks.csv"
    with index.open(newline="") as handle:
        entries = [r for r in csv.DictReader(handle) if r["day"] == day]
    if len(entries) != 1 or ";" in entries[0]["upstream_keys"]:
        raise RuntimeError("pilot requires exactly one indexed upstream object")
    indexed = entries[0]
    key = indexed["upstream_keys"]
    url = "https://aws-public-blockchain.s3.us-east-2.amazonaws.com/" + key
    raw = out / "source.parquet"
    started = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()
    with urllib.request.urlopen(url, timeout=60) as response, raw.with_suffix(".partial").open("wb") as handle:
        headers = dict(response.headers)
        while block := response.read(1024 * 1024):
            handle.write(block)
    raw.with_suffix(".partial").replace(raw)
    acquisition_seconds = time.perf_counter() - t0
    if raw.stat().st_size != int(indexed["upstream_sizes"]):
        raise RuntimeError("download byte count differs from historical source index")
    import pyarrow.parquet as pq
    t0 = time.perf_counter()
    table = pq.read_table(raw, columns=["number", "hash", "timestamp", "transaction_count"])
    items = table.to_pylist()
    items.sort(key=lambda r: int(r["number"]))
    events = []
    for row in items:
        timestamp = row["timestamp"]
        if not isinstance(timestamp, datetime):
            raise TypeError(f"unsupported source timestamp: {type(timestamp)}")
        # AWS table partitions and timestamp convention are UTC.
        timestamp = timestamp.replace(tzinfo=timezone.utc) if timestamp.tzinfo is None else timestamp.astimezone(timezone.utc)
        if timestamp.date().isoformat() != day:
            raise RuntimeError("record lies outside source UTC partition")
        events.append({"chain_id": config["chain_id"], "block_number": int(row["number"]),
                       "block_hash": str(row["hash"]).lower(), "event_time": timestamp.timestamp(),
                       "transaction_count": int(row["transaction_count"]), "tx_index": None,
                       "log_index": None, "trace_index": None, "observed_time": None,
                       "label_available_time": None})
    numbers = [r["block_number"] for r in events]
    hashes = [r["block_hash"] for r in events]
    stamps = [r["event_time"] for r in events]
    checks = {"row_count_matches_index": len(events) == int(indexed["rows"]),
              "unique_block_numbers": len(set(numbers)) == len(numbers),
              "unique_block_hashes": len(set(hashes)) == len(hashes),
              "consecutive_block_numbers": all(b == a + 1 for a, b in zip(numbers, numbers[1:])),
              "monotone_event_time": all(b > a for a, b in zip(stamps, stamps[1:])),
              "hash_format": all(len(h) == 66 and h.startswith("0x") for h in hashes)}
    if not events or not all(checks.values()):
        raise RuntimeError(f"input integrity failed: {checks}")
    hourly = {hour: 0 for hour in range(24)}
    for event in events:
        hourly[datetime.fromtimestamp(event["event_time"], timezone.utc).hour] += event["transaction_count"]
    peak = min(hourly, key=lambda h: (-hourly[h], h))
    intensive = [e for e in events if datetime.fromtimestamp(e["event_time"], timezone.utc).hour == peak]
    paths = []
    for name, rows in (("ordinary_day.jsonl", events), ("intensive_hour.jsonl", intensive)):
        path = out / name
        with path.open("w") as stream:
            for row in rows:
                stream.write(json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
        paths.append({"name": name, "sha256": sha256(path), "bytes": path.stat().st_size, "rows": len(rows)})
    normalization_seconds = time.perf_counter() - t0
    manifest = {"schema_version": "monitoring_pilot_input_v1", "source_day": day,
                "retrieved_started_utc": started, "retrieved_finished_utc": datetime.now(timezone.utc).isoformat(),
                "source_url": url, "source_key": key, "source_http_headers": headers,
                "historical_index_sha256": sha256(index), "historical_index_record": indexed,
                "config_sha256": sha256(args.config), "acquisition_seconds": acquisition_seconds,
                "parquet_decode_and_normalize_seconds": normalization_seconds,
                "source_parquet_schema": str(table.schema), "integrity_checks": checks,
                "first_block": numbers[0], "last_block": numbers[-1],
                "first_event_time": stamps[0], "last_event_time": stamps[-1],
                "hourly_transaction_totals": hourly, "intensive_utc_hour": peak,
                "selection": config["fragment_selection"], "ordinary_day_role": "predeclared date, no claim of absence of attacks",
                "intensive_role": config["fragment_role"],
                "license_status": "AWS Open Data source terms apply; raw redistribution not cleared or performed",
                "finality_scope": config["finality_scope"],
                "files": [{"name": raw.name, "sha256": sha256(raw), "bytes": raw.stat().st_size}] + paths}
    dump(manifest, out / "input_manifest.json")
    print(json.dumps({"manifest": str(out / "input_manifest.json"), "rows": len(events),
                      "intensive_hour": peak, "intensive_rows": len(intensive), "checks": checks}))


if __name__ == "__main__":
    main()
