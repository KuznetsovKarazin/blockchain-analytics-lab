"""Bounded, complete-emitter Ethereum log acquisition from partitioned Parquet.

Every address row is scanned. Only row groups with matching emitters are then
read for the required payload columns; every matching row is retained. HTTP
ranges are pinned with If-Match, cached with SHA-256, and counted. A projection
is not the whole source object and never receives a purported source SHA-256.
All raw byte ranges and selected logs stay in git-ignored data/raw/. This is
data acquisition, not an attack detector or a claim about cash outflows.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import resource
import shutil
import sys
import time
import urllib.request

BASE = "https://aws-public-blockchain.s3.us-east-2.amazonaws.com/"
ROOT = Path(__file__).resolve().parents[2]
PAPER = Path(__file__).resolve().parent
DEFAULT_LOGS = "v1.0/eth/logs/date=2023-03-01/part-00000-f66f43c5-ca46-452e-8e6f-f2f2dfb24829-c000.snappy.parquet"
DEFAULT_BLOCKS = "v1.0/eth/blocks/date=2023-03-01/part-00000-b750e33e-7fdd-47bc-b52d-f7835851062a-c000.snappy.parquet"
EULER = "0x27182842e098f60e3d576794a5bffb0777e025d3"
EULER_SOURCE = "https://github.com/euler-legacy-xyz/euler-contracts/blob/dfaa7788b17ac7c2a826a3ed242d7181998a778f/addresses/euler-addresses-mainnet.json"
HEX32 = re.compile(r"0x[0-9a-f]{64}\Z")
ADDRESS = re.compile(r"0x[0-9a-f]{40}\Z")
HEXDATA = re.compile(r"0x(?:[0-9a-f]{2})*\Z")


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def dump(value, path):
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")
    tmp.replace(path)


def inspect_remote(url):
    with urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=60) as response:
        headers = {key.lower(): value for key, value in response.headers.items()}
    for required in ("etag", "content-length"):
        if required not in headers:
            raise RuntimeError(f"remote object lacks {required}")
    return {"url": url, "size": int(headers["content-length"]), "etag": headers["etag"],
            "version_id": headers.get("x-amz-version-id"), "last_modified": headers.get("last-modified"),
            "http_headers": headers}


class CachedHTTPRangeFile(io.RawIOBase):
    """Seekable read-only object; every fetched span remains inspectable on disk."""
    def __init__(self, metadata, cache, byte_budget=500_000_000):
        super().__init__()
        self.metadata = metadata
        self.cache = Path(cache)
        self.cache.mkdir(parents=True, exist_ok=True)
        self.index_path = self.cache / "range_index.json"
        self.position = 0
        self.network_bytes_this_process = 0
        self.cache_bytes_served_this_process = 0
        self.byte_budget = byte_budget
        if self.index_path.exists():
            self.index = json.loads(self.index_path.read_text())
            prior = self.index["source"]
            if any(prior[key] != metadata[key] for key in ("url", "size", "etag", "version_id")):
                raise RuntimeError("source identity changed; use a new acquisition/cache")
        else:
            self.index = {"source": metadata, "ranges": {}, "partial_transfer_bytes": 0}
            dump(self.index, self.index_path)

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        origin = 0 if whence == 0 else self.position if whence == 1 else self.metadata["size"] if whence == 2 else None
        if origin is None or origin + offset < 0:
            raise ValueError("invalid seek")
        self.position = origin + offset
        return self.position

    def read(self, size=-1):
        size = min(self.metadata["size"] - self.position,
                   self.metadata["size"] - self.position if size < 0 else size)
        if size <= 0:
            return b""
        start, stop = self.position, self.position + size - 1
        name = f"{start}_{size}.bin"
        path = self.cache / name
        existing = self.index["ranges"].get(name)
        if existing is not None:
            if not path.exists() or path.stat().st_size != size or sha256(path) != existing["sha256"]:
                raise RuntimeError(f"range-cache integrity failure: {name}")
            result = path.read_bytes()
            self.cache_bytes_served_this_process += size
        else:
            fetched = sum(item["bytes"] for item in self.index["ranges"].values()) + self.index["partial_transfer_bytes"]
            if fetched + size > self.byte_budget:
                raise RuntimeError(f"range byte budget exceeded: {fetched}+{size}>{self.byte_budget}")
            request = urllib.request.Request(self.metadata["url"], headers={
                "Range": f"bytes={start}-{stop}", "If-Match": self.metadata["etag"]})
            t0 = time.perf_counter()
            written = 0
            tmp = path.with_suffix(".partial")
            try:
                with urllib.request.urlopen(request, timeout=90) as response:
                    if response.status != 206:
                        raise RuntimeError(f"server did not honor range: HTTP {response.status}")
                    expected = f"bytes {start}-{stop}/{self.metadata['size']}"
                    if response.headers.get("Content-Range") != expected:
                        raise RuntimeError("incorrect Content-Range")
                    if response.headers.get("ETag") != self.metadata["etag"]:
                        raise RuntimeError("remote ETag changed during acquisition")
                    with tmp.open("wb") as handle:
                        while block := response.read(min(1024 * 1024, size - written + 1)):
                            written += len(block)
                            self.network_bytes_this_process += len(block)
                            if written > size:
                                raise RuntimeError("range response contains excess bytes")
                            handle.write(block)
                if written != size:
                    raise RuntimeError(f"truncated range {written}/{size}")
                tmp.replace(path)
            except Exception:
                self.index["partial_transfer_bytes"] += written
                dump(self.index, self.index_path)
                raise
            record = {"start": start, "stop": stop, "bytes": size, "sha256": sha256(path),
                      "etag": self.metadata["etag"], "elapsed_seconds": time.perf_counter() - t0}
            self.index["ranges"][name] = record
            dump(self.index, self.index_path)
            result = path.read_bytes()
        self.position += size
        return result

    def manifest(self):
        return {**self.index, "network_bytes_this_process": self.network_bytes_this_process,
                "cache_bytes_served_this_process": self.cache_bytes_served_this_process,
                "total_cached_range_bytes": sum(item["bytes"] for item in self.index["ranges"].values()),
                "raw_whole_object_sha256": None,
                "hash_scope": "each exact cached byte range, not the unacquired whole object"}


def full_download(metadata, path):
    """Small header object, fetched in full with the same mutation guard."""
    path = Path(path)
    meta_path = path.with_suffix(".json")
    if path.exists():
        saved = json.loads(meta_path.read_text())
        if (any(saved[key] != metadata[key] for key in ("url", "size", "etag", "version_id"))
                or path.stat().st_size != metadata["size"] or saved["sha256"] != sha256(path)):
            raise RuntimeError("header cache mismatch")
        return {**saved, "network_bytes_this_process": 0, "reused": True}
    request = urllib.request.Request(metadata["url"], headers={"If-Match": metadata["etag"]})
    started = time.perf_counter()
    written = 0
    with urllib.request.urlopen(request, timeout=90) as response, path.with_suffix(".partial").open("wb") as out:
        if response.headers.get("ETag") != metadata["etag"]:
            raise RuntimeError("header ETag changed")
        while block := response.read(1024 * 1024):
            out.write(block)
            written += len(block)
    if written != metadata["size"]:
        raise RuntimeError("incomplete header object")
    path.with_suffix(".partial").replace(path)
    record = {**metadata, "sha256": sha256(path), "bytes": written,
              "elapsed_seconds": time.perf_counter() - started,
              "network_bytes_this_process": written, "reused": False}
    dump(record, meta_path)
    return record


def validate_logs(records, addresses, day, blocks):
    """No silent filtering or deduplication: a bad retained event aborts."""
    seen = set()
    tx_positions = {}
    hash_positions = {}
    for row in records:
        if row["chain_id"] != 1:
            raise ValueError("Ethereum source requires chain_id=1")
        if row["address"] not in addresses or not ADDRESS.fullmatch(row["address"]):
            raise ValueError("wrong emitter")
        for field in ("block_hash", "transaction_hash"):
            if not HEX32.fullmatch(row[field]):
                raise ValueError(f"invalid {field}")
        if (len(row["topics"]) > 4 or not HEXDATA.fullmatch(row["data"])
                or any(not HEX32.fullmatch(topic) for topic in row["topics"])):
            raise ValueError("invalid raw data/topics")
        for field in ("block_number", "transaction_index", "log_index", "event_time_ns"):
            if isinstance(row[field], bool) or not isinstance(row[field], int) or row[field] < 0:
                raise ValueError(f"invalid {field}")
        if datetime.fromtimestamp(row["event_time_ns"] // 1_000_000_000, timezone.utc).date().isoformat() != day:
            raise ValueError("log outside requested UTC day")
        key = (row["chain_id"], row["block_hash"], row["log_index"])
        if key in seen:
            raise ValueError("duplicate log identity; not deduplicated silently")
        seen.add(key)
        block = blocks.get(row["block_number"])
        if block is None or block["block_hash"] != row["block_hash"] or block["event_time_ns"] != row["event_time_ns"]:
            raise ValueError("log does not match header hash/time")
        if row["transaction_index"] >= block["transaction_count"]:
            raise ValueError("transaction_index outside header transaction count")
        tx_key = (row["block_number"], row["transaction_index"])
        if tx_key in tx_positions and tx_positions[tx_key] != row["transaction_hash"]:
            raise ValueError("transaction hash/index conflict")
        if row["transaction_hash"] in hash_positions and hash_positions[row["transaction_hash"]] != tx_key:
            raise ValueError("same transaction hash at multiple positions")
        tx_positions[tx_key] = row["transaction_hash"]
        hash_positions[row["transaction_hash"]] = tx_key
    ordered = sorted(records, key=lambda row: (row["block_number"], row["transaction_index"], row["log_index"]))
    if any(a["block_number"] == b["block_number"] and a["log_index"] >= b["log_index"] for a, b in zip(ordered, ordered[1:])):
        raise ValueError("global log_index is inconsistent with transaction order")
    return {"all_emitters_requested": True, "raw_hex_valid": True, "unique_log_identities": True,
            "all_logs_match_header_hash_and_time": True, "transaction_positions_consistent": True,
            "exact_order_fields_present": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--day", default="2023-03-01")
    parser.add_argument("--address", action="append")
    parser.add_argument("--address-source", default=EULER_SOURCE)
    parser.add_argument("--population", default="Euler core all-topic emitter event stream")
    parser.add_argument("--logs-key", default=DEFAULT_LOGS)
    parser.add_argument("--blocks-key", default=DEFAULT_BLOCKS)
    parser.add_argument("--run-id")
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--byte-budget", type=int, default=500_000_000)
    args = parser.parse_args()
    addresses = sorted({a.lower() for a in (args.address or [EULER])})
    if not all(ADDRESS.fullmatch(address) for address in addresses):
        raise ValueError("addresses must be 20-byte hex EVM addresses")
    if addresses != [EULER] and args.address_source == EULER_SOURCE:
        raise ValueError("custom emitters require their own --address-source provenance")
    if f"date={args.day}/" not in args.logs_key or f"date={args.day}/" not in args.blocks_key:
        raise ValueError("source partitions must match --day")
    run_id = args.run_id or datetime.now(timezone.utc).strftime("protocol_logs_%Y%m%dT%H%M%S_%fZ")
    if Path(run_id).name != run_id:
        raise ValueError("run-id must be a path component")
    out = PAPER / "runs" / run_id
    out.mkdir(parents=True, exist_ok=False)
    cache = (args.cache or ROOT / "data/raw/monitoring_jss/protocol_logs" / args.day).resolve()
    cache.mkdir(parents=True, exist_ok=True)
    selected_dir = cache / run_id
    selected_dir.mkdir(exist_ok=False)
    shutil.copy2(__file__, out / "acquire_protocol_logs_source.py")
    manifest = {"schema_version": "protocol_log_acquisition_v1", "status": "acquiring", "run_id": run_id,
                "command": [sys.executable, *sys.argv], "started_utc": datetime.now(timezone.utc).isoformat(),
                "scope": {"day_utc": args.day, "addresses": addresses, "address_source": args.address_source,
                          "population": args.population, "topics": "all", "independent_attack_case": False,
                          "semantic_warning": "Euler core events are not synonymous with token cash outflows; no amount/loss totals or detection are computed"},
                "source_code_sha256": sha256(__file__), "raw_storage": str(selected_dir.relative_to(ROOT)),
                "license_status": "source terms apply; raw logs/range bytes private and not redistributed",
                "historical_observed_time": None, "historical_label_available_time": None,
                "finality_scope": "archive canonical snapshot; no independent consensus finality measurement",
                "row_groups": [], "byte_budget_logs": args.byte_budget}
    dump(manifest, out / "acquisition_manifest.json")
    remote = None
    try:
        import pyarrow as pa
        import pyarrow.compute as pc
        import pyarrow.parquet as pq
        manifest["python"] = sys.version
        manifest["pyarrow"] = pa.__version__
        logs_metadata = inspect_remote(BASE + args.logs_key)
        blocks_metadata = inspect_remote(BASE + args.blocks_key)
        remote = CachedHTTPRangeFile(logs_metadata, cache / "log_ranges", args.byte_budget)
        parquet = pq.ParquetFile(remote)
        manifest["source_log_schema"] = str(parquet.schema_arrow)
        manifest["source_log_rows"] = parquet.metadata.num_rows
        manifest["source_log_row_groups"] = parquet.num_row_groups
        required = ["address", "topics", "data", "transaction_index", "log_index", "transaction_hash",
                    "block_number", "block_hash", "block_timestamp"]
        missing = [name for name in required if name not in parquet.schema_arrow.names]
        manifest["missing_required_fields"] = missing
        if missing:
            raise RuntimeError(f"missing fields: {missing}")
        selected = {}
        scanned = 0
        for group in range(parquet.num_row_groups):
            table = parquet.read_row_group(group, columns=["address"], use_threads=False)
            normalized = pc.utf8_lower(table["address"])
            matches = pc.is_in(normalized, value_set=pa.array(addresses))
            indices = pc.indices_nonzero(matches).to_pylist()
            selected[group] = indices
            metadata = parquet.metadata.row_group(group)
            record = {"row_group": group, "source_row_start": scanned, "source_rows": metadata.num_rows,
                      "address_rows_scanned": table.num_rows, "address_null_rows": table["address"].null_count,
                      "matching_rows": len(indices), "payload_acquired": False}
            if metadata.num_rows != table.num_rows:
                raise RuntimeError("address scan row count mismatch")
            manifest["row_groups"].append(record)
            scanned += table.num_rows
            manifest["logs_range_acquisition"] = remote.manifest()
            dump(manifest, out / "acquisition_manifest.json")
            print(json.dumps({"stage": "address_scan", **record}), flush=True)
        if scanned != parquet.metadata.num_rows:
            raise RuntimeError("incomplete address scan")
        rows = []
        for group, indices in selected.items():
            if not indices:
                continue
            # Column-by-column decoding bounds memory by the largest column,
            # rather than the entire ~700k-row nested record group.
            selected_columns = {}
            for column in required:
                table = parquet.read_row_group(group, columns=[column], use_threads=False)
                values = table[column].take(pa.array(indices, type=pa.int64()))
                if column == "block_timestamp":
                    unit = values.type.unit
                    scale = {"s": 1_000_000_000, "ms": 1_000_000, "us": 1_000, "ns": 1}[unit]
                    selected_columns["event_time_ns"] = [int(v) * scale for v in pc.cast(values, pa.int64()).to_pylist()]
                else:
                    selected_columns[column] = values.to_pylist()
                del table, values
            for offset, ordinal in enumerate(indices):
                event = {name: values[offset] for name, values in selected_columns.items()}
                for name in ("address", "block_hash", "transaction_hash", "data"):
                    event[name] = event[name].lower()
                event["topics"] = [topic.lower() for topic in event["topics"]]
                event.update(chain_id=1, source_row_group=group, source_row_index=ordinal,
                             source_global_row_index=manifest["row_groups"][group]["source_row_start"] + ordinal,
                             observed_time=None, label_available_time=None)
                rows.append(event)
            manifest["row_groups"][group]["payload_acquired"] = True
            manifest["logs_range_acquisition"] = remote.manifest()
            dump(manifest, out / "acquisition_manifest.json")
            print(json.dumps({"stage": "payload", "group": group, "selected_rows": len(indices),
                              "network_bytes": remote.network_bytes_this_process}), flush=True)
        header_file = cache / "headers.parquet"
        manifest["header_acquisition"] = full_download(blocks_metadata, header_file)
        header_table = pq.read_table(header_file, columns=["number", "hash", "parent_hash", "timestamp", "transaction_count"])
        stamps = pc.cast(header_table["timestamp"], pa.int64()).to_pylist()
        unit = header_table["timestamp"].type.unit
        scale = {"s": 1_000_000_000, "ms": 1_000_000, "us": 1_000, "ns": 1}[unit]
        headers = []
        for row, stamp in zip(header_table.to_pylist(), stamps):
            headers.append({"block_number": int(row["number"]), "block_hash": row["hash"].lower(),
                            "parent_hash": row["parent_hash"].lower(), "event_time_ns": int(stamp) * scale,
                            "transaction_count": int(row["transaction_count"])})
        headers.sort(key=lambda row: row["block_number"])
        if not headers or not all(datetime.fromtimestamp(r["event_time_ns"] // 1_000_000_000, timezone.utc).date().isoformat() == args.day for r in headers):
            raise RuntimeError("headers empty or outside requested UTC day")
        if len({r["block_hash"] for r in headers}) != len(headers) or not all(HEX32.fullmatch(r["block_hash"]) and HEX32.fullmatch(r["parent_hash"]) for r in headers):
            raise RuntimeError("duplicate or invalid header hashes")
        if len({r["block_number"] for r in headers}) != len(headers):
            raise RuntimeError("duplicate header block numbers")
        if not all(b["block_number"] == a["block_number"] + 1 and b["parent_hash"] == a["block_hash"] and b["event_time_ns"] > a["event_time_ns"] for a, b in zip(headers, headers[1:])):
            raise RuntimeError("header order/parent linkage failure")
        block_map = {row["block_number"]: row for row in headers}
        checks = validate_logs(rows, set(addresses), args.day, block_map)
        expected = sum(len(indices) for indices in selected.values())
        if len(rows) != expected:
            raise RuntimeError("some matched log rows lost during payload projection")
        rows.sort(key=lambda row: (row["block_number"], row["transaction_index"], row["log_index"]))
        matched_headers = [block_map[number] for number in sorted({row["block_number"] for row in rows})]
        files = []
        for name, records in (("selected_logs.jsonl", rows), ("matching_headers.jsonl", matched_headers)):
            path = selected_dir / name
            with path.open("w") as handle:
                for row in records:
                    handle.write(json.dumps(row, separators=(",", ":"), sort_keys=True, allow_nan=False) + "\n")
            files.append({"path": str(path.relative_to(ROOT)), "sha256": sha256(path), "bytes": path.stat().st_size, "rows": len(records)})
        counts = {}
        for event in rows:
            key = event["topics"][0] if event["topics"] else "no_topics"
            counts[key] = counts.get(key, 0) + 1
        manifest.update(status="complete", finished_utc=datetime.now(timezone.utc).isoformat(),
                        complete_address_rows_scanned=scanned, selected_log_count=len(rows),
                        selected_transaction_count=len({r["transaction_hash"] for r in rows}),
                        matching_header_count=len(matched_headers), full_header_count=len(headers),
                        header_parent_links_checked=max(0, len(headers)-1), topic0_counts=counts,
                        files=files, checks={**checks, "complete_address_scan": scanned == parquet.metadata.num_rows,
                                           "no_matched_rows_lost": len(rows) == expected},
                        timestamp_precision="integer nanoseconds from source; historical observation time unknown",
                        peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
                        rss_scope="whole Linux acquisition process high-water, including column decoding",
                        source_script_unchanged=sha256(__file__) == manifest["source_code_sha256"])
        manifest["logs_range_acquisition"] = remote.manifest()
        manifest["projection_transfer_ratio"] = remote.manifest()["total_cached_range_bytes"] / logs_metadata["size"]
        dump(manifest, out / "acquisition_manifest.json")
        print(json.dumps({"status": "complete", "manifest": str(out / "acquisition_manifest.json"),
                          "source_logs": scanned, "selected_logs": len(rows), "transactions": manifest["selected_transaction_count"],
                          "headers": len(matched_headers), "network_bytes": remote.network_bytes_this_process}), flush=True)
    except Exception as error:
        manifest.update(status="failed_incomplete", error=f"{type(error).__name__}: {error}",
                        finished_utc=datetime.now(timezone.utc).isoformat())
        if remote is not None:
            manifest["logs_range_acquisition"] = remote.manifest()
        dump(manifest, out / "acquisition_manifest.json")
        raise


if __name__ == "__main__":
    main()
