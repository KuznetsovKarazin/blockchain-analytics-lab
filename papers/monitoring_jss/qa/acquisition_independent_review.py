"""Reproduce acquisition QA offline; source/raw/run artifacts are read-only.

Run from the checkout with its existing private raw cache:
  python -B papers/monitoring_jss/qa/acquisition_independent_review.py \
    --output papers/monitoring_jss/qa/acquisition_independent_review.json
Only --output and temporary synthetic fixtures are written. No download fallback.
The preserved partition listing is historical evidence, not a fresh remote query.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
PAPER = ROOT / "papers/monitoring_jss"
RUN = "protocol_logs_20261025T083346_282558Z"


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OfflineRanges(io.RawIOBase):
    """Independent reader: only existing covering spans; never writes/downloads."""
    def __init__(self, cache, index):
        super().__init__()
        self.cache, self.index, self.position = cache, index, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        origin = {0: 0, 1: self.position, 2: self.index["source"]["size"]}[whence]
        if origin + offset < 0:
            raise ValueError("negative position")
        self.position = origin + offset
        return self.position

    def read(self, size=-1):
        remaining = self.index["source"]["size"] - self.position
        size = min(remaining, remaining if size < 0 else size)
        if size <= 0:
            return b""
        for name, span in self.index["ranges"].items():
            if span["start"] <= self.position and self.position + size <= span["stop"] + 1:
                with (self.cache / name).open("rb") as stream:
                    stream.seek(self.position - span["start"])
                    result = stream.read(size)
                if len(result) != size:
                    raise RuntimeError("short cached range")
                self.position += size
                return result
        raise RuntimeError(f"uncached span {self.position}:{size}; network disabled")


def rejected(call):
    try:
        call()
    except (ValueError, RuntimeError) as error:
        return {"rejected": True, "reason": str(error)}
    return {"rejected": False}


def adversarial(module):
    address = "0x" + "a" * 40
    row = {"chain_id": 1, "block_number": 100, "block_hash": "0x" + "b" * 64,
           "transaction_index": 0, "log_index": 1, "transaction_hash": "0x" + "c" * 64,
           "address": address, "topics": ["0x" + "d" * 64], "data": "0x0001",
           "event_time_ns": 1677628800000000000}
    blocks = {100: {"block_hash": row["block_hash"], "event_time_ns": row["event_time_ns"],
                    "transaction_count": 3}}
    cases = {
        "same_transaction_hash_multiple_positions": [row, {**row, "transaction_index": 1, "log_index": 2}],
        "global_log_order_reversed": [row, {**row, "transaction_index": 1, "log_index": 0,
                                            "transaction_hash": "0x" + "e" * 64}],
    }
    results = {name: rejected(lambda pair=pair: module.validate_logs(pair, {address}, "2023-03-01", blocks))
               for name, pair in cases.items()}
    with tempfile.TemporaryDirectory(prefix="acquisition-audit-") as temp:
        path = Path(temp) / "headers.parquet"
        path.write_bytes(b"abc")
        identity = {"url": "https://example.invalid/original", "size": 3,
                    "etag": '"same"', "version_id": "v1"}
        path.with_suffix(".json").write_text(json.dumps({**identity, "sha256": digest(path)}))
        for name, change in (("url", "https://example.invalid/other"), ("size", 100), ("version_id", "v2")):
            results[f"header_cache_changed_{name}"] = rejected(
                lambda name=name, change=change: module.full_download({**identity, name: change}, path))
    return results


def review(run_id=RUN, partition_listing=None):
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.parquet as pq

    manifest_path = PAPER / "runs" / run_id / "acquisition_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    source_path = PAPER / "acquire_protocol_logs.py"
    snapshot_path = manifest_path.parent / "acquire_protocol_logs_source.py"
    current = load_module(source_path, "acquisition_current_audit")
    snapshot = load_module(snapshot_path, "acquisition_snapshot_audit")
    cache = ROOT / manifest["raw_storage"]
    range_cache = cache.parent / "log_ranges"
    index = json.loads((range_cache / "range_index.json").read_text())
    files = {Path(item["path"]).name: item for item in manifest["files"]}
    rows = [json.loads(line) for line in (ROOT / files["selected_logs.jsonl"]["path"]).read_text().splitlines()]
    selected_headers = [json.loads(line) for line in (ROOT / files["matching_headers.jsonl"]["path"]).read_text().splitlines()]
    checks = {}
    checks["snapshot_hash_matches_run"] = digest(snapshot_path) == manifest["source_code_sha256"]
    checks["outputs_size_and_hash"] = all((ROOT / item["path"]).stat().st_size == item["bytes"]
                                         and digest(ROOT / item["path"]) == item["sha256"] for item in files.values())
    checks["cached_ranges_size_and_hash"] = all((range_cache / name).stat().st_size == span["bytes"]
        and digest(range_cache / name) == span["sha256"] for name, span in index["ranges"].items())
    checks["range_index_matches_run"] = index["ranges"] == manifest["logs_range_acquisition"]["ranges"]
    checks["range_source_identity_matches_run"] = index["source"] == manifest["logs_range_acquisition"]["source"]
    checks["whole_logs_object_sha_is_null"] = manifest["logs_range_acquisition"]["raw_whole_object_sha256"] is None

    parquet = pq.ParquetFile(OfflineRanges(range_cache, index))
    positions, group_counts, scanned, nulls = [], [], 0, 0
    addresses = set(manifest["scope"]["addresses"])
    for group in range(parquet.num_row_groups):
        values = parquet.read_row_group(group, columns=["address"], use_threads=False)["address"].to_pylist()
        matches = [i for i, value in enumerate(values) if value is not None and value.lower() in addresses]
        positions.extend((group, i, scanned + i) for i in matches)
        group_counts.append(len(matches))
        scanned += len(values)
        nulls += sum(value is None for value in values)
    checks["complete_address_scan"] = scanned == parquet.metadata.num_rows == manifest["source_log_rows"]
    checks["retained_source_positions_exact"] = sorted(positions) == sorted(
        (row["source_row_group"], row["source_row_index"], row["source_global_row_index"]) for row in rows)

    header_path = cache.parent / "headers.parquet"
    checks["full_header_hash_and_size"] = digest(header_path) == manifest["header_acquisition"]["sha256"] and header_path.stat().st_size == manifest["header_acquisition"]["size"]
    table = pq.read_table(header_path, columns=["number", "hash", "parent_hash", "timestamp", "transaction_count"])
    scale = {"s": 10**9, "ms": 10**6, "us": 1000, "ns": 1}[table["timestamp"].type.unit]
    timestamps = pc.cast(table["timestamp"], pa.int64()).to_pylist()
    headers = sorted(({"block_number": row["number"], "block_hash": row["hash"].lower(),
                       "parent_hash": row["parent_hash"].lower(), "event_time_ns": stamp * scale,
                       "transaction_count": row["transaction_count"]}
                      for row, stamp in zip(table.to_pylist(), timestamps)), key=lambda row: row["block_number"])
    blocks = {row["block_number"]: row for row in headers}
    checks["header_numbers_and_hashes_unique"] = len(blocks) == len(headers) == len({row["block_hash"] for row in headers})
    checks["all_header_parent_links"] = all(b["block_number"] == a["block_number"] + 1
        and b["parent_hash"] == a["block_hash"] and b["event_time_ns"] > a["event_time_ns"]
        for a, b in zip(headers, headers[1:]))
    checks["retained_headers_exact"] = selected_headers == [blocks[number] for number in sorted({row["block_number"] for row in rows})]
    checks["all_logs_match_full_headers"] = all(row["block_hash"] == blocks[row["block_number"]]["block_hash"]
        and row["event_time_ns"] == blocks[row["block_number"]]["event_time_ns"] for row in rows)
    checks["current_validator_accepts_real_data"] = all(current.validate_logs(rows, addresses, manifest["scope"]["day_utc"], blocks).values())
    ordered = sorted(rows, key=lambda row: (row["block_number"], row["transaction_index"], row["log_index"]))
    checks["output_execution_order"] = ordered == rows
    checks["global_log_order"] = all(a["block_number"] != b["block_number"] or a["log_index"] < b["log_index"] for a, b in zip(ordered, ordered[1:]))
    tx_positions = {}
    checks["transaction_hash_positions_unique"] = True
    for row in rows:
        position = (row["block_number"], row["transaction_index"])
        if tx_positions.setdefault(row["transaction_hash"], position) != position:
            checks["transaction_hash_positions_unique"] = False

    listing_path = Path(partition_listing).resolve() if partition_listing else Path(__file__).with_name("acquisition_partition_listing.json")
    listing = json.loads(listing_path.read_text())
    source_identities = (index["source"], manifest["header_acquisition"])
    checks["partition_inventory_single_object_matches"] = all(entry["is_truncated"] == "false"
        and len(entry["objects"]) == 1 and source["url"].endswith(entry["objects"][0]["Key"])
        and int(entry["objects"][0]["Size"]) == source["size"] and entry["objects"][0]["ETag"] == source["etag"]
        for entry, source in zip(listing, source_identities)) and len(listing) == 2

    with patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden during audit")):
        old_adversarial, new_adversarial = adversarial(snapshot), adversarial(current)
        suite = unittest.defaultTestLoader.discover(str(PAPER / "tests"), pattern="test_acquire_protocol_logs.py")
        log = io.StringIO()
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    checks["hardened_adversarial_cases_rejected"] = all(case["rejected"] for case in new_adversarial.values())
    checks["unit_tests_pass"] = result.wasSuccessful()
    elapsed = (datetime.fromisoformat(manifest["finished_utc"]) - datetime.fromisoformat(manifest["started_utc"])).total_seconds()
    return {
        "schema_version": "independent_offline_acquisition_review_v1",
        "checked_utc": datetime.now(timezone.utc).isoformat(), "passed": all(checks.values()), "checks": checks,
        "run_manifest": str(manifest_path.relative_to(ROOT)), "run_manifest_sha256": digest(manifest_path),
        "audit_script_sha256": digest(__file__), "source_snapshot_sha256": digest(snapshot_path),
        "current_source_sha256": digest(source_path), "current_source_differs_from_completed_run": digest(source_path) != digest(snapshot_path),
        "partition_listing": {"path": str(listing_path.relative_to(ROOT)), "sha256": digest(listing_path), "captured_evidence": listing},
        "counts": {"source_rows": scanned, "row_groups": parquet.num_row_groups, "matches_per_group": group_counts,
                   "null_addresses": nulls, "retained_logs": len(rows), "transactions": len(tx_positions),
                   "matching_headers": len(selected_headers), "full_headers": len(headers),
                   "parent_links": max(0, len(headers) - 1), "cached_ranges": len(index["ranges"])},
        "files": list(files.values()),
        "tests": {"run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "log": log.getvalue()},
        "adversarial_original_snapshot": old_adversarial, "adversarial_hardened_current_source": new_adversarial,
        "findings": ([
            {"id": "ACQ-01", "status": "resolved_current_code_original_run_unaffected", "original_location": "acquire_protocol_logs_source.py:162-170", "issue": "Header cache ignored URL,size,version identity on reuse; current code rejects each change independently. Original run fetched headers fresh."},
            {"id": "ACQ-02", "status": "resolved_current_code_original_run_unaffected", "original_location": "acquire_protocol_logs_source.py:190-222", "issue": "Original validator missed hash-to-position conflicts and reversed block-global log order; current code rejects both. Real saved rows pass both independent checks."}]
            if not all(case["rejected"] for case in old_adversarial.values()) else []),
        "resource_scope": {"acquisition_elapsed_seconds_from_utc": elapsed,
            "logs_source_bytes": index["source"]["size"], "cached_range_bytes": manifest["logs_range_acquisition"]["total_cached_range_bytes"],
            "header_network_bytes": manifest["header_acquisition"]["network_bytes_this_process"],
            "projection_transfer_ratio": manifest["projection_transfer_ratio"], "peak_rss_bytes": manifest["peak_rss_bytes"],
            "rss_scope": manifest["rss_scope"], "audit_network_requests": 0},
        "limitations": [
            "Requires existing private raw cache; the script fails on uncached spans and never downloads.",
            "Offline address projection independently checks membership and all retained source positions; other payload columns are code-reviewed and output-validated, not all independently re-decoded.",
            "Historical partition listing is preserved evidence, not a current source inventory query.",
            "Euler core all-topic emitter events are not equivalent to token cash outflows. No detection, training, losses or independent attack-case claim.",
            "Archive parent continuity does not establish consensus finality or historical observation/label times.",
            f"Projection transferred {manifest['projection_transfer_ratio']:.2%} of logs object plus full headers; do not infer large byte savings from projection alone.",
            "Acquisition timestamp duration is not a separately timed complete subprocess runtime; logs byte budget excludes header transfer."],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", default=RUN)
    parser.add_argument("--partition-listing", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = review(args.run, args.partition_listing)
    encoded = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output:
        args.output.write_text(encoded)
        print(json.dumps({"passed": report["passed"], "output": str(args.output), "counts": report["counts"]}))
    else:
        print(encoded, end="")
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
