#!/usr/bin/env python3
"""Six bounded trailer/footer reads; never reads or decodes Parquet row data."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def need(value, message):
    if not value:
        raise ValueError(message)


def stamp():
    return datetime.now(timezone.utc).isoformat()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def merge_ranges(columns):
    spans = sorted((row["start"], row["end_exclusive"]) for row in columns)
    merged = []
    for start, end in spans:
        need(start >= 4 and end > start, "Invalid column interval")
        if merged and start == merged[-1][1]:
            merged[-1][1] = end
        else:
            need(not merged or start >= merged[-1][1], "Overlapping column intervals")
            merged.append([start, end])
    return [{"start": start, "end_exclusive": end, "bytes": end - start} for start, end in merged]


def describe_footer(source, footer, trailer, plan, pa, pq):
    """Synthetic PAR1 is only a local metadata decoder envelope, not source bytes."""
    need(trailer[4:] == b"PAR1" and int.from_bytes(trailer[:4], "little") == len(footer), "Footer trailer mismatch")
    pf = pq.ParquetFile(pa.BufferReader(b"PAR1" + footer + trailer), pre_buffer=False)
    metadata, schema = pf.metadata, pf.schema_arrow
    caps = plan["caps"]
    need(0 < metadata.num_row_groups <= caps["max_row_groups"] and 0 < metadata.num_rows <= caps["max_rows"], "Metadata row/group cap")
    need(0 < len(schema.names) <= caps["max_top_level_columns"] and len(set(schema.names)) == len(schema.names), "Column name/count constraint")
    required = plan["required_columns"][source["table"]]
    need(bool(required) and len(required) == len(set(required)) and set(required) <= set(schema.names), "Required source field absent/repeated")
    if source["table"] == "transactions":
        need(schema.field("receipt_status").type == pa.int64(), "Receipt status is not the frozen integer type")
    timestamp = "timestamp" if source["table"] == "blocks" else "block_timestamp"
    need(pa.types.is_timestamp(schema.field(timestamp).type) and schema.field(timestamp).type.unit in ("s", "ms", "us", "ns"),
         "Unsupported timestamp metadata type")
    selected, row_groups, footer_start = [], [], source["size_bytes"] - 8 - len(footer)
    total_rows = 0
    for rg_index in range(metadata.num_row_groups):
        rg = metadata.row_group(rg_index)
        need(rg.num_columns <= caps["max_leaf_columns"] and rg.num_rows >= 0, "Row-group leaf/row cap")
        total_rows += rg.num_rows
        row_groups.append({"row_group": rg_index, "rows": rg.num_rows, "leaf_columns": rg.num_columns})
        found = set()
        for column_index in range(rg.num_columns):
            column = rg.column(column_index)
            top = column.path_in_schema.split(".", 1)[0]
            if top not in required:
                continue
            need(column.file_path in (None, ""), "External column file is outside this source plan")
            starts = [value for value in (column.dictionary_page_offset, column.data_page_offset)
                      if type(value) is int and value >= 4]
            need(bool(starts) and column.total_compressed_size > 0, "Missing column offset or compressed size")
            start, size = min(starts), column.total_compressed_size
            need(start + size <= footer_start, "Column span intersects footer or source end")
            selected.append({"row_group": rg_index, "column": top, "leaf_path": column.path_in_schema,
                "physical_type": column.physical_type, "compression": column.compression,
                "start": start, "end_exclusive": start + size, "compressed_bytes": size,
                "dictionary_page_offset": column.dictionary_page_offset, "data_page_offset": column.data_page_offset})
            found.add(top)
        need(found == set(required), "Required column missing in a row group")
    need(total_rows == metadata.num_rows, "Row-group/footer row totals differ")
    scenarios = []
    for name, names in plan["projection_scenarios"][source["table"]].items():
        need(bool(names) and len(names) == len(set(names)) and set(names) <= set(required), "Projection scenario has missing/repeated/out-of-contract columns")
        columns = [row for row in selected if row["column"] in names]
        ranges = merge_ranges(columns)
        scenarios.append({"name": name, "columns": names, "column_chunks": len(columns), "merged_ranges": ranges,
                          "range_request_count": len(ranges), "compressed_payload_bytes": sum(row["bytes"] for row in ranges),
                          "rows_read_or_decoded": 0, "meaning": "Exact footer-derived full selected-column span cost; no predicate result or payload acquired."})
    return {"table": source["table"], "day_utc": source["day_utc"], "key": source["key"],
        "source_size_bytes": source["size_bytes"], "source_etag_opaque": source["etag_opaque"],
        "footer_bytes": len(footer), "footer_sha256": sha(footer), "trailer_sha256": sha(trailer),
        "schema": [{"name": field.name, "type": str(field.type), "nullable": field.nullable} for field in schema],
        "row_count_metadata": metadata.num_rows, "row_group_count": metadata.num_row_groups, "row_groups": row_groups,
        "selected_column_chunks": selected, "projection_scenarios": scenarios,
        "statistics_values_exported": False, "row_data_read_or_decoded": False,
        "whole_source_sha256_verified": False, "local_decoder_envelope": "synthetic PAR1 + exact retained footer + exact retained trailer"}


class Capture:
    def __init__(self, plan, output):
        self.plan, self.output = plan, output
        self.started = time.monotonic()
        self.requests, self.bytes = [], 0
        self.opener = urllib.request.build_opener(NoRedirect())

    def fetch(self, source, kind, start, length):
        caps = self.plan["caps"]
        remaining = caps["wall_seconds"] - (time.monotonic() - self.started)
        need(remaining > 0 and len(self.requests) < caps["requests"], "Time/request cap reached")
        need(kind in ("trailer", "footer") and start >= 4 and length > 0 and start + length <= source["size_bytes"], "Unexpected range")
        need(length <= (8 if kind == "trailer" else caps["max_footer_bytes"]) and self.bytes + length <= caps["total_response_bytes"], "Range/total byte cap")
        ordinal = len(self.requests) + 1
        prefix = f"{ordinal:03d}_{source['table']}_{kind}"
        headers = {"Range": f"bytes={start}-{start + length - 1}", "If-Match": source["etag_opaque"],
                   "User-Agent": "Article2-footer-metadata/1", "Accept": "application/octet-stream"}
        request = {"method": "GET", "url": source["url"], "headers": headers, "kind": kind,
                   "start": start, "length": length, "source_size_bytes": source["size_bytes"]}
        save(self.output / (prefix + "_request.json"), request)
        record = {"ordinal": ordinal, "table": source["table"], "kind": kind, "started_utc": stamp(),
                  "request_file": prefix + "_request.json", "request_sha256": file_sha(self.output / (prefix + "_request.json")),
                  "transport_ok": False}
        self.requests.append(record)
        raw = bytearray()
        try:
            req = urllib.request.Request(source["url"], headers=headers)
            try:
                response = self.opener.open(req, timeout=min(caps["request_timeout_seconds"], remaining))
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                record.update(http_status=response.status, etag=response.headers.get("ETag"),
                    content_range=response.headers.get("Content-Range"), content_length=response.headers.get("Content-Length"))
                need(response.status == 206 and response.geturl() == source["url"], "Range HTTP error/redirect")
                need(record["etag"] == source["etag_opaque"], "ETag changed")
                need(record["content_range"] == f"bytes {start}-{start + length - 1}/{source['size_bytes']}", "Content-Range mismatch")
                need(record["content_length"] is not None and record["content_length"].isdigit()
                     and int(record["content_length"]) == length, "Content-Length mismatch")
                while len(raw) < length:
                    need(time.monotonic() - self.started < caps["wall_seconds"], "Wall cap during footer read")
                    chunk = response.read(min(65536, length - len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
                need(len(raw) == length, "Truncated exact range")
            record["transport_ok"] = True
            return bytes(raw)
        except Exception as exc:
            record["failure"] = type(exc).__name__ + ": " + str(exc)
            raise
        finally:
            body = bytes(raw)
            self.bytes += len(body)
            (self.output / (prefix + "_response.bin")).write_bytes(body)
            record.update(completed_utc=stamp(), response_file=prefix + "_response.bin",
                          response_bytes=len(body), response_sha256=sha(body),
                          error_body_retained=False if not record["transport_ok"] and not body else None)
            save(self.output / "requests.json", self.requests)


def main():
    parser = argparse.ArgumentParser()
    for name in ("plan", "inventory", "dependencies", "wheel", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--accepted-plan-sha256", required=True)
    parser.add_argument("--accepted-runner-sha256", required=True)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    need(file_sha(args.plan) == args.accepted_plan_sha256 and file_sha(Path(__file__)) == args.accepted_runner_sha256, "Exact plan/runner freeze differs")
    plan = json.loads(args.plan.read_bytes())
    need(plan["schema_version"] == "article2_phase14_first_day_footer_plan_v1", "Wrong plan schema")
    need(plan["endpoint"] == "https://aws-public-blockchain.s3.us-east-2.amazonaws.com/"
         and plan["caps"] == {"requests": 6, "max_footer_bytes": 1048576, "total_response_bytes": 3145752,
             "wall_seconds": 300, "request_timeout_seconds": 30, "max_rows": 100000000,
             "max_row_groups": 1024, "max_top_level_columns": 128, "max_leaf_columns": 256,
             "retries": 0, "concurrency": 1}, "Endpoint or frozen metadata caps differ")
    need(file_sha(args.inventory) == plan["inventory_summary_sha256"], "Inventory binding differs")
    inventory = json.loads(args.inventory.read_bytes())
    need(inventory["status"] == "COMPLETE_LISTING_METADATA_ONLY", "Inventory incomplete")
    need([row["table"] for row in plan["sources"]] == ["logs", "blocks", "transactions"] and plan["day_utc"] == "2022-02-19", "First-day table schedule differs")
    for source in plan["sources"]:
        cell = next(row for row in inventory["day_table_cells"] if row["day_utc"] == plan["day_utc"] and row["table"] == source["table"])
        need(cell["status"] == "LISTED_NONEMPTY" and len(cell["objects"]) == 1, "First-day expected single object absent")
        need(source == {**cell["objects"][0], "table": cell["table"], "day_utc": cell["day_utc"]}, "Source identity differs from inventory")
        need(source["url"] == plan["endpoint"] + source["key"] and source["size_bytes"] > 12, "Endpoint/source size differs")
    need(file_sha(args.wheel) == plan["dependency"]["wheel_sha256"], "Retained dependency wheel differs")
    sys.path.insert(0, str(args.dependencies.resolve()))
    import pyarrow as pa
    import pyarrow.parquet as pq
    need(pa.__version__ == plan["dependency"]["version"]
         and Path(pa.__file__).resolve().is_relative_to(args.dependencies.resolve()), "Parser version/origin differs")
    if args.preflight_only:
        print(json.dumps({"status": "PREFLIGHT_PASS_NO_NETWORK", "maximum_range_requests": 6,
                          "row_data_queries": 0, "pyarrow_version": pa.__version__}))
        return
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "frozen_plan.json").write_bytes(args.plan.read_bytes())
    (args.output / "runner_source.py").write_bytes(Path(__file__).read_bytes())
    save(args.output / "acceptance.json", {"started_utc": stamp(), "plan_sha256": args.accepted_plan_sha256,
        "runner_sha256": args.accepted_runner_sha256, "dependency_wheel_sha256": plan["dependency"]["wheel_sha256"],
        "pyarrow_version": pa.__version__})
    capture = Capture(plan, args.output)
    result = {"schema_version": "article2_phase14_first_day_footer_result_v1", "plan_sha256": args.accepted_plan_sha256,
        "runner_sha256": args.accepted_runner_sha256, "inventory_summary_sha256": plan["inventory_summary_sha256"],
        "day_utc": plan["day_utc"], "sources": [], "row_data_read_or_decoded": False,
        "new_package_downloads_or_installs": 0, "detector_scores": 0, "scientific_admissions": 0,
        "whole_source_hashes_verified": False, "full_window_cost_established": False}
    try:
        for source in plan["sources"]:
            trailer = capture.fetch(source, "trailer", source["size_bytes"] - 8, 8)
            need(trailer[4:] == b"PAR1", "Missing Parquet trailer magic")
            length = int.from_bytes(trailer[:4], "little")
            need(0 < length <= plan["caps"]["max_footer_bytes"] and length + 12 <= source["size_bytes"], "Footer length outside cap/source")
            footer = capture.fetch(source, "footer", source["size_bytes"] - 8 - length, length)
            result["sources"].append(describe_footer(source, footer, trailer, plan, pa, pq))
            save(args.output / "progress.json", result)
        result["status"] = "COMPLETE_FIRST_DAY_SCHEMA_AND_PROJECTION_METADATA_ONLY"
    except Exception as exc:
        result.update(status="UNAVAILABLE_OR_PARTIAL_FIRST_DAY_FOOTER_METADATA", failure=type(exc).__name__ + ": " + str(exc))
    finally:
        result.update(completed_utc=stamp(), new_range_requests=len(capture.requests), retained_response_bytes=capture.bytes,
            fully_described_sources=len(result["sources"]),
            interpretation="Exact compressed span cost for full chosen columns of the fixed first date; predicate-dependent payload and other dates remain unmeasured.")
        save(args.output / "summary.json", result)
    print(json.dumps({key: value for key, value in result.items() if key != "sources"}, indent=2))


if __name__ == "__main__":
    main()
