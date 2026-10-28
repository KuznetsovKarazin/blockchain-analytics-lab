#!/usr/bin/env python3
"""Bounded original-byte Parquet range acquisition, with no detector or labels.

Successful HTTP bodies live at their exact offsets in sparse source files. Every
readable column is backed by complete hash-bound ranges; sparse holes are never
represented as acquired data. Callers own scientific acceptance and source lists.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

ENDPOINT = "https://aws-public-blockchain.s3.us-east-2.amazonaws.com/"
TABLES = {"blocks", "logs", "transactions"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def need(value, message):
    if not value:
        raise ValueError(message)


def integer(value, name, minimum=0):
    need(type(value) is int and value >= minimum, "invalid integer: " + name)
    return value


def file_sha(path, start=0, length=None):
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        handle.seek(start)
        remaining = length
        while remaining is None or remaining:
            block = handle.read(1048576 if remaining is None else min(1048576, remaining))
            if not block:
                need(remaining in (None, 0), "retained range truncated")
                break
            h.update(block)
            if remaining is not None:
                remaining -= len(block)
    return h.hexdigest()


def save(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".pending")
    temporary.write_bytes(json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n")
    temporary.replace(path)


def stamp():
    return datetime.now(timezone.utc).isoformat()


def identity(source):
    table, day, key = source["table"], source["day_utc"], source["key"]
    need(table in TABLES and type(day) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}", day), "source table/date")
    need(type(key) is str and re.fullmatch(r"v1\.0/eth/" + table + r"/date=" + day + r"/[A-Za-z0-9_.-]+\.parquet", key), "source key outside frozen layout")
    need(source.get("url", ENDPOINT + key) == ENDPOINT + key, "source URL differs")
    integer(source["size_bytes"], "source size", 12)
    need(type(source["etag_opaque"]) is str and bool(source["etag_opaque"]), "opaque source ETag missing")
    return {"table": table, "day_utc": day, "key": key, "size_bytes": source["size_bytes"],
            "etag_opaque": source["etag_opaque"], "url": ENDPOINT + key}


def merge_ranges(spans):
    """Canonical union of possibly overlapping/adjacent half-open spans."""
    result = []
    for start, end in sorted(set(tuple(x) for x in spans)):
        integer(start, "range start")
        integer(end, "range end", 1)
        need(end > start, "empty range")
        if result and start <= result[-1][1]:
            result[-1][1] = max(end, result[-1][1])
        else:
            result.append([start, end])
    return result


def missing_ranges(wanted, available):
    available = merge_ranges(available)
    result = []
    for start, end in merge_ranges(wanted):
        cursor = start
        for a, b in available:
            if b <= cursor or a >= end:
                continue
            if a > cursor:
                result.append([cursor, min(a, end)])
            cursor = max(cursor, min(b, end))
            if cursor == end:
                break
        if cursor < end:
            result.append([cursor, end])
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class RangeSession:
    """One bounded attempt. No retries, provider switching, or hidden HEAD calls."""
    def __init__(self, plan, capture_dir, opener=None, *, resume=False):
        need(plan.get("schema_version") == "article2_phase16_range_source_plan_v1", "range plan schema")
        need(plan.get("endpoint") == ENDPOINT, "range endpoint")
        self.plan = plan
        self.caps = plan["caps"]
        for name in ("requests", "total_response_bytes", "wall_seconds", "request_timeout_seconds",
                     "max_range_bytes", "max_footer_bytes", "max_rows", "max_row_groups",
                     "max_top_level_columns", "max_leaf_columns", "max_source_bytes"):
            integer(self.caps[name], name, 1)
        need(self.caps["retries"] == 0 and type(self.caps["retries"]) is int
             and self.caps["concurrency"] == 1 and type(self.caps["concurrency"]) is int, "unsupported retry/concurrency")
        self.output = Path(capture_dir)
        self.opener = opener or urllib.request.build_opener(NoRedirect())
        if resume:
            prior = json.loads((self.output / "session.json").read_bytes())
            need(canonical(json.loads((self.output / "plan.json").read_bytes())) == canonical(plan)
                 and prior["plan_canonical_sha256"] == digest(plan), "resume plan differs")
            need(prior["status"] == "OPEN", "only a clean open checkpoint can resume")
            self.started_utc = prior["started_utc"]
            original_start = datetime.fromisoformat(self.started_utc)
            need(original_start.tzinfo is not None, "resume clock lacks timezone")
            elapsed = (datetime.now(timezone.utc) - original_start).total_seconds()
            need(elapsed >= 0 and elapsed >= prior["wall_seconds_elapsed"] - 1
                 and elapsed < self.caps["wall_seconds"], "resume original deadline elapsed or clock reversed")
            self.started = time.monotonic() - elapsed
            self.requests = json.loads((self.output / "requests.json").read_bytes())
            need(all(x.get("transport_ok") is True and x.get("response_bytes") == x["length"]
                     for x in self.requests), "failed or pending request cannot resume")
            need(len(self.requests) == prior["request_count"], "resume request accounting differs")
            self.bytes = sum(x["response_bytes"] for x in self.requests)
            need(self.bytes == prior["retained_response_bytes"], "resume byte accounting differs")
            self.reused_sources = prior["cache_or_full_object_reuses"]
        else:
            self.output.mkdir(parents=True, exist_ok=False)
            self.started = time.monotonic()
            self.started_utc = stamp()
            self.requests = []
            self.bytes = 0
            self.reused_sources = []
            save(self.output / "plan.json", plan)
        self.attempt_id = digest({"plan": digest(plan), "started_utc": self.started_utc})
        self.failed = False
        self.inflight = False
        self.checkpoint("OPEN")

    def checkpoint(self, status):
        save(self.output / "requests.json", self.requests)
        save(self.output / "session.json", {
            "schema_version": "article2_phase16_range_capture_v1", "status": status,
            "started_utc": self.started_utc, "updated_utc": stamp(), "attempt_id": self.attempt_id,
            "plan_canonical_sha256": digest(self.plan), "request_count": len(self.requests),
            "retained_response_bytes": self.bytes, "wall_seconds_elapsed": time.monotonic() - self.started,
            "cache_or_full_object_reuses": self.reused_sources, "retries": 0,
            "body_storage": "Exact source offsets in sparse files; only recorded ranges are acquired bytes."})

    def fetch_into(self, source, kind, start, length, target):
        need(not self.failed and not self.inflight, "failed or active session cannot start another request")
        source = identity(source)
        integer(start, "range start")
        integer(length, "range length", 1)
        need(start + length <= source["size_bytes"] and source["size_bytes"] <= self.caps["max_source_bytes"], "range/source cap")
        need(length <= self.caps["max_range_bytes"], "per-range byte cap")
        need(self.bytes + length <= self.caps["total_response_bytes"], "total byte cap")
        remaining = self.caps["wall_seconds"] - (time.monotonic() - self.started)
        need(remaining > 0 and len(self.requests) < self.caps["requests"], "wall/request cap")
        headers = {"Range": f"bytes={start}-{start + length - 1}", "If-Match": source["etag_opaque"],
                   "Accept": "application/octet-stream", "Accept-Encoding": "identity",
                   "User-Agent": "Article2-fixed-core-source/1"}
        record = {"ordinal": len(self.requests) + 1, "source": source, "kind": kind,
                  "method": "GET", "request_headers": headers, "start": start, "length": length,
                  "started_utc": stamp(), "transport_ok": False, "response_bytes": 0,
                  "stored_file_name": Path(target).name, "stored_offset": start}
        self.requests.append(record)
        self.inflight = True
        self.checkpoint("OPEN_REQUEST_PENDING")
        got, h = 0, hashlib.sha256()
        try:
            request = urllib.request.Request(source["url"], headers=headers)
            try:
                response = self.opener.open(request, timeout=min(self.caps["request_timeout_seconds"], remaining))
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                record.update(http_status=response.status, response_url=response.geturl(),
                    etag=response.headers.get("ETag"), content_range=response.headers.get("Content-Range"),
                    content_length=response.headers.get("Content-Length"), content_encoding=response.headers.get("Content-Encoding"))
                need(response.status == 206 and response.geturl() == source["url"], "HTTP status/redirect")
                need(record["etag"] == source["etag_opaque"], "ETag changed")
                need(record["content_range"] == f"bytes {start}-{start + length - 1}/{source['size_bytes']}", "Content-Range mismatch")
                need(record["content_length"] is not None and record["content_length"].isdigit()
                     and int(record["content_length"]) == length, "Content-Length mismatch")
                need(record["content_encoding"] in (None, "identity"), "encoded response")
                with Path(target).open("r+b") as handle:
                    handle.seek(start)
                    while got < length:
                        need(time.monotonic() - self.started < self.caps["wall_seconds"], "wall cap during range")
                        chunk = response.read(min(1048576, length - got))
                        if not chunk:
                            break
                        need(len(chunk) <= length - got, "oversize response chunk")
                        handle.write(chunk)
                        h.update(chunk)
                        got += len(chunk)
                        need(time.monotonic() - self.started < self.caps["wall_seconds"], "wall cap after range read")
                    handle.flush()
                need(got == length, "truncated exact range")
            need(time.monotonic() - self.started < self.caps["wall_seconds"], "wall cap after response close")
            record["transport_ok"] = True
            return record
        except Exception as exc:
            record["failure"] = type(exc).__name__ + ": " + str(exc)
            raise
        finally:
            self.bytes += got
            self.inflight = False
            self.failed = not record["transport_ok"]
            record.update(completed_utc=stamp(), response_bytes=got, response_sha256=h.hexdigest(),
                          invalid_header_body_read=False)
            self.checkpoint("OPEN" if record["transport_ok"] else "FAILED_RANGE_ATTEMPT")

    def close(self, status="COMPLETE"):
        need(not self.inflight, "cannot close active request")
        need(status != "COMPLETE" or not self.failed, "failed transport cannot be complete")
        self.checkpoint(status)


class SourceReader:
    def __init__(self, source, session, cache_dir, pa, pq, reuse=None):
        self.source = identity(source)
        self.session, self.pa, self.pq = session, pa, pq
        self.source_id = digest(self.source)
        self.directory = Path(cache_dir) / self.source_id
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "source.parquet"
        self.cache_manifest = self.directory / "ranges.json"
        self.ranges = []
        self.reuse = reuse
        self.metadata = self.schema = None
        self.described_chunks = []
        self.reads = []
        self.footer_start = None
        self._opened = False

    def _persist(self):
        save(self.cache_manifest, {"schema_version": "article2_phase16_source_range_cache_v1",
            "source": self.source, "attempt_id": self.session.attempt_id, "ranges": self.ranges})

    def _load_cache(self):
        if self.cache_manifest.exists():
            value = json.loads(self.cache_manifest.read_bytes())
            need(value["schema_version"] == "article2_phase16_source_range_cache_v1"
                 and canonical(value["source"]) == canonical(self.source)
                 and value["attempt_id"] == self.session.attempt_id, "cache source/attempt differs")
            need(self.path.is_file() and self.path.stat().st_size == self.source["size_bytes"], "cache sparse size differs")
            # A clean capture checkpoint may precede the final cache-index write.
            # Recover only its successful, already charged original responses.
            records = list(value["ranges"])
            known = {(x["start"], x["length"]) for x in records}
            for record in self.session.requests:
                if canonical(record["source"]) == canonical(self.source) and (record["start"], record["length"]) not in known:
                    need(record.get("transport_ok") is True, "unaccepted captured cache range")
                    records.append(record)
                    known.add((record["start"], record["length"]))
            spans = []
            accepted = {x["ordinal"]: x for x in self.session.requests if x.get("transport_ok") is True}
            for record in records:
                need(record.get("ordinal") in accepted and canonical(record) == canonical(accepted[record["ordinal"]]),
                     "cached receipt differs from charged capture")
                start, length = record["start"], record["length"]
                integer(start, "cache start")
                integer(length, "cache length", 1)
                need(start + length <= self.source["size_bytes"], "cache range outside source")
                need(record["transport_ok"] is True and record["http_status"] == 206
                     and canonical(record["source"]) == canonical(self.source), "unaccepted cached range")
                need(record["etag"] == self.source["etag_opaque"]
                     and record["content_range"] == f"bytes {start}-{start + length - 1}/{self.source['size_bytes']}"
                     and record["content_length"] == str(length)
                     and record["response_bytes"] == length
                     and record["request_headers"]["If-Match"] == self.source["etag_opaque"]
                     and record["request_headers"]["Range"] == f"bytes={start}-{start + length - 1}", "cached header binding differs")
                need(file_sha(self.path, start, length) == record["response_sha256"], "cached original bytes changed")
                spans.append([start, start + length])
            need(sum(b-a for a,b in spans) == sum(b-a for a,b in merge_ranges(spans)), "overlapping cached responses")
            self.ranges = records
            self._persist()
            self.session.reused_sources.append({"source_id": self.source_id, "kind": "verified_range_cache",
                                                "ranges": len(self.ranges), "bytes": sum(b-a for a,b in spans)})
        else:
            need(not self.path.exists(), "unbound existing sparse source")
            with self.path.open("xb") as handle:
                handle.truncate(self.source["size_bytes"])
            self._persist()

    def _ensure_ranges(self, spans, kind):
        if self.reuse is not None:
            return
        missing = missing_ranges(spans, [[r["start"], r["start"] + r["length"]] for r in self.ranges])
        for start, end in missing:
            while start < end:
                length = min(end - start, self.session.caps["max_range_bytes"])
                record = self.session.fetch_into(self.source, kind, start, length, self.path)
                self.ranges.append(record)
                self._persist()
                start += length

    def _read_exact(self, start, length):
        need(self.reuse is not None or not missing_ranges([[start, start + length]],
             [[r["start"], r["start"] + r["length"]] for r in self.ranges]), "attempt to read sparse hole")
        with self.path.open("rb") as handle:
            handle.seek(start)
            raw = handle.read(length)
        need(len(raw) == length, "local original range truncated")
        return raw

    def open(self):
        need(not self._opened, "source already opened")
        need(self.source["size_bytes"] <= self.session.caps["max_source_bytes"], "source size cap")
        if self.reuse is not None:
            value = self.reuse
            need(value["source_key"] == self.source["key"] and value["size_bytes"] == self.source["size_bytes"]
                 and value["etag_opaque"] == self.source["etag_opaque"], "whole-object reuse identity differs")
            self.path = Path(value["path"])
            need(self.path.is_file() and self.path.stat().st_size == self.source["size_bytes"]
                 and file_sha(self.path) == value["sha256"], "whole-object reuse bytes differ")
            self.session.reused_sources.append({"source_id": self.source_id, "kind": "verified_whole_object",
                                               "bytes": self.source["size_bytes"], "sha256": value["sha256"]})
        else:
            self._load_cache()
        size = self.source["size_bytes"]
        self._ensure_ranges([[0, 4]], "leading_magic")
        need(self._read_exact(0, 4) == b"PAR1", "leading Parquet magic differs")
        self._ensure_ranges([[size - 8, size]], "trailer")
        trailer = self._read_exact(size - 8, 8)
        length = int.from_bytes(trailer[:4], "little")
        need(trailer[4:] == b"PAR1" and 0 < length <= self.session.caps["max_footer_bytes"]
             and length + 12 <= size, "footer trailer/length invalid")
        self.footer_start = size - 8 - length
        self._ensure_ranges([[self.footer_start, size - 8]], "footer")
        footer = self._read_exact(self.footer_start, length)
        pf = self.pq.ParquetFile(self.pa.BufferReader(b"PAR1" + footer + trailer), pre_buffer=False)
        self.metadata, self.schema = pf.metadata, pf.schema_arrow
        caps = self.session.caps
        need(0 <= self.metadata.num_rows <= caps["max_rows"] and 0 <= self.metadata.num_row_groups <= caps["max_row_groups"], "metadata row/group cap")
        need(self.source["table"] == "logs" or self.metadata.num_rows > 0, "empty block/transaction source")
        names = self.schema.names
        need(0 < len(names) <= caps["max_top_level_columns"] and len(names) == len(set(names)), "schema names/cap")
        required = self.session.plan["required_columns"][self.source["table"]]
        need(type(required) is list and len(required) == len(set(required)) and bool(required)
             and set(required) <= set(names), "required schema fields missing/repeated")
        timestamp = "timestamp" if self.source["table"] == "blocks" else "block_timestamp"
        need(self.pa.types.is_timestamp(self.schema.field(timestamp).type)
             and self.schema.field(timestamp).type.unit in ("s", "ms", "us", "ns"), "timestamp type unsupported")
        if self.source["table"] == "transactions":
            need(self.schema.field("receipt_status").type == self.pa.int64(), "status is not int64")
        total_rows = 0
        all_spans = []
        for rg in range(self.metadata.num_row_groups):
            group = self.metadata.row_group(rg)
            total_rows += group.num_rows
            need(group.num_columns <= caps["max_leaf_columns"], "leaf column cap")
            found = set()
            for index in range(group.num_columns):
                column = group.column(index)
                top = column.path_in_schema.split(".", 1)[0]
                if top not in required:
                    continue
                need(column.file_path in (None, ""), "external column file unsupported")
                starts = [x for x in (column.dictionary_page_offset, column.data_page_offset)
                          if type(x) is int and x >= 4]
                need(starts and column.total_compressed_size > 0, "column offset/size absent")
                start = min(starts)
                end = start + column.total_compressed_size
                need(end <= self.footer_start, "column span overlaps footer")
                self.described_chunks.append({"row_group": rg, "column": top,
                    "leaf_path": column.path_in_schema, "start": start, "end_exclusive": end,
                    "compressed_bytes": end - start, "compression": column.compression,
                    "physical_type": column.physical_type})
                all_spans.append([start, end])
                found.add(top)
            need(found == set(required), "row group required columns absent")
        need(total_rows == self.metadata.num_rows, "footer group row total differs")
        need(sum(b-a for a,b in all_spans) == sum(b-a for a,b in merge_ranges(all_spans)), "required column chunks overlap")
        self._opened = True
        self.session.checkpoint("OPEN")
        return self

    def ensure_columns(self, columns, row_groups=None):
        need(self._opened, "source not opened")
        need(type(columns) in (list, tuple) and bool(columns) and len(columns) == len(set(columns)), "column list")
        required = self.session.plan["required_columns"][self.source["table"]]
        need(set(columns) <= set(required), "column outside frozen projection")
        groups = list(range(self.metadata.num_row_groups)) if row_groups is None else list(row_groups)
        need(groups == sorted(set(groups)) and all(type(x) is int and 0 <= x < self.metadata.num_row_groups for x in groups), "row group list")
        chunks = [x for x in self.described_chunks if x["row_group"] in groups and x["column"] in columns]
        self._ensure_ranges([[x["start"], x["end_exclusive"]] for x in chunks], "column_chunks")
        return chunks

    def read_row_group(self, index, columns):
        self.ensure_columns(columns, [index])
        pf = self.pq.ParquetFile(str(self.path), pre_buffer=False, memory_map=False)
        table = pf.read_row_group(index, columns=list(columns), use_threads=False)
        need(table.num_rows == self.metadata.row_group(index).num_rows and set(table.column_names) == set(columns), "decoded projection shape differs")
        self.reads.append({"row_group": index, "columns": list(columns), "rows": table.num_rows})
        return table

    def iter_row_groups(self, columns, row_groups=None):
        groups = list(range(self.metadata.num_row_groups)) if row_groups is None else list(row_groups)
        self.ensure_columns(columns, groups)
        for index in groups:
            yield index, self.read_row_group(index, columns)

    def manifest(self):
        need(self._opened, "source not opened")
        available = merge_ranges([[r["start"], r["start"] + r["length"]] for r in self.ranges])
        if self.reuse is not None:
            available = [[0, self.source["size_bytes"]]]
        return {"schema_version": "article2_phase16_projected_source_manifest_v1", "source": self.source,
            "source_id": self.source_id, "source_file_name": self.path.name,
            "whole_source_sha256_verified": self.reuse is not None,
            "whole_source_sha256": None if self.reuse is None else self.reuse["sha256"],
            "schema": [{"name": x.name, "type": str(x.type), "nullable": x.nullable} for x in self.schema],
            "row_count_metadata": self.metadata.num_rows, "row_group_count": self.metadata.num_row_groups,
            "row_group_rows": [self.metadata.row_group(x).num_rows for x in range(self.metadata.num_row_groups)],
            "column_chunks": [{**x, "acquired": not missing_ranges([[x["start"], x["end_exclusive"]]], available)} for x in self.described_chunks],
            "successful_original_ranges": self.ranges, "available_ranges": available,
            "available_original_bytes": sum(b-a for a,b in available), "read_projections": self.reads,
            "statistics_values_exported_or_used": False, "holes_are_original_bytes": False,
            "receipt_roots_verified": False, "independent_chain_completeness_verified": False}
