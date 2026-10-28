"""Independent, offline, exact-interval reader for authenticated source blobs.

The immutable logical source consists only of explicitly verified intervals.
Unacquired bytes are never allocated, synthesized, returned, or interpreted.
This module imports no producer reader or transport implementation.
"""
from __future__ import annotations
import hashlib
import io
from pathlib import Path
import re


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024**2), b""):
            h.update(chunk)
    return h.hexdigest()


class IndependentIntervalFile(io.RawIOBase):
    """Read-only random access, rejecting the entire read if any byte is absent."""
    def __init__(self, logical_size, verified_blobs):
        super().__init__()
        need(type(logical_size) is int and logical_size >= 12, "invalid logical source size")
        self.logical_size = logical_size
        self.position = 0
        self.intervals = []
        self.read_events = []
        for item in verified_blobs:
            lo, length = item["start"], item["length"]
            need(type(lo) is int and type(length) is int and lo >= 0 and length > 0
                 and lo + length <= logical_size, "invalid verified interval")
            expected = item["sha256"]
            need(type(expected) is str and re.fullmatch("[0-9a-f]{64}", expected), "invalid blob digest")
            path = Path(item["path"])
            need(path.is_file() and path.stat().st_size == length, "verified blob length differs")
            need(sha(path) == expected, "verified blob bytes changed after transport audit")
            stat = path.stat()
            self.intervals.append((lo, lo + length, path, (stat.st_dev, stat.st_ino, stat.st_size,
                                                         stat.st_mtime_ns, stat.st_ctime_ns)))
        self.intervals.sort(key=lambda item: item[0])
        need(self.intervals and all(a[1] <= b[0] for a, b in zip(self.intervals, self.intervals[1:])),
             "overlapping verified blob intervals")

    def readable(self):
        return True

    def seekable(self):
        return True

    def writable(self):
        return False

    def tell(self):
        self._checkClosed()
        return self.position

    def seek(self, offset, whence=io.SEEK_SET):
        self._checkClosed()
        need(type(offset) is int and whence in (io.SEEK_SET, io.SEEK_CUR, io.SEEK_END), "invalid seek")
        base = 0 if whence == io.SEEK_SET else self.position if whence == io.SEEK_CUR else self.logical_size
        position = base + offset
        need(0 <= position <= self.logical_size, "seek outside logical source")
        self.position = position
        return position

    def read(self, size=-1):
        self._checkClosed()
        need(size is None or type(size) is int, "invalid read size")
        end = self.logical_size if size is None or size < 0 else min(self.logical_size, self.position + size)
        start = self.position
        if end == start:
            return b""
        pieces, cursor = [], start
        for lo, hi, path, snapshot in self.intervals:
            if hi <= cursor:
                continue
            if lo > cursor:
                break
            take_end = min(hi, end)
            pieces.append((path, cursor - lo, take_end - cursor, snapshot))
            cursor = take_end
            if cursor == end:
                break
        need(cursor == end, "unacquired interval requested; no missing bytes synthesized")
        # Coverage is established for the entire request before any blob read.
        values = []
        for path, offset, length, snapshot in pieces:
            stat = path.stat()
            need((stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns) == snapshot,
                 "immutable verified blob changed during source audit")
            with path.open("rb") as handle:
                handle.seek(offset)
                value = handle.read(length)
            need(len(value) == length, "verified blob truncated during read")
            values.append(value)
        self.position = end
        self.read_events.append([start, end])
        return b"".join(values)

    def readinto(self, target):
        value = self.read(len(target))
        target[:len(value)] = value
        return len(value)


class IndependentCompactSource:
    """Same row-auditor interface, backed by verified blobs instead of holes."""
    def __init__(self, source, manifest, transport, pa, pq):
        identity = {key: source[key] for key in ("table", "day_utc", "key", "size_bytes", "etag_opaque", "url")}
        self.source, self.manifest, self.transport = identity, manifest, transport
        need(identity == manifest["source"] == transport["source"], "source identity differs")
        need(identity["key"] == transport["source_key"], "transport source key differs")
        if transport["storage_kind"] == "compact_descriptor":
            blobs = transport["verified_blobs"]
        elif transport["storage_kind"] == "verified_whole_object":
            blobs = [{"start": 0, "length": identity["size_bytes"], "path": transport["path"],
                      "sha256": transport["sha256"]}]
        else:
            raise ValueError("unsupported independently verified source storage")
        self.backing = IndependentIntervalFile(identity["size_bytes"], blobs)
        self.spans = [[lo, hi] for lo, hi, _, _ in self.backing.intervals]
        need(self.spans == transport["available_ranges"], "verified ranges differ from actual blob extents")
        size = identity["size_bytes"]
        need(self.backing.read(4) == b"PAR1", "leading magic differs")
        self.backing.seek(size - 8)
        trailer = self.backing.read(8)
        length = int.from_bytes(trailer[:4], "little")
        need(trailer[4:] == b"PAR1" and 0 < length <= 1024**2 and length + 12 <= size,
             "invalid verified footer envelope")
        self.footer_start = size - 8 - length
        self.backing.seek(self.footer_start)
        footer = self.backing.read(length)
        # This temporary decoder envelope is scaffolding, not acquired source
        # content. Every footer byte and both actual source magic words above
        # were independently authenticated. Original column offsets remain.
        decoded = pq.ParquetFile(pa.BufferReader(b"PAR1" + footer + trailer), pre_buffer=False)
        self.metadata = decoded.metadata
        self.arrow_file = pa.PythonFile(self.backing, mode="r")
        self.file = pq.ParquetFile(self.arrow_file, metadata=self.metadata,
                                   pre_buffer=False, buffer_size=0)
        need(self.metadata.num_rows == manifest["row_count_metadata"]
             and self.metadata.num_row_groups == manifest["row_group_count"], "metadata totals differ")
        need([self.metadata.row_group(i).num_rows for i in range(self.metadata.num_row_groups)]
             == manifest["row_group_rows"], "metadata group sizes differ")
        self.reads = []

    def read(self, group, columns):
        need(type(group) is int and 0 <= group < self.metadata.num_row_groups, "invalid row group")
        need(type(columns) in (list, tuple) and len(columns) == len(set(columns)), "invalid projected columns")
        rg = self.metadata.row_group(group)
        found = set()
        for index in range(rg.num_columns):
            column = rg.column(index)
            top = column.path_in_schema.split(".", 1)[0]
            if top not in columns:
                continue
            need(column.file_path in (None, ""), "external column source")
            starts = [x for x in (column.dictionary_page_offset, column.data_page_offset)
                      if type(x) is int and x >= 4]
            need(starts and column.total_compressed_size > 0, "invalid chunk extent")
            lo = min(starts); hi = lo + column.total_compressed_size
            need(hi <= self.footer_start, "chunk overlaps footer")
            cursor = lo
            for left, right in self.spans:
                if left <= cursor < right:
                    cursor = right
                if cursor >= hi:
                    break
            need(cursor >= hi, "unacquired projected column chunk requested")
            found.add(top)
        need(found == set(columns), "missing projected column chunk")
        table = self.file.read_row_group(group, columns=columns, use_threads=False)
        need(len(table) == rg.num_rows, "decoded row group count differs")
        self.reads.append({"source_key": self.source["key"], "row_group": group, "rows": len(table), "columns": columns})
        return table
