"""Focused invented-byte transport and sparse projection checks; no network."""
from datetime import datetime, timezone
from email.message import Message
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pyarrow as pa
import pyarrow.parquet as pq

import range_collector as rc


COLUMNS = ["address", "topics", "data", "transaction_index", "log_index", "transaction_hash",
           "block_number", "block_hash", "block_timestamp"]


def plan(**overrides):
    caps = {"requests": 1000, "total_response_bytes": 10485760, "wall_seconds": 300,
            "request_timeout_seconds": 10, "max_range_bytes": 1048576,
            "max_footer_bytes": 1048576, "max_rows": 10000, "max_row_groups": 100,
            "max_top_level_columns": 128, "max_leaf_columns": 256,
            "max_source_bytes": 10485760, "retries": 0, "concurrency": 1}
    caps.update(overrides)
    return {"schema_version": "article2_phase16_range_source_plan_v1", "endpoint": rc.ENDPOINT,
            "caps": caps, "required_columns": {"logs": COLUMNS, "blocks": ["timestamp"],
                                               "transactions": ["block_timestamp", "receipt_status"]}}


def fake_parquet():
    rows = []
    for i in range(6):
        rows.append({"address": "0x" + f"{i:040x}", "topics": ["0x" + "a" * 64], "data": "0x" + f"{i:064x}",
                     "transaction_index": i, "log_index": i, "transaction_hash": "0x" + f"{i:064x}",
                     "block_number": 1, "block_hash": "0x" + "b" * 64,
                     "block_timestamp": datetime(2022, 2, 19, tzinfo=timezone.utc)})
    stream = pa.BufferOutputStream()
    pq.write_table(pa.Table.from_pylist(rows), stream, row_group_size=3, compression="snappy")
    return stream.getvalue().to_pybytes()


class Response:
    def __init__(self, raw, source, start, length, changes=None, truncate=0):
        self.status = 206
        self.url = source["url"]
        self.headers = Message()
        for key, value in {"ETag": source["etag_opaque"], "Content-Range": f"bytes {start}-{start+length-1}/{len(raw)}",
                           "Content-Length": str(length)}.items():
            self.headers[key] = value
        for key, value in (changes or {}).items():
            if key == "status": self.status = value
            elif key == "url": self.url = value
            else:
                if key in self.headers: del self.headers[key]
                self.headers[key] = value
        body = raw[start:start+length]
        self.stream = io.BytesIO(body[:-truncate] if truncate else body)
        self.read_calls = 0

    def __enter__(self): return self
    def __exit__(self, *args): return False
    def geturl(self): return self.url
    def read(self, length):
        self.read_calls += 1
        return self.stream.read(length)


class Opener:
    def __init__(self, raw, source, changes=None, truncate=0):
        self.raw, self.source = raw, source
        self.changes, self.truncate = changes, truncate
        self.responses = []
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        start, end = [int(x) for x in request.get_header("Range")[6:].split("-")]
        response = Response(self.raw, self.source, start, end-start+1, self.changes, self.truncate)
        self.responses.append(response)
        return response


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.raw = fake_parquet()
        key = "v1.0/eth/logs/date=2022-02-19/invented.snappy.parquet"
        self.source = {"table": "logs", "day_utc": "2022-02-19", "key": key,
                       "url": rc.ENDPOINT+key, "etag_opaque": '"invented"', "size_bytes": len(self.raw)}
        self.opener = Opener(self.raw, self.source)
        self.session = rc.RangeSession(plan(), self.root / "capture", self.opener)

    def tearDown(self): self.tmp.cleanup()
    def reader(self, session=None, reuse=None):
        return rc.SourceReader(self.source, session or self.session, self.root / "cache", pa, pq, reuse)

    def test_projection_is_exact_and_original_header_retained(self):
        reader = self.reader().open()
        tables = [t for _, t in reader.iter_row_groups(["address", "block_number"])]
        self.assertEqual(pa.concat_tables(tables).num_rows, 6)
        self.assertEqual(self.session.requests[0]["start"], 0)
        self.assertEqual(self.session.requests[0]["length"], 4)
        for record in self.session.requests:
            self.assertEqual(rc.file_sha(reader.path, record["start"], record["length"]), record["response_sha256"])
        self.assertFalse(reader.manifest()["holes_are_original_bytes"])

    def test_projection_cannot_read_unrequested_sparse_holes(self):
        reader = self.reader().open()
        with self.assertRaisesRegex(ValueError, "sparse hole"):
            reader._read_exact(4, 1)
        reader.ensure_columns(["address"], [0])
        chunks = reader.manifest()["column_chunks"]
        self.assertTrue(next(x for x in chunks if x["column"] == "address" and x["row_group"] == 0)["acquired"])
        self.assertFalse(next(x for x in chunks if x["column"] == "address" and x["row_group"] == 1)["acquired"])

    def test_outside_projection_and_bad_groups_rejected(self):
        reader = self.reader().open()
        count = len(self.opener.requests)
        for columns, groups in [(["not_frozen"], [0]), (["address"], [True]), (["address"], [1, 0]), (["address", "address"], [0])]:
            with self.assertRaises(ValueError): reader.ensure_columns(columns, groups)
        self.assertEqual(len(self.opener.requests), count)

    def test_changed_etag_rejected_before_body(self):
        self.opener.changes = {"ETag": '"different"'}
        with self.assertRaisesRegex(ValueError, "ETag"): self.reader().open()
        self.assertEqual(self.opener.responses[0].read_calls, 0)
        self.assertEqual(self.session.bytes, 0)

    def test_status_200_rejected_before_body(self):
        self.opener.changes = {"status": 200}
        with self.assertRaisesRegex(ValueError, "HTTP"): self.reader().open()
        self.assertEqual(self.opener.responses[0].read_calls, 0)

    def test_wrong_range_and_length_rejected(self):
        self.opener.changes = {"Content-Range": f"bytes 1-4/{len(self.raw)}"}
        with self.assertRaisesRegex(ValueError, "Content-Range"): self.reader().open()
        self.assertEqual(self.opener.responses[0].read_calls, 0)

    def test_encoding_rejected_before_body(self):
        self.opener.changes = {"Content-Encoding": "gzip"}
        with self.assertRaisesRegex(ValueError, "encoded"): self.reader().open()
        self.assertEqual(self.opener.responses[0].read_calls, 0)

    def test_redirect_rejected_before_body(self):
        self.opener.changes = {"url": "https://example.invalid/other"}
        with self.assertRaisesRegex(ValueError, "HTTP"): self.reader().open()
        self.assertEqual(self.opener.responses[0].read_calls, 0)

    def test_partial_body_is_retained_counted_and_not_resumable(self):
        self.opener.truncate = 1
        reader = self.reader()
        with self.assertRaisesRegex(ValueError, "truncated"): reader.open()
        self.assertEqual(self.session.bytes, 3)
        self.assertEqual(reader.path.read_bytes()[:3], b"PAR")
        self.assertFalse(self.session.requests[0]["transport_ok"])
        with self.assertRaisesRegex(ValueError, "clean open"):
            rc.RangeSession(plan(), self.root / "capture", self.opener, resume=True)

    def test_global_byte_cap_applies_before_request(self):
        session = rc.RangeSession(plan(total_response_bytes=3), self.root / "small", self.opener)
        with self.assertRaisesRegex(ValueError, "total byte cap"): self.reader(session).open()
        self.assertEqual(len(self.opener.requests), 0)

    def test_global_request_cap_applies_before_second_request(self):
        session = rc.RangeSession(plan(requests=1), self.root / "small", self.opener)
        with self.assertRaisesRegex(ValueError, "request cap"): self.reader(session).open()
        self.assertEqual(len(self.opener.requests), 1)

    def test_deterministic_small_range_splitting(self):
        session = rc.RangeSession(plan(max_range_bytes=64), self.root / "small", self.opener)
        reader = self.reader(session).open()
        reader.ensure_columns(COLUMNS)
        self.assertTrue(all(x["length"] <= 64 for x in session.requests))
        self.assertEqual(sum(x["response_bytes"] for x in session.requests), session.bytes)
        self.assertEqual(sum(t.num_rows for _, t in reader.iter_row_groups(COLUMNS)), 6)

    def test_wrong_original_magic_is_not_synthesized(self):
        self.opener.raw = b"FAKE" + self.raw[4:]
        with self.assertRaisesRegex(ValueError, "leading"): self.reader().open()
        self.assertEqual(len(self.opener.requests), 1)

    def test_whole_object_reuse_requires_original_sha_and_identity(self):
        path = self.root / "original.parquet"
        path.write_bytes(self.raw)
        reuse = {"path": str(path), "sha256": rc.file_sha(path), "source_key": self.source["key"],
                 "size_bytes": len(self.raw), "etag_opaque": self.source["etag_opaque"]}
        reader = self.reader(reuse=reuse).open()
        self.assertEqual(sum(t.num_rows for _, t in reader.iter_row_groups(COLUMNS)), 6)
        self.assertEqual(len(self.opener.requests), 0)
        self.assertTrue(reader.manifest()["whole_source_sha256_verified"])
        reuse["sha256"] = "0"*64
        with self.assertRaisesRegex(ValueError, "reuse bytes"): self.reader(reuse=reuse).open()

    def test_clean_resume_preserves_cumulative_caps_and_original_clock(self):
        reader = self.reader().open()
        old_count, old_bytes, started = len(self.session.requests), self.session.bytes, self.session.started_utc
        resumed = rc.RangeSession(plan(), self.root / "capture", self.opener, resume=True)
        resumed_reader = self.reader(resumed).open()
        self.assertEqual(len(resumed.requests), old_count)
        self.assertEqual(resumed.bytes, old_bytes)
        self.assertEqual(resumed.started_utc, started)
        self.assertEqual(resumed.attempt_id, self.session.attempt_id)
        resumed_reader.ensure_columns(["address"])
        self.assertGreater(resumed.bytes, old_bytes)

    def test_range_cache_cannot_reset_attempt_accounting(self):
        self.reader().open()
        fresh = rc.RangeSession(plan(), self.root / "fresh", self.opener)
        with self.assertRaisesRegex(ValueError, "attempt differs"): self.reader(fresh).open()

    def test_pending_capture_cannot_resume(self):
        self.session.checkpoint("OPEN_REQUEST_PENDING")
        with self.assertRaisesRegex(ValueError, "clean open"):
            rc.RangeSession(plan(), self.root / "capture", self.opener, resume=True)

    def test_tampered_cached_range_is_rejected(self):
        reader = self.reader().open()
        with reader.path.open("r+b") as handle: handle.write(b"FAIL")
        with self.assertRaisesRegex(ValueError, "original bytes changed"): self.reader().open()

    def test_cached_receipt_must_equal_charged_capture(self):
        reader = self.reader().open()
        value = json.loads(reader.cache_manifest.read_text())
        value["ranges"][0]["content_encoding"] = "gzip"
        rc.save(reader.cache_manifest, value)
        with self.assertRaisesRegex(ValueError, "charged capture"): self.reader().open()

    def test_failed_live_session_cannot_issue_another_request(self):
        self.opener.changes = {"status": 200}
        reader = self.reader()
        with self.assertRaises(ValueError): reader.open()
        self.opener.changes = None
        with self.assertRaisesRegex(ValueError, "failed or active"):
            self.session.fetch_into(self.source, "leading_magic", 0, 4, reader.path)
        with self.assertRaisesRegex(ValueError, "cannot be complete"): self.session.close()
        self.assertEqual(len(self.opener.requests), 1)

    def test_final_slow_read_is_retained_but_not_accepted(self):
        clock = [self.session.started]
        old_open = self.opener.open
        def open_with_slow_read(request, timeout):
            response = old_open(request, timeout)
            old_read = response.read
            def slow_read(length):
                value = old_read(length)
                clock[0] += 301
                return value
            response.read = slow_read
            return response
        self.opener.open = open_with_slow_read
        with patch.object(rc.time, "monotonic", side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(ValueError, "wall cap after range read"): self.reader().open()
        self.assertEqual(self.session.bytes, 4)
        self.assertFalse(self.session.requests[0]["transport_ok"])


if __name__ == "__main__":
    unittest.main()
