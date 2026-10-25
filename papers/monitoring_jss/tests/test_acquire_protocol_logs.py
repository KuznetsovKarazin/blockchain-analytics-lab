"""Network-free checks for range identity, cache integrity and event ordering."""
import io
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from acquire_protocol_logs import CachedHTTPRangeFile, full_download, validate_logs


class FakeRangeResponse(io.BytesIO):
    status = 206

    def __init__(self, content, start, stop, etag='"pinned"'):
        super().__init__(content[start:stop+1])
        self.headers = {"Content-Range": f"bytes {start}-{stop}/{len(content)}", "ETag": etag}


class AcquisitionTests(unittest.TestCase):
    def metadata(self):
        return {"url": "https://example.invalid/source", "size": 10, "etag": '"pinned"', "version_id": None}

    def opener(self, request, timeout):
        self.assertEqual(request.get_header("If-match"), '"pinned"')
        start, stop = (int(s) for s in request.get_header("Range")[6:].split("-"))
        return FakeRangeResponse(b"0123456789", start, stop)

    def test_range_read_uses_if_match_and_cache(self):
        with tempfile.TemporaryDirectory() as temp, patch("urllib.request.urlopen", side_effect=self.opener) as opening:
            source = CachedHTTPRangeFile(self.metadata(), temp)
            source.seek(3)
            self.assertEqual(source.read(4), b"3456")
            source.seek(3)
            self.assertEqual(source.read(4), b"3456")
            self.assertEqual(opening.call_count, 1)
            self.assertEqual(source.network_bytes_this_process, 4)
            self.assertEqual(source.cache_bytes_served_this_process, 4)
            self.assertIsNone(source.manifest()["raw_whole_object_sha256"])

    def test_changed_etag_fails_before_accepting_range(self):
        with tempfile.TemporaryDirectory() as temp, patch("urllib.request.urlopen", return_value=FakeRangeResponse(b"0123456789", 0, 3, '"changed"')):
            source = CachedHTTPRangeFile(self.metadata(), temp)
            with self.assertRaisesRegex(RuntimeError, "ETag changed"):
                source.read(4)
            self.assertEqual(len(source.index["ranges"]), 0)

    def test_corrupt_cached_range_is_not_silently_reused(self):
        with tempfile.TemporaryDirectory() as temp, patch("urllib.request.urlopen", side_effect=self.opener):
            source = CachedHTTPRangeFile(self.metadata(), temp)
            source.read(4)
            (Path(temp)/"0_4.bin").write_bytes(b"xxxx")
            source.seek(0)
            with self.assertRaisesRegex(RuntimeError, "integrity failure"):
                source.read(4)

    def test_budget_blocks_unbounded_read(self):
        with tempfile.TemporaryDirectory() as temp, patch("urllib.request.urlopen") as opening:
            source = CachedHTTPRangeFile(self.metadata(), temp, byte_budget=4)
            with self.assertRaisesRegex(RuntimeError, "budget exceeded"):
                source.read(5)
            opening.assert_not_called()

    def fixture(self):
        address = "0x" + "a"*40
        row = {"chain_id": 1, "block_number": 100, "block_hash": "0x"+"b"*64,
               "transaction_index": 1, "log_index": 5, "transaction_hash": "0x"+"c"*64,
               "address": address, "topics": ["0x"+"d"*64], "data": "0x0001",
               "event_time_ns": 1677628800000000000}
        blocks = {100: {"block_hash": row["block_hash"], "event_time_ns": row["event_time_ns"], "transaction_count": 3}}
        return row, address, blocks

    def test_duplicate_log_does_not_disappear(self):
        row, address, blocks = self.fixture()
        self.assertTrue(all(validate_logs([row], {address}, "2023-03-01", blocks).values()))
        with self.assertRaisesRegex(ValueError, "duplicate log"):
            validate_logs([row, dict(row)], {address}, "2023-03-01", blocks)

    def test_header_mismatch_rejected(self):
        row, address, blocks = self.fixture()
        blocks[100]["block_hash"] = "0x"+"e"*64
        with self.assertRaisesRegex(ValueError, "does not match header"):
            validate_logs([row], {address}, "2023-03-01", blocks)

    def test_one_transaction_hash_cannot_have_two_positions(self):
        row, address, blocks = self.fixture()
        another = {**row, "transaction_index": 2, "log_index": 6}
        with self.assertRaisesRegex(ValueError, "multiple positions"):
            validate_logs([row, another], {address}, "2023-03-01", blocks)

    def test_global_log_order_must_follow_transaction_order(self):
        row, address, blocks = self.fixture()
        another = {**row, "transaction_index": 2, "log_index": 4, "transaction_hash": "0x"+"f"*64}
        with self.assertRaisesRegex(ValueError, "global log_index"):
            validate_logs([row, another], {address}, "2023-03-01", blocks)

    def test_header_cache_identity_includes_url_size_and_version(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"headers.parquet"
            path.write_bytes(b"headers")
            meta = {"url": "https://example.invalid/a", "size": 7, "etag": '"same"', "version_id": "v1"}
            path.with_suffix(".json").write_text(json.dumps({**meta, "sha256": hashlib.sha256(b"headers").hexdigest()}))
            for change in ({"url": "https://example.invalid/b"}, {"size": 8}, {"version_id": "v2"}):
                with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, "cache mismatch"):
                    full_download({**meta, **change}, path)


if __name__ == "__main__":
    unittest.main()
