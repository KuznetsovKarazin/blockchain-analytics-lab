"""Offline metadata-parser and request-bound verification; no payload/network."""
import importlib.util
import io
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("list_source_metadata", Path(__file__).with_name("list_source_metadata.py"))
source = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source)
PREFIX = "v1.0/eth/logs/date=2022-02-26/"


def xml(prefix=PREFIX, objects=None, truncated=False, token=None, continuation=None):
    objects = [(PREFIX + "part.parquet", "123", '"opaque-etag"')] if objects is None else objects
    contents = "".join(f"<Contents><Key>{key}</Key><Size>{size}</Size><ETag>{etag}</ETag></Contents>" for key, size, etag in objects)
    extra = (f"<NextContinuationToken>{token}</NextContinuationToken>" if token is not None else "")
    extra += (f"<ContinuationToken>{continuation}</ContinuationToken>" if continuation is not None else "")
    return (f'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>aws-public-blockchain</Name>'
            f'<Prefix>{prefix}</Prefix><KeyCount>{len(objects)}</KeyCount><IsTruncated>{str(truncated).lower()}</IsTruncated>'
            f'{contents}{extra}</ListBucketResult>').encode()


class Response(io.BytesIO):
    def __init__(self, body, headers=None, url=None):
        super().__init__(body)
        self.headers = headers or {}
        self.status = 200
        self.url = url

    def geturl(self):
        return self.url


class ListingTests(unittest.TestCase):
    def test_valid_complete_and_empty(self):
        objects, truncated, token = source.parse_listing(xml(), PREFIX)
        self.assertEqual(objects[0]["size_bytes"], 123)
        self.assertEqual(objects[0]["etag_opaque"], '"opaque-etag"')
        self.assertFalse(truncated)
        self.assertIsNone(token)
        self.assertEqual(source.parse_listing(xml(objects=[]), PREFIX), ([], False, None))

    def test_wrong_prefix_key_duplicate_size_and_missing_token(self):
        malformed = [xml(prefix="wrong/"), xml(objects=[("wrong/key", "1", "x")]),
                     xml(objects=[(PREFIX + "same", "1", "x")] * 2),
                     xml(objects=[(PREFIX + "k", "-1", "x")]),
                     xml(objects=[(PREFIX + "k", "NaN", "x")]),
                     xml(truncated=True), xml(continuation="unexpected")]
        for payload in malformed:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                source.parse_listing(payload, PREFIX)

    def test_response_cap_and_complete_content_length(self):
        self.assertEqual(source.read_bounded(Response(b"abcd", {"Content-Length": "4"}), 4), b"abcd")
        self.assertEqual(source.read_bounded(Response(b"abc"), 4), b"abc")
        for body, headers in [(b"abcde", {"Content-Length": "5"}), (b"abcd", {}),
                              (b"abc", {"Content-Length": "4"}), (b"abc", {"Content-Length": "-1"})]:
            with self.subTest(body=body, headers=headers), self.assertRaises(ValueError):
                source.read_bounded(Response(body, headers), 4)

    def test_pagination_loop_fails_without_third_request(self):
        bodies = [xml(truncated=True, token="again"),
                  xml(objects=[], truncated=True, token="again", continuation="again")]
        class FakeOpener:
            calls = 0
            def open(self, request, timeout):
                payload = bodies[self.calls]
                self.calls += 1
                return Response(payload, {"Content-Length": str(len(payload))}, request.full_url)
        fake = FakeOpener()
        config = {"max_pages_per_prefix": 2, "max_keys_per_page": 1000,
                  "max_response_bytes": 1048576, "timeout_seconds": 30}
        item = {"day_utc": "2022-02-26", "table": "logs", "prefix": PREFIX}
        with tempfile.TemporaryDirectory() as temp, patch.object(source.urllib.request, "build_opener", return_value=fake):
            stop = threading.Event()
            result = source.fetch_partition(item, config, Path(temp), stop)
            self.assertEqual(fake.calls, 2)
            self.assertFalse(result["listing_complete"])
            self.assertTrue(stop.is_set())
            self.assertIn("pagination token loop", result["pages"][-1]["error"])
            self.assertEqual(len(list(Path(temp).glob("*.xml"))), 2)

    def test_cancellation_makes_zero_requests(self):
        stop = threading.Event()
        stop.set()
        result = source.fetch_partition({"day_utc": "2022-02-26", "table": "logs", "prefix": PREFIX},
                                        {"max_pages_per_prefix": 2}, Path("unused"), stop)
        self.assertEqual(result["requests_attempted"], 0)
        self.assertEqual(result["status"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
