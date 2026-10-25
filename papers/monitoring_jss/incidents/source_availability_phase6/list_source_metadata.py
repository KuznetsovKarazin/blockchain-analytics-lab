"""Bounded S3 ListObjectsV2 metadata only; never fetches object payloads.

Every original response is retained privately. ETags are opaque metadata, not
content hashes. A complete listing proves neither Parquet readability nor block
continuity, emitter completeness, incident labels, or scientific cohort status.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import csv
import sys
from pathlib import Path
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

BASE = "https://aws-public-blockchain.s3.us-east-2.amazonaws.com/"
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def put_json(path, value):
    with Path(path).open("x") as f:
        json.dump(value, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def parse_listing(data, prefix, continuation_token=None):
    root = ET.fromstring(data)
    if root.tag != NS + "ListBucketResult":
        raise ValueError("not an S3 ListBucketResult")
    text = lambda name: root.findtext(NS + name)
    if text("Name") != "aws-public-blockchain" or text("Prefix") != prefix:
        raise ValueError("bucket or prefix mismatch")
    if text("ContinuationToken") != continuation_token:
        raise ValueError("continuation token mismatch")
    if text("IsTruncated") not in ("true", "false"):
        raise ValueError("invalid or missing IsTruncated")
    if root.findall(NS + "CommonPrefixes"):
        raise ValueError("unexpected grouped prefixes")
    objects, seen = [], set()
    for node in root.findall(NS + "Contents"):
        item = {"key": node.findtext(NS + "Key"), "size_bytes": node.findtext(NS + "Size"),
                "etag_opaque": node.findtext(NS + "ETag"),
                "last_modified_metadata": node.findtext(NS + "LastModified"),
                "storage_class_metadata": node.findtext(NS + "StorageClass")}
        if not item["key"] or not item["key"].startswith(prefix) or item["key"] in seen:
            raise ValueError("object key missing, repeated, or outside requested prefix")
        if not item["size_bytes"] or not item["size_bytes"].isdigit() or item["etag_opaque"] is None:
            raise ValueError("missing object size/ETag metadata")
        item["size_bytes"] = int(item["size_bytes"])
        objects.append(item)
        seen.add(item["key"])
    if text("KeyCount") is None or int(text("KeyCount")) != len(objects):
        raise ValueError("KeyCount differs from complete returned object list")
    truncated = text("IsTruncated") == "true"
    token = text("NextContinuationToken")
    if truncated and not token:
        raise ValueError("truncated listing lacks continuation token")
    return objects, truncated, token


def read_bounded(response, cap):
    length = response.headers.get("Content-Length")
    if length is not None and (not length.isdigit() or int(length) > cap):
        raise ValueError("advertised response length exceeds cap or is invalid")
    body = response.read(cap)
    if length is not None and len(body) != int(length):
        raise ValueError("response byte count differs from Content-Length")
    if len(body) == cap and length is None:
        raise ValueError("response reached cap without a complete-body length")
    return body


def fetch_partition(item, config, private, stop):
    result = {**item, "status": "inconclusive", "listing_complete": False,
              "objects": [], "pages": [], "requests_attempted": 0}
    prefix = item["prefix"]
    token = None
    keys = set()
    tokens = set()
    for page in range(1, config["max_pages_per_prefix"] + 1):
        if stop.is_set():
            result["reason"] = "not_requested_after_provider_or_network_error"
            return result
        query = {"list-type": "2", "prefix": prefix, "max-keys": str(config["max_keys_per_page"])}
        if token is not None:
            query["continuation-token"] = token
        url = BASE + "?" + urllib.parse.urlencode(query)
        name = item["day_utc"] + "_" + item["table"] + f"_page{page:02d}"
        started = datetime.now(timezone.utc).isoformat()
        t0 = time.perf_counter()
        receipt = {"request_url": url, "method": "GET", "request_kind": "S3 ListObjectsV2 metadata",
                   "started_utc": started, "page": page, "body_complete": False}
        result["requests_attempted"] += 1
        body = b""
        try:
            request = urllib.request.Request(url, headers={"Accept": "application/xml",
                                                          "User-Agent": "blockchain-monitoring-source-metadata/1"})
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=config["timeout_seconds"]) as response:
                receipt["http_status"] = response.status
                receipt["http_headers"] = dict(response.headers.items())
                if response.status != 200 or response.geturl() != url:
                    raise ValueError("non-200 status or redirected endpoint")
                body = read_bounded(response, config["max_response_bytes"])
                receipt["body_complete"] = True
            objects, truncated, next_token = parse_listing(body, prefix, token)
            if truncated and next_token in tokens:
                raise ValueError("pagination token loop")
            if next_token is not None:
                tokens.add(next_token)
            if any(obj["key"] in keys for obj in objects):
                raise ValueError("object key repeated between pages")
            keys.update(obj["key"] for obj in objects)
            result["objects"].extend(objects)
            receipt["parsed_object_count"] = len(objects)
            receipt["is_truncated"] = truncated
            if not truncated:
                result["listing_complete"] = True
                result["status"] = "listed_nonempty" if result["objects"] else "listed_empty"
            token = next_token
        except urllib.error.HTTPError as error:
            receipt["http_status"] = error.code
            receipt["http_headers"] = dict(error.headers.items()) if error.headers else {}
            body = error.read(config["max_response_bytes"])
            receipt["error"] = str(error)
            result["reason"] = "provider_http_error_no_retry"
            stop.set()
        except (OSError, ValueError, ET.ParseError, urllib.error.URLError) as error:
            receipt["error"] = type(error).__name__ + ": " + str(error)
            result["reason"] = "transport_or_validation_error_no_retry"
            stop.set()
        receipt.update(elapsed_seconds=time.perf_counter() - t0,
                       body_bytes=len(body), body_sha256=sha(body),
                       raw_response_file=name + ".xml")
        with (private / (name + ".xml")).open("xb") as f:
            f.write(body)
        put_json(private / (name + ".receipt.json"), receipt)
        result["pages"].append({k: v for k, v in receipt.items() if k != "http_headers"})
        if result["listing_complete"] or stop.is_set():
            return result
    result["reason"] = "pagination_limit_reached"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--raw-output", type=Path, required=True)
    args = parser.parse_args()
    config_bytes, freeze_bytes = args.config.read_bytes(), args.freeze.read_bytes()
    config, freeze = json.loads(config_bytes), json.loads(freeze_bytes)
    if sha(config_bytes) != freeze["config_sha256"] or sha(Path(__file__).read_bytes()) != freeze["script_sha256"]:
        raise ValueError("config or script differs from pre-call freeze")
    if config["endpoint"] != BASE or config["max_pages_per_prefix"] != 2 or config["max_response_bytes"] != 1048576:
        raise ValueError("frozen endpoint or request limits changed")
    if config["timeout_seconds"] != 30 or config["workers"] != 4 or config["max_keys_per_page"] != 1000:
        raise ValueError("frozen timeout/concurrency/key limits changed")
    if len(config["partitions"]) != 60 or len({r["prefix"] for r in config["partitions"]}) != 60:
        raise ValueError("exact 60 unique partition prefixes required")
    for row in config["partitions"]:
        if row["table"] not in ("logs", "blocks") or row["prefix"] != f"v1.0/eth/{row['table']}/date={row['day_utc']}/":
            raise ValueError("unexpected table/prefix")
    args.output.mkdir(parents=True, exist_ok=False)
    args.raw_output.mkdir(parents=True, exist_ok=False)
    put_json(args.raw_output / "config.json", config)
    put_json(args.raw_output / "freeze.json", freeze)
    stop = threading.Event()
    results = []
    started = datetime.now(timezone.utc).isoformat()
    with ThreadPoolExecutor(max_workers=config["workers"]) as executor:
        futures = {executor.submit(fetch_partition, item, config, args.raw_output, stop): item
                   for item in config["partitions"]}
        for future in futures:
            results.append(future.result())
    results.sort(key=lambda r: (r["day_utc"], r["table"]))
    totals = {table: {"partitions_requested": sum(r["requests_attempted"] > 0 for r in results if r["table"] == table),
                      "complete_nonempty_listings": sum(r["status"] == "listed_nonempty" for r in results if r["table"] == table),
                      "complete_empty_listings": sum(r["status"] == "listed_empty" for r in results if r["table"] == table),
                      "listed_objects": sum(len(r["objects"]) for r in results if r["table"] == table),
                      "listed_object_bytes_metadata": sum(o["size_bytes"] for r in results if r["table"] == table for o in r["objects"])}
              for table in ("logs", "blocks")}
    requests = sum(r["requests_attempted"] for r in results)
    if requests > 120:
        raise ValueError("global request cap exceeded")
    report = {"schema_version": "source_partition_listing_availability_v1",
              "status": "metadata_listing_complete" if all(r["listing_complete"] for r in results) else "inconclusive_or_partial",
              "started_utc": started, "completed_utc": datetime.now(timezone.utc).isoformat(),
              "config_sha256": sha(config_bytes), "freeze_sha256": sha(freeze_bytes),
              "script_sha256": sha(Path(__file__).read_bytes()), "endpoint": BASE,
              "execution_command": [sys.executable, *sys.argv], "cwd": str(Path.cwd()),
              "requests_attempted": requests, "response_bytes": sum(p["body_bytes"] for r in results for p in r["pages"]),
              "summary_by_table": totals, "partitions": results,
              "scope": "Proposal-level metadata feasibility only; no object payloads, incident outcomes, scores or new labels retrieved.",
              "not_proven": ["Parquet payload retrieval/readability", "header continuity", "complete selected-emitter stream",
                             "contract deployment or incident identity", "independent scientific cohort eligibility"],
              "etag_interpretation": "Opaque listing metadata only, not an object SHA or content validation"}
    put_json(args.output / "availability.json", report)
    with (args.output / "availability.csv").open("x", newline="") as f:
        fields = ["day_utc", "table", "status", "listing_complete", "objects", "object_bytes_metadata", "pages", "reason"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow({"day_utc": r["day_utc"], "table": r["table"], "status": r["status"],
                             "listing_complete": r["listing_complete"], "objects": len(r["objects"]),
                             "object_bytes_metadata": sum(o["size_bytes"] for o in r["objects"]),
                             "pages": len(r["pages"]), "reason": r.get("reason", "")})
    print(json.dumps({k: report[k] for k in ("status", "requests_attempted", "response_bytes", "summary_by_table")}))


if __name__ == "__main__":
    main()
