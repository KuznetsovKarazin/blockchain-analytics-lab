#!/usr/bin/env python3
"""Bounded metadata enumeration for fixed-window observation feasibility.

Only ListObjectsV2 XML is requested. No Parquet object, log/transaction row,
contract call or detector result is acquired. Reused listings remain dated
prior observations, and every subsequent payload must validate its own identity.
"""
import argparse
from datetime import date, datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def put(path, value):
    with path.open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")


def need(value, message):
    if not value:
        raise ValueError(message)


def load_bound(path, expected):
    raw = path.read_bytes()
    need(sha(raw) == expected, "Bound input differs: " + path.name)
    return json.loads(raw)


def import_bound(path, expected):
    need(sha(path.read_bytes()) == expected, "Bound parser differs")
    spec = importlib.util.spec_from_file_location("phase14_listing_parser", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stamp():
    return datetime.now(timezone.utc).isoformat()


def partition_inventory(listings, days, endpoint, max_objects):
    """Retain empty/missing cells; metadata outside the study window is counted."""
    cells = {(day, table): [] for day in days for table in ("blocks", "logs", "transactions")}
    complete = {}
    outside = 0
    for listing in listings:
        complete[listing["prefix"]] = listing["listing_complete"]
        for item in listing["objects"]:
            match = re.fullmatch(r"v1\.0/eth/(blocks|logs|transactions)/date=(\d{4}-\d{2}-\d{2})/[^/]+\.parquet", item["key"])
            need(match is not None, "Unrecognized object key in frozen table prefix")
            table, day = match.groups()
            need(date.fromisoformat(day).isoformat() == day, "Noncanonical partition date")
            if day not in days:
                outside += 1
                continue
            target = cells[(day, table)]
            need(not any(row["key"] == item["key"] for row in target), "Duplicate selected object key")
            need(len(target) < max_objects and item["size_bytes"] > 0, "Selected object count/positive-size cap")
            target.append({**item, "url": endpoint + item["key"], "listing_prefix": listing["prefix"],
                           "listing_origin": listing["origin"]})
    result = []
    for (day, table), objects in sorted(cells.items()):
        prefix = f"v1.0/eth/{table}/date={day[:7]}-"
        listing_complete = complete.get(prefix, False)
        result.append({"day_utc": day, "table": table, "listing_complete": listing_complete,
                       "status": "LISTED_NONEMPTY" if listing_complete and objects else
                                 "LISTED_EMPTY" if listing_complete else "UNAVAILABLE_OR_INCOMPLETE_LISTING",
                       "objects": sorted(objects, key=lambda row: row["key"]),
                       "object_bytes_metadata": sum(row["size_bytes"] for row in objects),
                       "object_content_sha256_verified": False, "parquet_readability_verified": False})
    return result, outside


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--accepted-plan-sha256", required=True)
    parser.add_argument("--accepted-runner-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    plan = load_bound(args.plan, args.accepted_plan_sha256)
    need(sha(Path(__file__).read_bytes()) == args.accepted_runner_sha256, "Accepted runner digest differs")
    need(plan["schema_version"] == "article2_phase14_measurement_metadata_plan_v1", "Wrong plan schema")
    paper = Path(__file__).resolve().parents[2]
    helper = import_bound(paper / plan["parser_binding"]["path"], plan["parser_binding"]["sha256"])
    need(plan["endpoint"] == helper.BASE, "Unexpected endpoint")
    expected = [(date(2022, 2, 19) + timedelta(days=index)).isoformat() for index in range(30)]
    need(plan["days_utc"] == expected, "Original thirty-day measurement window differs")
    expected_prefixes = [f"v1.0/eth/{table}/date={month}-" for table, month in
        [("logs", "2022-02"), ("blocks", "2022-02"), ("transactions", "2022-02"), ("transactions", "2022-03")]]
    need(plan["new_prefixes"] == expected_prefixes, "Fixed metadata schedule differs")
    need(plan["caps"] == {"requests": 8, "pages_per_prefix": 2, "max_keys_per_page": 1000,
        "per_response_bytes": 1048576, "total_response_bytes": 8388608,
        "wall_seconds": 300, "request_timeout_seconds": 30, "max_objects_per_day_table": 4,
        "retries": 0, "concurrency": 1}, "Frozen caps differ")
    listings, reuse = [], []
    for row in plan["reused_listings"]:
        raw = (paper / row["path"]).read_bytes()
        need(sha(raw) == row["sha256"], "Reused monthly XML differs")
        objects, truncated, token = helper.parse_listing(raw, row["prefix"])
        need(not truncated and token is None, "Reused monthly listing not complete")
        listings.append({"prefix": row["prefix"], "objects": objects, "listing_complete": True,
                         "origin": "retained_phase4_month_listing", "new_requests": 0})
        reuse.append({**row, "bytes": len(raw), "objects": len(objects), "new_requests": 0})
    need(len(reuse) == 2 and {row["prefix"] for row in reuse} == {"v1.0/eth/logs/date=2022-03-", "v1.0/eth/blocks/date=2022-03-"},
         "Unexpected reused listing set")
    phase6 = load_bound(paper / plan["phase6_comparison"]["path"], plan["phase6_comparison"]["sha256"])
    partition_inventory(listings, plan["days_utc"], plan["endpoint"], plan["caps"]["max_objects_per_day_table"])
    if args.preflight_only:
        print(json.dumps({"status": "PREFLIGHT_PASS_NO_NETWORK", "reused_month_listings": len(reuse),
                          "planned_new_prefixes": len(expected_prefixes), "maximum_new_requests": 8}))
        return
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "frozen_plan.json").write_bytes(args.plan.read_bytes())
    (args.output / "runner_source.py").write_bytes(Path(__file__).read_bytes())
    put(args.output / "acceptance.json", {"started_utc": stamp(), "plan_sha256": args.accepted_plan_sha256,
        "runner_sha256": args.accepted_runner_sha256, "authority": "Root exact hashes accepted before first metadata request."})
    opener = urllib.request.build_opener(helper.NoRedirect())
    started, requests, total_bytes, failure = time.monotonic(), [], 0, None
    try:
        for prefix_index, prefix in enumerate(plan["new_prefixes"]):
            listing = {"prefix": prefix, "objects": [], "listing_complete": False, "origin": "fresh_phase14_metadata", "new_requests": 0}
            listings.append(listing)
            token, keys, tokens = None, set(), set()
            for page in range(1, plan["caps"]["pages_per_prefix"] + 1):
                remaining = plan["caps"]["wall_seconds"] - (time.monotonic() - started)
                need(remaining > 0 and len(requests) < plan["caps"]["requests"], "Time/request cap reached")
                need(total_bytes < plan["caps"]["total_response_bytes"], "Retained metadata byte cap reached")
                query = {"list-type": "2", "prefix": prefix, "max-keys": str(plan["caps"]["max_keys_per_page"])}
                if token is not None:
                    query["continuation-token"] = token
                url = plan["endpoint"] + "?" + urllib.parse.urlencode(query)
                ordinal = len(requests) + 1
                name = f"{ordinal:03d}_prefix{prefix_index}_page{page}"
                request = {"url": url, "method": "GET", "kind": "S3_ListObjectsV2_metadata", "prefix": prefix,
                           "page": page, "continuation_token": token}
                put(args.output / (name + "_request.json"), request)
                record = {"ordinal": ordinal, "started_utc": stamp(), "request_file": name + "_request.json",
                    "request_sha256": sha((args.output / (name + "_request.json")).read_bytes()), "body_complete": False}
                requests.append(record)
                listing["new_requests"] += 1
                body, raw = b"", bytearray()
                try:
                    req = urllib.request.Request(url, headers={"Accept": "application/xml", "User-Agent": "Article2-measurement-metadata/1"})
                    try:
                        response = opener.open(req, timeout=min(plan["caps"]["request_timeout_seconds"], remaining))
                    except urllib.error.HTTPError as exc:
                        response = exc
                    with response:
                        record["http_status"] = response.status
                        record["content_type"] = response.headers.get("Content-Type")
                        limit = min(plan["caps"]["per_response_bytes"], plan["caps"]["total_response_bytes"] - total_bytes)
                        while len(raw) < limit:
                            need(time.monotonic() - started < plan["caps"]["wall_seconds"], "Wall cap while reading metadata")
                            chunk = response.read(min(65536, limit - len(raw)))
                            if not chunk:
                                break
                            raw.extend(chunk)
                        body = bytes(raw)
                        record["body_at_cap_eof_unproved"] = len(body) == limit
                        need(not record["body_at_cap_eof_unproved"], "Metadata response reached cap; EOF unproved")
                        need(response.status == 200 and response.geturl() == url, "Metadata HTTP error/redirect")
                    objects, truncated, next_token = helper.parse_listing(body, prefix, token)
                    need(len(objects) <= plan["caps"]["max_keys_per_page"], "Returned key count exceeds requested page cap")
                    need(truncated or next_token is None, "Terminal listing page includes continuation token")
                    need(not any(row["key"] in keys for row in objects), "Repeated key across listing pages")
                    need(next_token is None or next_token not in tokens, "Repeated continuation token")
                    partition_inventory([*listings[:-1], {**listing, "objects": listing["objects"] + objects}],
                        plan["days_utc"], plan["endpoint"], plan["caps"]["max_objects_per_day_table"])
                    keys.update(row["key"] for row in objects)
                    if next_token is not None:
                        tokens.add(next_token)
                    listing["objects"].extend(objects)
                    record.update(body_complete=True, parsed_object_count=len(objects), is_truncated=truncated)
                    if not truncated:
                        listing["listing_complete"] = True
                    token = next_token
                except Exception as exc:
                    record["failure"] = type(exc).__name__ + ": " + str(exc)
                    raise
                finally:
                    body = bytes(raw)
                    total_bytes += len(body)
                    (args.output / (name + "_response.xml")).write_bytes(body)
                    record.update(completed_utc=stamp(), response_file=name + "_response.xml",
                                  response_bytes=len(body), response_sha256=sha(body))
                    (args.output / "requests.json").write_text(json.dumps(requests, indent=2, sort_keys=True) + "\n")
                if listing["listing_complete"]:
                    break
            need(listing["listing_complete"], "Predeclared pagination cap reached")
    except Exception as exc:
        failure = type(exc).__name__ + ": " + str(exc)
    cells, outside = partition_inventory(listings, plan["days_utc"], plan["endpoint"], plan["caps"]["max_objects_per_day_table"])
    previous = {(row["day_utc"], row["table"]): row for row in phase6["partitions"]}
    comparisons = []
    for row in cells:
        old = previous.get((row["day_utc"], row["table"]))
        if old is not None:
            key = lambda item: (item["key"], item["size_bytes"], item["etag_opaque"])
            comparisons.append({"day_utc": row["day_utc"], "table": row["table"],
                "identities_equal": row["listing_complete"] and sorted(map(key, row["objects"])) == sorted(map(key, old["objects"]))})
    result = {"schema_version": "article2_phase14_measurement_metadata_result_v1",
        "status": "COMPLETE_LISTING_METADATA_ONLY" if failure is None and all(row["listing_complete"] for row in cells)
                  else "UNAVAILABLE_OR_PARTIAL_LISTING_METADATA_ONLY",
        "plan_sha256": args.accepted_plan_sha256, "runner_sha256": args.accepted_runner_sha256,
        "completed_utc": stamp(), "failure": failure, "new_metadata_requests": len(requests),
        "new_metadata_response_bytes": total_bytes, "reused_listings": reuse,
        "new_listings": [row for row in listings if row["origin"] == "fresh_phase14_metadata"],
        "day_table_cells": cells, "selected_day_table_cell_count": len(cells),
        "listed_nonempty_cells": sum(row["status"] == "LISTED_NONEMPTY" for row in cells),
        "listed_empty_cells": sum(row["status"] == "LISTED_EMPTY" for row in cells),
        "unavailable_or_incomplete_cells": sum(row["status"] == "UNAVAILABLE_OR_INCOMPLETE_LISTING" for row in cells),
        "selected_object_count": sum(len(row["objects"]) for row in cells),
        "selected_object_total_bytes_metadata": sum(row["object_bytes_metadata"] for row in cells),
        "out_of_window_month_listing_object_count": outside,
        "phase6_overlapping_identity_comparisons": comparisons,
        "new_parquet_object_requests": 0, "new_chain_row_observations": 0, "detector_scores": 0,
        "scientific_admissions": 0, "fixed_address_scope_adoption_performed_by_this_program": False,
        "not_proved": ["Parquet footer/payload readability", "source columns and nullability", "continuous header links",
            "complete core-emitted logs", "selected transaction status/all-emitter logs", "scientific case admission"],
        "etag_interpretation": "Opaque listing metadata, not a content hash; payload acquisition must bind and verify its own response."}
    put(args.output / "summary.json", result)
    print(json.dumps({key: value for key, value in result.items() if key not in
        {"reused_listings", "new_listings", "day_table_cells", "phase6_overlapping_identity_comparisons", "not_proved"}}, indent=2))


if __name__ == "__main__":
    main()
