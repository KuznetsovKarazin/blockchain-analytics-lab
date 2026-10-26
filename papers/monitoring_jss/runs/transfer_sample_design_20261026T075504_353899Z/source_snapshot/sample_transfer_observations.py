"""Fixed development sample: Blockscout transaction metadata and paginated logs.

Selection is frozen from an already accepted ordinary-day Euler emitter stream
before any requested transaction is fetched. No labels, detector scores, token
metadata, traces, balance queries, or replacement transactions are requested.
Pagination exhaustion is an indexer claim, not a JSON-RPC receipt/root proof.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

PAPER = Path(__file__).resolve().parent
BASE = "https://eth.blockscout.com/api/v2/"
CORE = "0x27182842e098f60e3d576794a5bffb0777e025d3"
ARCHIVED_SHA256 = "49b205ef5691f27c3171de8ad6b9b005d67afc5f4a7683c76723e4c76239cd9a"
PAYLOAD_FIELDS = ("chain_id", "address", "block_number", "block_hash", "transaction_index",
                  "transaction_hash", "log_index", "event_time_ns", "topics", "data")
PAGINATION_KEYS = {"index", "items_count", "block_number"}
SOURCE_NAMES = ("sample_transfer_observations.py", "transfer_observation.py")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_hash(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def put_json(path, value):
    with Path(path).open("xb") as handle:
        handle.write(canonical(value))


def uint(value, name):
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value):
        return int(value, 16)
    raise ValueError("invalid nonnegative integer: " + name)


def hex_bytes(value, length, name):
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value):
        raise ValueError("invalid hexadecimal bytes: " + name)
    if length is not None and len(value) != 2 + length * 2:
        raise ValueError("invalid byte length: " + name)
    return value.lower()


def timestamp_ns(value):
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(?:Z|\+00:00)", value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("provider timestamp must carry UTC and at most nine fractional digits")
    stamp = datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + int((match[2] or "").ljust(9, "0"))


def topic_list(value):
    if not isinstance(value, list) or len(value) > 4:
        raise ValueError("invalid provider topics array")
    result = list(value)
    while result and result[-1] is None:
        result.pop()
    return [hex_bytes(topic, 32, "topic") for topic in result]


def provider_address(log):
    addresses = []
    for key in ("address_hash", "address"):
        value = log.get(key)
        if value is not None:
            addresses.append(hex_bytes(value.get("hash") if isinstance(value, dict) else value, 20, "emitter"))
    if not addresses or len(set(addresses)) != 1:
        raise ValueError("provider emitter missing or address/address_hash fields disagree")
    # Current Blockscout smart_contract may describe transaction.to_address,
    # not log.address. It is deliberately not an emitter identity source.
    return addresses[0]


def payload(log, bundle):
    return {key: (bundle[key] if key in ("chain_id", "event_time_ns") else log[key]) for key in PAYLOAD_FIELDS}


def select_transactions(input_path, expected_sha256, sample_size=10):
    """Select canonical first transactions without inspecting new provider data."""
    if file_hash(input_path) != expected_sha256:
        raise ValueError("archived input hash mismatch")
    ordered, by_tx, previous = [], {}, None
    with Path(input_path).open("rb") as source:
        for line in source:
            row = json.loads(line)
            normalized = {key: row[key] for key in PAYLOAD_FIELDS}
            for key, length in (("address", 20), ("block_hash", 32), ("transaction_hash", 32), ("data", None)):
                normalized[key] = hex_bytes(normalized[key], length, key)
            normalized["topics"] = topic_list(normalized["topics"])
            for key in ("chain_id", "block_number", "transaction_index", "log_index", "event_time_ns"):
                normalized[key] = uint(normalized[key], key)
            if normalized["chain_id"] != 1 or normalized["address"] != CORE:
                raise ValueError("archived population differs from fixed Ethereum Euler core")
            day = datetime.fromtimestamp(normalized["event_time_ns"] // 1_000_000_000, timezone.utc).date().isoformat()
            if day != "2023-03-01":
                raise ValueError("archived event outside fixed development day")
            order = tuple(normalized[key] for key in ("block_number", "transaction_index", "log_index"))
            if previous is not None and order <= previous:
                raise ValueError("archived source order is not strictly canonical")
            previous = order
            tx = normalized["transaction_hash"]
            if tx not in by_tx:
                ordered.append(tx)
                by_tx[tx] = []
            by_tx[tx].append(normalized)
    if sum(map(len, by_tx.values())) != 1247 or len(ordered) != 218:
        raise ValueError("archived day does not match accepted 1247-log/218-tx population")
    if sample_size != 10:
        raise ValueError("fixed development sample requires exactly ten transactions")
    selection = []
    for number, tx in enumerate(ordered[:sample_size]):
        rows = by_tx[tx]
        expected = {key: rows[0][key] for key in ("block_number", "block_hash", "transaction_index", "event_time_ns")}
        if any(any(row[key] != value for key, value in expected.items()) for row in rows):
            raise ValueError("archived transaction identity/timestamp conflict")
        selection.append({"selection_index": number, "transaction_hash": tx, "expected_block": expected,
                          "first_log_index": rows[0]["log_index"], "archived_core_logs": len(rows),
                          "archived_core_payload_sha256": digest(rows)})
    return selection, {tx: by_tx[tx] for tx in ordered[:sample_size]}


def normalize_bundle(selected, metadata, logs):
    expected = selected["expected_block"]
    tx = hex_bytes(metadata.get("hash"), 32, "transaction hash")
    if tx != selected["transaction_hash"]:
        raise ValueError("provider transaction hash mismatch")
    block = uint(metadata.get("block_number"), "provider block number")
    position = uint(metadata.get("position"), "provider transaction position")
    event_time = timestamp_ns(metadata.get("timestamp"))
    for key, value in (("block_number", block), ("transaction_index", position), ("event_time_ns", event_time)):
        if expected[key] != value:
            raise ValueError("provider/archived transaction mismatch: " + key)
    if metadata.get("block_hash") is not None and hex_bytes(metadata["block_hash"], 32, "metadata block hash") != expected["block_hash"]:
        raise ValueError("provider metadata block hash mismatch")
    status = metadata.get("status")
    if status not in ("ok", "error", None):
        raise ValueError("unknown provider transaction status")
    normalized, seen = [], set()
    for raw in logs:
        index = uint(raw.get("index"), "provider log index")
        if index in seen:
            raise ValueError("duplicate provider log index")
        seen.add(index)
        if (hex_bytes(raw.get("transaction_hash"), 32, "log transaction hash") != tx or
                uint(raw.get("block_number"), "log block number") != block or
                hex_bytes(raw.get("block_hash"), 32, "log block hash") != expected["block_hash"]):
            raise ValueError("provider log identity differs from selected transaction")
        if raw.get("transaction_index") is not None and uint(raw["transaction_index"], "log transaction index") != position:
            raise ValueError("provider log transaction index mismatch")
        if raw.get("block_timestamp") is not None and timestamp_ns(raw["block_timestamp"]) != event_time:
            raise ValueError("provider log block timestamp mismatch")
        removed = raw.get("removed")
        if removed not in (None, False) or type(removed) not in (type(None), bool):
            raise ValueError("removed provider log unsupported")
        normalized.append({"address": provider_address(raw), "block_number": block,
                           "block_hash": expected["block_hash"], "transaction_hash": tx,
                           "transaction_index": position, "log_index": index,
                           "topics": topic_list(raw.get("topics")),
                           "data": hex_bytes(raw.get("data"), None, "log data"), "removed": removed})
    normalized.sort(key=lambda row: row["log_index"])
    if not normalized:
        raise ValueError("empty provider logs cannot match nonempty archived core subset")
    return {"schema_version": "transaction_log_bundle_v1", "chain_id": 1, "block_number": block,
            "block_hash": expected["block_hash"], "transaction_hash": tx, "transaction_index": position,
            "event_time_ns": event_time, "receipt_status": {"ok": 1, "error": 0, None: None}[status],
            "logs": normalized}


def validate_page(value):
    if not isinstance(value, dict) or not isinstance(value.get("items"), list) or "next_page_params" not in value:
        raise ValueError("provider log page lacks items/explicit next_page_params")
    next_params = value["next_page_params"]
    if next_params is not None:
        if not isinstance(next_params, dict) or not next_params or not set(next_params).issubset(PAGINATION_KEYS):
            raise ValueError("unsupported pagination parameters")
        for key, number in next_params.items():
            if type(number) is not int or number < 0:
                raise ValueError("pagination values must be nonnegative integers")
    return value["items"], next_params


class AcquisitionFailure(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class BoundedFetcher:
    def __init__(self, limits, raw_root):
        self.limits, self.raw_root = limits, Path(raw_root)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.calls = 0

    def fetch(self, relative_path, params, folder, key):
        with self.lock:
            if self.stop.is_set():
                raise AcquisitionFailure("not requested after provider/transport failure")
            if self.calls >= self.limits["max_requests_total"]:
                raise AcquisitionFailure("global request cap reached")
            self.calls += 1
        url = BASE + relative_path
        if params:
            url += "?" + urllib.parse.urlencode(sorted(params.items()))
        receipt = {"key": key, "url": url, "method": "GET", "request_params": params,
                   "started_utc": datetime.now(timezone.utc).isoformat(), "body_complete": False}
        body, error = b"", None
        t0 = time.perf_counter()
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "Monitoring-development-sample/1"})
            with urllib.request.build_opener(NoRedirect()).open(req, timeout=self.limits["timeout_seconds"]) as response:
                receipt["status"] = response.status
                receipt["headers"] = dict(response.headers.items())
                if response.status != 200 or response.geturl() != url:
                    raise AcquisitionFailure("non-200 response or redirected endpoint")
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isdigit() or int(length) > self.limits["max_response_bytes"]):
                    raise AcquisitionFailure("response Content-Length invalid or above cap")
                body = response.read(self.limits["max_response_bytes"])
                if length is not None and int(length) != len(body):
                    raise AcquisitionFailure("response Content-Length mismatch")
                if length is None and len(body) == self.limits["max_response_bytes"]:
                    raise AcquisitionFailure("response reached cap without complete-body evidence")
                receipt["body_complete"] = True
        except urllib.error.HTTPError as exc:
            receipt["status"] = exc.code
            receipt["headers"] = dict(exc.headers.items()) if exc.headers else {}
            body = exc.read(self.limits["max_response_bytes"])
            error = repr(exc)
            if exc.code in (401, 403, 429):
                self.stop.set()
        except (OSError, ValueError, urllib.error.URLError, AcquisitionFailure) as exc:
            error = repr(exc)
            self.stop.set()
        receipt.update(completed_utc=datetime.now(timezone.utc).isoformat(),
                       elapsed_seconds=time.perf_counter() - t0, bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
        if error:
            receipt["error"] = error
        with (folder / key).open("xb") as handle:
            handle.write(body)
        put_json(folder / (key + ".receipt.json"), receipt)
        if error:
            raise AcquisitionFailure(error)
        try:
            value = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AcquisitionFailure("provider response is not JSON: " + str(exc)) from exc
        return value, body, receipt


def acquire_one(selected, config, selection_sha256, archived, raw_root, fetcher, observer):
    folder = Path(raw_root) / f"tx_{selected['selection_index']:02d}"
    folder.mkdir(exist_ok=False)
    summary = {"selection_index": selected["selection_index"], "transaction_hash": selected["transaction_hash"],
               "status": "not_accepted", "provider_pagination_exhausted": False,
               "archived_core_payloads_match": False, "provider_logs": None,
               "archived_core_logs": selected["archived_core_logs"]}
    tx = selected["transaction_hash"]
    sources, pages, logs, request_params, visited = {}, [], [], {}, set()
    try:
        metadata, body, receipt = fetcher.fetch("transactions/" + tx, {}, folder, "metadata.json")
        sources["metadata.json"] = body
        metadata_ref = {**{key: receipt[key] for key in ("key", "url", "sha256", "bytes")}, "http_status": 200}
        for number in range(1, config["limits"]["max_log_pages_per_transaction"] + 1):
            key = f"logs_page_{number:03d}.json"
            page, body, receipt = fetcher.fetch("transactions/" + tx + "/logs", request_params, folder, key)
            sources[key] = body
            rows, next_params = validate_page(page)
            logs.extend(rows)
            pages.append({**{name: receipt[name] for name in ("key", "url", "sha256", "bytes")},
                          "http_status": 200, "request_params": request_params, "next_page_params": next_params, "item_count": len(rows)})
            if next_params is None:
                summary["provider_pagination_exhausted"] = True
                break
            marker = canonical(next_params)
            if marker in visited:
                raise ValueError("provider pagination cursor loop")
            visited.add(marker)
            request_params = next_params
        if not summary["provider_pagination_exhausted"]:
            raise ValueError("provider pagination limit reached")
        bundle = normalize_bundle(selected, metadata, logs)
        actual_core = [payload(row, bundle) for row in bundle["logs"] if row["address"] == CORE]
        if canonical(actual_core) != canonical(archived) or digest(actual_core) != selected["archived_core_payload_sha256"]:
            raise ValueError("provider and archived core payload subsets differ")
        summary["archived_core_payloads_match"] = True
        bundle_bytes = canonical(bundle)
        source_record = {"schema_version": "transfer_source_record_v1", "source_kind": "blockscout_v2_paginated_transaction_logs",
                         "requested_transaction_hash": tx, "chain_id": 1,
                         "acquired_at_utc": datetime.now(timezone.utc).isoformat(),
                         "normalizer_source_sha256": file_hash(Path(__file__)),
                         "normalized_bundle_sha256": hashlib.sha256(bundle_bytes).hexdigest(),
                         "normalized_bundle_bytes": len(bundle_bytes), "expected_block": selected["expected_block"],
                         "selection_manifest_sha256": selection_sha256, "metadata": metadata_ref, "pages": pages,
                         "raw_receipt_acquired": False, "observed_time": None,
                         "normalization_notes": ["Only trailing null topics removed; internal null topics rejected.",
                                                 "Complete pages then sort by global log_index; duplicate indices rejected.",
                                                 "Log transaction index/time inherited from provider transaction metadata after archive cross-check.",
                                                 "Only address/address_hash identify the emitter; smart_contract may denote top-level transaction recipient.",
                                                 "No provider decoded labels, token metadata, balances or traces used."]}
        put_json(folder / "normalized_bundle.json", bundle)
        put_json(folder / "source_record.json", source_record)
        observation = observer(bundle_bytes, source_record, expected_source_record_sha256=digest(source_record),
                               monitored_addresses=[CORE], raw_sources=sources)
        put_json(folder / "transfer_observation.json", observation)
        summary.update(status="accepted_development_observation", provider_logs=len(bundle["logs"]),
                       provider_log_pages=len(pages), source_record_sha256=digest(source_record),
                       normalized_bundle_sha256=hashlib.sha256(bundle_bytes).hexdigest(),
                       observation_sha256=digest(observation), observation_counts=observation["counts"],
                       feature_observation_private=True)
    except (AcquisitionFailure, ValueError, TypeError, KeyError) as exc:
        summary["reason"] = type(exc).__name__ + ": " + str(exc)
    put_json(folder / "transaction_summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--raw-output", type=Path, required=True)
    args = parser.parse_args()
    config, frozen, selection = (json.loads(path.read_bytes()) for path in (args.config, args.freeze, args.selection))
    if file_hash(args.config) != frozen["config_sha256"] or file_hash(args.selection) != frozen["selection_sha256"]:
        raise ValueError("config or selection differs from pre-call freeze")
    if set(frozen["source_sha256"]) != set(SOURCE_NAMES) or config["archived_input_sha256"] != ARCHIVED_SHA256:
        raise ValueError("freeze must bind both exact sources and the accepted archived input")
    for name, checksum in frozen["source_sha256"].items():
        if file_hash(PAPER / name) != checksum:
            raise ValueError("source differs from pre-call freeze: " + name)
    if config["provider_base"] != BASE or config["limits"] != {
        "workers": 2, "timeout_seconds": 30, "max_response_bytes": 1048576,
        "max_log_pages_per_transaction": 10, "max_requests_total": 110, "retries": 0, "redirects": False}:
        raise ValueError("unrecognized endpoint or frozen request bounds")
    selected, archived = select_transactions(args.input, config["archived_input_sha256"])
    if selected != selection["transactions"]:
        raise ValueError("selection differs from exact archived first ten canonical transactions")
    args.output.mkdir(parents=True, exist_ok=False)
    args.raw_output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(PAPER))
    from transfer_observation import observe_transaction_log_bundle
    fetcher = BoundedFetcher(config["limits"], args.raw_output)
    started = datetime.now(timezone.utc).isoformat()
    with ThreadPoolExecutor(max_workers=config["limits"]["workers"]) as executor:
        futures = [executor.submit(acquire_one, item, config, frozen["selection_sha256"],
                                   archived[item["transaction_hash"]], args.raw_output, fetcher,
                                   observe_transaction_log_bundle) for item in selected]
        results = [future.result() for future in futures]
    unchanged = all(file_hash(PAPER / name) == checksum for name, checksum in frozen["source_sha256"].items())
    unchanged = unchanged and file_hash(args.config) == frozen["config_sha256"] and file_hash(args.selection) == frozen["selection_sha256"]
    unchanged = unchanged and file_hash(args.input) == config["archived_input_sha256"]
    if not unchanged:
        raise ValueError("frozen sources/config/selection/input changed during acquisition")
    report = {"schema_version": "transfer_development_sample_run_v1", "started_utc": started,
              "completed_utc": datetime.now(timezone.utc).isoformat(), "command": [sys.executable, *sys.argv],
              "cwd": str(Path.cwd()), "config_sha256": frozen["config_sha256"],
              "selection_sha256": frozen["selection_sha256"], "freeze_sha256": file_hash(args.freeze),
              "source_sha256": frozen["source_sha256"], "frozen_bytes_unchanged": unchanged,
              "selected_transactions": len(selected), "requests_attempted": fetcher.calls,
              "accepted_observations": sum(r["status"] == "accepted_development_observation" for r in results),
              "transactions": results,
              "scope": "Fixed development source/normalization exercise; no attack labels, detector, independent recall or prevention claim.",
              "completeness_limit": "Exhausted indexer log pagination plus exact archived core-payload comparison; omitted non-core logs remain possible without independent receipts."}
    put_json(args.output / "sample_summary.json", report)
    print(json.dumps({key: report[key] for key in ("selected_transactions", "requests_attempted", "accepted_observations")}))


if __name__ == "__main__":
    main()
