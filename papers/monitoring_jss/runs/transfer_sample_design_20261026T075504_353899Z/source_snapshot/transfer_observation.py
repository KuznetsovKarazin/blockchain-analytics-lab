"""Strict, source-bound observations of ERC-20-shaped transaction logs.

Pure standard-library boundary: no RPC, storage, detector or alert policy. Raw
Blockscout responses are bound to an externally anchored manifest and checked
against the explicitly normalized bundle. Event amounts are not state balances.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from urllib.parse import parse_qs, urlsplit

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
ZERO_ADDRESS = "0x" + "00" * 20
_HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})*\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_UTC = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|\+00:00)\Z")


class ObservationError(ValueError):
    """Malformed, inconsistent or unbound evidence; no observation is emitted."""


class ObservationUnavailable(ObservationError):
    """Missing/pending evidence, distinct from a successful empty transaction."""


def canonical_json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_sha256(value):
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require(condition, message):
    if not condition:
        raise ObservationError(message)


def _integer(value, name, minimum=0):
    _require(type(value) is int and value >= minimum, f"{name}: integer >= {minimum} required")
    return value


def _hex(value, name, size=None):
    _require(isinstance(value, str) and _HEX.fullmatch(value) is not None,
             f"{name}: whole 0x-prefixed hexadecimal bytes required")
    _require(size is None or len(value) == 2 + 2 * size, f"{name}: wrong byte length")
    return value.lower()


def _sha(value, name):
    _require(isinstance(value, str) and _SHA.fullmatch(value) is not None, f"{name}: SHA-256 required")
    return value


def _object(value, name):
    _require(type(value) is dict, f"{name}: object required")
    return value


def _json_bytes(data, name):
    _require(type(data) is bytes, f"{name}: original bytes required")
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, f"{name}: duplicate JSON key {key}")
            result[key] = value
        return result
    def bad_constant(value):
        raise ObservationError(f"{name}: nonfinite JSON constant {value}")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs,
                          parse_constant=bad_constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ObservationError(f"{name}: invalid UTF-8 JSON") from error


def utc_timestamp_ns(value):
    """Parse an explicit UTC timestamp without floating point or ns truncation."""
    _require(isinstance(value, str), "timestamp must be a UTC string")
    match = _UTC.fullmatch(value)
    _require(match is not None, "timestamp must specify UTC and at most nine fractional digits")
    y, mo, d, h, minute, sec = map(int, match.groups()[:6])
    _require(h < 24 and minute < 60 and sec < 60, "invalid clock time")
    try:
        days = (date(y, mo, d) - date(1970, 1, 1)).days
    except ValueError as error:
        raise ObservationError("invalid date") from error
    _require(days >= 0, "timestamp precedes Unix epoch")
    return ((days * 86400 + h * 3600 + minute * 60 + sec) * 1_000_000_000
            + int((match.group(7) or "").ljust(9, "0")))


def _provider_integer(value, name):
    if isinstance(value, str) and re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value):
        value = int(value, 16)
    return _integer(value, name)


def _source_json(record, raw_sources, expected_path, seen_keys):
    _object(record, "source item")
    key = record["key"]
    _require(isinstance(key, str) and key and key not in seen_keys, "duplicate/invalid source key")
    seen_keys.add(key)
    _require(key in raw_sources, "missing raw response")
    raw = raw_sources[key]
    _require(type(raw) is bytes, "raw response must be bytes")
    _require(len(raw) == _integer(record["bytes"], "source bytes"), "raw byte count mismatch")
    _require(hashlib.sha256(raw).hexdigest() == _sha(record["sha256"], "source sha256"), "raw SHA-256 mismatch")
    if "http_status" in record:
        _require(type(record["http_status"]) is int and record["http_status"] == 200, "HTTP response not successful")
    url = urlsplit(record["url"])
    _require(url.scheme == "https" and bool(url.netloc) and not url.fragment
             and url.username is None and url.password is None, "invalid source URL")
    _require(url.path.rstrip("/") == expected_path, "source URL does not name requested transaction endpoint")
    return _json_bytes(raw, key), url


def _pagination_params(value, name, allow_null=False):
    if value is None and allow_null:
        return None
    _object(value, name)
    _require(all(isinstance(k, str) and k and type(v) in (str, int)
                 and (not isinstance(v, str) or v) for k, v in value.items()), "invalid pagination parameters")
    return value


def _emitter(item):
    candidates = []
    # Blockscout's smart_contract field can describe transaction.to rather than
    # the LOG emitter; it must never substitute for or constrain emitter identity.
    for name in ("address_hash", "address"):
        value = item.get(name)
        if value is None:
            continue
        if isinstance(value, dict):
            value = value.get("hash")
        candidates.append(_hex(value, name, 20))
    _require(bool(candidates) and len(set(candidates)) == 1, "missing/conflicting log emitter")
    return candidates[0]


def _provider_log(item, tx):
    _object(item, "provider log")
    topics = item["topics"]
    _require(isinstance(topics, list) and len(topics) <= 4, "invalid provider topics")
    topics = list(topics)
    while topics and topics[-1] is None:
        topics.pop()
    _require(all(topic is not None for topic in topics), "internal topic null is not padding")
    # Transaction index is attached from independently bound tx metadata because
    # Blockscout log items do not consistently include it.
    index = _provider_integer(item["index"], "provider log index")
    if "transaction_index" in item:
        _require(_provider_integer(item["transaction_index"], "provider tx index") == tx["transaction_index"], "provider tx index conflict")
    if item.get("block_timestamp") is not None:
        _require(utc_timestamp_ns(item["block_timestamp"]) == tx["event_time_ns"], "provider log timestamp conflict")
    removed = item.get("removed")
    _require(removed is None or type(removed) is bool and not removed, "removed log is unsupported")
    return {"address": _emitter(item), "topics": [_hex(v, "topic", 32) for v in topics],
            "data": _hex(item["data"], "data"), "log_index": index,
            "block_number": _provider_integer(item["block_number"], "provider block number"),
            "block_hash": _hex(item["block_hash"], "provider block hash", 32),
            "transaction_hash": _hex(item["transaction_hash"], "provider tx hash", 32),
            "transaction_index": tx["transaction_index"], "removed": removed}


def decode_transfer_shape(log):
    """Decode one already identity-checked log; event shape is not token proof."""
    topics = log["topics"]
    _require(isinstance(topics, list) and len(topics) <= 4, "invalid topics")
    topics = [_hex(topic, "topic", 32) for topic in topics]
    data = _hex(log["data"], "data")
    if not topics or topics[0] != TRANSFER_TOPIC:
        return {"kind": "opaque"}
    _require(len(topics) in (3, 4), "matching Transfer has unsupported topic count")
    for address_topic in topics[1:3]:
        _require(address_topic[2:26] == "0" * 24, "noncanonical indexed address padding")
    sender, recipient = "0x" + topics[1][-40:], "0x" + topics[2][-40:]
    if len(topics) == 4:
        _require(data == "0x", "ERC-721-shaped Transfer must have empty data")
        return {"kind": "erc721_shaped", "from_address": sender, "to_address": recipient,
                "token_id": int(topics[3][2:], 16)}
    _require(len(data) == 66, "ERC-20-shaped Transfer requires exactly one uint256 word")
    return {"kind": "erc20_shaped", "from_address": sender, "to_address": recipient,
            "amount_raw": int(data[2:], 16)}


def observe_transaction_log_bundle(bundle_bytes, source_record, *,
                                   expected_source_record_sha256, monitored_addresses,
                                   raw_sources):
    """Return one immutable observation, or fail without partial aggregation.

    `expected_source_record_sha256` must come from the collector's independently
    retained manifest, not be manufactured by this function from untrusted input.
    Exhausted provider pagination is checked; blockchain completeness is not.
    """
    try:
        return _observe(bundle_bytes, source_record,
                        expected_source_record_sha256=expected_source_record_sha256,
                        monitored_addresses=monitored_addresses, raw_sources=raw_sources)
    except (KeyError, TypeError, AttributeError, OverflowError) as error:
        raise ObservationError("missing or malformed required evidence field") from error
    except ValueError as error:
        if isinstance(error, ObservationError):
            raise
        raise ObservationError("invalid evidence value") from error


def _observe(bundle_bytes, source_record, *, expected_source_record_sha256,
             monitored_addresses, raw_sources):
    _object(source_record, "source_record")
    _require(canonical_sha256(source_record) == _sha(expected_source_record_sha256, "expected source record hash"), "external source-record digest mismatch")
    _require(source_record["schema_version"] == "transfer_source_record_v1", "unsupported source schema")
    _require(source_record["source_kind"] == "blockscout_v2_paginated_transaction_logs", "unsupported source kind")
    _require(source_record.get("raw_receipt_acquired", False) is False, "indexer bundle is not a raw RPC receipt")
    _sha(source_record["normalizer_source_sha256"], "normalizer hash")
    _sha(source_record["selection_manifest_sha256"], "selection manifest hash")
    utc_timestamp_ns(source_record["acquired_at_utc"])
    _require(type(bundle_bytes) is bytes, "normalized bundle bytes required")
    _require(len(bundle_bytes) == _integer(source_record["normalized_bundle_bytes"], "bundle bytes"), "bundle byte count mismatch")
    _require(hashlib.sha256(bundle_bytes).hexdigest() == _sha(source_record["normalized_bundle_sha256"], "bundle hash"), "bundle hash mismatch")
    bundle = _object(_json_bytes(bundle_bytes, "bundle"), "bundle")
    _require(bundle_bytes == canonical_json_bytes(bundle), "normalized bundle must use canonical JSON bytes")
    _require(bundle["schema_version"] == "transaction_log_bundle_v1", "unsupported bundle schema")
    tx = {k: _integer(bundle[k], k, 1 if k == "chain_id" else 0)
          for k in ("chain_id", "block_number", "transaction_index", "event_time_ns")}
    tx.update({k: _hex(bundle[k], k, 32) for k in ("block_hash", "transaction_hash")})
    _require(tx["chain_id"] == _integer(source_record["chain_id"], "source chain", 1), "chain mismatch")
    _require(tx["transaction_hash"] == _hex(source_record["requested_transaction_hash"], "requested transaction", 32), "requested transaction mismatch")
    expected = _object(source_record["expected_block"], "expected block")
    for key in ("block_hash", "block_number", "transaction_index", "event_time_ns"):
        val = _hex(expected[key], key, 32) if key == "block_hash" else _integer(expected[key], key)
        _require(tx[key] == val, "bundle differs from bound block context: " + key)
    _require(isinstance(monitored_addresses, (list, tuple)) and bool(monitored_addresses), "nonempty explicit address population required")
    population = [_hex(v, "monitored address", 20) for v in monitored_addresses]
    _require(len(set(population)) == len(population) and ZERO_ADDRESS not in population, "duplicate or zero monitored address")
    population = set(population)
    _object(raw_sources, "raw_sources")
    keys = set()
    base_path = "/api/v2/transactions/" + tx["transaction_hash"]
    metadata, meta_url = _source_json(source_record["metadata"], raw_sources, base_path, keys)
    _require(not meta_url.query, "metadata endpoint must be unfiltered")
    if metadata is None:
        raise ObservationUnavailable("transaction metadata is absent/pending")
    _object(metadata, "transaction metadata")
    _require(_hex(metadata["hash"], "metadata tx hash", 32) == tx["transaction_hash"], "metadata tx mismatch")
    if metadata.get("block_number") is None or metadata.get("position") is None or metadata.get("timestamp") is None:
        raise ObservationUnavailable("transaction lacks mined ordering/time metadata")
    _require(_provider_integer(metadata["block_number"], "metadata block") == tx["block_number"], "metadata block mismatch")
    _require(_provider_integer(metadata["position"], "metadata position") == tx["transaction_index"], "metadata transaction position mismatch")
    _require(utc_timestamp_ns(metadata["timestamp"]) == tx["event_time_ns"], "metadata timestamp mismatch")
    if metadata.get("block_hash") is not None:
        _require(_hex(metadata["block_hash"], "metadata block hash", 32) == tx["block_hash"], "metadata block hash mismatch")
    status = {"ok": 1, "error": 0}.get(metadata.get("status"))
    if status is None or bundle.get("receipt_status") is None:
        raise ObservationUnavailable("provider execution status is unavailable")
    _require(type(bundle["receipt_status"]) is int and bundle["receipt_status"] == status, "normalized execution status mismatch")
    pages = source_record["pages"]
    _require(isinstance(pages, list) and bool(pages), "at least one terminal log page required")
    provider_logs, prior_next, cursors = [], {}, set()
    for page_index, record in enumerate(pages):
        params = _pagination_params(record["request_params"], "request params")
        _require(params == prior_next, "pagination request does not continue exact preceding cursor")
        cursor = canonical_sha256(params)
        _require(cursor not in cursors, "pagination cursor repeated")
        cursors.add(cursor)
        body, url = _source_json(record, raw_sources, base_path + "/logs", keys)
        _require(url.netloc == meta_url.netloc, "mixed provider hosts")
        _require(parse_qs(url.query, keep_blank_values=True) == {k: [str(v)] for k, v in params.items()}, "page URL differs from recorded pagination parameters")
        _object(body, "log page")
        _require(isinstance(body["items"], list), "page items must be an array")
        _require(len(body["items"]) == _integer(record["item_count"], "item count"), "page item count mismatch")
        next_params = _pagination_params(body["next_page_params"], "next page params", allow_null=True)
        _require(next_params == record["next_page_params"], "recorded pagination evidence differs from raw page")
        _require((next_params is None) == (page_index == len(pages) - 1), "pagination must end exactly at a terminal page")
        provider_logs.extend(_provider_log(item, tx) for item in body["items"])
        prior_next = next_params
    _require(set(raw_sources) == keys, "unaccounted raw responses")
    logs = bundle["logs"]
    _require(isinstance(logs, list), "normalized logs must be an array")
    # Providers may paginate in descending index order. Canonicalization happens
    # once the entire provider log set is available, never during incremental
    # decisions. The supplied normalized bundle itself must already be canonical.
    provider_logs.sort(key=lambda log: log["log_index"])
    for log in logs:
        _object(log, "normalized log")
        for name in ("log_index", "transaction_index", "block_number"):
            _integer(log[name], name)
        for name, size in (("address", 20), ("transaction_hash", 32), ("block_hash", 32)):
            _require(_hex(log[name], name, size) == log[name], "normalized hexadecimal fields must be lowercase")
        _require(log["removed"] is None or type(log["removed"]) is bool and not log["removed"], "invalid normalized removed status")
        _require(isinstance(log["topics"], list), "normalized topics must be a list")
        for topic in log["topics"]:
            _require(_hex(topic, "topic", 32) == topic, "normalized topics must be lowercase")
        _require(_hex(log["data"], "data") == log["data"], "normalized data must be lowercase")
    _require(logs == provider_logs, "normalized log bundle differs from raw provider records")
    _require(status != 0 or not logs, "failed transaction cannot contain committed logs")
    indices = []
    decoded = []
    for log in logs:
        for key in ("block_hash", "block_number", "transaction_hash", "transaction_index"):
            _require(log[key] == tx[key], "mixed transaction/block identity: " + key)
        indices.append(log["log_index"])
        decoded.append(decode_transfer_shape(log))
    _require(all(b == a + 1 for a, b in zip(indices, indices[1:])), "duplicate, unordered or noncontiguous per-transaction global log indices")
    counts = {"logs": len(logs), "erc20_shaped": 0, "erc721_shaped": 0,
              "opaque": 0, "monitored_erc20_shaped": 0, "zero_value_transfers": 0}
    flows = {}
    for log, event in zip(logs, decoded):
        counts[event["kind"]] += 1
        if event["kind"] != "erc20_shaped":
            continue
        value, sender, recipient = event["amount_raw"], event["from_address"], event["to_address"]
        counts["zero_value_transfers"] += value == 0
        if sender not in population and recipient not in population:
            continue
        counts["monitored_erc20_shaped"] += 1
        token = log["address"]
        row = flows.setdefault(token, {"chain_id": tx["chain_id"], "token_address": token,
            "external_in_raw": 0, "external_out_raw": 0, "internal_raw": 0,
            "mint_from_zero_raw": 0, "burn_to_zero_raw": 0, "transfer_log_count": 0,
            "external_in_count": 0, "external_out_count": 0, "internal_count": 0,
            "mint_from_zero_count": 0, "burn_to_zero_count": 0})
        if sender in population and recipient in population:
            category = "internal"
        elif sender == ZERO_ADDRESS:
            category = "mint_from_zero"
        elif recipient == ZERO_ADDRESS:
            category = "burn_to_zero"
        elif recipient in population:
            category = "external_in"
        else:
            category = "external_out"
        row[category + "_raw"] += value
        row[category + "_count"] += 1
        row["transfer_log_count"] += 1
    for row in flows.values():
        row["net_external_in_raw"] = row["external_in_raw"] - row["external_out_raw"]
        row["net_event_in_raw"] = row["net_external_in_raw"] + row["mint_from_zero_raw"] - row["burn_to_zero_raw"]
        # JSON numbers are commonly consumed as binary64. Keep raw uint256,
        # larger sums and negative differences portable as decimal strings.
        for name in row:
            if name.endswith("_raw"):
                row[name] = str(row[name])
    return {"schema_version": "transfer_observation_v1",
            "status": "observed_success" if status else "observed_failed_transaction",
            "provider_execution_status": status, "transaction": tx,
            "population_addresses": sorted(population), "counts": counts,
            "raw_amount_encoding": "base10_integer_string",
            "token_flows": [flows[token] for token in sorted(flows)],
            "evidence": {"tier": "provider_pagination_exhausted_structure_checked",
                "source_record_sha256": expected_source_record_sha256,
                "selection_manifest_sha256": source_record["selection_manifest_sha256"],
                "normalizer_source_sha256": source_record["normalizer_source_sha256"],
                "raw_receipt_acquired": False, "receipt_root_verified": False,
                "historical_deployed_abi_verified": False, "token_erc20_compliance_verified": False,
                "observed_time": None, "full_chain_completeness_verified": False,
                "provider_page_count": len(pages)},
            "unavailable_fields": ["actual_balance_change", "native_asset_flow", "token_decimals",
                "token_price", "economic_loss", "historical_observed_time", "attack_label"]}
