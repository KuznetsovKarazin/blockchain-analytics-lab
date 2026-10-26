"""Causal, token-separated gross-outflow rank observations; no network or budget.

This is a conditional magnitude rule on declared development data. Its rank
fraction is neither a calibrated p-value nor a transaction false-alarm rate.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re


class SemanticFlowError(ValueError):
    """An invalid input must halt the enclosing accepted replay."""


def canonical_json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_sha256(value):
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require(value, message):
    if not value:
        raise SemanticFlowError(message)


def _integer(value, name, minimum=0):
    _require(type(value) is int and value >= minimum, "invalid integer: " + name)
    return value


def _hex(value, size, name):
    _require(isinstance(value, str) and re.fullmatch("0x[0-9a-f]{" + str(2 * size) + "}", value),
             "invalid canonical hex: " + name)
    return value


def _sha(value, name):
    _require(isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value),
             "invalid SHA-256: " + name)
    return value


def _raw(value, name, signed=False):
    pattern = r"(?:0|-[1-9][0-9]*|[1-9][0-9]*)" if signed else r"(?:0|[1-9][0-9]*)"
    _require(isinstance(value, str) and re.fullmatch(pattern, value),
             "invalid decimal raw amount: " + name)
    return int(value)


_CONFIG_FIELDS = {"schema_version", "chain_id", "population_addresses", "history_size",
                  "min_history", "threshold_numerator", "threshold_denominator",
                  "grouping_ns", "max_tokens"}
_CATEGORIES = ("external_in", "external_out", "internal", "mint_from_zero", "burn_to_zero")
_COUNT_FIELDS = {"logs", "erc20_shaped", "erc721_shaped", "opaque",
                 "monitored_erc20_shaped", "zero_value_transfers"}
_TX_FIELDS = {"chain_id", "block_number", "block_hash", "transaction_index",
              "transaction_hash", "event_time_ns"}
_HISTORY_FIELDS = {"amount_raw", "event_time_ns", "block_number", "transaction_index",
                   "observation_sha256"}


def _config(config):
    _require(type(config) is dict and set(config) == _CONFIG_FIELDS, "invalid config fields")
    _require(config["schema_version"] == "semantic_flow_monitor_config_v1", "unknown config schema")
    for key in ("chain_id", "history_size", "min_history", "threshold_numerator",
                "threshold_denominator", "max_tokens"):
        _integer(config[key], key, 1)
    _integer(config["grouping_ns"], "grouping_ns")
    _require(config["min_history"] <= config["history_size"], "warmup exceeds history window")
    _require(config["threshold_numerator"] <= config["threshold_denominator"], "invalid rank threshold")
    addresses = config["population_addresses"]
    _require(type(addresses) is list and bool(addresses), "nonempty population required")
    for address in addresses:
        _hex(address, 20, "population address")
        _require(address != "0x" + "0" * 40, "zero monitored address")
    _require(addresses == sorted(set(addresses)), "population must be sorted and unique")
    return copy.deepcopy(config)


def _transaction(tx, chain_id):
    _require(type(tx) is dict and set(tx) == _TX_FIELDS, "invalid transaction fields")
    for key in ("chain_id", "block_number", "transaction_index", "event_time_ns"):
        _integer(tx[key], key, 1 if key == "chain_id" else 0)
    _hex(tx["block_hash"], 32, "block hash")
    _hex(tx["transaction_hash"], 32, "transaction hash")
    _require(tx["chain_id"] == chain_id, "wrong chain")
    return tx


def _key(tx):
    return tx["block_number"], tx["transaction_index"]


def _validate_observation(observation, config, expected_digest, source_audit_sha256):
    _require(type(observation) is dict, "observation object required")
    _sha(expected_digest, "observation digest")
    _require(canonical_sha256(observation) == expected_digest, "observation digest mismatch")
    schema = observation.get("schema_version")
    _require(schema in ("transfer_observation_v1", "archive_transfer_observation_v1"), "unsupported observation schema")
    archive = schema == "archive_transfer_observation_v1"
    status = observation.get("dataset_execution_status" if archive else "provider_execution_status")
    _require(type(status) is int and status in (0, 1), "unknown execution status")
    _require(not archive or status == 1, "archive study requires confirmed successful execution")
    _require(observation.get("status") == ("observed_success" if status else "observed_failed_transaction"),
             "execution status mismatch")
    evidence = observation.get("evidence")
    _require(type(evidence) is dict, "evidence object required")
    expected_tier = ("enumerated_daily_partition_and_transaction_metadata_checked" if archive
                     else "provider_pagination_exhausted_structure_checked")
    _require(evidence.get("tier") == expected_tier, "unsupported evidence tier")
    if archive:
        _require(_sha(evidence.get("source_audit_manifest_sha256"), "source audit") == source_audit_sha256,
                 "source audit binding mismatch")
    else:
        _sha(evidence.get("source_record_sha256"), "source record")
        _sha(evidence.get("normalizer_source_sha256"), "normalizer source")
    _sha(evidence.get("selection_manifest_sha256"), "selection manifest")
    _require(evidence.get("observed_time") is None, "historical observed_time must remain unknown")
    _require(evidence.get("raw_receipt_acquired") is False, "unsupported raw receipt claim")
    _require(evidence.get("receipt_root_verified") is False, "unsupported receipt-root claim")
    _require(evidence.get("full_chain_completeness_verified") is False, "unsupported completeness claim")
    _require(evidence.get("historical_deployed_abi_verified") is False, "unsupported historical ABI claim")
    _require(evidence.get("token_erc20_compliance_verified") is False, "unsupported token compliance claim")
    _require(observation.get("raw_amount_encoding") == "base10_integer_string", "unknown amount encoding")
    _require(observation.get("population_addresses") == config["population_addresses"], "population mismatch")
    tx = _transaction(observation.get("transaction"), config["chain_id"])
    counts = observation.get("counts")
    _require(type(counts) is dict and set(counts) == _COUNT_FIELDS, "invalid count fields")
    for key, value in counts.items():
        _integer(value, key)
    _require(counts["logs"] == sum(counts[k] for k in ("erc20_shaped", "erc721_shaped", "opaque")),
             "inconsistent shape counts")
    _require(counts["monitored_erc20_shaped"] <= counts["erc20_shaped"], "monitored count exceeds total")
    _require(counts["zero_value_transfers"] <= counts["erc20_shaped"], "zero count exceeds total")
    if archive:
        _require(_integer(observation.get("archived_core_log_count"), "archived core log count") <= counts["logs"],
                 "core count exceeds all-emitter count")
    rows = observation.get("token_flows")
    _require(type(rows) is list, "token flows must be a list")
    tokens, monitored_count, positive = [], 0, []
    required = {"chain_id", "token_address", "transfer_log_count", "net_external_in_raw", "net_event_in_raw"}
    required |= {cat + suffix for cat in _CATEGORIES for suffix in ("_raw", "_count")}
    for row in rows:
        _require(type(row) is dict and set(row) == required, "invalid token flow fields")
        token = _hex(row["token_address"], 20, "token address")
        _require(_integer(row["chain_id"], "flow chain", 1) == config["chain_id"], "flow chain mismatch")
        tokens.append(token)
        amounts = {cat: _raw(row[cat + "_raw"], cat) for cat in _CATEGORIES}
        category_counts = {cat: _integer(row[cat + "_count"], cat) for cat in _CATEGORIES}
        for cat in _CATEGORIES:
            _require(amounts[cat] == 0 or category_counts[cat] > 0, "amount without an event")
        count = _integer(row["transfer_log_count"], "transfer count", 1)
        _require(count == sum(category_counts.values()), "category count mismatch")
        monitored_count += count
        net_external = _raw(row["net_external_in_raw"], "net external", signed=True)
        net_event = _raw(row["net_event_in_raw"], "net event", signed=True)
        _require(net_external == amounts["external_in"] - amounts["external_out"], "external arithmetic mismatch")
        _require(net_event == net_external + amounts["mint_from_zero"] - amounts["burn_to_zero"],
                 "event arithmetic mismatch")
        if amounts["external_out"] > 0:
            positive.append((token, amounts["external_out"], row))
    _require(tokens == sorted(set(tokens)), "token rows must be sorted and unique")
    _require(monitored_count == counts["monitored_erc20_shaped"], "flow/count mismatch")
    _require(status != 0 or counts["logs"] == 0, "failed transaction with logs")
    return tx, positive, evidence["tier"]


def validate_observation(observation, *, expected_observation_sha256, config,
                         source_audit_sha256, source_scope):
    """Pure shared validation for semantic and count comparison arms.

    Source acquisition/audit and observation-manifest membership are external
    responsibilities. This function validates their retained digest bindings,
    identity fields, execution status and all internal observation arithmetic.
    """
    try:
        checked = _config(config)
        _sha(source_audit_sha256, "source audit")
        _require(isinstance(source_scope, str) and bool(source_scope.strip()), "source scope required")
        tx, positive, tier = _validate_observation(observation, checked, expected_observation_sha256, source_audit_sha256)
        return {"transaction": copy.deepcopy(tx), "positive_flows": copy.deepcopy(positive),
                "source_evidence_tier": tier,
                "archived_core_log_count": observation.get("archived_core_log_count")}
    except SemanticFlowError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError, AttributeError) as error:
        raise SemanticFlowError("malformed semantic observation") from error


class SemanticFlowMonitor:
    """Atomic past-only scores and budget-independent transaction grouping.

    The replay controller must independently verify the audited source manifest
    and its exact observation membership. A digest is an integrity anchor, not
    proof that the source indexed every transaction or log.
    """

    def __init__(self, config, *, source_audit_sha256, source_scope):
        self._config = _config(config)
        self.config_sha256 = canonical_sha256(self._config)
        self.source_audit_sha256 = _sha(source_audit_sha256, "source audit")
        _require(isinstance(source_scope, str) and bool(source_scope.strip()), "source scope required")
        self.source_scope = source_scope
        self._histories = {}
        self._last_transaction = None
        self._last_candidate_time_ns = None
        self._processed = 0
        self._observation_schema = None

    @property
    def config(self):
        return copy.deepcopy(self._config)

    def observe(self, observation, *, expected_observation_sha256):
        try:
            return self._observe(observation, expected_observation_sha256)
        except SemanticFlowError:
            raise
        except (KeyError, TypeError, ValueError, OverflowError, AttributeError) as error:
            raise SemanticFlowError("malformed semantic observation") from error

    def _observe(self, observation, expected_digest):
        tx, positive, tier = _validate_observation(observation, self._config, expected_digest, self.source_audit_sha256)
        schema = observation["schema_version"]
        _require(self._observation_schema is None or self._observation_schema == schema,
                 "mixed observation schema in one source-bound monitor")
        previous = self._last_transaction
        if previous is not None:
            _require(_key(tx) > _key(previous), "duplicate or out-of-order transaction")
            _require(tx["event_time_ns"] >= previous["event_time_ns"], "decreasing event time")
            _require(tx["transaction_hash"] != previous["transaction_hash"], "repeated transaction hash")
            if tx["block_number"] == previous["block_number"]:
                _require(tx["block_hash"] == previous["block_hash"], "conflicting block identity")
                _require(tx["event_time_ns"] == previous["event_time_ns"], "conflicting block timestamp")
        new_tokens = {token for token, _, _ in positive if token not in self._histories}
        _require(len(self._histories) + len(new_tokens) <= self._config["max_tokens"], "token capacity exceeded")
        # Nothing changes until every field, ordering condition and capacity has
        # passed. All scores see the same state strictly before this transaction.
        scores, triggering, eligible_count = [], [], 0
        for token, amount, row in positive:
            history = self._histories.get(token, [])
            n = len(history)
            eligible = n >= self._config["min_history"]
            numerator = 1 + sum(_raw(h["amount_raw"], "history amount") >= amount for h in history)
            denominator = n + 1
            trigger = eligible and numerator * self._config["threshold_denominator"] <= denominator * self._config["threshold_numerator"]
            eligible_count += eligible
            if trigger:
                triggering.append(token)
            scores.append({"token_address": token, "external_out_raw": str(amount),
                "external_in_raw": row["external_in_raw"], "net_external_in_raw": row["net_external_in_raw"],
                "history_count": n, "eligible": eligible, "trigger": trigger,
                "tail_rank": {"numerator": numerator, "denominator": denominator},
                "reference_oldest_event_time_ns": history[0]["event_time_ns"] if history else None,
                "reference_newest_event_time_ns": history[-1]["event_time_ns"] if history else None})
        raw_trigger = bool(triggering)
        grouped = raw_trigger and self._last_candidate_time_ns is not None and tx["event_time_ns"] - self._last_candidate_time_ns < self._config["grouping_ns"]
        candidate = raw_trigger and not grouped
        reason = ("candidate" if candidate else "grouped" if grouped else
                  "no_positive_external_outflow" if not positive else
                  "cold_start_only" if not eligible_count else "rank_not_exceeded")
        result = {"schema_version": "semantic_flow_decision_v1", "transaction": copy.deepcopy(tx),
            "config_sha256": self.config_sha256, "source_audit_sha256": self.source_audit_sha256,
            "source_scope": self.source_scope, "source_evidence_tier": tier,
            "observation_sha256": expected_digest, "positive_token_count": len(positive),
            "eligible_token_count": eligible_count, "cold_start_token_count": len(positive) - eligible_count,
            "triggering_token_addresses": triggering, "token_scores": scores,
            "raw_trigger": raw_trigger, "group_candidate": candidate, "grouping_reason": reason,
            "last_candidate_time_ns_before": self._last_candidate_time_ns,
            "historical_observed_time": None, "rank_is_calibrated_p_value": False}
        for token, amount, _ in positive:
            entry = {"amount_raw": str(amount), "event_time_ns": tx["event_time_ns"],
                     "block_number": tx["block_number"], "transaction_index": tx["transaction_index"],
                     "observation_sha256": expected_digest}
            self._histories[token] = (self._histories.get(token, []) + [entry])[-self._config["history_size"]:]
        if candidate:
            self._last_candidate_time_ns = tx["event_time_ns"]
        self._last_transaction = copy.deepcopy(tx)
        self._processed += 1
        self._observation_schema = schema
        result["history_token_count_after"] = len(self._histories)
        result["history_record_count_after"] = sum(map(len, self._histories.values()))
        return result

    def snapshot(self):
        return {"schema_version": "semantic_flow_monitor_state_v1", "config": copy.deepcopy(self._config),
                "config_sha256": self.config_sha256, "source_audit_sha256": self.source_audit_sha256,
                "source_scope": self.source_scope, "processed_observations": self._processed,
                "observation_schema": self._observation_schema,
                "last_transaction": copy.deepcopy(self._last_transaction),
                "last_candidate_time_ns": self._last_candidate_time_ns,
                "histories": copy.deepcopy(dict(sorted(self._histories.items())))}

    @classmethod
    def from_snapshot(cls, snapshot, *, expected_snapshot_sha256):
        try:
            return cls._from_snapshot(snapshot, expected_snapshot_sha256)
        except SemanticFlowError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise SemanticFlowError("malformed semantic checkpoint") from error

    @classmethod
    def _from_snapshot(cls, snapshot, expected_digest):
        _sha(expected_digest, "checkpoint digest")
        _require(type(snapshot) is dict and canonical_sha256(snapshot) == expected_digest, "checkpoint digest mismatch")
        fields = {"schema_version", "config", "config_sha256", "source_audit_sha256", "source_scope",
                  "processed_observations", "observation_schema", "last_transaction", "last_candidate_time_ns", "histories"}
        _require(set(snapshot) == fields and snapshot["schema_version"] == "semantic_flow_monitor_state_v1",
                 "unsupported checkpoint schema")
        obj = cls(snapshot["config"], source_audit_sha256=snapshot["source_audit_sha256"], source_scope=snapshot["source_scope"])
        _require(obj.config_sha256 == snapshot["config_sha256"], "checkpoint config mismatch")
        processed = _integer(snapshot["processed_observations"], "processed observations")
        schema = snapshot["observation_schema"]
        _require((schema is None) == (processed == 0), "checkpoint observation schema/count mismatch")
        _require(schema is None or schema in ("transfer_observation_v1", "archive_transfer_observation_v1"),
                 "unsupported checkpoint observation schema")
        last = snapshot["last_transaction"]
        _require((last is None) == (processed == 0), "checkpoint watermark/count mismatch")
        if last is not None:
            _transaction(last, obj._config["chain_id"])
        anchor = snapshot["last_candidate_time_ns"]
        if anchor is not None:
            _integer(anchor, "candidate time")
            _require(last is not None and anchor <= last["event_time_ns"], "future grouping anchor")
        histories = snapshot["histories"]
        _require(type(histories) is dict and len(histories) <= obj._config["max_tokens"], "invalid token history map")
        contexts, block_times = {}, {}
        for token, history in histories.items():
            _hex(token, 20, "history token")
            _require(type(history) is list and 0 < len(history) <= obj._config["history_size"], "invalid history length")
            _require(last is not None and len(history) <= processed, "history without processed observations")
            previous = None
            for entry in history:
                _require(type(entry) is dict and set(entry) == _HISTORY_FIELDS, "invalid history entry")
                _require(_raw(entry["amount_raw"], "history amount") > 0, "history must contain positive outflows")
                for key in ("event_time_ns", "block_number", "transaction_index"):
                    _integer(entry[key], key)
                _sha(entry["observation_sha256"], "history observation")
                _require(_key(entry) <= _key(last) and entry["event_time_ns"] <= last["event_time_ns"], "future history")
                context = (entry["event_time_ns"], entry["observation_sha256"])
                key = _key(entry)
                _require(key not in contexts or contexts[key] == context, "conflicting retained transaction context")
                contexts[key] = context
                block = entry["block_number"]
                _require(block not in block_times or block_times[block] == entry["event_time_ns"], "conflicting retained block time")
                block_times[block] = entry["event_time_ns"]
                if block == last["block_number"]:
                    _require(entry["event_time_ns"] == last["event_time_ns"], "last-block history time mismatch")
                if previous is not None:
                    _require(_key(entry) > _key(previous) and entry["event_time_ns"] >= previous["event_time_ns"], "unordered history")
                previous = entry
        _require(len(contexts) <= processed, "more retained transactions than processed")
        if anchor is not None:
            _require(processed >= obj._config["min_history"] + 1 and
                     any(len(h) >= obj._config["min_history"] for h in histories.values()),
                     "grouping anchor impossible before warmup")
        obj._processed, obj._last_transaction = processed, copy.deepcopy(last)
        obj._observation_schema = schema
        obj._last_candidate_time_ns, obj._histories = anchor, copy.deepcopy(histories)
        return obj
