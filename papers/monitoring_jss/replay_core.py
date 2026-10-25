"""Causal, single-chain, finalized-header replay for the feasibility pilot.

All time numbers are UTC POSIX seconds. ``observed_time`` is historical fact
and normally unknown. ``replay_available_time``, ``feature_ready_time`` and
``decision_time`` are explicitly the replay/scenario clock, not reconstructed
historical arrival times. The caller supplies these clocks and measures local
execution separately. No future labels, batch size or future scores are read.

One population/rule defines a notification group. The first qualifying event is
admitted immediately if budget permits. A fixed event-time cooldown is anchored
only on an emitted notification; grouped and budget-rejected raw triggers never
extend it. Admission is applied AFTER grouping, using the decision's UTC day.
Neither dropping late events nor duplicate delivery revises earlier decisions.

Snapshots provide deterministic continuation, not a transactional delivery
service. Exactly-once external delivery is NOT guaranteed across a crash between
log writing and state persistence. The caller must atomically persist state and
an outbox/log, or reconcile alert_id at an idempotent sink before making that claim.
Seen IDs are retained for the entire run; memory cost is intentionally measured.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from typing import Any, Callable


VERSION = "finalized_header_fixed_count_v1"
HASH = re.compile(r"0x[0-9a-fA-F]{64}\Z")


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


def _time(value: Any, field: str, *, nullable: bool = False) -> float | None:
    if value is None and nullable:
        return None
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise ValueError(f"{field} must be finite POSIX seconds")
    value = float(value)
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{field} must be finite nonnegative POSIX seconds")
    return value


def _integer(value: Any, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{field} must be an integer >= {minimum}")
    return value


@dataclass(frozen=True)
class ReplayConfig:
    threshold: int = 300
    cooldown_seconds: float = 300.0
    daily_budget: int = 5
    chain_id: int = 1
    population_id: str = "ethereum_block_headers"

    def __post_init__(self) -> None:
        _integer(self.threshold, "threshold")
        _integer(self.daily_budget, "daily_budget")
        _integer(self.chain_id, "chain_id", 1)
        _time(self.cooldown_seconds, "cooldown_seconds")
        if not isinstance(self.population_id, str) or not self.population_id:
            raise ValueError("population_id must be a nonempty string")

    @property
    def model_version(self) -> str:
        return VERSION + ":" + _digest(asdict(self))[:16]


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    """Validate the header contract; labels are metadata and never scored."""
    chain_id = _integer(event["chain_id"], "chain_id", 1)
    block_number = _integer(event["block_number"], "block_number")
    block_hash = event["block_hash"]
    if not isinstance(block_hash, str) or not HASH.fullmatch(block_hash):
        raise ValueError("block_hash must be a 0x-prefixed 32-byte hex string")
    for key in ("tx_index", "log_index", "trace_index"):
        if event.get(key) is not None:
            raise ValueError(f"{key} must be null for a block header")
    return {
        "chain_id": chain_id, "block_number": block_number,
        "block_hash": block_hash.lower(), "tx_index": None, "log_index": None,
        "trace_index": None, "event_time": _time(event["event_time"], "event_time"),
        "observed_time": _time(event.get("observed_time"), "observed_time", nullable=True),
        "label_available_time": _time(event.get("label_available_time"), "label_available_time", nullable=True),
        "transaction_count": _integer(event["transaction_count"], "transaction_count"),
    }


class ReplayState:
    """Ordered local decision state; instantiate one state per pilot population."""

    def __init__(self, config: ReplayConfig | None = None) -> None:
        self.config = config or ReplayConfig()
        self.seen: dict[str, str] = {}
        self.high_water_block = -1
        self.high_water_event_time: float | None = None
        self.last_emitted_event_time: float | None = None
        self.last_decision_time: float | None = None
        self.daily_counts: dict[str, int] = {}
        self.emitted_alert_ids: list[str] = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "replay_state_v1", "config": asdict(self.config),
            "seen": dict(self.seen), "high_water_block": self.high_water_block,
            "high_water_event_time": self.high_water_event_time,
            "last_emitted_event_time": self.last_emitted_event_time,
            "last_decision_time": self.last_decision_time,
            "daily_counts": dict(self.daily_counts),
            "emitted_alert_ids": list(self.emitted_alert_ids),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ReplayState":
        if value.get("schema_version") != "replay_state_v1":
            raise ValueError("unsupported state schema")
        state = cls(ReplayConfig(**value["config"]))
        state.seen = dict(value["seen"])
        state.high_water_block = value["high_water_block"]
        state.high_water_event_time = value["high_water_event_time"]
        state.last_emitted_event_time = value["last_emitted_event_time"]
        state.last_decision_time = value["last_decision_time"]
        state.daily_counts = dict(value["daily_counts"])
        state.emitted_alert_ids = list(value["emitted_alert_ids"])
        return state

    def process(self, event: dict[str, Any], *, replay_available_time: float,
                decision_time: float | Callable[[], float],
                feature_ready_time: float | None = None) -> dict[str, Any]:
        """Return an audit row; invalid input fails before state mutation.

        ``decision_time`` may be a callback sampled after scoring/grouping and
        immediately before budget admission. This lets the runner add measured
        local elapsed time to its explicit scenario clock without backdating the
        decision. Supply ``feature_ready_time`` when using a callback.

        Equal decision times follow call order. ``late`` means an unseen block
        at/below the accepted block watermark, or an older timestamp. Such rows
        are dropped; this is not reorg handling. Conflicting duplicates fail closed.
        """
        e = normalize_event(event)
        if e["chain_id"] != self.config.chain_id:
            raise ValueError("event belongs to a different chain")
        available = _time(replay_available_time, "replay_available_time")
        if callable(decision_time) and feature_ready_time is None:
            raise ValueError("feature_ready_time is required with a decision callback")
        ready = _time(decision_time if feature_ready_time is None else feature_ready_time,
                      "feature_ready_time")
        if not e["event_time"] <= available <= ready:
            raise ValueError("require event_time <= replay availability <= feature ready")
        event_id = "event:" + _digest([e["chain_id"], e["block_hash"], "header"])
        fingerprint = _digest({key: e[key] for key in
                               ("chain_id", "block_number", "block_hash", "event_time", "transaction_count")})
        reason = None
        score = raw_trigger = None
        group_candidate = accepted = False
        if event_id in self.seen:
            if self.seen[event_id] != fingerprint:
                raise ValueError("conflicting payload for previously seen event_id")
            reason = "duplicate"
        elif (e["block_number"] <= self.high_water_block or
              (self.high_water_event_time is not None and e["event_time"] < self.high_water_event_time)):
            reason = "late"
        else:
            accepted = True
            score = e["transaction_count"]
            raw_trigger = score > self.config.threshold
            if not raw_trigger:
                reason = "below_threshold"
            elif (self.last_emitted_event_time is not None and
                  e["event_time"] - self.last_emitted_event_time < self.config.cooldown_seconds):
                reason = "grouped"
            else:
                group_candidate = True
        # Historical observed_time and replay clocks are different domains.
        # Never infer historical availability from a modeled replay timestamp.
        decision = _time(decision_time() if callable(decision_time) else decision_time,
                         "decision_time")
        if decision < ready:
            raise ValueError("decision_time must be >= feature_ready_time")
        if self.last_decision_time is not None and decision < self.last_decision_time:
            raise ValueError("decision clock cannot move backwards")
        day = datetime.fromtimestamp(decision, timezone.utc).date().isoformat()
        emitted = group_candidate and self.daily_counts.get(day, 0) < self.config.daily_budget
        if group_candidate and not emitted:
            reason = "budget"
        alert_id = ("alert:" + _digest([self.config.model_version, event_id])) if emitted else None
        # All validation above precedes mutation.
        self.seen[event_id] = fingerprint
        if accepted:
            self.high_water_block = e["block_number"]
            self.high_water_event_time = e["event_time"]
        if emitted:
            self.daily_counts[day] = self.daily_counts.get(day, 0) + 1
            self.last_emitted_event_time = e["event_time"]
            self.emitted_alert_ids.append(alert_id)
        self.last_decision_time = decision
        return {
            "schema_version": "replay_decision_v1", **e, "event_id": event_id,
            "population_id": self.config.population_id,
            "clock_domain": "replay_scenario_posix_seconds",
            "replay_available_time": available, "feature_ready_time": ready,
            "decision_time": decision, "model_version": self.config.model_version,
            "score": score, "threshold": self.config.threshold, "raw_trigger": raw_trigger,
            "group_candidate": group_candidate, "notification_emitted": emitted,
            "alert_id": alert_id, "suppression_reason": reason,
            "budget_day_utc": day, "daily_budget": self.config.daily_budget,
            "notifications_on_day": self.daily_counts.get(day, 0), "label_used": False,
        }
