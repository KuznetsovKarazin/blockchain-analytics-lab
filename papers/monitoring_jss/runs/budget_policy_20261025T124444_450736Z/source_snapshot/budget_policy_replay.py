"""Exact event-time allocation study; no labels, learned detector, or delivery claims.

The policy clock is original integer event_time_ns. It is a logical simulation
clock, not an observed arrival or CPU clock. State starts cold once, persists
across daily files, and supports orderly JSON checkpoint continuation. Neither
crash-safe notification delivery nor an outbox is implemented. The rolling deque
covers 60 seconds; exact identity and order-key ledgers grow over the finite
study horizon.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

# The old module is a frozen dependency. Its decoding helper does not interpret
# ABI data or use labels; its playback-clock policy is NOT used here.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from event_log_replay import ADDRESS, decode_event, digest, dump, hex_field, integer, sha256

PAPER = Path(__file__).resolve().parent
ROOT = PAPER.parents[1]
NS = 1_000_000_000
DAY_NS = 86_400 * NS
POLICIES = ("greedy", "paced_cumulative", "token_bucket")


def utc_day(t):
    return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(days=t // DAY_NS)).date().isoformat()


def utc_ns(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None or dt.utcoffset() != timedelta(0) or dt.microsecond:
        raise ValueError("horizon must use exact integral UTC seconds")
    delta = dt - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86_400 + delta.seconds) * NS


@dataclass(frozen=True)
class BudgetConfig:
    policy: str
    daily_budget: int
    window_start_ns: int
    window_end_ns: int
    address: str = ADDRESS
    chain_id: int = 1
    window_seconds: int = 60
    threshold_count: int = 10
    cooldown_seconds: int = 300

    def __post_init__(self):
        if self.policy not in POLICIES:
            raise ValueError("unknown allocation policy")
        object.__setattr__(self, "address", hex_field(self.address, "address", 20)[0])
        for name in ("daily_budget", "window_start_ns", "window_end_ns", "cooldown_seconds"):
            integer(getattr(self, name), name)
        for name in ("chain_id", "window_seconds", "threshold_count"):
            integer(getattr(self, name), name, 1)
        if self.window_end_ns <= self.window_start_ns:
            raise ValueError("empty or reversed study horizon")

    @property
    def policy_version(self):
        return "event_time_allocation_v1:" + digest(asdict(self))[:24]


class PolicyReplayState:
    def __init__(self, config):
        self.config = config
        self.seen = {}
        self.order_keys = {}
        self.watermark = None
        self.window = deque()
        self.policy_clock_ns = config.window_start_ns
        self.last_emitted_time_ns = None
        self.daily_counts = {}
        self.token_credit_units = DAY_NS
        self.alert_ids = []

    def to_dict(self):
        return {"schema_version": "budget_policy_state_v1", "config": asdict(self.config),
                "seen": dict(self.seen), "order_keys": dict(self.order_keys), "watermark": self.watermark,
                "window": list(self.window), "policy_clock_ns": self.policy_clock_ns,
                "last_emitted_time_ns": self.last_emitted_time_ns,
                "daily_counts": dict(self.daily_counts), "token_credit_units": self.token_credit_units,
                "alert_ids": list(self.alert_ids)}

    @classmethod
    def from_dict(cls, value):
        if value.get("schema_version") != "budget_policy_state_v1":
            raise ValueError("unsupported checkpoint schema")
        state = cls(BudgetConfig(**value["config"]))
        state.seen = dict(value["seen"])
        state.order_keys = dict(value["order_keys"])
        state.watermark = tuple(value["watermark"]) if value["watermark"] is not None else None
        state.window = deque(value["window"])
        state.policy_clock_ns = integer(value["policy_clock_ns"], "policy_clock_ns")
        state.last_emitted_time_ns = value["last_emitted_time_ns"]
        state.daily_counts = dict(value["daily_counts"])
        state.token_credit_units = integer(value["token_credit_units"], "token_credit_units")
        state.alert_ids = list(value["alert_ids"])
        if not state.config.window_start_ns <= state.policy_clock_ns < state.config.window_end_ns:
            raise ValueError("checkpoint clock outside horizon")
        if state.token_credit_units > DAY_NS:
            raise ValueError("checkpoint token capacity exceeded")
        if any(type(n) is not int or not 0 <= n <= state.config.daily_budget for n in state.daily_counts.values()):
            raise ValueError("checkpoint daily cap exceeded")
        if len(state.alert_ids) != len(set(state.alert_ids)):
            raise ValueError("checkpoint repeats notification ID")
        if set(state.order_keys.values()) != set(state.seen):
            raise ValueError("checkpoint identity and order-key ledgers disagree")
        return state

    def process(self, event):
        """Process one decode_event result. All invalid/conflict checks precede mutation.

        Precedence: duplicate/late; below threshold; grouped; hard daily cap;
        paced quota or token shortage; emitted. A dropped redelivery retains its
        source event timestamp but cannot rewind or advance the policy clock.
        """
        e, c = event, self.config
        t = integer(e["event_time_ns"], "event_time_ns")
        if not c.window_start_ns <= t < c.window_end_ns:
            raise ValueError("event outside study horizon")
        if e["chain_id"] != c.chain_id or e["address"] != c.address:
            raise ValueError("event outside configured emitter/chain")
        key = (e["block_number"], e["transaction_index"], e["log_index"])
        order_id = ":".join(map(str, key))
        eid = "event:" + digest([e["chain_id"], e["block_hash"], e["transaction_hash"], e["log_index"]])
        fingerprint = digest({k: e[k] for k in ("chain_id", "address", "block_number", "block_hash",
                             "transaction_index", "transaction_hash", "log_index", "event_time_ns", "topics", "data", "removed")})
        accepted, reason = False, None
        if order_id in self.order_keys and self.order_keys[order_id] != eid:
            raise ValueError("different log identity at previously observed exact order key")
        if eid in self.seen:
            if self.seen[eid] != fingerprint:
                raise ValueError("conflicting payload for same log identity")
            reason = "duplicate"
        elif self.watermark is not None and key < self.watermark:
            reason = "late"
        elif self.watermark is not None and key == self.watermark:
            raise ValueError("different log identity at same exact order key")
        else:
            if t < self.policy_clock_ns:
                raise ValueError("timestamp decreases in increasing canonical chain order")
            accepted = True

        score, raw, candidate, emitted, aid = None, None, False, False, None
        next_clock = t if accepted else self.policy_clock_ns
        day = utc_day(next_clock)
        used = self.daily_counts.get(day, 0)
        quota = (min(c.daily_budget, 1 + c.daily_budget * (next_clock % DAY_NS) // DAY_NS)
                 if c.policy == "paced_cumulative" and c.daily_budget else c.daily_budget)
        credit = self.token_credit_units
        if accepted:
            if c.policy == "token_bucket":
                credit = min(DAY_NS, credit + (t - self.policy_clock_ns) * c.daily_budget)
            # Every accepted log contributes, irrespective of policy admission.
            cutoff = t - c.window_seconds * NS
            while self.window and self.window[0] <= cutoff:
                self.window.popleft()
            self.window.append(t)
            score = len(self.window)
            raw = score >= c.threshold_count
            if not raw:
                reason = "below_threshold"
            elif self.last_emitted_time_ns is not None and t - self.last_emitted_time_ns < c.cooldown_seconds * NS:
                reason = "grouped"
            else:
                candidate = True
                if used >= c.daily_budget:
                    reason = "budget"
                elif c.policy == "paced_cumulative" and used >= quota:
                    reason = "quota"
                elif c.policy == "token_bucket" and credit < DAY_NS:
                    reason = "token"
                else:
                    emitted = True
                    aid = "alert:" + digest([c.policy_version, eid])
                    if c.policy == "token_bucket":
                        credit -= DAY_NS
                    self.last_emitted_time_ns = t
                    self.daily_counts[day] = used + 1
                    self.alert_ids.append(aid)
            self.watermark, self.policy_clock_ns = key, t
            self.token_credit_units = credit
        # Remember late identities as well: a later conflicting copy must fail.
        self.seen[eid] = fingerprint
        self.order_keys[order_id] = eid
        return {"schema_version": "budget_policy_decision_v1", "event_id": eid,
                "chain_id": e["chain_id"], "address": e["address"], "block_number": e["block_number"],
                "block_hash": e["block_hash"], "transaction_hash": e["transaction_hash"],
                "transaction_index": e["transaction_index"], "log_index": e["log_index"],
                "event_time_ns": t, "policy_clock_ns": self.policy_clock_ns,
                "clock_domain": "historical_event_time_ns_logical_simulation",
                "observed_time": e.get("observed_time"), "removed": e["removed"], "label_used": False,
                "policy": c.policy, "policy_version": c.policy_version, "daily_budget": c.daily_budget,
                "accepted": accepted, "score": score, "raw_trigger": raw, "group_candidate": candidate,
                "notification_emitted": emitted, "notification_time_ns": t if emitted else None,
                "alert_id": aid, "suppression_reason": reason, "budget_day_utc": day,
                "notifications_on_day": self.daily_counts.get(day, 0), "daily_quota": quota,
                "token_credit_units": credit if c.policy == "token_bucket" else None,
                "token_units_per_token": DAY_NS if c.policy == "token_bucket" else None}


def validate_study_config(config):
    if config.get("schema_version") != "budget_policy_study_config_v1":
        raise ValueError("unsupported study config")
    w = config["window"]
    if (utc_ns(w["start_utc"]) != w["start_ns"] or utc_ns(w["end_utc"]) != w["end_ns"] or
            w["start_ns"] % DAY_NS or w["end_ns"] % DAY_NS or not w["end_exclusive"] or
            w["end_ns"] - w["start_ns"] != w["days"] * DAY_NS or w["days"] != 30):
        raise ValueError("study requires exactly 30 complete UTC days")
    if config["policies"] != list(POLICIES) or config["budgets"] != [1, 5, 20] or config["primary_budget"] != 5:
        raise ValueError("study policies/budgets differ from predeclared design")
    if config["detector"] != {"window_seconds": 60, "threshold_count": 10, "cooldown_seconds": 300}:
        raise ValueError("study detector differs from predeclared design")
    if len(config["emitters"]) != 2 or len({e["id"] for e in config["emitters"]}) != 2:
        raise ValueError("study requires two distinct emitters")
    if config["execution"]["cells"] != 18 or config["execution"]["repetitions"] != 1:
        raise ValueError("unexpected execution grid")
    return [utc_day(t) for t in range(w["start_ns"], w["end_ns"], DAY_NS)]


def resolve_path(value, root):
    path = Path(value)
    return path if path.is_absolute() else root / path


def validate_inputs(config, manifest, root):
    """Reject missing/unverified days; preflight every selected-file digest."""
    days = validate_study_config(config)
    if manifest.get("status") != "complete":
        raise ValueError("input manifest is not complete")
    populations = {p["population_id"]: p for p in manifest["populations"]}
    if len(populations) != len(manifest["populations"]):
        raise ValueError("repeated population in input manifest")
    if set(populations) != {e["id"] for e in config["emitters"]}:
        raise ValueError("input manifest population mismatch")
    result = {}
    for e in config["emitters"]:
        p = populations[e["id"]]
        if p["address"].lower() != e["address"].lower() or p["chain_id"] != e["chain_id"]:
            raise ValueError("manifest population identity mismatch")
        if (p.get("start_utc", config["window"]["start_utc"]) != config["window"]["start_utc"] or
                p.get("end_utc_exclusive", config["window"]["end_utc"]) != config["window"]["end_utc"]):
            raise ValueError("manifest population horizon mismatch")
        inputs = p["inputs"]
        if [r["day_utc"] for r in inputs] != days:
            raise ValueError("missing, repeated or unordered manifest days")
        result[e["id"]] = []
        for item in inputs:
            if (("status" in item and item["status"] != "complete") or
                    ("status" not in item and item.get("complete") is not True) or
                    ("complete" in item and item["complete"] is not True)):
                raise ValueError("day lacks completed acquisition validation")
            integer(item["rows"], "rows")
            path = resolve_path(item["path"], root).resolve()
            if "bytes" in item and path.stat().st_size != integer(item["bytes"], "bytes"):
                raise ValueError("input size mismatch")
            if sha256(path) != item["sha256"]:
                raise ValueError(f"input SHA-256 mismatch: {path}")
            result[e["id"]].append({**item, "path": str(path)})
    return result


def blank_aggregate():
    return {"records": 0, "accepted_events": 0, "raw_triggers": 0, "group_candidates": 0,
            "notifications": 0, "suppression_counts": {}, "first_notification_time_ns": None,
            "last_notification_time_ns": None}


def add_row(aggregate, row):
    aggregate["records"] += 1
    for key, source in (("accepted_events", "accepted"), ("raw_triggers", "raw_trigger"),
                        ("group_candidates", "group_candidate"), ("notifications", "notification_emitted")):
        aggregate[key] += row[source] is True
    if row["suppression_reason"] is not None:
        reason = row["suppression_reason"]
        aggregate["suppression_counts"][reason] = aggregate["suppression_counts"].get(reason, 0) + 1
    if row["notification_emitted"]:
        if aggregate["first_notification_time_ns"] is None:
            aggregate["first_notification_time_ns"] = row["notification_time_ns"]
        aggregate["last_notification_time_ns"] = row["notification_time_ns"]


def write_jsonl(handle, value):
    handle.write(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")


def execute_cell(config, emitter, policy, budget, inputs, out):
    cell_id = f"{emitter['id']}__{policy}__B{budget}"
    cell = out / "cells" / cell_id
    cell.mkdir(parents=True, exist_ok=False)
    w = config["window"]
    state = PolicyReplayState(BudgetConfig(policy=policy, daily_budget=budget,
        window_start_ns=w["start_ns"], window_end_ns=w["end_ns"],
        address=emitter["address"], chain_id=emitter["chain_id"], **config["detector"]))
    days = {r["day_utc"]: blank_aggregate() for r in inputs}
    hours = {f"{day}T{hour:02d}:00:00Z": blank_aggregate() for day in days for hour in range(24)}
    total, accepted_hash = blank_aggregate(), hashlib.sha256()
    notifications, unknown = set(), Counter()
    decisions = cell / "decisions.jsonl.gz"
    with gzip.open(decisions, "wt", compresslevel=6) as sink:
        for item in inputs:
            n = 0
            with Path(item["path"]).open("rb") as source:
                for line in source:
                    event = decode_event(json.loads(line))
                    if utc_day(event["event_time_ns"]) != item["day_utc"]:
                        raise ValueError("input record outside declared UTC partition")
                    row = state.process(event)
                    write_jsonl(sink, row)
                    n += 1
                    if row["accepted"]:
                        accepted_hash.update(json.dumps([row["event_id"], row["score"], row["raw_trigger"]], separators=(",", ":")).encode() + b"\n")
                    # Partition attribution follows the immutable source event;
                    # accepted records alone can contribute raw/issued counts.
                    hour = f"{item['day_utc']}T{(event['event_time_ns'] % DAY_NS) // (3600 * NS):02d}:00:00Z"
                    for aggregate in (total, days[item["day_utc"]], hours[hour]):
                        add_row(aggregate, row)
                    unknown["unknown_observed_time"] += row["observed_time"] is None
                    unknown["unknown_removed"] += row["removed"] is None
                    if row["notification_emitted"]:
                        notifications.add(row["event_id"])
            if n != item["rows"]:
                raise ValueError("manifest row count differs from input")
            if sha256(item["path"]) != item["sha256"]:
                raise ValueError("input changed while replaying")
    exceedances = sum(a["notifications"] > budget for a in days.values())
    if exceedances or len(notifications) != total["notifications"] or len(set(state.alert_ids)) != total["notifications"]:
        raise ValueError("hard-cap or notification identity invariant failed")
    daily = [{"day_utc": day, **a, "daily_budget": budget,
              "unused_daily_slots": budget - a["notifications"], "at_cap": a["notifications"] == budget}
             for day, a in days.items()]
    hourly = [{"hour_utc": hour, **a} for hour, a in hours.items()]
    dump(daily, cell / "daily.json")
    dump(hourly, cell / "hourly.json")
    with gzip.open(cell / "final_state.json.gz", "wt", compresslevel=6) as handle:
        json.dump(state.to_dict(), handle, sort_keys=True, separators=(",", ":"), allow_nan=False)
    summary = {"cell_id": cell_id, "population_id": emitter["id"], "policy": policy,
               "daily_budget": budget, "primary_budget": budget == config["primary_budget"],
               **total, **unknown, "days": len(days), "hard_cap_exceedances": exceedances,
               "unique_alert_ids": len(set(state.alert_ids)), "days_at_cap": sum(r["at_cap"] for r in daily),
               "unused_daily_slots": sum(r["unused_daily_slots"] for r in daily),
               "raw_trigger_active_hours": sum(r["raw_triggers"] > 0 for r in hourly),
               "raw_trigger_active_hours_with_notification": sum(r["raw_triggers"] > 0 and r["notifications"] > 0 for r in hourly),
               "accepted_feature_stream_sha256": accepted_hash.hexdigest(),
               "identity_ledger_entries": len(state.seen), "order_key_ledger_entries": len(state.order_keys),
               "window_entries_at_end": len(state.window),
               "decision_log": {"path": str(decisions.relative_to(out)), "sha256": sha256(decisions), "rows": total["records"]},
               "artifacts": {p.name: sha256(p) for p in sorted(cell.iterdir()) if p.is_file()},
               "state_semantics": "finite-horizon exact identity/order ledgers; orderly checkpoint, no crash-safe delivery"}
    dump(summary, cell / "summary.json")
    return summary, notifications


def execute_run(out):
    """Internal entry point: invoked only from the captured source snapshot."""
    if Path(__file__).resolve().parent != (out / "source_snapshot").resolve():
        raise ValueError("worker must execute the captured source snapshot")
    config = json.loads((out / "config.json").read_text())
    validate_study_config(config)
    inputs = json.loads((out / "resolved_inputs.json").read_text())
    summaries, notification_sets = [], {}
    for emitter in config["emitters"]:
        for budget in config["budgets"]:
            for policy in config["policies"]:
                summary, ids = execute_cell(config, emitter, policy, budget, inputs[emitter["id"]], out)
                summaries.append(summary)
                notification_sets[summary["cell_id"]] = ids
    overlaps = []
    for emitter in config["emitters"]:
        cells = [s for s in summaries if s["population_id"] == emitter["id"]]
        if len({s["accepted_feature_stream_sha256"] for s in cells}) != 1:
            raise ValueError("raw feature/trigger streams differ between allocation cells")
        for budget in config["budgets"]:
            selected = [s for s in cells if s["daily_budget"] == budget]
            for i, a in enumerate(selected):
                for b in selected[i + 1:]:
                    x, y = notification_sets[a["cell_id"]], notification_sets[b["cell_id"]]
                    overlaps.append({"population_id": emitter["id"], "daily_budget": budget,
                        "policy_a": a["policy"], "policy_b": b["policy"], "notifications_a": len(x),
                        "notifications_b": len(y), "intersection": len(x & y), "union": len(x | y),
                        "jaccard": len(x & y) / len(x | y) if x | y else None})
    dump({"status": "worker_completed_pending_integrity_check", "cells": summaries,
          "notification_set_overlap": overlaps, "raw_feature_streams_identical": True,
          "clock_domain": "historical_event_time_ns_logical_simulation", "labels_used": False}, out / "study_summary.json")


def verify_written_artifacts(out, summary):
    """Read back every gzip through EOF/CRC and check all recorded artifact hashes."""
    gzip_files = 0
    decision_rows = 0
    for cell in summary["cells"]:
        directory = out / "cells" / cell["cell_id"]
        for name, expected in cell["artifacts"].items():
            path = directory / name
            if sha256(path) != expected:
                raise ValueError("written artifact SHA-256 changed")
            if name.endswith(".gz"):
                gzip_files += 1
                if name == "decisions.jsonl.gz":
                    with gzip.open(path, "rt") as handle:
                        count = sum(1 for line in handle if json.loads(line))
                    if count != cell["decision_log"]["rows"]:
                        raise ValueError("written decision row count mismatch")
                    decision_rows += count
                elif name == "final_state.json.gz":
                    with gzip.open(path, "rt") as handle:
                        PolicyReplayState.from_dict(json.load(handle))
                else:
                    with gzip.open(path, "rb") as handle:
                        for _ in iter(lambda: handle.read(1024 * 1024), b""):
                            pass
    return {"status": "pass", "gzip_files_read_to_eof": gzip_files,
            "decision_rows_read_back": decision_rows, "all_recorded_artifact_hashes_match": True}


def launch(args):
    config_path, manifest_path = args.config.resolve(), args.input_manifest.resolve()
    config, manifest = json.loads(config_path.read_text()), json.loads(manifest_path.read_text())
    inputs = validate_inputs(config, manifest, ROOT)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", args.run_id):
        raise ValueError("run-id must be a simple unique name")
    out = PAPER / "runs" / args.run_id
    out.mkdir(parents=True, exist_ok=False)
    snapshot = out / "source_snapshot"
    snapshot.mkdir()
    sources = [Path(__file__).resolve(), PAPER / "event_log_replay.py", PAPER / "tests" / "test_budget_policy_replay.py"]
    tracked = {str(p): sha256(p) for p in sources + [config_path, manifest_path]}
    for source in sources:
        destination = snapshot / ("tests" if source.parent.name == "tests" else "") / source.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    shutil.copyfile(config_path, out / "config.json")
    shutil.copyfile(manifest_path, out / "input_manifest.json")
    if (json.loads((out / "config.json").read_text()) != config or
            json.loads((out / "input_manifest.json").read_text()) != manifest):
        raise ValueError("config or input manifest changed during preflight")
    dump(inputs, out / "resolved_inputs.json")
    # Provenance files are copied as opaque bytes. No label is parsed or joined.
    opaque = [("inventory", config["acquisition"]["inventory"]),
              ("label_manifest", config["labels_separate"]["label_manifest"])]
    provenance = {}
    for name, value in opaque:
        path = resolve_path(value, PAPER).resolve()
        checksum = sha256(path)
        tracked[str(path)] = checksum
        destination = out / "provenance" / f"{name}{path.suffix}"
        destination.parent.mkdir(exist_ok=True)
        shutil.copyfile(path, destination)
        if sha256(destination) != checksum:
            raise ValueError("provenance file changed while capturing snapshot")
        provenance[name] = {"source": str(path), "sha256": checksum, "copy": str(destination.relative_to(out))}
    frozen = {str(p.relative_to(out)): sha256(p) for p in sorted(out.rglob("*")) if p.is_file()}
    if any(sha256(path) != checksum for path, checksum in tracked.items()):
        raise ValueError("source/config/manifest changed during snapshot creation")
    for source in sources:
        destination = snapshot / ("tests" if source.parent.name == "tests" else "") / source.name
        if sha256(destination) != tracked[str(source)]:
            raise ValueError("source changed while capturing executable snapshot")
    record = {"schema_version": "budget_policy_run_v1", "status": "running",
              "started_at_utc": datetime.now(timezone.utc).isoformat(),
              "command": [sys.executable, *sys.argv], "cwd": str(Path.cwd()),
              "config_sha256": sha256(config_path), "input_manifest_sha256": sha256(manifest_path),
              "tracked_source_sha256": tracked, "frozen_file_sha256": frozen, "provenance": provenance,
              "environment": {"python": sys.version, "platform": platform.platform()},
              "memory_scope": "streamed inputs and decisions; rolling deque plus finite-30-day identity/order ledgers",
              "interpretation": "functional logical-event-time simulation; no observed delivery or performance claim"}
    dump(record, out / "run_manifest.json")
    command = [sys.executable, str(snapshot / "budget_policy_replay.py"), "--execute-run", str(out)]
    record["executed_command"] = command
    dump(record, out / "run_manifest.json")
    try:
        subprocess.run(command, check=True)
        unchanged = all(sha256(path) == checksum for path, checksum in tracked.items())
        unchanged = unchanged and all(sha256(out / path) == checksum for path, checksum in frozen.items())
        unchanged = unchanged and all(sha256(r["path"]) == r["sha256"] for items in inputs.values() for r in items)
        record["frozen_sources_config_inputs_unchanged"] = unchanged
        if not unchanged:
            raise ValueError("source/config/input integrity changed during replay")
        summary = json.loads((out / "study_summary.json").read_text())
        record["written_artifact_verification"] = verify_written_artifacts(out, summary)
        summary["status"] = "complete"
        dump(summary, out / "study_summary.json")
        record["result_artifact_sha256"] = {
            str(p.relative_to(out)): sha256(p)
            for p in sorted((out / "cells").rglob("*")) if p.is_file()}
        record["result_artifact_sha256"]["study_summary.json"] = sha256(out / "study_summary.json")
        record["status"] = "complete"
    except Exception as error:
        record["status"], record["error"] = "failed", repr(error)
        raise
    finally:
        record["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
        dump(record, out / "run_manifest.json")
    print(str(out))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--input-manifest", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--execute-run", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.execute_run is not None:
        if any((args.config, args.input_manifest, args.run_id)):
            parser.error("internal worker does not accept study overrides")
        execute_run(args.execute_run.resolve())
    else:
        if not all((args.config, args.input_manifest, args.run_id)):
            parser.error("--config, --input-manifest and --run-id are required")
        launch(args)


if __name__ == "__main__":
    main()
