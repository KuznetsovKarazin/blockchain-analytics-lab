"""Verify causal/reliability invariants using the real pilot header stream.

The input is historical data. Deliberate suffix changes, duplicate deliveries,
late deliveries and a checkpoint are fault injections for implementation QA,
not new historical observations or attack-detection evidence. No raw event or
decision records are written by this verifier. Optional --run validates every
persisted decision against that run's captured schema and input provenance.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import shlex
import subprocess
import sys
import time
import traceback

from replay_core import ReplayConfig, ReplayState

PAPER = Path(__file__).resolve().parent
ROOT = PAPER.parents[1]
CONFIG_KEYS = ("threshold", "cooldown_seconds", "daily_budget", "chain_id", "population_id")
# These columns describe delivery clocks or independent audit metadata rather
# than the semantic detector/admission decision. Historical event_time remains.
EXCLUDED_SEMANTIC_FIELDS = {
    "replay_available_time", "feature_ready_time", "decision_time",
    "observed_time", "label_available_time",
}


def digest_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def digest_value(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


def semantic(row):
    return {k: v for k, v in row.items() if k not in EXCLUDED_SEMANTIC_FIELDS}


def ensure(condition, message):
    if not condition:
        raise AssertionError(message)


def relative(path):
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=Path, required=True, help="Complete ordinary-day normalized JSONL")
    ap.add_argument("--config", type=Path, default=PAPER / "pilot_config.json")
    ap.add_argument("--run", type=Path, help="Optional completed pilot run containing captured source/schema")
    ap.add_argument("--out", type=Path, help="New QA output directory; must not exist")
    args = ap.parse_args()
    args.input = args.input.resolve()
    args.config = args.config.resolve()
    if args.run:
        args.run = args.run.resolve()
    out = args.out or PAPER / "qa" / datetime.now(timezone.utc).strftime("verify_%Y%m%dT%H%M%S_%fZ")
    out.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    start = time.perf_counter()
    cfg = json.loads(args.config.read_text())
    config = ReplayConfig(**{key: cfg[key] for key in CONFIG_KEYS})
    events = [json.loads(line) for line in args.input.read_text().splitlines() if line.strip()]
    ensure(len(events) >= 4, "at least four events required")
    origin = datetime.fromisoformat(cfg["playback_origin"]).timestamp()
    first_time = events[0]["event_time"]
    split = len(events) // 2
    report = {
        "schema_version": "monitoring_pilot_real_input_verification_v1",
        "started_utc": started,
        "evidence_role": "implementation QA on historical data plus explicit delivery/suffix fault injections; not attack-detection evidence",
        "command_argv": [sys.executable, *sys.argv],
        "command_shell": shlex.join([sys.executable, *sys.argv]),
        "environment": {"python": sys.version, "platform": platform.platform()},
        "input": {"path": relative(args.input), "sha256": digest_file(args.input), "events": len(events)},
        "sources": {relative(p): digest_file(p) for p in
                    (Path(__file__), PAPER / "replay_core.py", args.config,
                     PAPER / "event.schema.json", PAPER / "decision.schema.json")},
        "config": {key: cfg[key] for key in CONFIG_KEYS},
        "playback_origin": cfg["playback_origin"], "playback_speed": 1,
        "verification_service_seconds": 0.001,
        "clock_scope": "fixed deterministic verification clock, not measured runtime; original event gaps retained",
        "split_index": split,
        "semantic_fields_excluded": sorted(EXCLUDED_SEMANTIC_FIELDS),
        "tests": [],
    }
    try:
        report["git_base_commit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        report["git_base_commit"] = None

    def apply(state, e, *, replay_time=None):
        arrival = origin + e["event_time"] - first_time if replay_time is None else replay_time
        return state.process(e, replay_available_time=arrival,
                             feature_ready_time=arrival + .0005, decision_time=arrival + .001)

    def replay(items):
        state = ReplayState(config)
        return state, [apply(state, event) for event in items]

    def check(name, fn):
        t0 = time.perf_counter()
        try:
            details = fn()
            report["tests"].append({"name": name, "passed": True,
                                    "runtime_seconds": time.perf_counter() - t0, "details": details})
        except Exception as exc:
            report["tests"].append({"name": name, "passed": False,
                                    "runtime_seconds": time.perf_counter() - t0,
                                    "error": f"{type(exc).__name__}: {exc}"})

    baseline_state, baseline = replay(events)
    baseline_semantic = [semantic(r) for r in baseline]
    report["baseline_semantic_sha256"] = digest_value(baseline_semantic)
    report["baseline_state_sha256"] = digest_value(baseline_state.to_dict())
    report["baseline_notifications"] = len(baseline_state.emitted_alert_ids)

    def prefix_check():
        _, short = replay(events[:split])
        modified = events[:split] + [
            {**e, "transaction_count": 0 if i % 2 else config.threshold + 10000,
             "label": i % 2, "label_available_time": origin + 365 * 86400}
            for i, e in enumerate(events[split:])]
        _, altered = replay(modified)
        ensure([semantic(r) for r in short] == baseline_semantic[:split], "standalone prefix changed")
        ensure([semantic(r) for r in altered[:split]] == baseline_semantic[:split], "future changes altered prefix")
        return {"prefix_events": split, "mutated_future_events": len(events) - split,
                "prefix_semantic_sha256": digest_value(baseline_semantic[:split])}

    def labels_check():
        mutated = [{**e, "label": i % 2,
                    "label_available_time": origin + (0 if i % 2 else 365 * 86400)}
                   for i, e in enumerate(events)]
        state, rows = replay(mutated)
        ensure([semantic(r) for r in rows] == baseline_semantic, "label metadata altered semantic decisions")
        ensure(state.to_dict() == baseline_state.to_dict(), "labels changed detector state")
        ensure(all(r["label_used"] is False for r in rows), "fixed detector used labels")
        return {"mutated_label_metadata_rows": len(rows), "adaptation_tested": False}

    def duplicates_check():
        state = ReplayState(config)
        originals, duplicated = [], []
        for i, e in enumerate(events):
            row = apply(state, e)
            originals.append(row)
            if i % 137 == 0 or row["notification_emitted"]:
                before = state.to_dict()
                duplicate = apply(state, e)
                duplicated.append(duplicate)
                ensure(duplicate["suppression_reason"] == "duplicate", "duplicate not diagnosed")
                ensure(duplicate["alert_id"] is None and not duplicate["notification_emitted"], "duplicate emitted")
                ensure(before == state.to_dict(), "duplicate consumed budget or altered state")
        ensure([semantic(r) for r in originals] == baseline_semantic, "duplicates changed subsequent decisions")
        ensure(state.to_dict() == baseline_state.to_dict(), "duplicate run final state differs")
        ensure(len(state.emitted_alert_ids) == len(set(state.emitted_alert_ids)), "repeated alert ID")
        return {"inserted_duplicate_deliveries": len(duplicated), "notifications": len(state.emitted_alert_ids)}

    def restart_check():
        state, rows = replay(events[:split])
        snapshot = json.loads(json.dumps(state.to_dict(), sort_keys=True, allow_nan=False))
        restored = ReplayState.from_dict(snapshot)
        rows.extend(apply(restored, e) for e in events[split:])
        ensure(rows == baseline, "restart differs even with identical deterministic clocks")
        ensure(restored.to_dict() == baseline_state.to_dict(), "restart final state differs")
        return {"checkpoint_after_events": split, "snapshot_sha256": digest_value(snapshot),
                "atomic_external_delivery_tested": False}

    def late_check():
        held = min(10, split - 1)
        initial = events[:held] + events[held + 1:split]
        state, rows = replay(initial)
        before_rows = digest_value(rows)
        before = state.to_dict()
        arrival = origin + events[split - 1]["event_time"] - first_time + .01
        row = apply(state, events[held], replay_time=arrival)
        ensure(row["suppression_reason"] == "late", "previously unseen older header not rejected as late")
        ensure(row["score"] is None and row["raw_trigger"] is None, "late header scored")
        ensure(not row["notification_emitted"] and row["alert_id"] is None, "late event notified")
        ensure(before_rows == digest_value(rows), "prior decisions rewritten")
        after = state.to_dict()
        for key in ("high_water_block", "high_water_event_time", "last_emitted_event_time",
                    "daily_counts", "emitted_alert_ids"):
            ensure(before[key] == after[key], f"late event changed {key}")
        ensure(len(after["seen"]) == len(before["seen"]) + 1, "late event not recorded as seen")
        return {"delayed_original_input_index": held, "delivered_after_original_index": split - 1,
                "prior_decision_digest_unchanged": True, "reorg_tested": False}

    def budgets_check():
        counts = Counter(r["budget_day_utc"] for r in baseline if r["notification_emitted"])
        ensure(all(v <= config.daily_budget for v in counts.values()), "daily emitted budget exceeded")
        ensure(dict(counts) == baseline_state.daily_counts, "state budget differs from journal")
        ensure(all(r["notifications_on_day"] <= config.daily_budget for r in baseline), "row budget counter exceeded")
        emitted = [r for r in baseline if r["notification_emitted"]]
        ensure(all(r["raw_trigger"] and r["group_candidate"] for r in emitted), "notification not admitted after grouping")
        ensure(len({r["alert_id"] for r in emitted}) == len(emitted), "nonunique emitted IDs")
        return {"notification_counts_by_playback_day": dict(counts), "limit": config.daily_budget,
                "raw_triggers": sum(r["raw_trigger"] is True for r in baseline)}

    def unknown_times_check():
        ensure(all(e.get("observed_time") is None for e in events), "source observation times not unknown")
        ensure(all(r["observed_time"] is None for r in baseline), "unknown historical arrival replaced")
        ensure(all(r["label_available_time"] is None for r in baseline), "unknown historical label time replaced")
        ensure(all(r["event_time"] == e["event_time"] for r, e in zip(baseline, events)), "historical event times rewritten")
        ensure(all(r["replay_available_time"] <= r["feature_ready_time"] <= r["decision_time"] for r in baseline), "replay clock ordering violated")
        return {"historical_observed_null_rows": len(baseline), "event_times_unchanged": True}

    check("prefix_invariance_under_future_counts_and_labels", prefix_check)
    check("label_metadata_has_no_effect_on_fixed_detector", labels_check)
    check("duplicate_delivery_no_repeated_notification_or_budget_consumption", duplicates_check)
    check("json_checkpoint_restart_exact_continuation", restart_check)
    check("held_back_real_header_late_drop_without_history_rewrite", late_check)
    check("hard_budget_and_unique_alert_ids", budgets_check)
    check("unknown_historical_observation_preserved", unknown_times_check)

    if args.run:
        def schema_check():
            import jsonschema
            report["environment"]["jsonschema_version"] = importlib.metadata.version("jsonschema")
            run_config = args.run / "config.json"
            captured_core = args.run / "source_snapshot/replay_core.py"
            captured_schema = args.run / "source_snapshot/decision.schema.json"
            ensure(digest_file(run_config) == digest_file(args.config), "run config differs from verified config")
            ensure(digest_file(captured_core) == digest_file(PAPER / "replay_core.py"), "run core differs from verified current core")
            schema = json.loads(captured_schema.read_text())
            jsonschema.Draft202012Validator.check_schema(schema)
            validator = jsonschema.Draft202012Validator(schema)
            files = sorted(args.run.glob("*/decisions.jsonl.gz"))
            ensure(bool(files), "no captured decision logs found")
            results = []
            matching_input = 0
            for path in files:
                summary = json.loads((path.parent / "summary.json").read_text())
                counts, ids = Counter(), set()
                n = 0
                with gzip.open(path, "rt") as handle:
                    for n, line in enumerate(handle, 1):
                        row = json.loads(line)
                        errors = list(validator.iter_errors(row))
                        ensure(not errors, f"{path.parent.name} row {n}: {errors[0].message if errors else ''}")
                        ensure(row["observed_time"] is None, "run replaced unknown historical arrival")
                        if row["notification_emitted"]:
                            counts[row["budget_day_utc"]] += 1
                            ensure(row["alert_id"] not in ids, "persisted duplicate alert_id")
                            ids.add(row["alert_id"])
                ensure(n == summary["events"], "persisted record count differs from summary")
                ensure(all(v <= config.daily_budget for v in counts.values()), "persisted log budget exceeded")
                if summary["input_sha256"] == report["input"]["sha256"]:
                    matching_input += 1
                results.append({"path": relative(path), "sha256": digest_file(path),
                                "validated_records": n, "notification_counts_by_day": dict(counts)})
            ensure(matching_input > 0, "run does not contain verified ordinary-day input")
            return {"run": relative(args.run), "schema_sha256": digest_file(captured_schema),
                    "matching_ordinary_input_cells": matching_input,
                    "total_validated_records": sum(f["validated_records"] for f in results), "logs": results}
        check("persisted_pilot_decision_schema_and_provenance", schema_check)
    else:
        report["persisted_run_validation"] = "not_requested"

    report["passed"] = all(t["passed"] for t in report["tests"])
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    report["runtime_seconds"] = time.perf_counter() - start
    target = out / "verification.json"
    target.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
    print(json.dumps({"passed": report["passed"], "tests": len(report["tests"]),
                      "events": len(events), "report": relative(target)}))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
