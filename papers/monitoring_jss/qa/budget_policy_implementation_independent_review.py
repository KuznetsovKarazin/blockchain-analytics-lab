"""Synthetic independent oracle checks; never reads or replays real study payloads."""
import argparse
from bisect import bisect_right
from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import sys
import tempfile

PAPER = Path(__file__).resolve().parents[1]
SOURCE = PAPER / "budget_policy_replay.py"
T = 86400 * 10**9
START = 1647648000000000000
END = START + 30*T
ADDRESS = "0x27182842e098f60e3d576794a5bffb0777e025d3"


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def event(number, timestamp, *, key=None, nonce=0):
    block = number if key is None else key
    return {"chain_id": 1, "address": ADDRESS, "block_number": block, "transaction_index": 0,
            "log_index": 0, "block_hash": f"0x{block+nonce:064x}",
            "transaction_hash": f"0x{number+nonce:064x}", "event_time_ns": timestamp,
            "topics": ["0x"+"00"*32], "data": "0x", "removed": None,
            "observed_time": None, "label_available_time": None}


def event_id(e):
    return "event:" + digest([e["chain_id"], e["block_hash"], e["transaction_hash"], e["log_index"]])


def day(t):
    return datetime.fromtimestamp(t//10**9, timezone.utc).date().isoformat()


class Oracle:
    """Independent list/bisection counts and elapsed-since-emission bucket math."""
    def __init__(self, policy, budget):
        self.policy, self.budget = policy, budget
        self.timestamps, self.seen, self.order_keys = [], {}, {}
        self.watermark, self.last_emitted, self.clock = None, None, START
        self.counts = defaultdict(int)
        self.ids = []

    def process(self, e):
        eid, timestamp = event_id(e), e["event_time_ns"]
        key = (e["block_number"], e["transaction_index"], e["log_index"])
        payload = {k: e[k] for k in ("chain_id", "address", "block_number", "block_hash", "transaction_index", "transaction_hash", "log_index", "event_time_ns", "topics", "data", "removed")}
        accepted, reason = False, None
        if eid in self.seen:
            assert self.seen[eid] == payload
            reason = "duplicate"
        elif self.watermark is not None and key < self.watermark:
            assert key not in self.order_keys
            reason = "late"
        else:
            assert self.watermark is None or key > self.watermark
            assert timestamp >= self.clock
            accepted = True
        score = raw = None
        candidate = emitted = False
        if accepted:
            self.timestamps.append(timestamp)
            self.clock, self.watermark = timestamp, key
            score = len(self.timestamps) - bisect_right(self.timestamps, timestamp - 60*10**9)
            raw = score >= 10
            if not raw:
                reason = "below_threshold"
            elif self.last_emitted is not None and timestamp-self.last_emitted < 300*10**9:
                reason = "grouped"
            else:
                candidate = True
                used = self.counts[day(timestamp)]
                # Count release instants directly; no production floor formula.
                quota = sum(j*T <= self.budget*(timestamp % T) for j in range(self.budget))
                if used >= self.budget:
                    reason = "budget"
                elif self.policy == "paced_cumulative" and used >= quota:
                    reason = "quota"
                elif (self.policy == "token_bucket" and self.last_emitted is not None
                      and self.budget*(timestamp-self.last_emitted) < T):
                    reason = "token"
                else:
                    emitted = True
                    self.counts[day(timestamp)] += 1
                    self.last_emitted = timestamp
                    self.ids.append(eid)
        self.seen[eid], self.order_keys[key] = payload, eid
        quota = sum(j*T <= self.budget*(self.clock % T) for j in range(self.budget)) if self.policy == "paced_cumulative" else self.budget
        credit = None
        if self.policy == "token_bucket":
            credit = T if self.last_emitted is None else min(T, self.budget*(self.clock-self.last_emitted))
        return {"event_id": eid, "accepted": accepted, "score": score, "raw_trigger": raw,
                "group_candidate": candidate, "notification_emitted": emitted, "suppression_reason": reason,
                "policy_clock_ns": self.clock, "budget_day_utc": day(self.clock),
                "notifications_on_day": self.counts[day(self.clock)], "daily_quota": quota,
                "token_credit_units": credit, "notification_time_ns": timestamp if emitted else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_suffix(".json"))
    args = parser.parse_args()
    before_sha = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    spec = importlib.util.spec_from_file_location("independent_budget_target", SOURCE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    checks, compared, restores = [], 0, 0
    # Every day, release boundary +/-1ns, same-time bursts, and cross-midnight groups.
    times = {START, END-1}
    for offset in range(30):
        midnight = START + offset*T
        for budget in (1, 5, 20):
            for j in range(budget):
                boundary = midnight + j*T//budget
                for delta in (-1, 0, 1):
                    if START <= boundary+delta < END:
                        times.add(boundary+delta)
        for seconds in (299, 300, 301, 85800, 86399):
            times.add(midnight + seconds*10**9)
    boundary_events = []
    for timestamp in sorted(times):
        for _ in range(11):
            boundary_events.append(event(len(boundary_events)+10, timestamp))
    randomized = []
    for seed in range(5):
        rng = random.Random(seed)
        timestamps = sorted(rng.randrange(START, END) for _ in range(250))
        stream = []
        for timestamp in timestamps:
            for _ in range(rng.randrange(1, 18)):
                stream.append(event(len(stream)+10, timestamp))
        # Exact duplicate and a previously unseen late identity with a never-used key.
        stream.insert(len(stream)//2, deepcopy(stream[2]))
        stream.insert(len(stream)//2+1, event(1, START, key=1, nonce=1000000))
        randomized.append(stream)
    for policy in ("greedy", "paced_cumulative", "token_bucket"):
        for budget in (0, 1, 5, 20):
            for stream_name, stream in [("all_day_boundaries", boundary_events)] + [(f"random_seed_{s}", rows) for s, rows in enumerate(randomized)]:
                state = module.PolicyReplayState(module.BudgetConfig(policy, budget, START, END))
                oracle = Oracle(policy, budget)
                rows = []
                for index, e in enumerate(stream):
                    actual, expected = state.process(e), oracle.process(e)
                    assert {key: actual[key] for key in expected} == expected, (policy, budget, stream_name, index, actual, expected)
                    rows.append(actual)
                    compared += 1
                    if index and index % 503 == 0:
                        old = state.to_dict()
                        state = module.PolicyReplayState.from_dict(json.loads(json.dumps(old)))
                        assert json.loads(json.dumps(state.to_dict())) == json.loads(json.dumps(old)), "checkpoint state mismatch"
                        restores += 1
                assert all(n <= budget for n in state.daily_counts.values())
                if policy == "token_bucket" and budget:
                    emitted = [r["event_time_ns"] for r in rows if r["notification_emitted"]]
                    assert all(budget*(b-a) >= T for a, b in zip(emitted, emitted[1:]))
                if stream_name == "all_day_boundaries":
                    checks.append({"check": "exact_boundary_30day_oracle", "policy": policy, "budget": budget,
                                   "rows": len(rows), "notifications": len(state.alert_ids), "pass": True})
    # Explicit invalid-input tests require no partial state mutation.
    state = module.PolicyReplayState(module.BudgetConfig("token_bucket", 5, START, END))
    a, b = event(10, START+1000), event(20, START+2000)
    state.process(a)
    state.process(b)
    invalid = [dict(a, data="0x01"), event(10, START+1000, nonce=500),
               event(30, START+1999), event(30, END), dict(event(30, START+3000), address="0x"+"01"*20)]
    for bad in invalid:
        before = state.to_dict()
        try:
            state.process(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid/conflicting event accepted")
        assert state.to_dict() == before
    late = event(2, START, key=2, nonce=1000)
    assert state.process(late)["suppression_reason"] == "late"
    before = state.to_dict()
    try:
        state.process(event(2, START, key=2, nonce=2000))
    except ValueError:
        pass
    else:
        raise AssertionError("conflicting previously late order key accepted")
    assert state.to_dict() == before
    checks.append({"check": "invalid_input_atomicity_and_all_observed_key_conflicts", "cases": 6, "pass": True})
    # Prefix results cannot depend on future arrivals or new partition boundaries.
    prefix = boundary_events[:1100]
    for policy in ("greedy", "paced_cumulative", "token_bucket"):
        snapshots = []
        for suffix in ([], boundary_events[1100:2200], boundary_events[1100:]):
            state = module.PolicyReplayState(module.BudgetConfig(policy, 5, START, END))
            prefix_rows = [state.process(e) for e in prefix]
            snapshots.append((prefix_rows, state.to_dict()))
            for e in suffix:
                state.process(e)
        assert snapshots[0] == snapshots[1] == snapshots[2]
    checks.append({"check": "future_suffix_prefix_invariance", "policies": 3, "pass": True})
    # Real configuration structure, but empty temporary synthetic files only.
    config = json.loads((PAPER / "budget_policy_study_config.json").read_text())
    days = module.validate_study_config(config)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        empty = root / "empty.jsonl"
        empty.write_bytes(b"")
        item = {"status": "complete", "rows": 0, "path": str(empty), "sha256": hashlib.sha256(b"").hexdigest()}
        manifest = {"status": "complete", "populations": [{"population_id": e["id"], "chain_id": e["chain_id"], "address": e["address"],
                    "inputs": [{**item, "day_utc": date} for date in days]} for e in config["emitters"]]}
        module.validate_inputs(config, manifest, root)
        for status, complete in (("failed", True), ("running", True), ("complete", False)):
            bad = deepcopy(manifest)
            bad["populations"][0]["inputs"][0].update(status=status, complete=complete)
            try:
                module.validate_inputs(config, bad, root)
            except ValueError:
                pass
            else:
                raise AssertionError("contradictory incomplete day accepted")
        missing = deepcopy(manifest)
        missing["populations"][0]["inputs"].pop()
        try:
            module.validate_inputs(config, missing, root)
        except ValueError:
            pass
        else:
            raise AssertionError("missing day accepted as empty")
    checks.append({"check": "verified_empty_days_vs_missing_or_contradictory_completion", "cases": 5, "pass": True})
    after_sha = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    assert before_sha == after_sha, "source changed while auditing; rerun after freeze"
    report = {"schema_version": "budget_policy_implementation_independent_review_v1", "verdict": "PASS_SYNTHETIC_PRE_REAL_INPUT",
              "all_checks_pass": True, "source_sha256": before_sha,
              "review_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "config_sha256": hashlib.sha256((PAPER / "budget_policy_study_config.json").read_bytes()).hexdigest(),
              "oracle": "Independent prefix-list/bisection count, release-instant counting, and token eligibility from elapsed time since last emitted event; not the production deque/floor/refill recurrence.",
              "synthetic_decisions_compared": compared, "checkpoint_round_trips": restores,
              "random_seeds": list(range(5)), "budgets_tested": [0, 1, 5, 20], "checks": checks,
              "real_payloads_read": 0, "new_policy_outcomes_on_real_data": 0,
              "resolved_review_findings": ["All observed order-key conflicts now fail, including old accepted and previously late identities.", "Explicit failed/running acquisition status or complete=false cannot be overridden by another completion flag."],
              "limits": ["This verifies policy semantics and synthetic input gates; complete real-window archive/Parquet/source correctness requires the separate acquisition audit.", "Orderly checkpoint continuation is tested; arbitrary-crash delivery and cryptographic authenticity of user-supplied checkpoints are not claimed.", "The actual emitter population, source clock assumptions and label-informed window selection remain those of the separately approved design."]}
    args.output.write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({"file": str(args.output), "compared": compared, "restores": restores, "all_checks_pass": True}))


if __name__ == "__main__":
    main()
