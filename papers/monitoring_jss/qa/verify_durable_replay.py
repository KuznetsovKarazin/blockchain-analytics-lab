"""Read-only artifact verification, without importing the durable/replay implementation.

Written by the implementation author; independent reviewer execution/review is
recorded separately. Unclean databases are inspected only in disposable copies.
"""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile

PAPER = Path(__file__).resolve().parents[1]
ROOT = PAPER.parents[1]


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest_bytes(Path(path).read_bytes())


def digest_json(value):
    return digest_bytes(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())


def semantic(row):
    return {k:v for k,v in row.items() if k not in ("replay_available_time", "feature_ready_time", "decision_time", "observed_time", "label_available_time")}


def inspect_copy(folder):
    with tempfile.TemporaryDirectory(prefix="durable_verify_") as temp:
        target = Path(temp)
        for file in folder.iterdir():
            if file.is_file():
                shutil.copy2(file, target / file.name)
        local, sink = sqlite3.connect(target / "local.sqlite"), sqlite3.connect(target / "sink.sqlite")
        result = {
            "decisions": local.execute("SELECT seq,event_id,payload FROM decisions ORDER BY seq").fetchall(),
            "checkpoint": local.execute("SELECT cursor,state FROM checkpoint").fetchone(),
            "outbox": local.execute("SELECT alert_id,seq,payload,acknowledged FROM outbox ORDER BY seq").fetchall(),
            "effects": sink.execute("SELECT alert_id,payload FROM effects ORDER BY alert_id").fetchall(),
            "attempts": sink.execute("SELECT attempt,alert_id,inserted FROM attempts ORDER BY attempt").fetchall(),
            "integrity": [local.execute("PRAGMA integrity_check").fetchone()[0], sink.execute("PRAGMA integrity_check").fetchone()[0]],
        }
        local.close(); sink.close()
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, default=PAPER / "runs/durable_20261025T092104_711695Z")
    parser.add_argument("--output", type=Path, default=PAPER / "qa/durable_verification.json")
    args = parser.parse_args()
    args.run = args.run.resolve()
    manifest = json.loads((args.run / "manifest.json").read_text())
    result = json.loads((args.run / "pilot_summary.json").read_text())
    reference = json.loads((PAPER / "runs/event_logs_20261025T084327_927529Z/day_x1_r1/summary.json").read_text())
    private_root = ROOT / manifest["private_path"]
    inputs = [json.loads(line) for line in (ROOT / manifest["input_path"]).read_text().splitlines()]
    common_checks = {
        "input_sha256": sha(ROOT / manifest["input_path"]) == manifest["input_sha256"],
        "source_hashes": all(sha(args.run / "source_snapshot" / name) == h for name,h in manifest["source_hashes"].items()),
        "fifteen_cells": len(result["cells"]) == 15,
        "first_cell_uninterrupted": result["cells"][0]["fault"] is None,
    }
    cells = []
    for row in result["cells"]:
        name, private = row["cell"], private_root / row["cell"]
        hashes = row["private_file_hashes"]
        checks = {"private_file_hashes": all(sha(private / f) == h for f,h in hashes.items())}
        data = inspect_copy(private)
        decisions = [json.loads(d[2]) for d in data["decisions"]]
        gzip_path = args.run / name / "decisions.jsonl.gz"
        with gzip.open(gzip_path, "rt") as f:
            exported = [json.loads(line) for line in f]
        effects = [dict(alert_id=e[0], payload_sha256=digest_bytes(e[1].encode())) for e in data["effects"]]
        emitted = [d for d in decisions if d["notification_emitted"]]
        first_emitted = next(i for i,d in enumerate(decisions) if d["notification_emitted"])
        checks.update({
            "sqlite_integrity": set(data["integrity"]) == {"ok"},
            "gzip_sha256_crc_eof_and_rows": sha(gzip_path) == row["file_hashes"]["decisions.jsonl.gz"] and exported == decisions,
            "input_length_and_contiguous_sequence": len(decisions) == len(inputs) == row["decision_count"] and [d[0] for d in data["decisions"]] == list(range(len(inputs))),
            "event_identity_matches_decision": all(event_id == json.loads(payload)["event_id"] for _,event_id,payload in data["decisions"]),
            "input_order_and_timestamp_preserved": all(d["transaction_hash"] == i["transaction_hash"] and d["log_index"] == i["log_index"] and d["event_time_ns"] == i["event_time_ns"] for d,i in zip(decisions, inputs)),
            "decisions_hash": digest_json(decisions) == row["decisions_sha256"],
            "same_semantics_as_prior_independently_audited_pilot": digest_json([semantic(d) for d in decisions]) == reference["semantic_decisions_sha256"] == row["semantic_decisions_sha256"],
            "checkpoint_hash_and_final_cursor": digest_bytes(data["checkpoint"][1].encode()) == row["state_sha256"] and data["checkpoint"][0] == len(inputs)-1,
            "sink_effect_hash": digest_json(effects) == row["sink_effects_sha256"],
            "sink_exactly_emitted_ids_and_payloads": {i:json.loads(p) for i,p in data["effects"]} == {d["alert_id"]:d for d in emitted},
            "outbox_exactly_emitted_and_acknowledged": {a:json.loads(p) for a,_,p,ack in data["outbox"] if ack == 1} == {d["alert_id"]:d for d in emitted} and all(r[3] == 1 for r in data["outbox"]),
            "attempt_count": len(data["attempts"]) == row["sink_delivery_attempts"],
            "logical_effect_count": sum(a[2] for a in data["attempts"]) == len(data["effects"]) == 5,
            "expected_duplicate_attempts": sum(a[2] == 0 for a in data["attempts"]) == (1 if row["fault"] == "after_sink_commit" else 0),
            "serialization_commit_counts": row["stage_distributions"]["state_serialization_seconds"]["n"] == row["stage_distributions"]["local_commit_seconds"]["n"] == row["events_processed_this_process"],
            "sqlite_settings_recorded": row["sqlite"]["journal_mode"] == "wal" and row["sqlite"]["synchronous"] == 2,
        })
        fault_observation = None
        if row["fault"]:
            saved = private / "unclean_snapshot"
            crash = inspect_copy(saved)
            expected = first_emitted + (0 if row["fault"] == "before_local_commit" else 1)
            actual = {"cursor": crash["checkpoint"][0], "decisions": len(crash["decisions"]), "outbox": len(crash["outbox"]),
                      "pending": sum(not r[3] for r in crash["outbox"]), "sink_effects": len(crash["effects"]), "attempts": len(crash["attempts"])}
            fault_observation = actual
            checks.update({
                "unclean_bytes_match_pre_restart_capture": all(sha(saved / name) == h for name,h in row["post_crash_observation"]["unclean_file_sha256"].items()),
                "fault_at_first_notification": row["post_crash_observation"]["marker"]["seq"] == first_emitted,
                "crash_cursor_and_decisions": actual["cursor"] == expected-1 and actual["decisions"] == expected,
                "crash_outbox": actual["outbox"] == (0 if row["fault"] == "before_local_commit" else 1),
                "crash_pending": actual["pending"] == (1 if row["fault"] in ("after_local_commit", "after_sink_commit") else 0),
                "crash_sink_and_attempts": actual["sink_effects"] == actual["attempts"] == (1 if row["fault"] in ("after_sink_commit", "after_ack") else 0),
                "unclean_original_not_pre_recovered": row["post_crash_observation"]["original_unclean_files_unchanged_before_restart"],
                "restart_cursor_matches_crash": row["resumed_cursor"] == actual["cursor"],
            })
        cells.append({"cell":name, "checks":checks, "all_checks_pass":all(checks.values()), "fault_snapshot":fault_observation})
    report = {"schema_version":"durable_artifact_verification_v1", "verified_utc":datetime.now(timezone.utc).isoformat(),
              "verifier_role":"implementation-author artifact verification; no production-code import; independent review may run this verifier and inspect its logic",
              "run":str(args.run.relative_to(ROOT)), "common_checks":common_checks, "cells":cells,
              "all_checks_pass":all(common_checks.values()) and all(c["all_checks_pass"] for c in cells),
              "cells_checked":len(cells), "crash_snapshots_checked":sum(c["fault_snapshot"] is not None for c in cells),
              "limits":["fifteen local cells; one selected emission position", "os._exit bypasses cleanup but does not simulate power loss", "unique logical sink effects require the tested idempotent sink contract", "restoration timer includes input hashing, DB open/integrity/restore; completion timer additionally processes the remaining input", "diagnostic crash snapshots are excluded from final database storage figures"]}
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({"all_checks_pass":report["all_checks_pass"],"cells":len(cells),"output":str(args.output)}))
    if not report["all_checks_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
