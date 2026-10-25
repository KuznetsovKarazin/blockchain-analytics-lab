"""Extend the original read-only durable audit with sealed-copy/archive checks."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("durable_original_auditor", HERE / "durable_independent_review.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def review(run_id):
    report = audit.review(run_id)
    run = audit.PAPER / "runs" / run_id
    manifest, pilot = audit.read(run / "manifest.json"), audit.read(run / "pilot_summary.json")
    private = audit.ROOT / manifest["private_path"]
    before = audit.inventory(private)
    checks, cells = {}, []
    checks["original_audit_passed"] = report["passed"]
    checks["recorded_runtime_location"] = bool(manifest.get("runtime_path")) and isinstance(manifest.get("runtime_device_id"), int) and manifest.get("runtime_filesystem_fragment_bytes", 0) > 0
    for cell in pilot["cells"]:
        name = cell["cell"]
        directory = private / name
        operational, error1 = audit.observe_safely(directory)
        sealed, error2 = audit.observe_safely(directory / "sealed")
        handoff = cell["final_database_handoff"]
        local_checks = {
            "operational_and_sealed_readable": error1 is None and error2 is None,
            "operational_and_sealed_logical_state_identical": operational is not None and operational == sealed,
            "no_final_sidecars": not list(directory.glob("*.sqlite-*")) and not list((directory / "sealed").glob("*.sqlite-*")),
            "recorded_child_return_codes": cell["initial_returncode"] == (73 if cell["fault"] else 0) and cell["resume_returncode"] == (0 if cell["fault"] else None),
            "checkpoint_and_journal_handoff": all(handoff[n]["checkpoint_truncate_result"] == [0, 0, 0] and handoff[n]["final_journal_mode"] == "delete" and handoff[n]["sealed_integrity"] == "ok" for n in ("local.sqlite", "sink.sqlite")),
            "sealed_sha_and_size": all(audit.sha(directory / "sealed" / n) == handoff[n]["sealed_sha256"] and (directory / "sealed" / n).stat().st_size == handoff[n]["sealed_bytes"] for n in ("local.sqlite", "sink.sqlite")),
            "standalone_sqlite_headers": all((directory / sub / n).read_bytes()[18:20] == b"\x01\x01" for sub in ("", "sealed") for n in ("local.sqlite", "sink.sqlite")),
            "handoff_time_separate_nonnegative": cell["final_database_handoff_seconds"] >= 0,
        }
        cells.append({"cell": name, "passed": all(local_checks.values()), "checks": local_checks,
                      "errors": [error for error in (error1, error2) if error is not None]})
    receipt = audit.read(run / "archive_receipt.json")
    path = audit.ROOT / receipt["path"]
    checks["archive_sha_and_size"] = audit.sha(path) == receipt["sha256"] and path.stat().st_size == receipt["bytes"]
    with zipfile.ZipFile(path) as archive:
        archive_manifest = json.loads(archive.read("ARCHIVE_MANIFEST.json"))
        records = archive_manifest["files"]
        checks["archive_crc"] = archive.testzip() is None
        checks["archive_expected_member_names"] = set(archive.namelist()) == {r["path"] for r in records} | {"ARCHIVE_MANIFEST.json"}
        checks["archive_record_count"] = len(records) == receipt["members_verified"]
        checks["every_archived_member_sha_and_size"] = all(len(archive.read(r["path"])) == r["bytes"] and hashlib.sha256(archive.read(r["path"])).hexdigest() == r["sha256"] for r in records)
        checks["every_archived_member_matches_current_source"] = all((audit.ROOT / r["path"]).stat().st_size == r["bytes"] and audit.sha(audit.ROOT / r["path"]) == r["sha256"] for r in records)
    checks["original_private_bytes_unchanged"] = before == audit.inventory(private)
    report["passed"] = all(checks.values()) and all(cell["passed"] for cell in cells)
    report["sealed_evidence_extension"] = {"verifier": str(Path(__file__).relative_to(audit.ROOT)), "verifier_sha256": audit.sha(__file__),
        "checks": checks, "cells": cells, "archive_receipt": receipt,
        "runtime_location": {k: v for k, v in manifest.items() if k.startswith("runtime_")},
        "interpretation": "New run uses explicit checkpoint/DELETE handoff, sealed backup and temporary runtime storage. It passes these artifact checks, but does not identify the original failure cause or establish general exactly-once delivery."}
    report["limitations"] = [s for s in report["limitations"] if not s.startswith("Markers plus")]
    report["limitations"].append("Parent summaries now explicitly record observed subprocess return codes: twelve73fault exits and twelve0resumes. They remain experiment records, not an independent OS trace.")
    for item in report["measurement_review"]:
        item["location"] = "source_snapshot/durable_replay.py::" + ("main" if "Parent initial" in item["finding"] else "worker/drain")
    report["measurement_review"].append({"location": "source_snapshot/durable_replay.py::finish_databases/main", "finding": "Persistence timings use the recorded temporary runtime directory. Successful-end sealing and workspace evidence copying are additional stages; this is a changed storage/handoff protocol, not a controlled timing comparison against the quarantined run."})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = review(args.run)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
    print(json.dumps({"passed": report["passed"], "output": str(args.output), "global": report["sealed_evidence_extension"]["checks"]}))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
