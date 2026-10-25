"""Technical retry wrapper: identical policy bytes, isolated staging, sealed evidence.

This wrapper does not alter any policy, parameter, source input, or failed-run
record. The only addition to the failed directory is quarantine.json. Executed
outputs are closed and verified in /tmp, then sealed before export to workspace.
Atomic publication is a preservation precaution; it does not identify or prove
the cause of the first run's later gzip truncations.
"""
from __future__ import annotations

from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile

PAPER = Path(__file__).resolve().parent
ROOT = PAPER.parents[1]
FAILED_ID = "budget_policy_20261025T124444_450736Z"
INPUT_MANIFEST = PAPER / "runs/protocol_window_20261025T123312_675327Z/manifest.json"
CONFIG = PAPER / "budget_policy_study_config.json"
JOIN_FREEZE = PAPER / "runs/budget_policy_label_join_design_20261025T124034_554024Z/join_freeze.json"
EXPECTED = {
    PAPER / "budget_policy_replay.py": "549450dfc7db970ee039f17ef2c86d7a75820acc5b7128c46e340d1ebaf31726",
    PAPER / "event_log_replay.py": "a5e414d052b7b340175575209ba94c58952ba440913268ca2effd192e5208ac2",
    PAPER / "tests/test_budget_policy_replay.py": "984f87d3630f66b288016d8c01b36331bcf43f806915d6d92c3df42613f168c0",
    CONFIG: "7b83aaa220f5527f58faf801fbc3977c657ef9f6a427d7523136694e0a41ea0d",
    INPUT_MANIFEST: "7505e42dec974609355d388313e7b446354f8c78a57421245e52b8107787431b",
    JOIN_FREEZE: "7562d0958d4e840c457c50a947bde7be8398aa345995b1694a2b0fd6ea7eb9ab",
    PAPER / "qa/phase4_common_window_feasibility_20261025T122103_763107Z/common_window_inventory.json":
        "6135153b5496370a82374edb4f41d39d8b79086fb0db8d6d73332da5d015bacb",
    PAPER / "incidents/labels/beanstalk_20220417_labels.json":
        "3518e1c753a3f0ba31b6977ab5b4f3811c5a3846569e1e930922af9084115046",
}


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def dump(value, path):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def verify_zip(path, expected):
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) != len(expected) or {i.filename for i in infos} != set(expected):
            raise ValueError("sealed archive member set mismatch")
        for info in infos:
            h, n = hashlib.sha256(), 0
            with archive.open(info) as member:
                for chunk in iter(lambda: member.read(1024 * 1024), b""):
                    h.update(chunk)
                    n += len(chunk)
            # Reading every member through EOF verifies the ZIP CRC as well.
            if h.hexdigest() != expected[info.filename]["sha256"] or n != expected[info.filename]["bytes"]:
                raise ValueError("sealed member SHA-256/size mismatch")
    return {"members": len(expected), "all_member_sha256_size_crc_match": True}


def make_zip(directory, path):
    files = sorted(p for p in directory.rglob("*") if p.is_file())
    expected = {str(p.relative_to(directory)): {"sha256": sha(p), "bytes": p.stat().st_size} for p in files}
    # Decision and state payloads are already gzip-compressed. ZIP_STORED avoids
    # any transformation of their observed bytes and permits quick verification.
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_STORED) as archive:
        for source in files:
            archive.write(source, str(source.relative_to(directory)))
    with path.open("rb") as handle:
        os.fsync(handle.fileno())
    verify_zip(path, expected)
    if any(sha(directory / name) != item["sha256"] for name, item in expected.items()):
        raise ValueError("source output changed during sealing")
    return expected


def publish_archive(source, destination, expected):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(destination)
    checksum = sha(source)
    fd, temporary = tempfile.mkstemp(prefix=".sealed-copy-", suffix=".part", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as target, source.open("rb") as original:
            shutil.copyfileobj(original, target, length=1024 * 1024)
            target.flush()
            os.fsync(target.fileno())
        if sha(temporary) != checksum:
            raise ValueError("sealed archive copy differs")
        os.replace(temporary, destination)
        directory_fd = os.open(destination.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        if sha(destination) != checksum:
            raise ValueError("published sealed archive differs")
        verify_zip(destination, expected)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return {"path": str(destination), "sha256": checksum, "bytes": destination.stat().st_size,
            **verify_zip(destination, expected)}


def export_from_seal(archive_path, destination, expected):
    destination.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(archive_path) as archive:
        for name in expected:
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("unsafe seal member")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=".export-", suffix=".part", dir=target.parent)
            try:
                with os.fdopen(fd, "wb") as sink, archive.open(name) as source:
                    shutil.copyfileobj(source, sink, length=1024 * 1024)
                    sink.flush()
                    os.fsync(sink.fileno())
                if sha(temporary) != expected[name]["sha256"]:
                    raise ValueError("export differs from sealed bytes")
                os.replace(temporary, target)
            finally:
                Path(temporary).unlink(missing_ok=True)
    if any(sha(destination / name) != item["sha256"] for name, item in expected.items()):
        raise ValueError("exported file changed after atomic publication")


def main():
    start = datetime.now(timezone.utc)
    run_id = "budget_policy_" + start.strftime("%Y%m%dT%H%M%S_%fZ")
    for path, expected in EXPECTED.items():
        if sha(path) != expected:
            raise ValueError(f"approved source/provenance changed: {path}")
    if shutil.disk_usage(ROOT).free < 500_000_000:
        raise ValueError("less than required 500 MB free disk")
    runtime = Path(tempfile.mkdtemp(prefix="budget-policy-sealed-"))
    stage_paper = runtime / "papers/monitoring_jss"
    stage_paper.mkdir(parents=True)
    (runtime / "data").symlink_to(ROOT / "data", target_is_directory=True)
    for relative in ("budget_policy_replay.py", "event_log_replay.py", "tests/test_budget_policy_replay.py"):
        target = stage_paper / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(PAPER / relative, target)
        if sha(target) != EXPECTED[PAPER / relative]:
            raise ValueError("staged source mismatch")
    config = json.loads(CONFIG.read_text())
    for relative in (config["acquisition"]["inventory"], config["labels_separate"]["label_manifest"]):
        source, target = PAPER / relative, stage_paper / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if sha(source) != sha(target):
            raise ValueError("opaque provenance copy mismatch")

    failed = PAPER / "runs" / FAILED_ID
    failed_summary = json.loads((failed / "study_summary.json").read_text())
    mismatches = []
    for cell in failed_summary["cells"]:
        for name, expected in cell["artifacts"].items():
            path = failed / "cells" / cell["cell_id"] / name
            if sha(path) != expected:
                item = {"path": str(path.relative_to(failed)), "recorded_sha256": expected,
                        "observed_sha256": sha(path), "observed_bytes": path.stat().st_size}
                try:
                    with gzip.open(path, "rb") as handle:
                        for _ in iter(lambda: handle.read(1024 * 1024), b""):
                            pass
                except Exception as error:
                    item["gzip_error"] = repr(error)
                mismatches.append(item)
    if len(mismatches) != 5:
        raise ValueError("failed run changed since authorized five-file diagnosis")
    quarantine = {"status": "quarantined_not_accepted", "reason": "five gzip decision artifacts changed after recorded hashes; cause unknown",
                  "quarantined_at_utc": datetime.now(timezone.utc).isoformat(), "mismatches": mismatches,
                  "records_repaired": False, "replacement_run_id": run_id}
    if (failed / "quarantine.json").exists():
        raise FileExistsError("failed-run quarantine already exists")
    dump(quarantine, failed / "quarantine.json")
    failed_zip = runtime / "failed_observed.zip"
    failed_members = make_zip(failed, failed_zip)
    archive_root = ROOT / "data/raw/monitoring_jss/budget"
    failed_archive = publish_archive(failed_zip, archive_root / f"{FAILED_ID}_failed_observed.zip", failed_members)

    command = [sys.executable, str(stage_paper / "budget_policy_replay.py"), "--config", str(CONFIG),
               "--input-manifest", str(INPUT_MANIFEST), "--run-id", run_id]
    print(json.dumps({"stage": "retry_started", "run_id": run_id, "runtime": str(runtime)}), flush=True)
    subprocess.run(command, cwd=runtime, check=True)
    out = stage_paper / "runs" / run_id
    manifest, summary = json.loads((out / "run_manifest.json").read_text()), json.loads((out / "study_summary.json").read_text())
    if manifest["status"] != "complete" or summary["status"] != "complete" or not manifest["frozen_sources_config_inputs_unchanged"]:
        raise ValueError("staged replay did not complete verification")
    for path, expected in EXPECTED.items():
        if sha(path) != expected:
            raise ValueError("original approved source/provenance changed during retry")
    shutil.copyfile(Path(__file__), out / "provenance/seal_budget_policy_retry.py")
    shutil.copyfile(JOIN_FREEZE, out / "provenance/join_freeze.json")
    execution = {"schema_version": "budget_policy_sealed_retry_v1", "run_id": run_id,
                 "reason": "technical artifact-preservation retry; unchanged approved computation",
                 "failed_run_id": FAILED_ID, "failed_observed_archive": failed_archive,
                 "started_at_utc": start.isoformat(), "sealed_at_utc": datetime.now(timezone.utc).isoformat(),
                 "command": command, "wrapper_command": [sys.executable, *sys.argv], "wrapper_sha256": sha(__file__),
                 "source_hashes": {str(p): h for p, h in EXPECTED.items()},
                 "path_resolution": {"runtime_root": str(runtime), "staged_paper": str(stage_paper),
                                     "data_symlink": str(runtime / "data"), "data_realpath": str((runtime / "data").resolve()),
                                     "original_root": str(ROOT), "config_realpath": str(CONFIG.resolve()),
                                     "input_manifest_realpath": str(INPUT_MANIFEST.resolve())},
                 "environment": {"python": sys.version, "platform": platform.platform()},
                 "policy_or_parameter_changes": False, "labels_joined": False,
                 "preservation_scope": "Closed outputs sealed before workspace export; cause of prior corruption remains unknown"}
    dump(execution, out / "sealed_execution.json")
    inventory = {str(p.relative_to(out)): {"sha256": sha(p), "bytes": p.stat().st_size}
                 for p in sorted(out.rglob("*")) if p.is_file()}
    dump({"schema_version": "sealed_member_manifest_v1", "members": inventory,
          "self_exclusion": "this inventory excludes itself; outer publication record hashes complete ZIP"}, out / "sealed_member_manifest.json")
    sealed_zip = runtime / f"{run_id}_sealed_evidence.zip"
    members = make_zip(out, sealed_zip)
    publication = publish_archive(sealed_zip, archive_root / sealed_zip.name, members)
    exported = PAPER / "runs" / run_id
    export_from_seal(Path(publication["path"]), exported, members)
    publication.update({"run_id": run_id, "exported_run": str(exported), "status": "sealed_verified_and_exported",
                        "study_summary_sha256": sha(out / "study_summary.json"), "wrapper_sha256": sha(__file__)})
    dump(publication, archive_root / f"{run_id}_sealed_publication.json")
    # Final archive verification occurs after export too; independent audits use
    # this archive directly, rather than treating mutable exported copies as canonical.
    verify_zip(Path(publication["path"]), members)
    print(json.dumps(publication, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
