"""Build a concrete per-case root acceptance after all final source files exist.

No acquisition, scoring or scientific adjudication occurs here. The explicit
--confirm-before-payload flag is a recorded root assertion, not a clock proof.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys

PAPER = Path(__file__).resolve().parents[2]
REPO = PAPER.parents[1]
PROTOCOL = Path(__file__).resolve().parent
sys.path.insert(0, str(PAPER / "phase15" / "driver"))
import fixed_address_replay as driver


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def copied(source, destination):
    source = Path(source)
    if not source.is_file():
        raise ValueError("missing gate file: " + str(source))
    shutil.copyfile(source, destination)
    if sha(source) != sha(destination):
        raise ValueError("gate copy mismatch")
    return {"path": Path(destination).name, "sha256": sha(destination)}


def checked_relative_source(path):
    path = Path(path).resolve()
    relative = path.relative_to(REPO)
    if not path.is_file() or ".." in relative.parts:
        raise ValueError("execution source must be a real repository file")
    return {"path": str(relative), "sha256": sha(path)}


def prepare(*, case, source_plan, execution_sources, output, confirm_before_payload):
    if confirm_before_payload is not True:
        raise ValueError("root must assert acceptance precedes affected payload use")
    if case not in ("lifi", "revest"):
        raise ValueError("undeclared case")
    config_path = PROTOCOL / "configs" / (case + ".json")
    config = driver.validate_config(driver.frozen.strict_json(config_path.read_bytes()))
    frame_path = PAPER / "phase15" / "frame_dispositions.json"
    cohort_path = PAPER / "phase15" / "cohort_selection.json"
    frame = driver.frozen.strict_json(frame_path.read_bytes())
    cohort = driver.frozen.strict_json(cohort_path.read_bytes())
    if frame["status"] != "COMPLETE_BOUNDED_DISPOSITIONS_NOT_ALL_CASES_RESOLVED" or len(frame["rows"]) != 13:
        raise ValueError("all original frame dispositions are required")
    if cohort["selected_catalogue_lines"] != [65, 70]:
        raise ValueError("prospective cohort changed")
    core = driver.frozen.strict_json((PROTOCOL / "core_nominations.json").read_bytes())
    nomination = next(x for x in core["cases"] if x["case_id"] == config["case_id"])
    if nomination["population_addresses"] != config["population_addresses"] or nomination["window"] != config["window"]:
        raise ValueError("fixed nomination differs from config")
    if not execution_sources:
        raise ValueError("bind final collector and pipeline sources before acceptance")
    sources = [checked_relative_source(p) for p in execution_sources]
    if len({x["path"] for x in sources}) != len(sources):
        raise ValueError("duplicate execution source")
    source_plan = Path(source_plan)
    source_plan_value = driver.frozen.strict_json(source_plan.read_bytes())
    if not isinstance(source_plan_value, dict) or not source_plan_value:
        raise ValueError("source plan must be a concrete nonempty JSON object")
    # Validate every input before creating a new immutable acceptance directory.
    source_gates = {
        "frame_dispositions": frame_path,
        "cohort_selection": cohort_path,
        "core_nomination": PROTOCOL / "core_nominations.json",
        "label_join_protocol": PROTOCOL / "label_join_protocol.json",
        "denominators": PROTOCOL / "denominators.json",
    }
    for path in source_gates.values():
        driver.frozen.strict_json(path.read_bytes())
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    copied(config_path, output / "config.json")
    bindings = {name: copied(path, output / (name + ".json")) for name, path in source_gates.items()}
    copied(source_plan, output / "source_plan_original.json")
    copied(PROTOCOL / "measurement_protocol.json", output / "measurement_protocol.json")
    source_gate = {
        "schema_version": "article2_phase16_bound_source_execution_gate_v1",
        "status": "ROOT_ACCEPTED_AS_PART_OF_DECLARED_MEASUREMENT",
        "source_plan": {"path": "source_plan_original.json", "sha256": sha(source_plan)},
        "measurement_protocol": {"path": "measurement_protocol.json", "sha256": sha(PROTOCOL / "measurement_protocol.json")},
        "execution_source_bindings": sources,
        "source_plan_adjudication": "Root acceptance binds these exact files; this helper does not establish source completeness or technical sufficiency.",
        "before_payload_scope": "Includes restoration/reuse of prior raw archive tables newly consumed by the affected case workload, as well as new network acquisition.",
    }
    write(output / "source_plan.json", source_gate)
    bindings["source_plan"] = {"path": "source_plan.json", "sha256": sha(output / "source_plan.json")}
    acceptance = {
        "schema_version": "fixed_address_measurement_acceptance_v1",
        "status": "ACCEPTED_FOR_DECLARED_FIXED_ADDRESS_MEASUREMENT",
        "accepted_utc": datetime.now(timezone.utc).isoformat(),
        "accepted_before_affected_payload": True,
        "all_frame_dispositions_completed": True,
        "config_sha256": sha(output / "config.json"),
        "driver_sha256": sha(PAPER / "phase15" / "driver" / "fixed_address_replay.py"),
        "dependency_sha256": driver.DEPENDENCIES,
        "gate_bindings": bindings,
    }
    acceptance_path = output / "measurement_acceptance.json"
    write(acceptance_path, acceptance)
    driver.validate_freeze(acceptance_path, output / "config.json", expected_freeze_sha256=sha(acceptance_path))
    receipt = {"case_id": config["case_id"], "acceptance_file": "measurement_acceptance.json", "acceptance_sha256": sha(acceptance_path),
               "config_file": "config.json", "config_sha256": sha(output / "config.json"), "status": "EXACT_ROOT_ACCEPTANCE_BOUND_AND_DRIVER_VALIDATED"}
    write(output / "acceptance_receipt.json", receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=("lifi", "revest"), required=True)
    parser.add_argument("--source-plan", type=Path, required=True)
    parser.add_argument("--execution-source", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--confirm-before-payload", action="store_true")
    args = parser.parse_args()
    print(json.dumps(prepare(case=args.case, source_plan=args.source_plan, execution_sources=args.execution_source,
                             output=args.output, confirm_before_payload=args.confirm_before_payload)))


if __name__ == "__main__":
    main()
