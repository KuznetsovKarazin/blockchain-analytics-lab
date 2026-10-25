"""Offline, text-only Revest exposure audit. Never executes Solidity or an exploit.

Obtain the exact private source fixtures named in SOURCE_SPECS from the pinned
URLs before running. Third-party source files are not distributed with this script.
Example:
 python audit_revest_metadata.py --source-root /path/to/private/fixtures \
   --repo-root /path/to/blockchain-analytics-lab --output /new/audit.json
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as dt
import hashlib
import importlib.util
import json
import platform
import re
import sys
from pathlib import Path

DEFI_PIN = "23c7bd83ccb4524972a9493617fcc8764ab6269b"
CURRENT_PIN = "77bf3d8a3aed1bf394fd850903e7fd59ad129187"
OLD_PIN = "2c2c7723cb9fa42ff46fb6f252652056a74f9223"
POC = "src/test/2022-03/Revest_exp.sol"
DAY = "2022-03-27"
SOURCE_SPECS = {
    "main_defi_loader.py": {
        "repository": "KuznetsovKarazin/blockchain-detector-eval", "ref": CURRENT_PIN,
        "repository_path": "src/bal/data/defi.py",
        "git_blob_sha": "6972ae660e24f787c2f779fd4cfd0083a1a7d25c",
        "sha256": "52931e09a7f985b68a22d9a67bc0112693c6e45f359d0929fd43918c8fa1b7c6",
    },
    "old_defi_loader.py": {
        "repository": "KuznetsovKarazin/blockchain-detector-eval", "ref": OLD_PIN,
        "repository_path": "src/bal/data/defi.py",
        "git_blob_sha": "b7a257e0c273d8eefa8649b73367f4cde6bb7613",
        "sha256": "fa4e0674745a07fd38d5d7bfd7d5164516480cb665d7cb1409d783e120015042",
    },
    "DeFiHackLabs/README.md": {
        "repository": "SunWeb3Sec/DeFiHackLabs", "ref": DEFI_PIN,
        "repository_path": "README.md",
        "git_blob_sha": "260f213c3399a7555614f3bafa698e5b7d60c095",
        "sha256": "6e904fcc02a8c571f4fdcd4825a018c5ccc75e7731ad24e7c9185bebbee2fa1e",
    },
    "DeFiHackLabs/past/2022/README.md": {
        "repository": "SunWeb3Sec/DeFiHackLabs", "ref": DEFI_PIN,
        "repository_path": "past/2022/README.md",
        "git_blob_sha": "0a4a65c2b249ce5c7f454a1a199fa9ce63751b30",
        "sha256": "e7668ddd37e305db9052d4f208bb3b87d1e75956950739d5e9f1fd66f4c26267",
    },
    "DeFiHackLabs/" + POC: {
        "repository": "SunWeb3Sec/DeFiHackLabs", "ref": DEFI_PIN,
        "repository_path": POC,
        "git_blob_sha": "97fefc5a3d06a9453f12182f74e4a36b6a2570f7",
        "sha256": "46b9e755db3871c6cbf2e2bbcaf4c47ac9170ccbc6ffc52dc548379195e141ea",
    },
}
REPO_SPECS = {
    "results/security/s2_v1/incidents.csv":
        "6f129aec0e9f31d930e374625992600d4cb25ce5892968c8698ae1b2642ccf8e",
    "papers/monitoring_jss/incidents/exposure_audit_20261025.json":
        "3942ff01b628a532a8ace13ada726bca7f4a0d97f09dfa3d6ea7cca5c26c9f00",
}


def digests(path: Path) -> dict:
    data = path.read_bytes()
    return {
        "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "git_blob_sha": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
    }


def load_exact_metadata_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # required by the unchanged dataclass definition
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    root = args.source_root.resolve()
    fixture = root / "DeFiHackLabs"
    source_provenance = []
    for name, spec in SOURCE_SPECS.items():
        actual = digests(root / name)
        assert actual["sha256"] == spec["sha256"], name
        assert actual["git_blob_sha"] == spec["git_blob_sha"], name
        source_provenance.append({"fixture_path": name, **spec, **actual,
            "url": f"https://github.com/{spec['repository']}/blob/{spec['ref']}/{spec['repository_path']}"})
    # A targeted fixture must contain only this one PoC and the declared READMEs.
    assert sorted(str(p.relative_to(fixture)) for p in fixture.rglob("*.sol")) == [POC]
    assert sorted(str(p.relative_to(fixture)) for p in fixture.rglob("README.md")) == ["README.md", "past/2022/README.md"]
    repo_provenance = []
    for name, expected in REPO_SPECS.items():
        actual = digests(args.repo_root / name)
        assert actual["sha256"] == expected, name
        repo_provenance.append({"path": name, **actual})
    # Fail closed if imported loader code or invoked metadata functions try to
    # spawn a process or use a network connection. No Foundry/Solidity invocation.
    forbidden = {"socket.connect", "socket.bind", "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}
    denied_attempts = []
    def audit_hook(event, arguments):
        if event in forbidden:
            denied_attempts.append(event)
            raise RuntimeError("Forbidden side effect during text-only metadata audit: " + event)
    sys.addaudithook(audit_hook)
    sys.dont_write_bytecode = True
    solidity = (fixture / POC).read_text()
    rows = []
    for label, path in [("current", "main_defi_loader.py"), ("old", "old_defi_loader.py")]:
        loader = load_exact_metadata_module(root / path, "revest_metadata_" + label)
        heading, readme_txs = loader._headings(fixture)[POC]
        fork = re.search(r'createSelectFork\(\s*"([^"]+)"\s*(?:,\s*([0-9_]+))?', solidity)
        gates = {
            "mainnet_fork_found": bool(fork and fork.group(1) == "mainnet"),
            "fork_block_metadata": int(fork.group(2).replace("_", "")) if fork and fork.group(2) else None,
            "literal_flash_substring_in_solidity": bool(re.search("flash", solidity, re.I)),
            "price_keyword_in_heading": bool(re.search(loader.PRICE_WORDS, heading.lower())),
            "source_tx_link_count": len(loader._txs(solidity)),
            "readme_tx_link_count": len(readme_txs),
        }
        for price_only in [True, False]:
            result = [dataclasses.asdict(row) for row in loader.load_incidents(fixture, price_only=price_only)]
            assert result == [], (label, price_only, result)
            rows.append({"loader": label, "price_only": price_only, "heading": heading,
                "incidents": result, "gates": gates,
                "raw_metadata_transaction_links": sorted(loader._txs(solidity) | readme_txs),
                "link_semantics": "Catalogue links only, not independently adjudicated complete positive labels.",
                "first_failing_gate": "literal_flash_substring_in_solidity"})
    s2 = []
    with (args.repo_root / "results/security/s2_v1/incidents.csv").open() as handle:
        for line, row in enumerate(csv.DictReader(handle), 2):
            if row["name"] == "Revest Finance" and row["date"] == DAY:
                s2.append({"csv_line": line, "row": row})
    assert len(s2) == 1
    historical = json.loads((args.repo_root / "papers/monitoring_jss/incidents/exposure_audit_20261025.json").read_text())
    overlap = []
    for run in historical["scope"]["detector"]["k4_run_inventory"]:
        overlap.append({"path": run["path"], "hosting_ref": run["hosting_ref"],
            "execution_commit": run["execution_commit"], "days_checked": len(run["days"]),
            "attack_day_listed": DAY in run["days"],
            "evidence_scope": "Previously audited manifest date inventory; no feature rows or outcomes inspected here."})
    assert len(overlap) == 3 and not any(r["attack_day_listed"] for r in overlap)
    result = {
        "schema_version": "revest_targeted_metadata_exposure_audit_v1",
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "PASS", "script_sha256": digests(Path(__file__))["sha256"],
        "python": platform.python_version(), "source_provenance": source_provenance,
        "repo_provenance": repo_provenance, "fixture_scope": "One pinned Revest PoC as inert text; original root and 2022 READMEs; exact current and old Python metadata loaders.",
        "loader_calls": rows, "s2_registry_matches": s2, "k4_manifest_date_overlap": overlap,
        "conclusion": {
            "confirmed_historical_exposure": "L1_catalogue",
            "L2_from_these_two_loader_paths": "not established; targeted fixture omitted by both modes of both exact loaders",
            "price_only_positive_cohort_selected": False,
            "all_mainnet_exclusion_loader_selected": False,
            "actual_attack_row_training_or_evaluation_exposure": "not found in listed dates; global absence not established",
            "independent_holdout_admitted": False,
            "current_study_exposure": "Case metadata and public postmortem inspected; no new incident payload or detector result inspected.",
        },
        "execution": {"solidity_compiled": False, "solidity_or_exploit_executed": False,
            "new_chain_payload_acquired": False, "detector_scores_or_outcomes_obtained": False,
            "network_or_process_attempts_during_audit": denied_attempts},
        "limitations": [
            "Targeted source fixture is not a complete rerun of the whole incident catalogue.",
            "Exclusion-loader omission does not prove any actual mislabeled Revest transaction entered K4 background rows.",
            "All binary background rows, all branches, private drafts, deleted work and personal prior knowledge are outside scope.",
            "An upstream PoC fork block or hardcoded contract address is metadata, not verified deployment/population evidence.",
            "The README transaction link is not a complete or adjudicated positive set.",
            "The missing literal flash gate is reported unchanged; this audit does not change K4 or book results.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"status": result["status"], "output": str(args.output),
        "loader_calls": len(rows), "confirmed_historical_exposure": "L1_catalogue",
        "both_loader_modes_omit_candidate": True, "no_exploit_execution": True}))


if __name__ == "__main__":
    main()
