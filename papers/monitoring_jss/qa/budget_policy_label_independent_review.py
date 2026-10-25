"""Independent descriptive label join from the immutable policy seal.

No production replay/evaluation imports, no refitting or policy selection.
"""
from pathlib import Path
from datetime import datetime, timezone
import collections
import gzip
import hashlib
import json
import zipfile

PAPER = Path(__file__).resolve().parents[1]
ROOT = PAPER.parents[1]
RUN = "budget_policy_20261025T125143_314640Z"
JOIN = "budget_policy_label_join_20261025T125414_524570Z"


def main():
    archive = ROOT / "data/raw/monitoring_jss/budget" / (RUN + "_sealed_evidence.zip")
    output = PAPER / "runs" / JOIN / "descriptive_label_evaluation.json"
    labels_path = PAPER / "runs/budget_policy_label_join_design_20261025T124034_554024Z/label_manifest.json"
    labels = json.loads(labels_path.read_text())
    positives = {r["tx_hash"].lower() for r in labels["exploit_transactions"]
                 if r["role"] == "exploit_execution" and r["positive_incident_label"] is True}
    assert len(positives) == 1
    reported = json.loads(output.read_text())
    manifest = json.loads((PAPER / "runs/protocol_window_20261025T123312_675327Z/manifest.json").read_text())
    population = next(p for p in manifest["populations"] if p["population_id"] == "beanstalk_diamond")
    identities = ("chain_id", "address", "block_number", "block_hash", "transaction_index",
                  "transaction_hash", "log_index", "event_time_ns")
    source_positive = []
    for entry in population["inputs"]:
        path = ROOT / entry["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"]
        with path.open() as stream:
            for line in stream:
                row = json.loads(line)
                if row["transaction_hash"] in positives:
                    source_positive.append({k: row[k] for k in identities})
    assert len(source_positive) == 6
    block = source_positive[0]["block_number"]
    assert block == 14602790 and all(r["block_number"] == block for r in source_positive)
    results = []
    with zipfile.ZipFile(archive) as seal:
        for cell in reported["cells"]:
            counts = collections.Counter()
            prior_by_day = collections.Counter()
            selected = []
            n = 0
            name = "cells/" + cell["cell_id"] + "/decisions.jsonl.gz"
            raw = seal.read(name)  # verifies outer ZIP CRC
            assert hashlib.sha256(raw).hexdigest() == cell["decisions_sha256"]
            import io
            with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as stream:
                for line in stream:
                    row = json.loads(line)
                    n += 1
                    if row["notification_emitted"] and row["block_number"] < block:
                        prior_by_day[row["budget_day_utc"]] += 1
                    if row["transaction_hash"] not in positives:
                        continue
                    selected.append({k: row[k] for k in identities})
                    counts["selected_exploit_logs"] += 1
                    counts["raw_triggers"] += row["raw_trigger"] is True
                    counts["group_candidates"] += row["group_candidate"] is True
                    counts["emitted"] += row["notification_emitted"] is True
                    reason = {"budget": "hard_budget_rejected", "quota": "quota_rejected",
                              "token": "token_rejected"}.get(row["suppression_reason"], row["suppression_reason"])
                    if reason:
                        counts[reason] += 1
            assert n == 28935 == cell["decision_rows_verified"]
            assert selected == source_positive
            assert all(counts[k] == v for k, v in cell["positive_execution_counts"].items())
            prior = cell["preceding_notifications"]
            assert dict(prior_by_day) == prior["by_utc_day"]
            assert sum(prior_by_day.values()) == prior["whole_window_before_block"]
            assert prior_by_day["2022-04-17"] == prior["positive_day_cap_used_before_block"]
            assert cell["daily_budget"] - prior_by_day["2022-04-17"] == prior["positive_day_cap_remaining_before_block"]
            assert counts["emitted"] == 0 and cell["first_positive_notification_admitted"] is None
            assert all(cell["first_positive_source_log"][k] == source_positive[0][k] for k in identities)
            results.append({"cell_id": cell["cell_id"], "rows_checked": n,
                            "positive_counts": dict(counts), "prior_same_day": prior_by_day["2022-04-17"]})
    assert len(results) == 9
    result = {"schema_version": "budget_policy_label_independent_review_v1",
              "checked_utc": datetime.now(timezone.utc).isoformat(), "all_checks_pass": True,
              "production_modules_imported": False, "policy_run": RUN, "join_run": JOIN,
              "label_sha256": hashlib.sha256(labels_path.read_bytes()).hexdigest(),
              "joined_output_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "decision_rows_checked": sum(r["rows_checked"] for r in results),
              "distinct_positive_source_logs": 6, "reported_incidents": 1,
              "independent_incident_test": False, "results": results,
              "scope": "One prior-L2 incident; no negative labels, recall estimate, observed latency or prevention inference."}
    target = PAPER / "qa/budget_policy_label_independent_review.json"
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"all_checks_pass": True, "cells": len(results), "rows": result["decision_rows_checked"]}))


if __name__ == "__main__":
    main()
