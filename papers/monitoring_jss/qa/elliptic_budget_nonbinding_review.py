"""Post-hoc read-only diagnostic of the frozen pilot; no parameter changes."""
import argparse
from collections import defaultdict
import gzip
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--run", type=Path, required=True)
parser.add_argument("--output", type=Path, default=Path(__file__).with_suffix(".json"))
args = parser.parse_args()
manifest = json.loads((args.run / "manifest.json").read_text())
assert manifest["status"] == "complete"
rows = []
for cell in manifest["cells"]:
    summary = json.loads((args.run / cell / "summary.json").read_text())
    path = args.run / cell / "decisions.jsonl.gz"
    assert sha(path) == summary["decision_sha256"]
    batches = defaultdict(list)
    with gzip.open(path, "rt") as source:
        for line in source:
            row = json.loads(line)
            batches[row["step"]].append(row)
    for step, batch in sorted(batches.items()):
        cap = len(batch) // 200
        raw = sum(row["raw_trigger"] for row in batch)
        admitted = sum(row["admitted"] for row in batch)
        assert raw >= cap and admitted == cap
        assert all(row["admitted"] == (row["rank_zero_based"] < cap) for row in batch)
        rows.append({"cell": cell, "step": step, "n_all": len(batch), "budget_k": cap,
                     "raw_threshold_alerts": raw, "raw_minus_k": raw-cap,
                     "admitted_equals_top_k_for_every_row": True})
report = {"schema_version": "elliptic_budget_nonbinding_review_v1", "run_id": manifest["run_id"],
          "scope": "Post-hoc descriptive check on frozen outputs; no refit, selection or retuning.",
          "script_sha256": sha(Path(__file__)), "all_checks_pass": True, "batches_checked": len(rows),
          "all_caps_filled": True, "all_admitted_sets_equal_unconditional_top_k": True,
          "minimum_raw_minus_k": min(row["raw_minus_k"] for row in rows),
          "interpretation": "The calibrated threshold does not further reduce admission in any observed batch. Differences in admitted sets reflect the fitted models' rankings under the shared cap, not a demonstrated benefit of threshold recalibration. This conclusion is specific to these frozen outputs.",
          "batches": rows}
args.output.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"report": str(args.output), "batches": len(rows), "minimum_raw_minus_k": report["minimum_raw_minus_k"], "all_checks_pass": True}))
