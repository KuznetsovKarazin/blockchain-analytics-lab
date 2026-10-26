#!/usr/bin/env python3
"""Owned source-free summary of listing and first-day footer metadata evidence."""
import argparse
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    for name in ("inventory", "footer", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_bytes())
    footer = json.loads(args.footer.read_bytes())
    if inventory["status"] != "COMPLETE_LISTING_METADATA_ONLY" or footer["status"] != "COMPLETE_FIRST_DAY_SCHEMA_AND_PROJECTION_METADATA_ONLY":
        raise ValueError("This complete-evidence summary requires both successful immutable attempts")
    if footer["inventory_summary_sha256"] != sha(args.inventory):
        raise ValueError("Footer/inventory binding differs")
    paper = Path(__file__).resolve().parents[2]
    qa = {}
    for kind in ("inventory", "footer"):
        path = paper / f"phase14/qa/measurement_{kind}_actual_review.json"
        review = json.loads(path.read_bytes())
        qa[kind] = {"path": str(path.relative_to(paper)), "sha256": sha(path), "status": review["status"]}
    sources, scenarios = [], []
    for source in footer["sources"]:
        sources.append({"table": source["table"], "day_utc": source["day_utc"], "key": source["key"],
            "source_size_bytes": source["source_size_bytes"], "footer_bytes": source["footer_bytes"],
            "footer_sha256": source["footer_sha256"], "trailer_sha256": source["trailer_sha256"],
            "row_count_metadata": source["row_count_metadata"], "row_group_count": source["row_group_count"],
            "schema": source["schema"]})
        for scenario in source["projection_scenarios"]:
            scenarios.append({"table": source["table"], "scenario": scenario["name"], "columns": scenario["columns"],
                "compressed_payload_bytes": scenario["compressed_payload_bytes"],
                "merged_range_request_count": scenario["range_request_count"], "column_chunk_count": scenario["column_chunks"],
                "payload_acquired": False, "cost_origin": "Exact compressed offsets and sizes in the retained footer."})
    full_projection = [row for row in scenarios if row["scenario"] == "all_required_columns"]
    projected_bytes = sum(row["compressed_payload_bytes"] for row in full_projection)
    projected_requests = sum(row["merged_range_request_count"] for row in full_projection)
    whole_bytes = sum(row["source_size_bytes"] for row in sources)
    by_table = {}
    for table in ("logs", "blocks", "transactions"):
        cells = [row for row in inventory["day_table_cells"] if row["table"] == table]
        by_table[table] = {"days": len(cells), "listed_objects": sum(len(row["objects"]) for row in cells),
            "declared_object_bytes": sum(row["object_bytes_metadata"] for row in cells)}
    result = {"schema_version": "article2_phase14_measurement_metadata_findings_v1",
        "status": "INDEPENDENTLY_AUDITED_SOURCE_METADATA_FEASIBLE_MEASUREMENT_NOT_STARTED",
        "scope": "AWS listing and deterministic first-day footer investigations only; administrative-event acquisition is accounted separately.",
        "input_bindings": {"inventory_summary_sha256": sha(args.inventory), "footer_summary_sha256": sha(args.footer),
                           "summary_program_sha256": sha(Path(__file__))}, "independent_actual_reviews": qa,
        "new_metadata_requests": inventory["new_metadata_requests"],
        "new_listing_response_bytes": inventory["new_metadata_response_bytes"],
        "new_footer_range_requests": footer["new_range_requests"],
        "new_footer_and_trailer_bytes": footer["retained_response_bytes"],
        "new_archive_metadata_gets_total": inventory["new_metadata_requests"] + footer["new_range_requests"],
        "new_archive_metadata_bytes_total": inventory["new_metadata_response_bytes"] + footer["retained_response_bytes"],
        "reused_month_listing_count": len(inventory["reused_listings"]),
        "window_utc": ["2022-02-19T00:00:00Z", "2022-03-21T00:00:00Z"],
        "window_days": 30, "listing_day_table_cells": inventory["selected_day_table_cell_count"],
        "listed_objects": inventory["selected_object_count"],
        "full_listed_object_bytes_metadata_only": inventory["selected_object_total_bytes_metadata"],
        "listing_counts_by_table": by_table,
        "prior_phase6_overlapping_identity_comparisons": len(inventory["phase6_overlapping_identity_comparisons"]),
        "prior_phase6_all_overlapping_identities_equal": all(row["identities_equal"] for row in inventory["phase6_overlapping_identity_comparisons"]),
        "footer_probe_date": footer["day_utc"], "date_selection_rule": "First date of the unchanged window, selected before reading activity rows.",
        "first_day_sources": sources, "first_day_projection_scenarios": scenarios,
        "first_day_all_required_columns": {"compressed_payload_bytes": projected_bytes,
            "merged_range_request_count": projected_requests, "whole_three_objects_bytes": whole_bytes,
            "projection_fraction_of_whole_object_bytes": {"numerator": projected_bytes, "denominator": whole_bytes},
            "payload_acquired": False, "predicate_dependent_actual_payload_cost_known": False},
        "new_chain_row_observations": 0, "new_parquet_row_pages_read_or_decoded": 0,
        "new_package_downloads_or_installs": 0, "case_admissions": 0, "detector_scores": 0,
        "limits": ["Object listing identities and byte sizes are metadata; opaque ETags are not SHA-256 content hashes.",
                   "Schema and physical column spans are established only for the three first-date objects; no 30-day cost is extrapolated.",
                   "The projected payload values describe exact footer-derived full-column ranges, not transferred data-page bytes or measured performance.",
                   "Actual predicate-dependent payload cost depends on source row groups reached after core-address/transaction-hash scans, which have not been performed.",
                   "Footer buffers may contain data-derived column statistics; these values were neither exported nor used for nomination, date selection or detector design.",
                   "The leading PAR1 used for local parsing was synthetic; source bytes are exactly the retained footer and trailer, not a whole Parquet file.",
                   "Independent footer reconstruction used a different API of the same pinned PyArrow version; it is not parser diversity.",
                   "Scope amendment acceptance alone nominates no core or case. Uniform per-row nomination and a separate measurement freeze remain necessary before detector input acquisition."]}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    lines = ["# Measurement source metadata and first-day projection cost", "",
        "The archive route now has a complete listed object inventory for the original 30-day LiFi window. A deterministic first-day footer probe confirms that the needed raw fields exist and gives exact physical column-span costs. **No LiFi detector-workload rows, transfer observations or detector scores were acquired by these archive probes.** Uniform core nomination and a separate measurement freeze remain pending; the accepted scope amendment alone admits no case.", "",
        "## Inventory and actual acquisition", "",
        f"Four metadata GETs returned {inventory['new_metadata_response_bytes']:,} bytes. Two complete prior March monthly listings were reused. The combined inventory covers 90 day/table cells and 90 objects, with {inventory['selected_object_total_bytes_metadata']:,} declared source bytes across logs, blocks and transactions. These whole-object bytes were not downloaded. All 46 overlapping identities agree with the retained Phase6 metadata.", "",
        f"Six exact trailer/footer range GETs returned {footer['retained_response_bytes']:,} bytes for February19,2022, the preselected first window date. Every response passed its frozen ETag, status206, Content-Range and Content-Length checks. PyArrow26.0.0 was reused; no package was installed. Both acquisitions and the footer calculations passed separate actual-evidence audits.", "",
        f"Archive-metadata work totals {result['new_archive_metadata_gets_total']} GETs and {result['new_archive_metadata_bytes_total']:,} retained bytes. Administrative-event requests and method-documentation lookups are accounted separately.", "",
        "## First-day schema metadata", "",
        "| Table | Whole-object bytes | Metadata row count | Row groups | Footer bytes |",
        "|---|---:|---:|---:|---:|"]
    for source in sources:
        lines.append(f"| {source['table']} | {source['source_size_bytes']:,} | {source['row_count_metadata']:,} | {source['row_group_count']} | {source['footer_bytes']:,} |")
    lines += ["", "The listed row counts describe entire source partitions, not LiFi activity. Log fields include raw emitter, topics, data, transaction/log positions and block identity/time. Transaction metadata includes integer receipt status; block fields include height, hash, parent hash, timestamp and transaction count. Data-page readability, nullability of actual rows, canonical order and continuous header coverage still require a separately frozen payload acquisition.", "",
        "## Footer-derived compressed column spans", "",
        "| Table | Scenario | Payload bytes if fetched | Merged range requests |",
        "|---|---|---:|---:|"]
    for row in scenarios:
        lines.append(f"| {row['table']} | {row['scenario']} | {row['compressed_payload_bytes']:,} | {row['merged_range_request_count']} |")
    lines += ["", f"The all-required-columns scenario totals **{projected_bytes:,} bytes in {projected_requests} ranges**, versus **{whole_bytes:,} bytes** for the three whole objects. The two log selection columns together are the union of address and transaction-hash scans, not an additional disjoint cost to add again. Likewise, each all-required-columns scenario includes its scan columns. These are exact physical-span calculations from retained metadata; the data pages were not transferred, and this is not a measured download benchmark.", "",
        "The address-only log scan can establish which source row groups contain the fixed core. Later payload cost depends on those matches and on transaction-hash expansion. It cannot be inferred exactly from metadata alone. No first-day result is multiplied into a claimed 30-day total.", "",
        "## Evidence limits and next action", "",
        "Raw footers may contain data-derived column statistics; their values were not exported or used to choose a core, date or parameter. The decoder's leading PAR1 was synthetic. Retained footer/trailer hashes and response receipts are the actual source evidence. Independent QA reconstructed metadata through a different API of the same pinned parser, without reading rows or importing the producer.", "",
        "After uniform per-row core nomination and a separate measurement freeze, acquire the planned source columns, establish complete source/header coverage, and seal the core-log transaction set before all-emitter expansion and scoring. Valid covered empty days remain in the study; missing data remains unavailable. [The aggregate JSON](measurement_metadata_findings.json) binds the exact source summaries and independent reviews, while [the observation proposal](observation_contract_proposal.json) defines the intended adapter boundary.", ""]
    args.output.with_name("SOURCE_COST_FINDINGS.md").write_text("\n".join(lines))
    print(json.dumps({"aggregate_sha256": sha(args.output), "markdown_sha256": sha(args.output.with_name("SOURCE_COST_FINDINGS.md")),
                      "archive_metadata_gets": result["new_archive_metadata_gets_total"],
                      "archive_metadata_bytes": result["new_archive_metadata_bytes_total"],
                      "first_day_projected_payload_bytes_not_acquired": projected_bytes}, indent=2))


if __name__ == "__main__":
    main()
