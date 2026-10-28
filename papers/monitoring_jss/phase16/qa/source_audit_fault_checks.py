"""New independent-source-auditor integration on generated tiny Parquet only."""
import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile
import audit_prepared_sources as audit
import streaming_fault_checks as fixtures


def run(dependencies):
    sys.path.insert(0, str(Path(dependencies).resolve()))
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.parquet as pq
    import numpy as np
    _, producer = fixtures.load_pipeline()
    f = fixtures.fixture(pa)
    checks = []
    with tempfile.TemporaryDirectory(prefix="phase16_independent_audit_fixture_") as directory:
        root = Path(directory)
        original = {"blocks": [f["header"]], "transactions": f["transactions"], "logs": f["logs"]}
        offline, readers = {}, {}
        for kind, rows in original.items():
            path = root / (kind + ".parquet")
            raw = fixtures.arrow_table(rows, kind, pa)
            pq.write_table(raw, path, row_group_size=2)
            metadata = pq.ParquetFile(path).metadata
            identity = {"key": kind, "size_bytes": path.stat().st_size, "day_utc": f["day"], "table": kind,
                        "etag_opaque": "invented", "url": "https://invented.invalid/" + kind}
            source = identity | {"role": "invented_fixture", "last_modified": "not_a_source_identity_field", "case_ids": ["a", "b"]}
            manifest = {"source": identity, "row_count_metadata": metadata.num_rows,
                        "row_group_count": metadata.num_row_groups,
                        "row_group_rows": [metadata.row_group(i).num_rows for i in range(metadata.num_row_groups)]}
            proof = {"source_key": kind, "path": str(path), "available_ranges": [[0, path.stat().st_size]]}
            offline[kind] = [audit.OfflineSource(source, manifest, proof, pa, pq)]
            reader = fixtures.Reader(kind, [raw.slice(i, 2) for i in range(0, len(raw), 2)])
            reader.manifest = lambda value=manifest: value
            readers[kind] = [reader]
        headers, _ = audit.header_rows(offline["blocks"], f["day"], pa, pc)
        configs = {"case_a": {"population_addresses": [f["a"]]}, "case_b": {"population_addresses": [f["b"]]}}
        limits = {"max_transaction_rows_per_day": 100, "max_log_rows_per_day": 100,
                  "max_selected_transactions_per_case_day": 100, "max_selected_logs_per_day": 100}
        producer.prepare_day(f["day"], readers, headers, f["previous"], f["following"], configs,
                             root / "prepared", pa, pc, np, limits)
        prep, summary = audit.audit_day(f["day"], offline, headers, f["previous"], f["following"], configs,
                                        root / "prepared", pa, pc, np)
        assert summary["all_transaction_rows"] == 4 and summary["all_log_identity_rows"] == 6
        assert summary["cases"]["case_a"]["selected_transactions"] == 1
        assert summary["cases"]["case_b"]["selected_transactions"] == 2
        checks.append("reread_real_generated_parquet_groups_reconstructs_both_case_selections_and_bundles")
        checks.append("inventory_annotation_fields_excluded_from_six_field_source_identity")
        damaged = copy.deepcopy(prep)
        damaged["cases"]["case_a"]["bundles"][0]["logs"][1]["data"] = "0x" + "0" * 64
        parts = audit.read_json(root / "prepared" / "source_parts.json")
        parts["prepared_cases_sha256"] = audit.value_sha(damaged["cases"])
        damaged["partition_manifest_sha256"] = audit.write(root / "prepared" / "source_parts.json", parts)
        audit.write(root / "prepared" / "prepared.json", damaged)
        try:
            audit.audit_day(f["day"], offline, headers, f["previous"], f["following"], configs,
                            root / "prepared", pa, pc, np)
        except ValueError as exc:
            assert "independently reread source" in str(exc)
        else:
            raise AssertionError("coherently rehashed prepared payload forgery accepted")
        checks.append("coherently_rehashed_prepared_payload_forgery_rejected_against_original_bytes")
        source = offline["logs"][0]
        rg = source.metadata.row_group(0)
        column = next(rg.column(i) for i in range(rg.num_columns) if rg.column(i).path_in_schema == "data")
        lo = min(n for n in (column.dictionary_page_offset, column.data_page_offset) if n >= 4)
        hi = lo + column.total_compressed_size
        source.spans = [[0, lo], [hi, source.path.stat().st_size]]
        before = len(source.reads)
        try:
            source.read(0, ["data"])
        except ValueError as exc:
            assert "unacquired column chunk" in str(exc)
        else:
            raise AssertionError("sparse hole was decoded")
        assert len(source.reads) == before
        checks.append("unacquired_column_chunk_rejected_before_parquet_decode")
    return {"status": "PASS_NEW_SYNTHETIC_SOURCE_AUDITOR_CHECKS_ONLY", "checks_passed": len(checks), "checks": checks,
            "reviewer_sha256": audit.file_sha(audit.__file__), "test_script_sha256": audit.file_sha(__file__),
            "real_source_rows_read": 0, "network_requests": 0, "old_suites_rerun": False, "detector_scores": 0}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dependencies", required=True)
    p.add_argument("--report", type=Path, required=True)
    args = p.parse_args()
    report = run(args.dependencies)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "checks_passed": report["checks_passed"]}))
