"""Synthetic, network-free integrity checks for the continuous-day collector."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import acquire_protocol_window as collector


class FakeResponse(io.BytesIO):
    def __init__(self, content, *, status=200, length=None, etag='"source-v1"', version=None):
        super().__init__(content)
        self.status = status
        self.headers = {"Content-Length": str(len(content) if length is None else length), "ETag": etag}
        if version is not None:
            self.headers["x-amz-version-id"] = version

    def getcode(self):
        return self.status


def source_metadata(content=b"synthetic parquet bytes"):
    return {"url": "https://example.invalid/day/source.parquet", "size": len(content),
            "etag": '"source-v1"', "version_id": None}


def downloader(source, path, opener, *, max_bytes=1000, min_free_bytes=0):
    return collector.download_object(source, path, max_bytes=max_bytes,
                                     min_free_bytes=min_free_bytes, opener=opener)


def test_full_get_is_pinned_and_verified_cache_does_not_refetch(tmp_path):
    content = b"synthetic parquet bytes"
    metadata = source_metadata(content)
    calls = []

    def opener(request, **kwargs):
        calls.append(request)
        assert request.get_header("If-match") == metadata["etag"]
        assert request.get_header("Range") is None
        return FakeResponse(content)

    path = tmp_path / "source.parquet"
    receipt = downloader(metadata, path, opener)
    assert path.read_bytes() == content
    assert receipt["sha256"] == hashlib.sha256(content).hexdigest()
    downloader(metadata, path, opener)
    assert len(calls) == 1


@pytest.mark.parametrize("response_kwargs,body", [
    ({"status": 206}, b"0123456789"),
    ({"etag": '"changed"'}, b"0123456789"),
    ({"length": 9}, b"0123456789"),
    ({"length": 10}, b"012345678"),
    ({"length": 10}, b"01234567890"),
])
def test_wrong_status_identity_length_truncation_or_excess_never_publish(tmp_path, response_kwargs, body):
    source = source_metadata(b"0123456789")
    path = tmp_path / "source.parquet"
    with pytest.raises((RuntimeError, ValueError, OSError)):
        downloader(source, path, lambda request, **kwargs: FakeResponse(body, **response_kwargs))
    assert not path.exists()


@pytest.mark.parametrize("change", [
    {"url": "https://example.invalid/changed/source.parquet"},
    {"size": 99},
    {"etag": '"changed"'},
    {"version_id": "version-2"},
])
def test_cached_source_identity_cannot_change(tmp_path, change):
    source = source_metadata()
    path = tmp_path / "source.parquet"
    downloader(source, path, lambda request, **kwargs: FakeResponse(b"synthetic parquet bytes"))

    def no_network(request, **kwargs):
        pytest.fail("Changed cache identity must not cause a network refresh")

    with pytest.raises((RuntimeError, ValueError)):
        downloader({**source, **change}, path, no_network)


def test_corrupt_complete_cache_is_rejected(tmp_path):
    source = source_metadata()
    path = tmp_path / "source.parquet"
    downloader(source, path, lambda request, **kwargs: FakeResponse(b"synthetic parquet bytes"))
    path.write_bytes(b"X" * source["size"])
    with pytest.raises((RuntimeError, ValueError)):
        downloader(source, path, lambda request, **kwargs: pytest.fail("Corrupt cache cannot silently refetch"))


def test_frozen_source_version_must_match_get_response(tmp_path):
    source = {**source_metadata(), "version_id": "expected-version"}
    path = tmp_path / "source.parquet"
    with pytest.raises((RuntimeError, ValueError)):
        downloader(source, path, lambda request, **kwargs: FakeResponse(b"synthetic parquet bytes", version="changed-version"))
    assert not path.exists()


@pytest.mark.parametrize("budget_kwargs", [{"max_bytes": 1}, {"min_free_bytes": 10**19}])
def test_resource_gate_precedes_network(tmp_path, budget_kwargs):
    with pytest.raises((RuntimeError, ValueError, OSError)):
        downloader(source_metadata(), tmp_path / "source.parquet",
                   lambda request, **kwargs: pytest.fail("Resource gate must precede request"), **budget_kwargs)


def header(number=100, day="2022-03-19", second=12, block_hash=None, parent_hash=None):
    midnight = int(datetime.fromisoformat(day).replace(tzinfo=timezone.utc).timestamp())
    return {"block_number": number, "block_hash": block_hash or "0x" + f"{number:064x}",
            "parent_hash": parent_hash or "0x" + f"{number-1:064x}",
            "event_time_ns": (midnight + second) * 10**9, "transaction_count": 10}


def test_day_headers_are_complete_unique_and_ordered():
    rows = [header(), header(101, second=24)]
    assert collector.validate_headers(rows, "2022-03-19")


@pytest.mark.parametrize("rows", [
    [],
    [header(), header()],
    [header(), header(102, second=24)],
    [header(), header(101, second=24, parent_hash="0x" + "f"*64)],
    [header(), header(101, second=12)],
    [header(day="2022-03-20")],
    [header(block_hash="0xinvalid")],
])
def test_invalid_or_incomplete_day_headers_are_rejected(rows):
    with pytest.raises((RuntimeError, ValueError)):
        collector.validate_headers(rows, "2022-03-19")


def day_entry(day, first, last):
    return {"day_utc": day, "first_header": first, "last_header": last}


def test_cross_day_boundary_checks_calendar_number_parent_and_time():
    first_day = day_entry("2022-03-19", header(), header(101, second=86388))
    second_day = day_entry("2022-03-20", header(102, day="2022-03-20"), header(103, day="2022-03-20", second=24))
    assert collector.validate_cross_day([first_day, second_day])
    bad_days = [
        {**second_day, "day_utc": "2022-03-21"},
        {**second_day, "first_header": {**second_day["first_header"], "block_number": 104}},
        {**second_day, "first_header": {**second_day["first_header"], "parent_hash": "0x"+"f"*64}},
        {**second_day, "first_header": {**second_day["first_header"], "event_time_ns": first_day["last_header"]["event_time_ns"]}},
    ]
    for bad in bad_days:
        with pytest.raises((RuntimeError, ValueError)):
            collector.validate_cross_day([first_day, bad])


def test_seal_validates_members_and_detects_repacked_content_change(tmp_path):
    day = tmp_path / "day"
    day.mkdir()
    (day / "selected_logs.jsonl").write_text('{"synthetic":true}\n')
    (day / "unfinished.partial").write_bytes(b"incomplete")
    source = tmp_path / "frozen.py"
    source.write_text("# synthetic frozen source\n")
    archive = tmp_path / "sealed.zip"
    receipt = collector.seal_day(day, archive, {"source/frozen.py": source})
    assert receipt["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert collector.verify_seal(archive)
    with zipfile.ZipFile(archive) as z:
        entries = {info.filename: z.read(info) for info in z.infolist()}
    assert not any(name.endswith(".partial") for name in entries)
    assert entries["source/frozen.py"] == source.read_bytes()
    selected = next(name for name in entries if name.endswith("selected_logs.jsonl"))
    entries[selected] = b'{"synthetic":false}\n'
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    with pytest.raises((RuntimeError, ValueError, AssertionError)):
        collector.verify_seal(archive)


def test_sealed_archive_cannot_be_overwritten(tmp_path):
    day = tmp_path / "day"
    day.mkdir()
    (day / "selected_logs.jsonl").write_text("")
    archive = tmp_path / "sealed.zip"
    collector.seal_day(day, archive, {})
    before = archive.read_bytes()
    with pytest.raises(FileExistsError):
        collector.seal_day(day, archive, {})
    assert archive.read_bytes() == before


def parquet_fixture(tmp_path, *, all_irrelevant=False, null_address=False, wrong_block_hash=False,
                    removed_values=None, removed_string_type=False):
    import pyarrow as pa
    import pyarrow.parquet as pq
    alpha, beta, irrelevant = ("0x" + char*40 for char in "abc")
    headers = [header(), header(101, second=24)]
    header_table = pa.table({
        "number": pa.array([r["block_number"] for r in headers], type=pa.int64()),
        "hash": [r["block_hash"] for r in headers],
        "parent_hash": [r["parent_hash"] for r in headers],
        "timestamp": pa.array([r["event_time_ns"] for r in headers], type=pa.timestamp("ns")),
        "transaction_count": pa.array([r["transaction_count"] for r in headers], type=pa.int64()),
    })
    records = []
    for address, block, tx_index, log_index, suffix in [
        (alpha.upper().replace("0X", "0x"), headers[0], 2, 5, "a"),
        (irrelevant, headers[0], 0, 0, "b"),
        (beta, headers[1], 1, 2, "c"),
        (alpha, headers[0], 1, 3, "d"),
    ]:
        records.append({"address": irrelevant if all_irrelevant else address,
                        "topics": ["0x"+"e"*64], "data": "0x0001",
                        "transaction_index": tx_index, "log_index": log_index,
                        "transaction_hash": "0x"+suffix*64, "block_number": block["block_number"],
                        "block_hash": block["block_hash"], "block_timestamp": block["event_time_ns"]})
    if null_address:
        records[1]["address"] = None
    if wrong_block_hash:
        records[0]["block_hash"] = "0x"+"f"*64
    schema = pa.schema([
        ("address", pa.string()), ("topics", pa.list_(pa.string())), ("data", pa.string()),
        ("transaction_index", pa.int64()), ("log_index", pa.int64()),
        ("transaction_hash", pa.string()), ("block_number", pa.int64()),
        ("block_hash", pa.string()), ("block_timestamp", pa.timestamp("ns")),
    ])
    if removed_values is not None:
        assert len(removed_values) == len(records)
        for record, value in zip(records, removed_values):
            record["removed"] = value
        schema = schema.append(pa.field("removed", pa.string() if removed_string_type else pa.bool_()))
    logs_path, headers_path = tmp_path/"logs.parquet", tmp_path/"headers.parquet"
    pq.write_table(pa.Table.from_pylist(records, schema=schema), logs_path, row_group_size=2)
    pq.write_table(header_table, headers_path)
    populations = [{"population_id": "alpha", "addresses": [alpha]},
                   {"population_id": "beta", "addresses": [beta]},
                   {"population_id": "zero", "addresses": ["0x"+"d"*40]}]
    return logs_path, headers_path, populations


def test_complete_union_selection_preserves_ordinals_and_explicit_zero_population(tmp_path):
    logs, headers, populations = parquet_fixture(tmp_path)
    out = tmp_path/"selected"
    result = collector.select_day(logs, headers, populations, "2022-03-19", out)
    assert result["complete_address_rows_scanned"] == 4
    assert result["union_selected_logs"] == 3
    assert sum(group["address_rows_scanned"] for group in result["row_groups"]) == 4
    assert sum(group["matching_rows"] for group in result["row_groups"]) == 3
    by_population = {r["population_id"]: r for r in result["population_outputs"]}
    assert {name: record["rows"] for name, record in by_population.items()} == {"alpha": 2, "beta": 1, "zero": 0}
    assert all(record["complete"] for record in by_population.values())
    assert (out/by_population["zero"]["path"]).read_bytes() == b""
    rows = [json.loads(line) for line in (out/by_population["alpha"]["path"]).read_text().splitlines()]
    assert [r["source_global_row_index"] for r in rows] == [3, 0]
    assert [r["transaction_index"] for r in rows] == [1, 2]
    assert all(r["observed_time"] is None and r["label_available_time"] is None for r in rows)
    assert result["source_missing_removed"] is True
    assert result["receipt_status"] is None
    assert result["headers_output"]["rows"] == 2


def test_no_matching_event_day_is_complete_zero_not_missing(tmp_path):
    logs, headers, populations = parquet_fixture(tmp_path, all_irrelevant=True)
    result = collector.select_day(logs, headers, populations, "2022-03-19", tmp_path/"selected")
    assert result["complete_address_rows_scanned"] == 4
    assert result["union_selected_logs"] == 0
    assert result["status"] == "complete"
    assert all(record["rows"] == 0 and record["complete"] for record in result["population_outputs"])


@pytest.mark.parametrize("fixture_kwargs", [{"null_address": True}, {"wrong_block_hash": True}])
def test_unknown_membership_or_header_mismatch_cannot_be_complete(tmp_path, fixture_kwargs):
    logs, headers, populations = parquet_fixture(tmp_path, **fixture_kwargs)
    with pytest.raises((RuntimeError, ValueError)):
        collector.select_day(logs, headers, populations, "2022-03-19", tmp_path/"selected")


def test_optional_removed_false_and_null_are_preserved_without_inventing_finality(tmp_path):
    logs, headers, populations = parquet_fixture(tmp_path, removed_values=[False, True, None, False])
    out = tmp_path/"selected"
    result = collector.select_day(logs, headers, populations, "2022-03-19", out)
    assert result["source_missing_removed"] is False
    rows = [json.loads(line) for record in result["population_outputs"]
            for line in (out/record["path"]).read_text().splitlines()]
    by_ordinal = {row["source_global_row_index"]: row for row in rows}
    assert by_ordinal[0]["removed"] is False
    assert by_ordinal[2]["removed"] is None
    assert by_ordinal[3]["removed"] is False
    assert result["receipt_status"] is None


@pytest.mark.parametrize("values,string_type", [
    ([True, False, None, False], False),
    (["false", None, None, None], True),
])
def test_selected_removed_true_or_nonboolean_is_rejected(tmp_path, values, string_type):
    logs, headers, populations = parquet_fixture(tmp_path, removed_values=values, removed_string_type=string_type)
    with pytest.raises((RuntimeError, ValueError)):
        collector.select_day(logs, headers, populations, "2022-03-19", tmp_path/"selected")
