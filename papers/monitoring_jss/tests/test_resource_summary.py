"""Independent hand-computable queue and aggregation cases; no real input replay."""
import importlib.util
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[1] / "summarize_resource_benchmark.py"
SPEC = importlib.util.spec_from_file_location("resource_summary", PATH)
summary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(summary)


def test_fcfs_simultaneous_arrivals_and_half_open_queue():
    result = summary.fifo_metrics([0, 0, 0], [1, 2, 3])
    assert result["makespan_ns"] == 6
    assert result["waiting_ns"] == {"count": 3, "total": 4, "p50": 1, "p95": 3, "p99": 3, "maximum": 3}
    assert result["response_ns"]["total"] == 10
    assert result["peak_waiting_records"] == 2
    assert result["peak_in_system_records"] == 3


def test_exact_completion_before_arrival_has_no_wait():
    result = summary.fifo_metrics([0, 1, 2], [1, 1, 1])
    assert result["waiting_ns"]["total"] == 0
    assert result["peak_waiting_records"] == 0
    assert result["peak_in_system_records"] == 1


def test_zero_service_intervals_are_excluded():
    zero = summary.fifo_metrics([0, 0, 0], [0, 0, 0])
    assert zero["peak_waiting_records"] == zero["peak_in_system_records"] == 0
    assert zero["modeled_busy_fraction"] is None
    queued_zero = summary.fifo_metrics([0, 0, 0], [0, 1, 0])
    assert queued_zero["peak_waiting_records"] == 1
    assert queued_zero["peak_in_system_records"] == 2


def test_uniform_delay_is_algebraic_translation():
    first = summary.fifo_metrics([0, 0, 3, 5], [2, 0, 4, 1])
    second = summary.fifo_metrics([180_000_000_000 + t for t in [0, 0, 3, 5]], [2, 0, 4, 1])
    assert first == second


def test_integer_arrivals_subtract_before_dividing():
    times = [1_650_000_000_000_000_001, 1_650_000_000_000_000_003, 1_650_000_000_000_000_005]
    assert summary.schedule_arrivals(times, {"kind": "event_gaps", "scale": 2}) == [0, 1, 2]
    assert summary.schedule_arrivals(times, {"kind": "constant_rate", "events_per_second": 3}) == [0, 333_333_333, 666_666_666]


def test_nearest_rank_and_repeat_aggregation_are_distinct():
    assert summary.nearest_rank(list(range(1, 101)), 95) == 95
    assert summary.nearest_rank([10, 20, 30], 50) == 20
    assert summary.repeat_summary([10, 20, 30, 40, 500]) == {"repetitions": 5, "minimum": 10, "median": 30, "maximum": 500}


@pytest.mark.parametrize("arrivals,services", [([], []), ([1, 0], [1, 1]), ([0], [True]), ([0], [-1]), ([0, 1], [2])])
def test_invalid_fifo_inputs_fail(arrivals, services):
    with pytest.raises(ValueError):
        summary.fifo_metrics(arrivals, services)
