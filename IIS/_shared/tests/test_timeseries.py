"""Tests for _shared.timeseries."""
from __future__ import annotations

import timeseries as ts


def _e(timestamp: str, status: int = 200, time_taken: int = 100):
    return {"timestamp": timestamp, "status": status, "time_taken": time_taken}


def test_empty_returns_empty():
    assert ts.bucketize([], bucket_seconds=60) == []


def test_single_bucket_basic():
    rows = [_e(f"2026-05-26 10:00:{s:02d}") for s in range(0, 30, 5)]
    out = ts.bucketize(rows, bucket_seconds=60)
    assert len(out) == 1
    assert out[0].count == 6
    assert out[0].avg_time_ms == 100


def test_fills_zero_buckets_between():
    rows = [
        _e("2026-05-26 10:00:00"),
        _e("2026-05-26 10:00:05"),
        # gap from 10:01 .. 10:03
        _e("2026-05-26 10:04:00"),
    ]
    out = ts.bucketize(rows, bucket_seconds=60)
    counts = [b.count for b in out]
    assert counts == [2, 0, 0, 0, 1]


def test_percentiles_and_error_counts():
    rows = (
        [_e("2026-05-26 10:00:00", status=200, time_taken=t) for t in range(100, 1001, 100)]
        + [_e("2026-05-26 10:00:30", status=500, time_taken=9000)]
        + [_e("2026-05-26 10:00:45", status=404, time_taken=200)]
    )
    out = ts.bucketize(rows, bucket_seconds=60)
    assert len(out) == 1
    b = out[0]
    assert b.count == 12
    assert b.error_5xx == 1
    assert b.error_4xx == 1
    assert b.max_time_ms == 9000


def test_detect_spike_returns_peak():
    rows: list = []
    # 10 buckets with low traffic
    for m in range(10):
        for s in range(0, 5):
            rows.append(_e(f"2026-05-26 10:{m:02d}:{s:02d}"))
    # one giant bucket
    for s in range(0, 200):
        rows.append(_e(f"2026-05-26 10:11:{s % 60:02d}"))
    out = ts.bucketize(rows, bucket_seconds=60)
    peak = ts.detect_spike(out, multiplier=5.0, min_count=50)
    assert peak is not None
    assert peak.count == 200


def test_detect_spike_below_threshold():
    rows = [_e(f"2026-05-26 10:{m:02d}:00") for m in range(5)]
    out = ts.bucketize(rows, bucket_seconds=60)
    assert ts.detect_spike(out) is None
