"""
_shared/timeseries.py

Bucket a list of normalised log entries into fixed-width time windows and
compute count + latency stats per bucket. Stdlib only.

`bucketize(entries, bucket_seconds)` returns a list[Bucket] sorted by start
time, with zero buckets included between sparse activity so charts render
continuously.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable

_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S.%f",
)


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    # Try fromisoformat first (handles many shapes incl. fractional secs).
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        pass
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _percentile(sorted_values: list[int], pct: float) -> int:
    if not sorted_values:
        return 0
    idx = min(len(sorted_values) - 1,
              max(0, int(len(sorted_values) * pct) - 1))
    return sorted_values[idx]


@dataclass
class Bucket:
    start: datetime
    count: int = 0
    avg_time_ms: float = 0.0
    p50_time_ms: int = 0
    p95_time_ms: int = 0
    p99_time_ms: int = 0
    max_time_ms: int = 0
    error_5xx: int = 0
    error_4xx: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start.isoformat(sep=" "),
            "count": self.count,
            "avg_time_ms": round(self.avg_time_ms, 2),
            "p50_time_ms": self.p50_time_ms,
            "p95_time_ms": self.p95_time_ms,
            "p99_time_ms": self.p99_time_ms,
            "max_time_ms": self.max_time_ms,
            "error_5xx": self.error_5xx,
            "error_4xx": self.error_4xx,
        }


def _floor(ts: datetime, seconds: int, anchor: datetime) -> datetime:
    delta = int((ts - anchor).total_seconds())
    floored = delta - (delta % seconds)
    return anchor + timedelta(seconds=floored)


def bucketize(entries: Iterable[dict[str, Any]],
              bucket_seconds: int = 60) -> list[Bucket]:
    """Group entries into fixed-width time windows. Returns sorted Buckets."""
    if bucket_seconds <= 0:
        raise ValueError("bucket_seconds must be positive")

    rows: list[tuple[datetime, dict[str, Any]]] = []
    for e in entries:
        ts = _parse_ts(str(e.get("timestamp", "")))
        if ts is not None:
            rows.append((ts, e))
    if not rows:
        return []

    rows.sort(key=lambda r: r[0])
    anchor = rows[0][0]

    grouped: dict[datetime, list[dict[str, Any]]] = {}
    for ts, entry in rows:
        key = _floor(ts, bucket_seconds, anchor)
        grouped.setdefault(key, []).append(entry)

    # Fill in zero buckets so charts have a continuous x-axis.
    start = min(grouped)
    end = max(grouped)
    step = timedelta(seconds=bucket_seconds)
    out: list[Bucket] = []
    cur = start
    while cur <= end:
        items = grouped.get(cur, [])
        if not items:
            out.append(Bucket(start=cur))
        else:
            times = sorted(int(i.get("time_taken", 0) or 0) for i in items)
            statuses = [int(i.get("status", 0) or 0) for i in items]
            out.append(Bucket(
                start=cur,
                count=len(items),
                avg_time_ms=sum(times) / len(times),
                p50_time_ms=_percentile(times, 0.50),
                p95_time_ms=_percentile(times, 0.95),
                p99_time_ms=_percentile(times, 0.99),
                max_time_ms=times[-1],
                error_5xx=sum(1 for s in statuses if 500 <= s < 600),
                error_4xx=sum(1 for s in statuses if 400 <= s < 500),
            ))
        cur += step
    return out


def detect_spike(buckets: list[Bucket], multiplier: float = 5.0,
                 min_count: int = 50) -> Bucket | None:
    """
    Return the peak bucket if it dwarfs the mean of the rest.

    A bucket is a spike when:
      * its count >= min_count, and
      * its count >= multiplier × mean(other buckets' counts)
    """
    if len(buckets) < 3:
        return None
    sorted_b = sorted(buckets, key=lambda b: b.count, reverse=True)
    top = sorted_b[0]
    rest = sorted_b[1:]
    if top.count < min_count:
        return None
    rest_mean = sum(b.count for b in rest) / max(1, len(rest))
    if rest_mean <= 0:
        return top if top.count >= min_count else None
    if top.count >= multiplier * rest_mean:
        return top
    return None


__all__ = ["Bucket", "bucketize", "detect_spike"]
