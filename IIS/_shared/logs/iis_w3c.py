"""
_shared/logs/iis_w3c.py — canonical reader for IIS W3C access logs.

This is the single source of truth for parsing %SystemDrive%\\inetpub\\logs\\…
files. The IIS analyzer + the orchestrator + any future skill must import
from here instead of duplicating the W3C field handling.
"""
from __future__ import annotations

import shlex
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Iterator

from _shared import log_discovery, log_filters

__all__ = [
    "IisFilter",
    "discover", "iter_entries", "normalise",
    "summarise", "apply_filter", "around_window", "query",
    "parse_w3c_log",  # legacy alias
]

# Per-kind filter is just FilterSpec for IIS W3C
IisFilter = log_filters.FilterSpec


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def discover(folder: Path | str, recursive: bool = True) -> list[Path]:
    """Return every IIS-classified log file under `folder`."""
    folder = Path(folder)
    if folder.is_file():
        # treat as IIS if classification agrees, else still allow caller
        return [folder]
    disc = log_discovery.discover_logs(folder, recursive=recursive)
    return list(disc.by_kind.get(log_discovery.IIS_KIND, []))


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _shlex_split(line: str) -> list[str]:
    try:
        return shlex.split(line, posix=False)
    except ValueError:
        return line.split()


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_w3c_log(path: Path) -> Iterator[dict[str, Any]]:
    """Stream-parse a W3C IIS log, yielding raw dicts keyed by header field name."""
    fields: list[str] = []
    with Path(path).open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line or line[0] == "\n":
                continue
            if line.startswith("#"):
                if line.startswith("#Fields:"):
                    fields = line[len("#Fields:"):].strip().split()
                continue
            if not fields:
                continue
            parts = _shlex_split(line.rstrip("\n"))
            if len(parts) < len(fields):
                parts = parts + ["-"] * (len(fields) - len(parts))
            yield dict(zip(fields, parts))


def normalise(row: dict[str, Any]) -> dict[str, Any]:
    """Project a raw W3C row onto the schema downstream skills consume."""
    date = row.get("date", "")
    time_ = row.get("time", "")
    user = row.get("cs-username", "-")
    return {
        "timestamp":  f"{date} {time_}".strip(),
        "method":     row.get("cs-method", "-"),
        "uri":        row.get("cs-uri-stem", "-"),
        "query":      row.get("cs-uri-query", "-"),
        "client_ip":  row.get("c-ip", "-"),
        "status":     _to_int(row.get("sc-status", "0")),
        "substatus":  _to_int(row.get("sc-substatus", "0")),
        "win_status": _to_int(row.get("sc-win32-status", "0")),
        "time_taken": _to_int(row.get("time-taken", "0")),
        "bytes_sent": _to_int(row.get("sc-bytes", "0")),
        "user_agent": row.get("cs(User-Agent)", "-"),
        "username":   user,
        "is_authenticated": bool(user and user != "-"),
    }


def iter_entries(path: Path) -> Iterator[dict[str, Any]]:
    """Yield normalised entries from a single IIS log file."""
    for raw in parse_w3c_log(path):
        yield normalise(raw)


# ---------------------------------------------------------------------------
# Filter / search helpers
# ---------------------------------------------------------------------------

def apply_filter(entries: Iterable[dict[str, Any]],
                 spec: log_filters.FilterSpec | None) -> list[dict[str, Any]]:
    if spec is None or spec.is_empty():
        return list(entries)
    return [e for e in entries if spec.matches(e)]


def _parse_entry_ts(ts_str: str) -> datetime | None:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def around_window(entries: Iterable[dict[str, Any]],
                  anchor: datetime,
                  window_seconds: int) -> list[dict[str, Any]]:
    lo = anchor - timedelta(seconds=window_seconds)
    hi = anchor + timedelta(seconds=window_seconds)
    out: list[dict[str, Any]] = []
    for e in entries:
        ts = _parse_entry_ts(str(e.get("timestamp", "")))
        if ts is None:
            continue
        if lo <= ts <= hi:
            out.append(e)
    return out


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def _percentile(sorted_values: list[int], pct: float) -> int:
    if not sorted_values:
        return 0
    idx = min(len(sorted_values) - 1, max(0, int(len(sorted_values) * pct) - 1))
    return sorted_values[idx]


def summarise(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not entries:
        return {"count": 0}
    statuses = [int(e.get("status", 0) or 0) for e in entries]
    times = sorted(int(e.get("time_taken", 0) or 0) for e in entries)
    return {
        "count": len(entries),
        "status_distribution": dict(Counter(statuses)),
        "top_uris": Counter(e.get("uri", "-") for e in entries).most_common(10),
        "top_ips": Counter(e.get("client_ip", "-") for e in entries).most_common(10),
        "avg_time_ms": sum(times) / len(times) if times else 0,
        "p95_time_ms": _percentile(times, 0.95),
        "max_time_ms": times[-1] if times else 0,
    }


# ---------------------------------------------------------------------------
# Unified query()
# ---------------------------------------------------------------------------

def query(sources: Iterable[Path | str],
          *,
          filter: log_filters.FilterSpec | None = None,
          time_range: tuple[datetime | None, datetime | None] | None = None,
          around: datetime | None = None,
          window_seconds: int = 300,
          limit: int | None = None) -> dict[str, Any]:
    """Run a single combined query across one or more IIS log files.

    Returns {summary, entries, truncated, source_files}.
    """
    src_files = [Path(p) for p in sources]
    entries: list[dict[str, Any]] = []
    for p in src_files:
        entries.extend(iter_entries(p))

    if time_range:
        start, end = time_range
        if start or end:
            def _in_range(e: dict[str, Any]) -> bool:
                ts = _parse_entry_ts(str(e.get("timestamp", "")))
                if ts is None:
                    return False
                if start and ts < start:
                    return False
                if end and ts > end:
                    return False
                return True
            entries = [e for e in entries if _in_range(e)]

    if around is not None:
        entries = around_window(entries, around, window_seconds)

    if filter is not None and not filter.is_empty():
        entries = apply_filter(entries, filter)

    truncated = False
    if limit is not None and len(entries) > limit:
        truncated = True
        entries = entries[:limit]

    return {
        "summary": summarise(entries),
        "entries": entries,
        "truncated": truncated,
        "source_files": [str(p) for p in src_files],
    }
