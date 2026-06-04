"""
_shared/logs/ftp_w3c.py — canonical reader for Microsoft FTP Service logs.

Lifts the W3C parser + projection from ftp_analyzer.py. Session
reconstruction stays in the skill — this module owns I/O + filter only.
"""
from __future__ import annotations

import shlex
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Iterator

from _shared import log_discovery, log_filters

__all__ = [
    "FtpFilter",
    "discover", "iter_entries", "normalise",
    "summarise", "apply_filter", "around_window", "query",
    "parse_ftp_log",
]

# FTP uses the same FilterSpec; method/uri/status/ip fields all apply
FtpFilter = log_filters.FilterSpec


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def discover(folder: Path | str, recursive: bool = True) -> list[Path]:
    folder = Path(folder)
    if folder.is_file():
        return [folder]
    disc = log_discovery.discover_logs(folder, recursive=recursive)
    return list(disc.by_kind.get(log_discovery.FTP_KIND, []))


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


def parse_ftp_log(path: Path) -> Iterator[dict[str, Any]]:
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
    date = row.get("date", "")
    time_ = row.get("time", "")
    return {
        "timestamp":      f"{date} {time_}".strip(),
        "client_ip":      row.get("c-ip", "-"),
        "user":           row.get("cs-username", "-"),
        "method":         (row.get("cs-method", "-") or "-").upper(),
        "uri":            row.get("cs-uri-stem", "-"),
        "query":          row.get("cs-uri-query", "-"),
        "status":         _to_int(row.get("sc-status", "0")),
        "win_status":     _to_int(row.get("sc-win32-status", "0")),
        "substatus":      _to_int(row.get("sc-substatus", "0")),
        "bytes_sent":     _to_int(row.get("sc-bytes", "0")),
        "bytes_received": _to_int(row.get("cs-bytes", "0")),
        "session_id":     row.get("x-session", "-"),
        "fullpath":       row.get("x-fullpath", "-"),
        "time_taken":     _to_int(row.get("time-taken", "0")),
        "user_agent":     "-",
    }


def iter_entries(path: Path) -> Iterator[dict[str, Any]]:
    for raw in parse_ftp_log(path):
        yield normalise(raw)


# ---------------------------------------------------------------------------
# Filter / window helpers
# ---------------------------------------------------------------------------

def apply_filter(entries: Iterable[dict[str, Any]],
                 spec: log_filters.FilterSpec | None) -> list[dict[str, Any]]:
    if spec is None or spec.is_empty():
        return list(entries)
    return [e for e in entries if spec.matches(e)]


def _parse_ts(ts_str: str) -> datetime | None:
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
        ts = _parse_ts(str(e.get("timestamp", "")))
        if ts is None:
            continue
        if lo <= ts <= hi:
            out.append(e)
    return out


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def summarise(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not entries:
        return {"count": 0}
    statuses = [int(e.get("status", 0) or 0) for e in entries]
    methods = Counter(e.get("method", "-") for e in entries)
    users = Counter(e.get("user", "-") for e in entries if e.get("user") != "-")
    ips = Counter(e.get("client_ip", "-") for e in entries)
    return {
        "count": len(entries),
        "status_distribution": dict(Counter(statuses)),
        "top_methods": methods.most_common(10),
        "top_users": users.most_common(10),
        "top_ips": ips.most_common(10),
        "bytes_uploaded": sum(int(e.get("bytes_received", 0) or 0) for e in entries),
        "bytes_downloaded": sum(int(e.get("bytes_sent", 0) or 0) for e in entries),
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
    src_files = [Path(p) for p in sources]
    entries: list[dict[str, Any]] = []
    for p in src_files:
        entries.extend(iter_entries(p))

    if time_range:
        start, end = time_range
        if start or end:
            def _in_range(e: dict[str, Any]) -> bool:
                ts = _parse_ts(str(e.get("timestamp", "")))
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
