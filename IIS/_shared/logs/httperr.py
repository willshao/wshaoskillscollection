"""
_shared/logs/httperr.py — canonical reader for HTTP.SYS error logs.

Wraps the parser previously embedded in httperr_analyzer.py. Skills that
need HTTPERR data import this module instead of reimplementing the split.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Iterator

from _shared import log_discovery

__all__ = [
    "HttpErrFilter",
    "discover", "iter_entries",
    "summarise", "apply_filter", "around_window", "query",
    "parse_line",  # legacy alias
]

DEFAULT_HTTPERR_DIR = Path(r"C:\Windows\System32\LogFiles\HTTPERR")


# ---------------------------------------------------------------------------
# Filter
# ---------------------------------------------------------------------------

@dataclass
class HttpErrFilter:
    """Filter for HTTPERR entries. All fields are optional and AND-ed."""
    reason: str | None = None          # substring match on reason phrase
    client_ip: str | None = None       # exact match
    app_pool: str | None = None        # substring match (last but one column)
    contains: str | None = None        # raw-line substring (case-insensitive)

    def is_empty(self) -> bool:
        return not any((self.reason, self.client_ip, self.app_pool, self.contains))

    def matches(self, e: dict[str, Any]) -> bool:
        if self.reason and self.reason.lower() not in str(e.get("reason", "")).lower():
            return False
        if self.client_ip and self.client_ip != e.get("client_ip"):
            return False
        if self.app_pool and self.app_pool.lower() not in str(e.get("app_pool", "")).lower():
            return False
        if self.contains and self.contains.lower() not in str(e.get("raw", "")).lower():
            return False
        return True


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def discover(folder: Path | str | None = None,
             recursive: bool = True) -> list[Path]:
    folder = Path(folder) if folder else DEFAULT_HTTPERR_DIR
    if not folder.exists():
        return []
    if folder.is_file():
        return [folder]
    disc = log_discovery.discover_logs(folder, recursive=recursive)
    files = list(disc.by_kind.get(log_discovery.HTTPERR_KIND, []))
    if files:
        return files
    # fallback: classic httperr*.log glob
    return sorted(folder.glob("httperr*.log"))


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

# Legacy positional fallback when no #Fields: header was found (pre-IIS-7 era).
_LEGACY_FIELDS = [
    "date", "time", "c-ip", "c-port", "s-ip", "s-port",
    "cs-version", "cs-method", "cs-uri", "sc-status",
    "s-siteid", "s-reason", "s-queuename",
]


def _row_to_entry(row: dict[str, Any], raw_line: str) -> dict[str, Any]:
    date = row.get("date", "")
    time_ = row.get("time", "")
    return {
        "timestamp": f"{date} {time_}".strip(),
        "client_ip":   row.get("c-ip", "-"),
        "client_port": row.get("c-port", "-"),
        "server_ip":   row.get("s-ip", "-"),
        "server_port": row.get("s-port", "-"),
        "method":      row.get("cs-method", "-"),
        "uri":         row.get("cs-uri", "-"),
        "status":      row.get("sc-status", "-"),
        "site_id":     row.get("s-siteid", "-"),
        "reason":      row.get("s-reason", "-"),
        "app_pool":    row.get("s-queuename", "-"),
        "raw":         raw_line.rstrip("\n"),
    }


def parse_line(line: str, fields: list[str] | None = None) -> dict[str, Any] | None:
    """Parse a single HTTPERR line.

    When `fields` (the most recent #Fields: header) is supplied, fields are
    mapped by name. Otherwise the legacy positional layout is assumed.
    """
    if not line or line.startswith("#"):
        return None
    parts = line.split()
    if len(parts) < 5:
        return None
    layout = fields if fields else _LEGACY_FIELDS
    if len(parts) < len(layout):
        parts = parts + ["-"] * (len(layout) - len(parts))
    row = dict(zip(layout, parts))
    return _row_to_entry(row, line)


def iter_entries(path: Path) -> Iterator[dict[str, Any]]:
    fields: list[str] | None = None
    with Path(path).open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#"):
                if line.startswith("#Fields:"):
                    fields = line[len("#Fields:"):].strip().split()
                continue
            entry = parse_line(line.rstrip("\n"), fields=fields)
            if entry is not None:
                yield entry


# ---------------------------------------------------------------------------
# Filter / time-window helpers
# ---------------------------------------------------------------------------

def apply_filter(entries: Iterable[dict[str, Any]],
                 spec: HttpErrFilter | None) -> list[dict[str, Any]]:
    if spec is None or spec.is_empty():
        return list(entries)
    return [e for e in entries if spec.matches(e)]


def _parse_ts(ts_str: str) -> datetime | None:
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
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
    reasons = Counter(e.get("reason", "-") for e in entries)
    ips = Counter(e.get("client_ip", "-") for e in entries)
    pools = Counter(e.get("app_pool", "-") for e in entries
                    if e.get("app_pool") not in ("-", None))
    return {
        "count": len(entries),
        "top_reasons": reasons.most_common(10),
        "top_client_ips": ips.most_common(10),
        "top_app_pools": pools.most_common(10),
    }


# ---------------------------------------------------------------------------
# Unified query()
# ---------------------------------------------------------------------------

def query(sources: Iterable[Path | str],
          *,
          filter: HttpErrFilter | None = None,
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
