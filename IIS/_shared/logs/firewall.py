"""
_shared/logs/firewall.py — Windows Firewall log reader.

Parses C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log (W3C-style
header). The parent `firewall` skill is currently a framework stub; this
module ships a working parser + filter so that real classification can be
added without duplicating I/O code.
"""
from __future__ import annotations

import shlex
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Iterator

__all__ = [
    "FirewallFilter",
    "discover", "iter_entries",
    "summarise", "apply_filter", "around_window", "query",
]

DEFAULT_FW_DIR = Path(r"C:\Windows\System32\LogFiles\Firewall")


@dataclass
class FirewallFilter:
    action: str | None = None         # "ALLOW" or "DROP"
    protocol: str | None = None       # "TCP" / "UDP" / "ICMP"
    src_ip: str | None = None
    dst_port: int | None = None

    def is_empty(self) -> bool:
        return not any((self.action, self.protocol, self.src_ip, self.dst_port))

    def matches(self, e: dict[str, Any]) -> bool:
        if self.action and str(e.get("action", "")).upper() != self.action.upper():
            return False
        if self.protocol and str(e.get("protocol", "")).upper() != self.protocol.upper():
            return False
        if self.src_ip and self.src_ip != e.get("src_ip"):
            return False
        if self.dst_port is not None:
            try:
                if int(e.get("dst_port", 0) or 0) != int(self.dst_port):
                    return False
            except (TypeError, ValueError):
                return False
        return True


def discover(folder: Path | str | None = None,
             recursive: bool = True) -> list[Path]:
    folder = Path(folder) if folder else DEFAULT_FW_DIR
    if not folder.exists():
        return []
    if folder.is_file():
        return [folder]
    pattern = "**/pfirewall*.log" if recursive else "pfirewall*.log"
    return sorted(folder.glob(pattern))


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


def iter_entries(path: Path) -> Iterator[dict[str, Any]]:
    """Stream-parse a pfirewall.log file (W3C header)."""
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
            row = dict(zip(fields, parts))
            date = row.get("date", "")
            time_ = row.get("time", "")
            yield {
                "timestamp": f"{date} {time_}".strip(),
                "action":    row.get("action", "-"),
                "protocol":  row.get("protocol", "-"),
                "src_ip":    row.get("src-ip", "-"),
                "dst_ip":    row.get("dst-ip", "-"),
                "src_port":  _to_int(row.get("src-port", "0")),
                "dst_port":  _to_int(row.get("dst-port", "0")),
                "size":      _to_int(row.get("size", "0")),
                "tcpflags":  row.get("tcpflags", "-"),
                "path":      row.get("path", "-"),
            }


def apply_filter(entries: Iterable[dict[str, Any]],
                 spec: FirewallFilter | None) -> list[dict[str, Any]]:
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


def summarise(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not entries:
        return {"count": 0}
    actions = Counter(e.get("action", "-") for e in entries)
    protocols = Counter(e.get("protocol", "-") for e in entries)
    src_ips = Counter(e.get("src_ip", "-") for e in entries)
    dst_ports = Counter(e.get("dst_port", 0) for e in entries)
    return {
        "count": len(entries),
        "actions": dict(actions),
        "protocols": dict(protocols),
        "top_src_ips": src_ips.most_common(10),
        "top_dst_ports": dst_ports.most_common(10),
    }


def query(sources: Iterable[Path | str],
          *,
          filter: FirewallFilter | None = None,
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
