"""
Edge/_shared/sources/netlog.py — Chromium net-export reader (stub).

edge://net-export produces a single JSON file that captures every
network request, DNS lookup, and proxy decision during a session. The
file format is large and event-stream-style; this module ships a minimal
reader so the netlog `log_kind` requested by playbooks can be consumed
once a real implementation lands.

Today the module simply parses the file's top-level `constants` /
`events` keys and counts events by phase/type. Future work: project
URL_REQUEST_START/END pairs into request entries with timing.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator

__all__ = [
    "NetlogFilter",
    "discover", "iter_entries",
    "summarise", "apply_filter", "around_window", "query",
]


@dataclass
class NetlogFilter:
    source_type: str | None = None   # e.g. "URL_REQUEST", "HOST_RESOLVER_IMPL"
    phase: int | None = None         # 0=begin, 1=end, 2=none
    contains: str | None = None      # substring on JSON-encoded params

    def is_empty(self) -> bool:
        return not any((self.source_type, self.phase is not None, self.contains))

    def matches(self, e: dict[str, Any]) -> bool:
        if self.source_type and self.source_type != e.get("source_type"):
            return False
        if self.phase is not None and int(e.get("phase", -1)) != int(self.phase):
            return False
        if self.contains:
            blob = json.dumps(e.get("params") or {}, ensure_ascii=False).lower()
            if self.contains.lower() not in blob:
                return False
        return True


def discover(folder: Path | str | None = None,
             recursive: bool = True) -> list[Path]:
    """Find .json files that look like edge-net-export under `folder`."""
    if folder is None:
        return []
    base = Path(folder)
    if base.is_file():
        return [base] if base.suffix.lower() == ".json" else []
    pattern = "**/*.json" if recursive else "*.json"
    return sorted(base.glob(pattern))


def iter_entries(path: Path) -> Iterator[dict[str, Any]]:
    """Yield normalised event rows from one net-export file."""
    p = Path(path)
    try:
        blob = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return
    events = blob.get("events") if isinstance(blob, dict) else None
    if not isinstance(events, list):
        return
    constants = blob.get("constants") or {}
    source_types_map = (constants.get("logSourceType") or {})
    inv_source = {int(v): k for k, v in source_types_map.items() if isinstance(v, int)} if source_types_map else {}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        src = ev.get("source") or {}
        st = src.get("type")
        yield {
            "time": ev.get("time"),
            "phase": ev.get("phase"),
            "source_id": src.get("id"),
            "source_type": inv_source.get(int(st), str(st)) if st is not None else None,
            "type": ev.get("type"),
            "params": ev.get("params"),
        }


def apply_filter(entries: Iterable[dict[str, Any]],
                 spec: NetlogFilter | None) -> list[dict[str, Any]]:
    if spec is None or spec.is_empty():
        return list(entries)
    return [e for e in entries if spec.matches(e)]


def around_window(entries: Iterable[dict[str, Any]],
                  anchor: datetime,
                  window_seconds: int) -> list[dict[str, Any]]:
    # net-export `time` is a millisecond string offset from session start;
    # absolute-time correlation requires constants.timeTickOffset which is
    # out of scope for this stub. Return unchanged.
    return list(entries)


def summarise(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not entries:
        return {"count": 0}
    by_src = Counter(e.get("source_type", "?") for e in entries)
    by_phase = Counter(e.get("phase", -1) for e in entries)
    return {
        "count": len(entries),
        "top_source_types": by_src.most_common(10),
        "phase_distribution": dict(by_phase),
    }


def query(sources: Iterable[Path | str],
          *,
          filter: NetlogFilter | None = None,
          time_range=None,
          around=None,
          window_seconds: int = 300,
          limit: int | None = None) -> dict[str, Any]:
    src_files = [Path(p) for p in sources]
    entries: list[dict[str, Any]] = []
    for p in src_files:
        entries.extend(iter_entries(p))

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
