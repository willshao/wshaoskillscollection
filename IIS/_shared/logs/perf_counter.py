"""
_shared/logs/perf_counter.py — Get-Counter wrapper (framework stub).

The parent `resource_monitor` skill is itself a framework stub. This module
exposes the canonical query() surface so callers can be written today and
upgraded for free once the real Get-Counter sampling lands.
"""
from __future__ import annotations

import json
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

__all__ = [
    "PerfCounterFilter",
    "discover", "iter_entries",
    "summarise", "apply_filter", "around_window", "query",
    "sample_counter",
]


@dataclass
class PerfCounterFilter:
    counter_paths: list[str] = field(default_factory=list)
    min_value: float | None = None
    max_value: float | None = None

    def is_empty(self) -> bool:
        return not any((self.counter_paths, self.min_value, self.max_value))

    def matches(self, e: dict[str, Any]) -> bool:
        if self.counter_paths and not any(
            cp.lower() in str(e.get("path", "")).lower() for cp in self.counter_paths
        ):
            return False
        v = e.get("value")
        if self.min_value is not None and (v is None or v < self.min_value):
            return False
        if self.max_value is not None and (v is None or v > self.max_value):
            return False
        return True


def discover(folder: Path | str | None = None,
             recursive: bool = True) -> list[Path]:
    """Perf counters have no on-disk artefacts in live mode."""
    return []


def sample_counter(path: str,
                   *,
                   max_samples: int = 1,
                   sample_interval_seconds: int = 1,
                   timeout: int = 30) -> list[dict[str, Any]]:
    """Take one (or N) sample of a Windows perf counter via Get-Counter."""
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$c = Get-Counter -Counter '%(path)s' -MaxSamples %(n)d "
        "-SampleInterval %(int)d -ErrorAction SilentlyContinue;"
        "if (-not $c) { '[]' | Out-Host; return };"
        "$rows = foreach ($s in $c.CounterSamples) {"
        "  [pscustomobject]@{"
        "    timestamp = $s.Timestamp.ToString('o');"
        "    path = $s.Path;"
        "    value = [double]$s.CookedValue"
        "  }"
        "};"
        "$rows | ConvertTo-Json -Depth 3 -Compress"
    ) % {"path": path.replace("'", "''"),
         "n": int(max_samples),
         "int": int(sample_interval_seconds)}
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        return []
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]


def iter_entries(path: Path | str) -> Iterable[dict[str, Any]]:
    return iter(())


def apply_filter(entries: Iterable[dict[str, Any]],
                 spec: PerfCounterFilter | None) -> list[dict[str, Any]]:
    if spec is None or spec.is_empty():
        return list(entries)
    return [e for e in entries if spec.matches(e)]


def around_window(entries: Iterable[dict[str, Any]],
                  anchor: datetime,
                  window_seconds: int) -> list[dict[str, Any]]:
    return list(entries)  # perf samples are inherently point-in-time


def summarise(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not entries:
        return {"count": 0}
    paths = Counter(e.get("path", "-") for e in entries)
    values = [float(e["value"]) for e in entries if isinstance(e.get("value"), (int, float))]
    return {
        "count": len(entries),
        "top_counters": paths.most_common(10),
        "min_value": min(values) if values else None,
        "max_value": max(values) if values else None,
        "avg_value": (sum(values) / len(values)) if values else None,
    }


def query(sources: Iterable[Path | str] | None = None,
          *,
          filter: PerfCounterFilter | None = None,
          time_range: tuple[datetime | None, datetime | None] | None = None,
          around: datetime | None = None,
          window_seconds: int = 300,
          limit: int | None = None,
          counters: Sequence[str] = (),
          samples: int = 1) -> dict[str, Any]:
    """Sample one or more counters live. `sources` is ignored (kept for API parity)."""
    entries: list[dict[str, Any]] = []
    for c in counters:
        entries.extend(sample_counter(c, max_samples=samples))

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
        "counters": list(counters),
    }
