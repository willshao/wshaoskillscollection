"""
Edge/_shared/sources/processes.py — enumerate running msedge.exe processes.
"""
from __future__ import annotations

import json
import os
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator

__all__ = [
    "ProcessFilter",
    "discover", "iter_entries",
    "summarise", "apply_filter", "around_window", "query",
    "count_msedge",
]


@dataclass
class ProcessFilter:
    min_cpu_seconds: float | None = None
    min_working_set_mb: float | None = None
    name_contains: str | None = None

    def is_empty(self) -> bool:
        return not any((self.min_cpu_seconds, self.min_working_set_mb, self.name_contains))

    def matches(self, e: dict[str, Any]) -> bool:
        if self.min_cpu_seconds is not None and float(e.get("cpu_seconds", 0) or 0) < self.min_cpu_seconds:
            return False
        if self.min_working_set_mb is not None and float(e.get("working_set_mb", 0) or 0) < self.min_working_set_mb:
            return False
        if self.name_contains and self.name_contains.lower() not in str(e.get("name", "")).lower():
            return False
        return True


def discover(folder: Path | str | None = None,
             recursive: bool = True) -> list[str]:
    return ["msedge"]


def count_msedge() -> int:
    """Quick helper used by edge_diagnostics."""
    if os.name != "nt":
        return 0
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "(Get-Process msedge -ErrorAction SilentlyContinue).Count"],
            capture_output=True, text=True, timeout=15,
        )
        return int((proc.stdout or "0").strip() or 0)
    except (FileNotFoundError, ValueError, subprocess.TimeoutExpired):
        return 0


def _list_processes(process_name: str = "msedge", timeout: int = 20) -> list[dict[str, Any]]:
    if os.name != "nt":
        return []
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$p = Get-Process %(name)s -ErrorAction SilentlyContinue;"
        "if (-not $p) { '[]'; return };"
        "$rows = foreach ($x in $p) {"
        "  [pscustomobject]@{"
        "    pid = $x.Id;"
        "    name = $x.ProcessName;"
        "    working_set_mb = [math]::Round($x.WorkingSet64 / 1MB, 2);"
        "    private_mb = [math]::Round($x.PrivateMemorySize64 / 1MB, 2);"
        "    cpu_seconds = if ($x.CPU) { [math]::Round($x.CPU, 2) } else { 0 };"
        "    started = if ($x.StartTime) { $x.StartTime.ToString('o') } else { $null };"
        "    threads = $x.Threads.Count;"
        "    handles = $x.HandleCount"
        "  }"
        "};"
        "$rows | ConvertTo-Json -Depth 3 -Compress"
    ) % {"name": process_name}
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


def iter_entries(process_name: str | None = None) -> Iterator[dict[str, Any]]:
    for row in _list_processes(process_name or "msedge"):
        yield row


def apply_filter(entries: Iterable[dict[str, Any]],
                 spec: ProcessFilter | None) -> list[dict[str, Any]]:
    if spec is None or spec.is_empty():
        return list(entries)
    return [e for e in entries if spec.matches(e)]


def around_window(entries: Iterable[dict[str, Any]], *_args, **_kwargs) -> list[dict[str, Any]]:
    return list(entries)


def summarise(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not entries:
        return {"count": 0}
    ws = [float(e.get("working_set_mb", 0) or 0) for e in entries]
    cpu = [float(e.get("cpu_seconds", 0) or 0) for e in entries]
    return {
        "count": len(entries),
        "total_working_set_mb": round(sum(ws), 2),
        "max_working_set_mb": max(ws) if ws else 0,
        "total_cpu_seconds": round(sum(cpu), 2),
        "max_cpu_seconds": max(cpu) if cpu else 0,
    }


def query(sources: Iterable[str] | None = None,
          *,
          filter: ProcessFilter | None = None,
          time_range=None,
          around=None,
          window_seconds: int = 300,
          limit: int | None = None) -> dict[str, Any]:
    names = list(sources) if sources else ["msedge"]
    entries: list[dict[str, Any]] = []
    for n in names:
        entries.extend(iter_entries(n))

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
        "process_names": names,
    }
