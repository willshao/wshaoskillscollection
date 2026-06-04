"""
Edge/_shared/sources/crashpad.py — canonical reader for Edge Crashpad reports.

Lifts the .dmp enumeration + signature heuristic from edge_crash. Skills
declare what they want via CrashpadFilter; this module does the I/O.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Iterator

from _shared.sources.user_data import default_user_data_dir, resolve_user_data_dir

__all__ = [
    "CrashpadFilter",
    "discover", "iter_entries",
    "summarise", "apply_filter", "around_window", "query",
    "extract_signature",
]


# ---------------------------------------------------------------------------
# Signature heuristics (must mirror edge_crash for back-compat)
# ---------------------------------------------------------------------------

_SIGNATURE_HINTS: list[tuple[re.Pattern[bytes], str]] = [
    (re.compile(rb"msedge\.dll", re.I),         "msedge.dll (main)"),
    (re.compile(rb"chrome_elf\.dll", re.I),     "chrome_elf.dll (early init)"),
    (re.compile(rb"v8\.dll", re.I),             "v8.dll (JS engine)"),
    (re.compile(rb"blink_core\.dll", re.I),     "blink_core (renderer)"),
    (re.compile(rb"libGLESv2\.dll", re.I),      "ANGLE/GPU (libGLESv2)"),
    (re.compile(rb"d3d11\.dll", re.I),          "d3d11 (GPU driver)"),
    (re.compile(rb"nvoglv64\.dll", re.I),       "NVIDIA driver"),
    (re.compile(rb"igd[a-z0-9_]+\.dll", re.I),  "Intel graphics driver"),
    (re.compile(rb"atio[a-z0-9_]+\.dll", re.I), "AMD graphics driver"),
    (re.compile(rb"WidevineCdm", re.I),         "WidevineCdm (DRM)"),
    (re.compile(rb"WinHttp\.dll", re.I),        "WinHTTP"),
]


def extract_signature(dmp: Path) -> str:
    """Best-effort signature from the first 8KB of a .dmp."""
    try:
        with Path(dmp).open("rb") as fh:
            head = fh.read(8192)
    except OSError:
        return "unknown"
    for pat, name in _SIGNATURE_HINTS:
        if pat.search(head):
            return name
    return "unknown"


# ---------------------------------------------------------------------------
# Filter
# ---------------------------------------------------------------------------

@dataclass
class CrashpadFilter:
    signature: str | None = None     # substring on resolved signature name
    process_type: str | None = None  # reserved; signature heuristics only today
    min_size_bytes: int | None = None

    def is_empty(self) -> bool:
        return not any((self.signature, self.process_type, self.min_size_bytes))

    def matches(self, e: dict[str, Any]) -> bool:
        if self.signature and self.signature.lower() not in str(e.get("signature", "")).lower():
            return False
        if self.process_type and self.process_type.lower() not in str(e.get("process_type", "")).lower():
            return False
        if self.min_size_bytes is not None and int(e.get("size_bytes", 0) or 0) < int(self.min_size_bytes):
            return False
        return True


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _default_reports_dir(udd: Path | None = None) -> Path | None:
    udd = udd or default_user_data_dir()
    if udd is None:
        return None
    p = udd / "Crashpad" / "reports"
    return p if p.exists() else None


def discover(folder: Path | str | None = None,
             recursive: bool = True) -> list[Path]:
    """Return .dmp paths under the Crashpad reports directory."""
    if folder is not None:
        base = Path(folder)
        if base.is_file() and base.suffix.lower() == ".dmp":
            return [base]
        if not base.exists():
            return []
        pattern = "**/*.dmp" if recursive else "*.dmp"
        return sorted(base.glob(pattern))
    reports = _default_reports_dir()
    if reports is None:
        return []
    pattern = "**/*.dmp" if recursive else "*.dmp"
    return sorted(reports.glob(pattern))


# ---------------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------------

def iter_entries(path: Path) -> Iterator[dict[str, Any]]:
    """Yield one normalised entry per .dmp under `path` (file or directory)."""
    p = Path(path)
    if p.is_file():
        dmps = [p]
    else:
        dmps = sorted(p.glob("*.dmp"))
    for dmp in dmps:
        try:
            st = dmp.stat()
        except OSError:
            continue
        mtime = datetime.fromtimestamp(st.st_mtime)
        yield {
            "file": dmp.name,
            "path": str(dmp),
            "size_bytes": st.st_size,
            "timestamp": mtime.isoformat(timespec="seconds"),
            "mtime_epoch": st.st_mtime,
            "minutes_ago": round((datetime.now() - mtime).total_seconds() / 60, 1),
            "signature": extract_signature(dmp),
        }


# ---------------------------------------------------------------------------
# Filter / window helpers
# ---------------------------------------------------------------------------

def apply_filter(entries: Iterable[dict[str, Any]],
                 spec: CrashpadFilter | None) -> list[dict[str, Any]]:
    if spec is None or spec.is_empty():
        return list(entries)
    return [e for e in entries if spec.matches(e)]


def around_window(entries: Iterable[dict[str, Any]],
                  anchor: datetime,
                  window_seconds: int) -> list[dict[str, Any]]:
    lo = anchor - timedelta(seconds=window_seconds)
    hi = anchor + timedelta(seconds=window_seconds)
    out: list[dict[str, Any]] = []
    for e in entries:
        try:
            ts = datetime.fromisoformat(str(e.get("timestamp", "")))
        except ValueError:
            continue
        if lo <= ts <= hi:
            out.append(e)
    return out


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def summarise(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not entries:
        return {"count": 0, "by_signature": {}}
    sigs = Counter(e.get("signature", "unknown") for e in entries)
    sizes = sorted(int(e.get("size_bytes", 0) or 0) for e in entries)
    return {
        "count": len(entries),
        "by_signature": dict(sigs.most_common()),
        "top_signature": sigs.most_common(1)[0] if sigs else None,
        "total_size_bytes": sum(sizes),
        "max_size_bytes": sizes[-1] if sizes else 0,
    }


# ---------------------------------------------------------------------------
# Unified query()
# ---------------------------------------------------------------------------

def query(sources: Iterable[Path | str] | None = None,
          *,
          filter: CrashpadFilter | None = None,
          time_range: tuple[datetime | None, datetime | None] | None = None,
          around: datetime | None = None,
          window_seconds: int = 300,
          limit: int | None = None,
          ctx: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run a single combined query across one or more Crashpad reports dirs.

    If `sources` is None, the default %LOCALAPPDATA% reports dir is used
    (honouring `ctx.extra.user_data_dir` when supplied).
    """
    if sources is None:
        udd = resolve_user_data_dir(ctx) if ctx else default_user_data_dir()
        reports = (udd / "Crashpad" / "reports") if udd else None
        src = [reports] if reports and reports.exists() else []
    else:
        src = [Path(p) for p in sources]

    entries: list[dict[str, Any]] = []
    for p in src:
        entries.extend(iter_entries(Path(p)))

    if time_range:
        start, end = time_range
        if start or end:
            def _in_range(e: dict[str, Any]) -> bool:
                try:
                    ts = datetime.fromisoformat(str(e.get("timestamp", "")))
                except ValueError:
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
        "reports_dirs": [str(p) for p in src],
    }
