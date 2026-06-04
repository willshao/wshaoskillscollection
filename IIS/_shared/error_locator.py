"""
_shared/error_locator.py

Cross-log error-pattern search with timestamp extraction.

Given a list of text log files (IIS W3C, FTP W3C, HTTPERR, plain *.log /
*.txt) and a regex, this module finds every line that matches and tries
to recover a timestamp from the line itself or the nearest preceding
header / data line. The orchestrator uses the resulting timestamps as
`--around` anchors so downstream skills can zoom into the right window.

Pure standard library.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

# Recognised timestamp shapes (most specific first).
_TS_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # ISO 8601 with optional fractional seconds and 'T' separator.
    (re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?"),
     "%Y-%m-%d %H:%M:%S"),
    # IIS/HTTPERR "YYYY-MM-DD HH:MM:SS"
    (re.compile(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})"),
     "%Y-%m-%d %H:%M:%S"),
    # syslog-ish "MMM dd HH:MM:SS" — year omitted, caller may not rely on this
    (re.compile(r"([A-Z][a-z]{2} +\d{1,2}) (\d{2}:\d{2}:\d{2})"),
     "%b %d %H:%M:%S"),
)

# How many lines to look back when the matching line has no timestamp.
_BACKTRACK_LINES = 5
# Cap scanned bytes per file to keep memory sane on huge logs.
_MAX_FILE_BYTES = 200 * 1024 * 1024  # 200 MB
# Cap the number of hits returned overall.
DEFAULT_MAX_HITS = 50


@dataclass(frozen=True)
class ErrorHit:
    file: str
    lineno: int
    timestamp: datetime | None
    excerpt: str
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "file": self.file,
            "lineno": self.lineno,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                         if self.timestamp else None,
            "excerpt": self.excerpt,
            "note": self.note,
        }


def _extract_timestamp(line: str) -> datetime | None:
    for pat, fmt in _TS_PATTERNS:
        m = pat.search(line)
        if not m:
            continue
        try:
            if len(m.groups()) == 2:
                raw = f"{m.group(1)} {m.group(2)}"
            else:
                raw = m.group(0)
            # Normalise 'T' to space so a single fmt works.
            raw = raw.replace("T", " ")
            # Drop fractional seconds if present.
            if "." in raw:
                raw = raw.split(".", 1)[0]
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def _iter_matches_in_file(path: Path, pattern: re.Pattern[str],
                          max_hits: int) -> Iterable[ErrorHit]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        yield ErrorHit(file=str(path), lineno=0, timestamp=None,
                       excerpt="", note=f"stat failed: {exc}")
        return
    if size > _MAX_FILE_BYTES:
        yield ErrorHit(file=str(path), lineno=0, timestamp=None,
                       excerpt="", note=f"skipped: file > {_MAX_FILE_BYTES} bytes")
        return

    recent: list[str] = []  # last N lines (for backtrack)
    hits = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                if not pattern.search(line):
                    if len(recent) >= _BACKTRACK_LINES:
                        recent.pop(0)
                    recent.append(line.rstrip("\n"))
                    continue
                ts = _extract_timestamp(line)
                if ts is None:
                    # Walk back looking for a recent line with a timestamp.
                    for prev in reversed(recent):
                        ts = _extract_timestamp(prev)
                        if ts is not None:
                            break
                excerpt = line.rstrip("\n")[:240]
                yield ErrorHit(file=str(path), lineno=lineno,
                               timestamp=ts, excerpt=excerpt)
                hits += 1
                if hits >= max_hits:
                    return
                if len(recent) >= _BACKTRACK_LINES:
                    recent.pop(0)
                recent.append(line.rstrip("\n"))
    except OSError as exc:
        yield ErrorHit(file=str(path), lineno=0, timestamp=None,
                       excerpt="", note=f"read failed: {exc}")


def find_error_anchors(files: Iterable[Path], pattern: str,
                       max_hits: int = DEFAULT_MAX_HITS) -> list[ErrorHit]:
    """
    Scan `files` for `pattern` (regex, case-insensitive) and return every
    matching line with its best-effort timestamp.

    Binary files (currently identified by `.evtx` suffix) are skipped; a
    single info-only ErrorHit is recorded for visibility.
    """
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ValueError(f"invalid --error regex: {exc}") from exc

    out: list[ErrorHit] = []
    for p in files:
        if p.suffix.lower() == ".evtx":
            out.append(ErrorHit(file=str(p), lineno=0, timestamp=None,
                                excerpt="", note="binary .evtx skipped by error locator"))
            continue
        for hit in _iter_matches_in_file(p, rx, max_hits=max_hits):
            out.append(hit)
            if len([h for h in out if h.excerpt]) >= max_hits:
                return out
    return out


def dedup_anchors(hits: Iterable[ErrorHit],
                  min_gap_seconds: int = 60) -> list[datetime]:
    """
    Collapse hit timestamps into a sorted, de-duplicated list of anchors.

    Two anchors closer than `min_gap_seconds` are merged into the earlier one.
    """
    stamps = sorted({h.timestamp for h in hits if h.timestamp is not None})
    if not stamps:
        return []
    gap = timedelta(seconds=min_gap_seconds)
    merged: list[datetime] = [stamps[0]]
    for ts in stamps[1:]:
        if ts - merged[-1] >= gap:
            merged.append(ts)
    return merged


__all__ = [
    "ErrorHit", "DEFAULT_MAX_HITS",
    "find_error_anchors", "dedup_anchors",
]
