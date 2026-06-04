#!/usr/bin/env python3
"""
event_log_analyzer.py — Windows Event Log correlator (v2)

Improvements vs v1:
  * Uses Get-WinEvent + FilterHashtable (faster, supports newer logs,
    works on systems where Get-EventLog has been deprecated)
  * Actually honours context.time_range instead of the fake "last 1 hour"
  * Uses _shared.contract for envelope + path resolution
  * Graceful degradation when not running elevated
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import (  # noqa: E402
    Finding, SkillResult, fail, load_context, parse_time, time_range, in_window,
    _normalize_tz,
)
from _shared import playbook  # noqa: E402
from _shared.logs import evtx as evtx_reader  # noqa: E402  (shared wrappers; kept for downstream reuse)

_ = evtx_reader  # silence unused-import while preserving the documented dependency

SKILL_ID = "event_log"

EVENT_ID_MAP: dict[int, dict[str, str]] = {
    1000: {"name": ".NET application crash", "severity": "critical"},
    1001: {"name": "Application pool recycle", "severity": "warning"},
    1026: {"name": ".NET runtime error",      "severity": "critical"},
    2004: {"name": "Resource exhaustion (perfmon alert)", "severity": "critical"},
     219: {"name": "Driver / disk warning",   "severity": "warning"},
    7000: {"name": "Service failed to start", "severity": "critical"},
    7009: {"name": "Service start timeout",   "severity": "warning"},
    7034: {"name": "Service terminated unexpectedly", "severity": "critical"},
    5719: {"name": "Domain controller unreachable", "severity": "warning"},
}

# Map IIS problem type → which event ids most likely explain it
ROOT_CAUSE_HINTS: dict[str, list[int]] = {
    "5xx_error":      [1000, 1001, 1026, 7034],
    "high_latency":   [2004, 219],
    "auth_error":     [],   # security log, see security_audit skill
}


def _query_winevent(log_name: str, start: datetime, end: datetime,
                    timeout: int = 45) -> list[dict[str, Any]]:
    """Query a Windows event log via PowerShell."""
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$f=@{LogName='%(log)s'; StartTime=[datetime]'%(start)s';"
        " EndTime=[datetime]'%(end)s'; Level=1,2,3};"
        "Get-WinEvent -FilterHashtable $f -ErrorAction SilentlyContinue |"
        " Select-Object @{n='TimeCreated';e={$_.TimeCreated.ToString('o')}},"
        "                Id, ProviderName, LevelDisplayName,"
        "                @{n='Message';e={$_.Message -replace \"`r`n\",' ' }} |"
        " ConvertTo-Json -Depth 3 -Compress"
    ) % {"log": log_name,
         "start": start.strftime("%Y-%m-%d %H:%M:%S"),
         "end":   end.strftime("%Y-%m-%d %H:%M:%S")}
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        return []  # Not on Windows
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]


def _query_winevent_from_path(evtx_path: Path, start: datetime, end: datetime,
                              timeout: int = 60) -> list[dict[str, Any]]:
    """Read a saved .evtx file with Get-WinEvent -Path and time-filter results."""
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$s=[datetime]'%(start)s'; $e=[datetime]'%(end)s';"
        "Get-WinEvent -Path '%(path)s' -ErrorAction SilentlyContinue |"
        " Where-Object { $_.TimeCreated -ge $s -and $_.TimeCreated -le $e } |"
        " Select-Object @{n='TimeCreated';e={$_.TimeCreated.ToString('o')}},"
        "                Id, ProviderName, LevelDisplayName,"
        "                @{n='Message';e={$_.Message -replace \"`r`n\",' ' }} |"
        " ConvertTo-Json -Depth 3 -Compress"
    ) % {"path":  str(evtx_path).replace("'", "''"),
         "start": start.strftime("%Y-%m-%d %H:%M:%S"),
         "end":   end.strftime("%Y-%m-%d %H:%M:%S")}
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        return []  # PowerShell unavailable (non-Windows)
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]


def correlate(events: list[dict[str, Any]], start: datetime, end: datetime,
              tolerance_min: float = 2.0) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ev in events:
        tc = ev.get("TimeCreated")
        if not tc:
            continue
        try:
            ts = parse_time(tc)
        except ValueError:
            continue
        if not in_window(ts, start, end, tolerance_min):
            continue
        eid = int(ev.get("Id", 0) or 0)
        meta = EVENT_ID_MAP.get(eid, {"name": "Unmapped event", "severity": "info"})
        diff_min = (_normalize_tz(ts, start)[0] - _normalize_tz(ts, start)[1]).total_seconds() / 60 if start else 0.0
        out.append({
            "event_id": eid,
            "name": meta["name"],
            "severity": meta["severity"],
            "time": tc,
            "provider": ev.get("ProviderName"),
            "message": (ev.get("Message") or "")[:400],
            "correlation": "strong" if abs(diff_min) <= 1 else "weak",
            "minutes_from_window_start": round(diff_min, 2),
        })
    out.sort(key=lambda x: abs(x["minutes_from_window_start"]))
    return out


def infer_root_cause(problem_type: str | None,
                     correlated: list[dict[str, Any]]) -> tuple[str | None, str]:
    """Return (root_cause_text, confidence)."""
    if not correlated:
        return None, "low"
    hints = set(ROOT_CAUSE_HINTS.get(problem_type or "", []))
    matches = [e for e in correlated if e["event_id"] in hints]
    if matches:
        e = matches[0]
        return f"{e['name']} (event {e['event_id']}) at {e['time']}", "high"
    crit = next((e for e in correlated if e["severity"] == "critical"), None)
    if crit:
        return f"{crit['name']} at {crit['time']}", "medium"
    return f"{correlated[0]['name']} at {correlated[0]['time']}", "low"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Windows Event Log correlator")
    ap.add_argument("context", nargs="?", default=None,
                    help="JSON context (string, @file) or omit to read stdin")
    ap.add_argument("--logs", nargs="+", default=["Application", "System"],
                    help="Event logs to query (live mode)")
    ap.add_argument("--evtx", action="append", default=[],
                    help="Path to a saved .evtx file. Repeat for multiple. "
                         "When given, --logs is ignored and offline mode is used.")
    ap.add_argument("--tolerance-min", type=float, default=2.0)
    args = ap.parse_args(argv)

    if args.context is None and not sys.stdin.isatty():
        ctx = json.loads(sys.stdin.read())
    else:
        ctx = load_context([args.context] if args.context else [])

    # Merge --evtx with extra.evtx_paths from JSON context.
    extra_paths = list((ctx.get("extra") or {}).get("evtx_paths") or [])
    evtx_paths = [Path(p) for p in (list(args.evtx) + extra_paths)]

    start, end = time_range(ctx)
    if start is None or end is None:
        # Fallback: last hour ending now
        end = datetime.now(timezone.utc).replace(tzinfo=None)
        start = end - timedelta(hours=1)

    all_events: list[dict[str, Any]] = []
    source_note: str
    if evtx_paths:
        missing = [p for p in evtx_paths if not p.exists()]
        usable  = [p for p in evtx_paths if p.exists()]
        for p in usable:
            all_events.extend(_query_winevent_from_path(p, start, end))
        source_note = "evtx:" + ",".join(str(p) for p in usable) if usable else "evtx:none"
        if missing:
            source_note += " (missing: " + ",".join(str(p) for p in missing) + ")"
    else:
        for log_name in args.logs:
            all_events.extend(_query_winevent(log_name, start, end))
        source_note = "live_eventlog:" + ",".join(args.logs)

    correlated = correlate(all_events, start, end, args.tolerance_min)
    root_cause, confidence = infer_root_cause(ctx.get("problem_type"), correlated)

    findings = [
        Finding(
            summary=f"{c['name']} (event {c['event_id']}) at {c['time']}",
            severity=c["severity"],
            evidence={"provider": c["provider"], "correlation": c["correlation"],
                      "delta_min": c["minutes_from_window_start"]},
        )
        for c in correlated[:10]
    ]
    if not findings:
        findings.append(Finding(
            summary="No correlated events in the requested window",
            severity="info",
        ))

    result = SkillResult(
        skill=SKILL_ID,
        ok=True,
        findings=findings,
        root_cause=root_cause,
        confidence=confidence,
        recommendations=(
            ["Inspect the listed events; cross-check with app_crash skill if event 1000/1026 is present."]
            if correlated else
            ["No system-level events explain the IIS symptom in this window."]
        ),
        raw={
            "source": source_note,
            "queried_logs": args.logs if not evtx_paths else [],
            "evtx_paths": [str(p) for p in evtx_paths],
            "window": {"start": start.isoformat(), "end": end.isoformat()},
            "total_events_returned": len(all_events),
            "correlated": correlated,
        },
    )
    # Seed playbook merge from the caller-supplied problem_type (e.g. "5xx_error").
    seed_pt = ctx.get("problem_type")
    if seed_pt:
        playbook.merge_into_result(result, [seed_pt])
    result.emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
