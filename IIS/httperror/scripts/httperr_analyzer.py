#!/usr/bin/env python3
"""
httperr_analyzer.py — HTTP.SYS error log analyzer (v2)

Parses C:\\Windows\\System32\\LogFiles\\HTTPERR\\httperr*.log, filters by
context.time_range, and reports recurring failure modes.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import (  # noqa: E402
    Finding, SkillResult, load_context, parse_time, time_range, in_window,
)
from _shared.log_discovery import (  # noqa: E402
    discover_logs, HTTPERR_KIND, IIS_KIND, FTP_KIND, UNKNOWN_KIND,
)
from _shared import playbook  # noqa: E402
from _shared.logs import httperr as httperr_reader  # noqa: E402

# Re-export shared parse_line so legacy imports + tests keep working
parse_line = httperr_reader.parse_line

# Map common HTTP.SYS reasons to playbook problem_types
REASON_TO_PROBLEM_TYPE = {
    "Connection_Abandoned_By_AppPool": "5xx_error",
    "Timer_AppPool":                   "5xx_error",
    "Timer_HeaderWait":                "high_latency",
    "Timer_EntityBody":                "high_latency",
    "Timer_MinBytesPerSecond":         "high_latency",
}

SKILL_ID = "httperror"
HTTPERR_DIR = Path(r"C:\Windows\System32\LogFiles\HTTPERR")

# Common HTTP.SYS reason phrases (Windows ships these in the log).
REASON_HINTS: dict[str, str] = {
    "Timer_ConnectionIdle":  "Idle connection closed by HTTP.SYS",
    "Timer_HeaderWait":      "Client did not send headers in time",
    "Timer_MinBytesPerSecond": "Slow client / network throttling",
    "Timer_EntityBody":      "Request body never finished",
    "Timer_AppPool":         "App pool failed to dequeue request in time",
    "Connection_Abandoned_By_AppPool": "App pool crashed/recycled",
    "Connection_Dropped":    "Lower-level connection drop",
    "URL_Length":            "Request URL exceeded configured limit",
    "BadRequest":            "Malformed HTTP request",
    "Forbidden":             "HTTP.SYS rejected the URL",
    "N/A":                   "Not classified",
    "-":                     "Not classified",
}


def latest_log() -> Path | None:
    files = httperr_reader.discover()
    return files[-1] if files else None


# parse_line lives in _shared.logs.httperr (re-exported above as parse_line).


def analyze(log_file: Path, start: datetime | None,
            end: datetime | None) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    with log_file.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            row = parse_line(line.rstrip("\n"))
            if not row:
                continue
            try:
                ts = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                rows.append(row)  # keep but unfiltered
                continue
            if not in_window(ts, start, end, tolerance_minutes=2):
                continue
            rows.append(row)

    reasons = Counter(r["reason"] for r in rows)
    top_ip, top_n = (Counter(r["client_ip"] for r in rows).most_common(1) or [(None, 0)])[0]
    suspicious = bool(top_ip and rows and top_n / len(rows) > 0.30)
    return {
        "log_file": str(log_file),
        "rows_in_window": len(rows),
        "top_reasons": reasons.most_common(5),
        "top_client_ip": {"ip": top_ip, "count": top_n} if top_ip else None,
        "ddos_suspected": suspicious,
        "sample": rows[:5],
    }


def _analyze_folder(folder: Path, recursive: bool,
                    start: datetime | None,
                    end: datetime | None) -> dict[str, Any]:
    """Discover every HTTPERR log under `folder` and aggregate stats across them."""
    disc = discover_logs(folder, recursive=recursive)
    httperr_files = list(disc.by_kind.get(HTTPERR_KIND, []))
    per_file: dict[str, dict[str, Any]] = {}
    total_rows = 0
    reasons: Counter[str] = Counter()
    ip_counter: Counter[str] = Counter()
    samples: list[dict[str, Any]] = []

    for f in httperr_files:
        d = analyze(f, start, end)
        per_file[str(f)] = d
        total_rows += d["rows_in_window"]
        for reason, n in d["top_reasons"]:
            reasons[reason] += n
        if d["top_client_ip"]:
            ip_counter[d["top_client_ip"]["ip"]] += d["top_client_ip"]["count"]
        samples.extend(d["sample"][:2])

    top_ip, top_n = (ip_counter.most_common(1) or [(None, 0)])[0]
    suspicious = bool(top_ip and total_rows and top_n / total_rows > 0.30)

    detected_other: dict[str, list[str]] = {}
    for kind in (IIS_KIND, FTP_KIND, UNKNOWN_KIND):
        files = disc.by_kind.get(kind, [])
        if files:
            detected_other[kind] = [str(p) for p in files]

    return {
        "folder": str(folder),
        "recursive": recursive,
        "log_files": [str(f) for f in httperr_files],
        "rows_in_window": total_rows,
        "top_reasons": reasons.most_common(5),
        "top_client_ip": {"ip": top_ip, "count": top_n} if top_ip else None,
        "ddos_suspected": suspicious,
        "sample": samples[:5],
        "per_file": per_file,
        "detected_other_logs": detected_other,
    }


def _findings_from_stats(top_reasons: list[tuple[str, int]],
                         top_client_ip: dict[str, Any] | None,
                         ddos_suspected: bool) -> list[Finding]:
    findings: list[Finding] = []
    for reason, count in top_reasons:
        findings.append(Finding(
            summary=f"{reason}: {count} hits — {REASON_HINTS.get(reason, 'see HTTP.SYS docs')}",
            severity="warning",
            evidence={"reason": reason, "count": count},
        ))
    if ddos_suspected and top_client_ip:
        findings.append(Finding(
            summary=f"Single client IP {top_client_ip['ip']} dominates "
                    f"({top_client_ip['count']} requests)",
            severity="critical",
            evidence=top_client_ip,
        ))
    if not findings:
        findings.append(Finding(
            summary="No HTTPERR entries in the requested window.",
            severity="info",
        ))
    return findings


def _emit_single(data: dict[str, Any]) -> None:
    findings = _findings_from_stats(
        data["top_reasons"], data["top_client_ip"], data["ddos_suspected"],
    )
    result = SkillResult(
        skill=SKILL_ID, ok=True,
        findings=findings,
        root_cause=(
            f"HTTP.SYS reason: {data['top_reasons'][0][0]}"
            if data["top_reasons"] else None
        ),
        confidence="medium" if data["top_reasons"] else "low",
        recommendations=[
            "Cross-check Application event log around the same window (event_log skill)",
        ],
        raw=data,
    )
    pts = _problem_types_from_data(data)
    playbook.merge_into_result(result, pts)
    result.emit()


def _emit_folder(agg: dict[str, Any]) -> None:
    findings = _findings_from_stats(
        agg["top_reasons"], agg["top_client_ip"], agg["ddos_suspected"],
    )
    if not agg["log_files"]:
        findings.insert(0, Finding(
            summary=f"No HTTPERR logs discovered under {agg['folder']}",
            severity="info",
            evidence={"detected_other_logs": agg["detected_other_logs"]},
        ))
    result = SkillResult(
        skill=SKILL_ID, ok=True,
        findings=findings,
        root_cause=(
            f"HTTP.SYS reason: {agg['top_reasons'][0][0]} "
            f"(aggregated over {len(agg['log_files'])} log(s))"
            if agg["top_reasons"] else None
        ),
        confidence="medium" if agg["top_reasons"] else "low",
        recommendations=[
            "Cross-check Application event log around the same window (event_log skill)",
        ],
        raw=agg,
    )
    pts = _problem_types_from_data(agg)
    playbook.merge_into_result(result, pts)
    result.emit()


def _problem_types_from_data(data: dict[str, Any]) -> list[str]:
    """Derive playbook problem_types from observed reasons + traffic patterns."""
    pts: list[str] = []
    for reason, _count in data.get("top_reasons") or []:
        mapped = REASON_TO_PROBLEM_TYPE.get(reason)
        if mapped and mapped not in pts:
            pts.append(mapped)
    if data.get("ddos_suspected") and "suspicious_traffic" not in pts:
        pts.append("suspicious_traffic")
    return pts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="HTTP.SYS error log analyzer")
    ap.add_argument("context", nargs="?", default=None,
                    help="JSON context (string, @file) or omit to read stdin")
    ap.add_argument("--log", help="Override path to a single httperr*.log")
    ap.add_argument("--folder",
                    help="Discover HTTPERR logs under this folder "
                         "(overrides default HTTPERR dir; --log takes precedence)")
    ap.add_argument("--no-recursive", action="store_true",
                    help="With --folder, do not descend into subfolders")
    args = ap.parse_args(argv)

    if args.context is None and not sys.stdin.isatty():
        import json
        ctx = json.loads(sys.stdin.read())
    else:
        ctx = load_context([args.context] if args.context else [])

    extra = ctx.get("extra") or {}
    folder_arg = args.folder or extra.get("folder")
    no_recursive = bool(args.no_recursive or extra.get("no_recursive"))

    start, end = time_range(ctx)

    # Resolution order: --log > --folder/extra.folder > latest_log() default dir.
    if args.log:
        log_file = Path(args.log)
        if not log_file.exists():
            SkillResult(
                skill=SKILL_ID, ok=True,
                findings=[Finding(
                    summary=f"--log path does not exist: {log_file}",
                    severity="info",
                )],
                confidence="low",
                raw={"log_file": str(log_file)},
            ).emit()
            return 0
        _emit_single(analyze(log_file, start, end))
        return 0

    if folder_arg:
        folder = Path(folder_arg)
        if not folder.exists():
            SkillResult(
                skill=SKILL_ID, ok=True,
                findings=[Finding(
                    summary=f"--folder does not exist: {folder}",
                    severity="info",
                )],
                confidence="low",
                raw={"folder": str(folder)},
            ).emit()
            return 0
        _emit_folder(_analyze_folder(folder, recursive=not no_recursive,
                                     start=start, end=end))
        return 0

    # Legacy default: latest log under C:\Windows\System32\LogFiles\HTTPERR.
    log_file = latest_log()
    if not log_file or not log_file.exists():
        SkillResult(
            skill=SKILL_ID, ok=True,
            findings=[Finding(
                summary=f"No HTTPERR log present under {HTTPERR_DIR}",
                severity="info",
                evidence={"searched_path": str(HTTPERR_DIR)},
            )],
            confidence="low",
            recommendations=[
                "Run this skill on the IIS host, pass --log <path>, or pass --folder <dir>.",
            ],
            raw={"log_file": None},
        ).emit()
        return 0

    _emit_single(analyze(log_file, start, end))
    return 0


if __name__ == "__main__":
    sys.exit(main())
