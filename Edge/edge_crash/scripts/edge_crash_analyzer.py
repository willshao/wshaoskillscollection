#!/usr/bin/env python3
"""
edge_crash_analyzer.py — enumerate Edge Crashpad reports.

Reads %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Crashpad\\reports\\*.dmp,
filters by the supplied time window (default: last 24h), and attempts a very
approximate signature extraction from the first 4KB of each minidump.

For real stack walking, use WinDbg with `srv*c:\\symbols*https://msdl.microsoft.com/download/symbols`.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import (  # noqa: E402
    Finding, SkillResult, load_context, time_range,
)
from _shared import playbook  # noqa: E402
from _shared.sources import crashpad as crashpad_src, user_data  # noqa: E402

SKILL_ID = "edge_crash"

# Back-compat re-exports (tests / other skills may import these symbols)
SIGNATURE_HINTS = crashpad_src._SIGNATURE_HINTS
_signature = crashpad_src.extract_signature
_default_user_data_dir = user_data.default_user_data_dir
_resolve_user_data_dir = user_data.resolve_user_data_dir


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Edge Crashpad analyzer")
    ap.add_argument("context", nargs="?", default=None)
    args = ap.parse_args(argv)

    ctx = load_context([args.context] if args.context else [])
    udd = _resolve_user_data_dir(ctx)

    if udd is None:
        no_udd = SkillResult(
            skill=SKILL_ID, ok=True,
            findings=[Finding(
                summary="No Edge User Data directory found.",
                severity="info",
            )],
            confidence="low",
            recommendations=["Confirm Edge is installed and has been launched at least once."],
        )
        playbook.merge_into_result(no_udd, ["crash"])
        no_udd.emit()
        return 0

    crashpad = udd / "Crashpad" / "reports"
    if not crashpad.exists():
        no_dir = SkillResult(
            skill=SKILL_ID, ok=True,
            findings=[Finding(
                summary=f"No Crashpad reports directory at {crashpad}.",
                severity="info",
                evidence={"user_data_dir": str(udd)},
            )],
            confidence="medium",
            recommendations=[
                "If you expect crashes, check whether MetricsReportingEnabled is disabled by policy.",
                "Reproduce the crash; Edge writes a .dmp file each time a process crashes.",
            ],
        )
        playbook.merge_into_result(no_dir, ["crash"])
        no_dir.emit()
        return 0

    start, end = time_range(ctx)
    if start is None:
        start = datetime.now() - timedelta(hours=24)
    if end is None:
        end = datetime.now()

    dmps: list[dict[str, Any]] = []
    sigs: Counter[str] = Counter()
    for dmp in sorted(crashpad.glob("*.dmp"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            mtime = datetime.fromtimestamp(dmp.stat().st_mtime)
        except OSError:
            continue
        if not (start <= mtime <= end):
            continue
        sig = _signature(dmp) or "unknown"
        sigs[sig] += 1
        if len(dmps) < 50:
            dmps.append({
                "file": dmp.name,
                "size_bytes": dmp.stat().st_size,
                "mtime": mtime.isoformat(timespec="seconds"),
                "minutes_ago": round((datetime.now() - mtime).total_seconds() / 60, 1),
                "signature": sig,
            })

    findings: list[Finding] = []
    root_cause: str | None = None
    confidence = "low"

    if not dmps and sigs.total() == 0:
        findings.append(Finding(
            summary=f"No Edge crashes in window {start.isoformat()} → {end.isoformat()}.",
            severity="info",
            evidence={"reports_dir": str(crashpad)},
        ))
        confidence = "high"
    else:
        top, top_n = sigs.most_common(1)[0]
        findings.append(Finding(
            summary=f"{sigs.total()} Edge crash report(s) in window; top signature: {top} ({top_n})",
            severity="critical" if sigs.total() >= 3 else "warning",
            evidence={"by_signature": dict(sigs.most_common())},
        ))
        if top != "unknown" and top_n / max(sigs.total(), 1) >= 0.5:
            root_cause = f"Repeated crashes match signature: {top}"
            confidence = "high" if sigs.total() >= 3 else "medium"

    recommendations: list[str] = []
    if dmps:
        recommendations.extend([
            "Open edge://crashes to see the crash list with upload state.",
            "If a single signature dominates, search learn.microsoft.com / Edge release notes for it.",
            "For a true stack walk, open the .dmp in WinDbg with Microsoft public symbols.",
        ])
        if any(d["signature"].endswith("(GPU)") or "graphics" in d["signature"].lower() for d in dmps):
            recommendations.append("Try launching Edge with `--disable-gpu` to confirm a GPU-driver root cause.")

    result = SkillResult(
        skill=SKILL_ID, ok=True,
        findings=findings, root_cause=root_cause, confidence=confidence,
        recommendations=recommendations,
        raw={
            "user_data_dir": str(udd),
            "reports_dir": str(crashpad),
            "window": {"start": start.isoformat(), "end": end.isoformat()},
            "total_reports_in_window": sigs.total(),
            "by_signature": dict(sigs.most_common()),
            "reports": dmps,
        },
    )
    # Always relevant problem_type for this skill
    pts = ["crash"]
    if any("graphics" in d["signature"].lower() or "GPU" in d["signature"] for d in dmps):
        pts.append("render_process_gone")
    playbook.merge_into_result(result, pts)
    result.emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
