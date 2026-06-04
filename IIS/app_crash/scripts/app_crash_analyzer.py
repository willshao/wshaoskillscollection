#!/usr/bin/env python3
"""
app_crash_analyzer.py — .NET / IIS worker process crash diagnosis (v2)

Pulls Application event log entries from sources known to produce crash
records (.NET Runtime, Application Error, IIS-W3SVC-WP) within the
context.time_range, then classifies the most common crash family and
suggests a remediation.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import (  # noqa: E402
    Finding, SkillResult, load_context, parse_time, time_range,
)
from _shared import playbook  # noqa: E402

SKILL_ID = "app_crash"

PROVIDERS = (
    ".NET Runtime",
    "Application Error",
    "IIS-W3SVC-WP",
    "ASP.NET 4.0.30319.0",
)

# Map of (token in message, lowercase) -> crash family
FAMILY_TOKENS: list[tuple[str, str]] = [
    ("outofmemory",        "memory_exhaustion"),
    ("stackoverflow",      "stack_overflow"),
    ("nullreference",      "null_reference"),
    ("argumentnull",       "invalid_argument"),
    ("argumentexception",  "invalid_argument"),
    ("timeout",            "operation_timeout"),
    ("sqlexception",       "database_error"),
    ("invalidoperation",   "invalid_operation"),
    ("filenotfound",       "io_error"),
    ("ioexception",        "io_error"),
    ("threadabort",        "thread_aborted"),
]

REMEDIATION: dict[str, dict[str, Any]] = {
    "memory_exhaustion": {
        "cause": "Worker process exhausted available memory",
        "actions": ["Profile for leaks", "Raise app pool memory limit",
                    "Tune GC / cache eviction"],
        "immediate": "Recycle the application pool",
    },
    "stack_overflow": {
        "cause": "Unbounded recursion",
        "actions": ["Audit recursive functions", "Add depth limit"],
        "immediate": "Patch and redeploy; recycle pool",
    },
    "null_reference": {
        "cause": "Null dereference in application code",
        "actions": ["Add null guards", "Improve input validation"],
        "immediate": "Patch and redeploy",
    },
    "operation_timeout": {
        "cause": "An external operation exceeded its timeout",
        "actions": ["Check downstream latency",
                    "Tune executionTimeout / connection timeouts"],
        "immediate": "Increase timeout temporarily",
    },
    "database_error": {
        "cause": "Database call failed",
        "actions": ["Verify connection string", "Check DB availability",
                    "Review long-running queries"],
        "immediate": "Confirm DB service is up",
    },
}
REMEDIATION_DEFAULT = {
    "cause": "Unclassified application exception",
    "actions": ["Inspect full stack trace", "Recycle the app pool"],
    "immediate": "Recycle the application pool",
}


def query_events(start: datetime, end: datetime, timeout: int = 45) -> list[dict[str, Any]]:
    providers = ",".join(f"'{p}'" for p in PROVIDERS)
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$f=@{LogName='Application'; ProviderName=@(%(prov)s);"
        " StartTime=[datetime]'%(s)s'; EndTime=[datetime]'%(e)s'};"
        "Get-WinEvent -FilterHashtable $f -ErrorAction SilentlyContinue |"
        " Select-Object @{n='TimeCreated';e={$_.TimeCreated.ToString('o')}},"
        "                Id, ProviderName,"
        "                @{n='Message';e={$_.Message -replace \"`r`n\",' '}} |"
        " ConvertTo-Json -Depth 3 -Compress"
    ) % {"prov": providers,
         "s": start.strftime("%Y-%m-%d %H:%M:%S"),
         "e": end.strftime("%Y-%m-%d %H:%M:%S")}
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


def classify(message: str) -> str:
    m = (message or "").lower()
    for token, family in FAMILY_TOKENS:
        if token in m:
            return family
    return "unclassified"


def extract_top_frame(message: str) -> str | None:
    m = re.search(r"at\s+([\w\.]+\.\w+)\(", message or "")
    return m.group(1) if m else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=".NET crash analyzer")
    ap.add_argument("context", nargs="?", default=None)
    args = ap.parse_args(argv)

    if args.context is None and not sys.stdin.isatty():
        ctx = json.loads(sys.stdin.read())
    else:
        ctx = load_context([args.context] if args.context else [])

    start, end = time_range(ctx)
    if start is None or end is None:
        end = datetime.now(timezone.utc).replace(tzinfo=None)
        start = end - timedelta(hours=1)

    events = query_events(start, end)
    if not events:
        no_evt = SkillResult(
            skill=SKILL_ID, ok=True,
            findings=[Finding(summary="No crash events from "
                              + ", ".join(PROVIDERS) + " in window.",
                              severity="info")],
            root_cause=None, confidence="low",
            recommendations=["No app crash explains this symptom; consider resource_monitor."],
            raw={"window": {"start": start.isoformat(), "end": end.isoformat()},
                 "providers": list(PROVIDERS)},
        )
        seed_pt = ctx.get("problem_type")
        if seed_pt:
            playbook.merge_into_result(no_evt, [seed_pt])
        no_evt.emit()
        return 0

    families = Counter(classify(e.get("Message", "")) for e in events)
    top_family, _ = families.most_common(1)[0]
    rem = REMEDIATION.get(top_family, REMEDIATION_DEFAULT)

    samples: list[dict[str, Any]] = []
    for e in events[:5]:
        samples.append({
            "time": e.get("TimeCreated"),
            "provider": e.get("ProviderName"),
            "id": e.get("Id"),
            "family": classify(e.get("Message", "")),
            "top_frame": extract_top_frame(e.get("Message", "")),
            "snippet": (e.get("Message") or "")[:300],
        })

    findings = [
        Finding(
            summary=f"{count} crash event(s) classified as {family}",
            severity="critical" if family in {"memory_exhaustion", "stack_overflow"} else "warning",
            evidence={"family": family, "count": count},
        )
        for family, count in families.most_common()
    ]

    result = SkillResult(
        skill=SKILL_ID, ok=True,
        findings=findings,
        root_cause=rem["cause"],
        confidence="high" if top_family != "unclassified" else "medium",
        recommendations=[f"Immediate: {rem['immediate']}"] + rem["actions"],
        raw={
            "total_events": len(events),
            "family_distribution": dict(families),
            "top_family": top_family,
            "samples": samples,
        },
    )
    # Crashes map to the 5xx_error problem type (app pool worker failure)
    seed_pt = ctx.get("problem_type") or "5xx_error"
    playbook.merge_into_result(result, [seed_pt])
    result.emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
