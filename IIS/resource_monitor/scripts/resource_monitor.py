#!/usr/bin/env python3
"""
resource_monitor.py — CPU/memory/disk pressure (framework, v2)

Real implementation samples \\Process(w3wp*) counters and correlates
spikes to IIS latency. This file ships the contract envelope.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import Finding, SkillResult, load_context  # noqa: E402
from _shared import playbook  # noqa: E402

SKILL_ID = "resource_monitor"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="System resource monitor (framework)")
    ap.add_argument("context", nargs="?", default=None)
    args = ap.parse_args(argv)

    if args.context is None and not sys.stdin.isatty():
        ctx = json.loads(sys.stdin.read())
    else:
        ctx = load_context([args.context] if args.context else [])

    result = SkillResult(
        skill=SKILL_ID, ok=True,
        findings=[Finding(
            summary="Framework stub: not implemented yet.",
            severity="info",
            evidence={"todo": [
                "Sample Get-Counter '\\Processor(_Total)\\% Processor Time'",
                "Sample '\\Memory\\Available MBytes' and per-w3wp Working Set",
                "Sample '\\PhysicalDisk(_Total)\\Avg. Disk sec/Read/Write'",
                "Flag readings above thresholds during context.time_range",
            ]},
        )],
        confidence="low",
        recommendations=[
            "Implement Get-Counter sampling for the requested time_range",
            "Until then, manually inspect Task Manager / Resource Monitor.",
        ],
        raw={"status": "framework"},
    )
    seed_pt = ctx.get("problem_type") or "high_latency"
    playbook.merge_into_result(result, [seed_pt])
    result.emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
