#!/usr/bin/env python3
"""
firewall_analyzer.py — firewall / WAF anomaly detection (framework, v2)

Real implementation parses Windows Firewall log
(C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log) and any WAF log,
clusters by client IP + URI, and flags DDoS-like patterns. This file
ships the contract envelope.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import Finding, SkillResult, load_context  # noqa: E402
from _shared import playbook  # noqa: E402

SKILL_ID = "firewall"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Firewall/WAF analyzer (framework)")
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
                "Parse pfirewall.log lines (action, protocol, src ip, dst port)",
                "Aggregate DROP per src IP",
                "Cross-check with IIS suspicious_traffic finding",
            ]},
        )],
        confidence="low",
        recommendations=[
            "Implement pfirewall.log parser (W3C-style header)",
            "Until then, use the suspicious-IP from iis_logs to add a temporary block rule.",
        ],
        raw={"status": "framework"},
    )
    seed_pt = ctx.get("problem_type") or "suspicious_traffic"
    playbook.merge_into_result(result, [seed_pt])
    result.emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
