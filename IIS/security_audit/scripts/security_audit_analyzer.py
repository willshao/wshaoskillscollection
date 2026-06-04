#!/usr/bin/env python3
"""
security_audit_analyzer.py — auth/permission diagnosis (framework, v2)

Real implementation queries the Security event log (4625 logon failure,
4656/4663 object access denied, 4672 privilege use, etc.) and correlates
to IIS 401/403 entries. This file ships the standard contract envelope so
downstream callers and the orchestrator integrate cleanly today.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import Finding, SkillResult, load_context  # noqa: E402
from _shared import playbook  # noqa: E402

SKILL_ID = "security_audit"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Auth/permission diagnosis (framework)")
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
            evidence={"todo": ["Query Security log for 4625/4656/4663/4672",
                              "Correlate to IIS 401/403 by client ip + time",
                              "Report top failing principals + targeted resources"]},
        )],
        confidence="low",
        recommendations=[
            "Implement Get-WinEvent FilterHashtable for LogName='Security'",
            "Until then, treat 401/403 spikes as configuration issues "
            "in app pool identity or NTFS ACLs.",
        ],
        raw={"status": "framework"},
    )
    seed_pt = ctx.get("problem_type") or "auth_error"
    playbook.merge_into_result(result, [seed_pt])
    result.emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
