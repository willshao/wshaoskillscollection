#!/usr/bin/env python3
"""
edge_policy.py — read Microsoft Edge managed policies from the registry.

Read-only. Walks HKLM and HKCU under `Software\\Policies\\Microsoft\\Edge`
plus `Software\\Policies\\Microsoft\\EdgeUpdate`.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import (  # noqa: E402
    Finding, SkillResult, load_context,
)
from _shared import playbook  # noqa: E402
from _shared.sources import edge_registry  # noqa: E402

SKILL_ID = "edge_policy"

POLICY_ROOTS = edge_registry.POLICY_ROOTS
CATEGORY_MAP = edge_registry.CATEGORY_MAP

# Back-compat aliases
_categorize    = edge_registry._categorise
_walk_registry = edge_registry._walk
_reg_type_name = edge_registry._reg_type_name
_coerce        = edge_registry._coerce


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Edge policy inspector")
    ap.add_argument("context", nargs="?", default=None)
    args = ap.parse_args(argv)

    _ = load_context([args.context] if args.context else [])

    all_rows: list[dict[str, Any]] = []
    for hive, base in POLICY_ROOTS:
        all_rows.extend(_walk_registry(hive, base))

    by_category: dict[str, int] = {}
    by_hive: dict[str, int] = {}
    for r in all_rows:
        by_category[r["category"]] = by_category.get(r["category"], 0) + 1
        by_hive[r["hive"]] = by_hive.get(r["hive"], 0) + 1

    findings: list[Finding] = []
    if not all_rows:
        findings.append(Finding(
            summary="No Edge group policies found on this machine.",
            severity="info",
        ))
    else:
        findings.append(Finding(
            summary=f"Edge is managed: {len(all_rows)} policy value(s) across {len(by_category)} categories.",
            severity="info",
            evidence={"by_category": by_category, "by_hive": by_hive},
        ))
        # Surface a few interesting ones explicitly
        for r in all_rows:
            n = r["name"].lower()
            if n in {"extensioninstallforcelist", "extensioninstallblocklist",
                     "syncdisabled", "browsersignin", "smartscreenenabled",
                     "proxymode", "internetexplorerintegrationlevel",
                     "updatedefault", "targetchannel"}:
                findings.append(Finding(
                    summary=f"{r['hive']}\\{r['subkey']}\\{r['name']} = {r['value']!r}",
                    severity="info",
                    evidence={"category": r["category"], "type": r["type"]},
                ))

    recommendations: list[str] = []
    if all_rows:
        recommendations.append("Policies here override user settings in edge://settings; tell the user to contact the IT admin for changes.")
        if any("ExtensionInstallForcelist" in r["subkey"] or r["name"] == "ExtensionInstallForcelist" for r in all_rows):
            recommendations.append("Forced extensions are present — combine with edge_extensions output to confirm they actually loaded.")
        if any(r["name"] in {"UpdateDefault", "TargetChannel"} for r in all_rows):
            recommendations.append("Auto-update behavior is managed; review `EdgeUpdate` policies for the intended channel.")
    else:
        recommendations.append("No managed policies. If user sees 'Managed by your organization', check installed extensions instead.")

    result = SkillResult(
        skill=SKILL_ID, ok=True,
        findings=findings,
        root_cause=("Edge is managed by group policy" if all_rows else None),
        confidence="high" if all_rows or os.name == "nt" else "low",
        recommendations=recommendations,
        raw={
            "policy_roots_searched": [{"hive": h, "subkey": s} for h, s in POLICY_ROOTS],
            "policies": all_rows,
            "by_category": by_category,
            "by_hive": by_hive,
        },
    )
    pts = ["managed_browser"] if all_rows else []
    playbook.merge_into_result(result, pts)
    result.emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
