#!/usr/bin/env python3
"""
edge_extensions.py — enumerate Microsoft Edge extensions per profile.

Reads:
  %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\<profile>\\Preferences
  %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\<profile>\\Extensions\\<id>\\<ver>\\manifest.json

Flags risky permissions, install sources, and legacy manifest v2 extensions.
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
from _shared.sources import user_data as ud_src  # noqa: E402

SKILL_ID = "edge_extensions"

# Map of integer install location codes used by Chromium-style extensions.settings
LOCATION_CODE = {
    1: "user",
    2: "external_pref",
    3: "external_registry",
    4: "unpacked",      # i.e. developer / sideloaded
    5: "component",
    6: "external_policy_download",
    7: "command_line",
    8: "external_policy",
    9: "external_component",
    10: "external_pref_download",
}

RISKY_HOST_PERMS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}


def _user_data_dir() -> Path | None:
    return ud_src.default_user_data_dir()


def _profiles(udd: Path, only: str | None) -> list[str]:
    profs = ud_src.list_profiles(udd)
    if only:
        profs = [p for p in profs if p == only]
    return profs


def _read_prefs(prefs: Path) -> dict[str, Any]:
    try:
        return json.loads(prefs.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}


def _manifest(udd: Path, profile: str, ext_id: str, version: str) -> dict[str, Any]:
    p = udd / profile / "Extensions" / ext_id / version / "manifest.json"
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}


def _collect(udd: Path, profile: str) -> list[dict[str, Any]]:
    prefs = _read_prefs(udd / profile / "Preferences")
    settings = (((prefs.get("extensions") or {}).get("settings")) or {})
    out: list[dict[str, Any]] = []
    for ext_id, entry in settings.items():
        if not isinstance(entry, dict):
            continue
        manifest = entry.get("manifest") or {}
        version = manifest.get("version") or ""
        if not manifest and version == "" and (udd / profile / "Extensions" / ext_id).exists():
            # Fall back to disk manifest if the prefs entry is sparse
            ver_dirs = [d for d in (udd / profile / "Extensions" / ext_id).iterdir() if d.is_dir()]
            if ver_dirs:
                version = ver_dirs[-1].name
                manifest = _manifest(udd, profile, ext_id, version)
        location = entry.get("location")
        location_name = LOCATION_CODE.get(location, str(location)) if location is not None else "unknown"
        state = entry.get("state")  # 0=disabled, 1=enabled, 2=blocklisted
        enabled = state == 1
        out.append({
            "id": ext_id,
            "name": manifest.get("name") or entry.get("path") or "(unknown)",
            "version": version,
            "manifest_version": manifest.get("manifest_version"),
            "enabled": enabled,
            "state_code": state,
            "installed_by": location_name,
            "update_url": manifest.get("update_url") or entry.get("update_url"),
            "permissions": list(manifest.get("permissions") or []),
            "host_permissions": list(manifest.get("host_permissions") or manifest.get("permissions") or []),
        })
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Edge extension inspector")
    ap.add_argument("context", nargs="?", default=None)
    args = ap.parse_args(argv)

    ctx = load_context([args.context] if args.context else [])
    only_profile = (ctx.get("extra") or {}).get("profile")

    udd = _user_data_dir()
    if udd is None:
        no_udd = SkillResult(
            skill=SKILL_ID, ok=True,
            findings=[Finding(summary="No Edge User Data directory found.", severity="info")],
            confidence="low",
        )
        playbook.merge_into_result(no_udd, ["extension_issue"])
        no_udd.emit()
        return 0

    profile_data: list[dict[str, Any]] = []
    findings: list[Finding] = []
    total = 0
    for prof in _profiles(udd, only_profile):
        exts = _collect(udd, prof)
        total += len(exts)
        profile_data.append({"profile": prof, "extensions": exts})
        for e in exts:
            risky = [p for p in (e["host_permissions"] or []) if str(p) in RISKY_HOST_PERMS]
            if risky:
                findings.append(Finding(
                    summary=f"{prof}: '{e['name']}' has broad host permission(s): {risky}",
                    severity="warning",
                    evidence={"id": e["id"], "version": e["version"], "enabled": e["enabled"]},
                ))
            if e["installed_by"] in {"external_pref", "external_registry", "external_pref_download"} and e["enabled"]:
                findings.append(Finding(
                    summary=f"{prof}: '{e['name']}' was sideloaded via {e['installed_by']}",
                    severity="warning",
                    evidence={"id": e["id"]},
                ))
            if e["installed_by"] in {"external_policy", "external_policy_download"}:
                findings.append(Finding(
                    summary=f"{prof}: '{e['name']}' is force-installed by policy",
                    severity="info",
                    evidence={"id": e["id"]},
                ))
            if e["manifest_version"] == 2:
                findings.append(Finding(
                    summary=f"{prof}: '{e['name']}' uses deprecated manifest v2",
                    severity="info",
                    evidence={"id": e["id"]},
                ))

    if total == 0:
        findings.append(Finding(
            summary="No extensions installed in inspected profiles.",
            severity="info",
        ))

    recommendations: list[str] = []
    if any(f.severity == "warning" for f in findings):
        recommendations.append("Disable the flagged extensions one at a time (edge://extensions) to bisect the symptom.")
    if any("policy" in (f.evidence.get("id", "") + str(f.summary)) for f in findings):
        recommendations.append("Force-installed extensions cannot be removed by the user; coordinate with IT.")
    if not recommendations:
        recommendations.append("Nothing obviously risky among the installed extensions.")

    result = SkillResult(
        skill=SKILL_ID, ok=True,
        findings=findings,
        confidence="high" if total else "medium",
        recommendations=recommendations,
        raw={
            "user_data_dir": str(udd),
            "profile_count": len(profile_data),
            "total_extensions": total,
            "profiles": profile_data,
        },
    )
    # Map skill state to playbook problem_types
    pts: list[str] = ["extension_issue"]
    if any("force-installed by policy" in str(f.summary) for f in findings):
        pts.append("extension_blocked")
    playbook.merge_into_result(result, pts)
    result.emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
