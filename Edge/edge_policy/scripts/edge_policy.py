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
    Finding, NextStep, SkillResult, load_context,
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

# Canonical reference page that always exists; used as a fetch target.
EDGE_POLICY_REFERENCE_URL = (
    "https://learn.microsoft.com/deployedge/microsoft-edge-policies"
)

# Policies the agent is most likely to want full docs for. These are surfaced
# first when building MCP suggestions so we don't blow up the suggestion list
# on machines with 50+ managed values.
HIGH_INTEREST_NAMES = {
    "ExtensionInstallForcelist", "ExtensionInstallBlocklist",
    "ExtensionInstallAllowlist", "ExtensionSettings",
    "SyncDisabled", "BrowserSignin", "SyncTypesListDisabled",
    "SmartScreenEnabled", "SSLVersionMin", "TLSCipherSuiteDenylist",
    "ProxyMode", "ProxyServer", "ProxyPacUrl", "AuthSchemes",
    "InternetExplorerIntegrationLevel", "InternetExplorerIntegrationSiteList",
    "HomepageLocation", "RestoreOnStartup",
    "DefaultSearchProviderEnabled", "DefaultSearchProviderSearchURL",
    "UpdateDefault", "TargetChannel", "InstallDefault",
}
# Hard cap on how many per-policy searches we ask the agent to run.
MAX_POLICY_SUGGESTIONS = 8


def _build_mslearn_suggestions(
    policies: list[dict[str, Any]],
    by_category: dict[str, int],
) -> dict[str, Any]:
    """
    Build a `raw.mslearn_lookup` block telling the agent which MS Learn MCP
    calls to make so it can look up the canonical documentation for the
    applied Edge policies.

    The Python skill itself never calls MCP tools (they are only available to
    the AI agent in Copilot CLI). It just *describes* the calls to run.
    """
    queries: list[dict[str, str]] = []

    # Always include a fetch of the master policy reference index.
    queries.append({
        "tool": "microsoft_docs_fetch",
        "query": EDGE_POLICY_REFERENCE_URL,
        "why": "Master index of every Edge policy with descriptions and valid values.",
    })

    if not policies:
        # No managed policies — agent may still want the reference to explain
        # the 'Managed by your organization' banner.
        return {
            "enabled": True,
            "rationale": (
                "No managed policies were found locally. The MS Learn "
                "reference still helps explain banners or features the user "
                "might attribute to policy."
            ),
            "site_filter_hint": "site:learn.microsoft.com deployedge",
            "suggested_calls": queries,
        }

    # Resolve the *real* policy name for each row. For scalar policies that's
    # just `r["name"]`. For list/dict policies like `ExtensionInstallForcelist`
    # the entries are numeric value-names ("1", "2", …) under the policy
    # subkey, so the real policy name is the subkey leaf.
    def _policy_name(r: dict[str, Any]) -> str:
        name = (r.get("name") or "").strip()
        if name and not name.isdigit():
            return name
        subkey = r.get("subkey") or ""
        return subkey.split("\\")[-1] if subkey else name

    # Dedupe by resolved policy name; high-interest first, then alphabetical.
    seen: set[str] = set()
    ordered_names: list[str] = []

    def _add(name: str) -> None:
        if name and name not in seen and not name.isdigit():
            seen.add(name)
            ordered_names.append(name)

    resolved = [_policy_name(p) for p in policies]
    for name in resolved:
        if name in HIGH_INTEREST_NAMES:
            _add(name)
    for name in sorted(resolved):
        _add(name)

    # One targeted search per policy, capped.
    for name in ordered_names[:MAX_POLICY_SUGGESTIONS]:
        queries.append({
            "tool": "microsoft_docs_search",
            "query": f"Microsoft Edge policy {name}",
            "why": f"Look up the official definition, valid values and deprecation status for '{name}'.",
        })

    # One search per category to catch related guidance not tied to a single
    # policy name (e.g. proxy modes, IE mode flow). Cap at 3 categories.
    for cat in list(by_category.keys())[:3]:
        queries.append({
            "tool": "microsoft_docs_search",
            "query": f"Microsoft Edge {cat.replace('_', ' ')} policies configure",
            "why": f"Discover related guidance for the '{cat}' policy category.",
        })

    truncated = len(ordered_names) > MAX_POLICY_SUGGESTIONS
    return {
        "enabled": True,
        "rationale": (
            "edge_policy discovers which policies are applied on this machine "
            "but does not embed the official documentation. The agent should "
            "fetch the master policy reference and run per-policy searches "
            "via the Microsoft Learn MCP, then merge descriptions and valid "
            "values into the final reply, citing URLs."
        ),
        "site_filter_hint": "site:learn.microsoft.com deployedge",
        "suggested_calls": queries,
        "truncated": truncated,
        "max_per_policy_suggestions": MAX_POLICY_SUGGESTIONS,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Edge policy inspector")
    ap.add_argument("context", nargs="?", default=None)
    args = ap.parse_args(argv)

    ctx = load_context([args.context] if args.context else [])
    extra = ctx.get("extra") or {}
    use_mslearn = bool(extra.get("use_mslearn", True))

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

    raw_block: dict[str, Any] = {
        "policy_roots_searched": [{"hive": h, "subkey": s} for h, s in POLICY_ROOTS],
        "policies": all_rows,
        "by_category": by_category,
        "by_hive": by_hive,
    }

    # MS Learn MCP integration: publish a structured block the Copilot CLI
    # agent can consume to enrich the per-policy view with official docs.
    if use_mslearn:
        raw_block["mslearn_lookup"] = _build_mslearn_suggestions(all_rows, by_category)
        recommendations.append(
            "[mcp:microsoft_docs_search] Agent: run the queries in "
            "`raw.mslearn_lookup.suggested_calls` to pull official policy "
            "definitions from Microsoft Learn and merge them into the reply."
        )

    result = SkillResult(
        skill=SKILL_ID, ok=True,
        findings=findings,
        root_cause=("Edge is managed by group policy" if all_rows else None),
        confidence="high" if all_rows or os.name == "nt" else "low",
        recommendations=recommendations,
        raw=raw_block,
    )

    if use_mslearn:
        result.next_steps.append(NextStep(
            action=(
                "Call microsoft_docs_fetch on the policy reference URL and "
                "microsoft_docs_search for each item in "
                "raw.mslearn_lookup.suggested_calls; merge official policy "
                "definitions and valid-value tables into the final answer."
            ),
            why="Registry walk lists names+values but not what each policy does.",
            skill="microsoft_docs_mcp",
        ))

    pts = ["managed_browser"] if all_rows else []
    playbook.merge_into_result(result, pts)
    result.emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
