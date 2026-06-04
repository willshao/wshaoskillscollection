---
id: edge_policy
name: Edge Policy Inspector
version: 1.0
role: follow_up
description: Read Edge policy registry hives (HKLM/HKCU\Software\Policies\Microsoft\Edge) and report applied managed policies.
runtime:
  python: scripts/edge_policy.py
needs_admin: false
triggers_for: [managed_browser, feature_blocked, update_blocked, extension_blocked]
---

## When to use
When the user reports "Managed by your organization", missing features,
forced extensions, blocked updates, or any behavior that looks like a Group
Policy / MDM override.

## What it reads

- `HKLM\Software\Policies\Microsoft\Edge` and its subkeys
- `HKCU\Software\Policies\Microsoft\Edge` and its subkeys
- `HKLM\Software\Policies\Microsoft\EdgeUpdate` (channel pinning, auto-update)

The skill **does not modify** any registry key.

## Output

`raw.policies` is a flat list:
```json
{
  "hive": "HKLM",
  "subkey": "ExtensionInstallForcelist",
  "name": "1",
  "type": "REG_SZ",
  "value": "abcd;https://edge.microsoft.com/extensionwebstorebase/v1/crx",
  "category": "extension_management"
}
```

`raw.categories` rolls these up by interest area (security, update, extension,
sync, browser_features, network).

## Categories surfaced

| Category | Sample policies |
|---|---|
| `update` | `UpdateDefault`, `Update<channel>`, `TargetChannel`, `InstallDefault` |
| `extension_management` | `ExtensionInstallForcelist`, `ExtensionInstallBlocklist`, `ExtensionInstallAllowlist`, `ExtensionSettings` |
| `security` | `SmartScreenEnabled`, `SSLVersionMin`, `TLSCipherSuiteDenylist` |
| `sync` | `SyncDisabled`, `BrowserSignin`, `SyncTypesListDisabled` |
| `network` | `ProxyMode`, `ProxyServer`, `ProxyPacUrl`, `AuthSchemes` |
| `browser_features` | `HomepageLocation`, `RestoreOnStartup`, `DefaultSearchProvider*`, `InternetExplorerIntegrationLevel` |

## Invocation

```powershell
# Default: registry walk + MS Learn MCP suggestions
python edge_policy\scripts\edge_policy.py

# Offline-only (no MS Learn suggestions)
python edge_policy\scripts\edge_policy.py '{"extra":{"use_mslearn":false}}'
```

## MS Learn MCP integration

The Python skill cannot call MCP tools itself — `microsoft_docs_search`,
`microsoft_docs_fetch`, and `microsoft_code_sample_search` are only available
to the AI agent running inside Copilot CLI. So the skill publishes a
structured `raw.mslearn_lookup` block telling the agent which MCP queries to
run in order to fetch the **official policy definitions, valid values, and
deprecation status** for each applied policy.

The agent contract is:

1. `edge_policy` walks the registry and returns `raw.policies[]` (names,
   values, types, categories).
2. The skill builds `raw.mslearn_lookup` containing:
   - A `microsoft_docs_fetch` call for the master policy reference
     (`https://learn.microsoft.com/deployedge/microsoft-edge-policies`).
   - Up to **8** `microsoft_docs_search` calls — one per applied policy,
     prioritising a curated list of high-interest names (forced extensions,
     IE mode, proxy, sync, SmartScreen, update channel pinning, …). Numeric
     value names like `"1"` inside list policies are resolved back to their
     parent subkey leaf (e.g. `ExtensionInstallForcelist`).
   - Up to **3** category-level searches (e.g. *"Microsoft Edge security
     policies configure"*) for cross-policy guidance.
   - A `truncated: true` flag if more policies exist than the per-policy cap.
3. The agent loops over `suggested_calls`, invokes each MCP tool, and merges
   the live results — official definitions, valid value tables, deprecation
   notes, references — into the final reply, citing the URLs.
4. To force offline behaviour (air-gapped, CI), set
   `extra.use_mslearn: false`; the skill then omits the block entirely.

A `[mcp:microsoft_docs_search]` tag is added to `recommendations[]` and a
`NextStep` with `skill: microsoft_docs_mcp` is appended so the cue surfaces
even in flattened views.

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- ``_shared/sources/edge_registry`` (``PolicyFilter``: ``category / name_contains / subkey_contains / hive``). Windows-only.

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
