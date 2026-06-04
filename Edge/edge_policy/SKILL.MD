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
python edge_policy\scripts\edge_policy.py
```

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- ``_shared/sources/edge_registry`` (``PolicyFilter``: ``category / name_contains / subkey_contains / hive``). Windows-only.

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
