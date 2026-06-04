---
id: edge_extensions
name: Edge Extension Inspector
version: 1.0
role: follow_up
description: Enumerate installed Edge extensions per profile and flag risky / disabled / force-installed entries.
runtime:
  python: scripts/edge_extensions.py
needs_admin: false
triggers_for: [extension_issue, high_memory, page_slow]
---

## When to use
When Edge is misbehaving in ways that point at an extension (memory bloat,
weird page modifications, unexpected redirects, forced add-ons under managed
config).

## What it reads

For each profile under `%LOCALAPPDATA%\Microsoft\Edge\User Data`:
- `Preferences` (JSON) → `extensions.settings` entries
- Per-extension `manifest.json` in `<profile>\Extensions\<id>\<version>\`

## Inputs

| Field | Required | Description |
|---|---|---|
| `extra.profile` | no | Profile name (default: scan all). |

## Output

`raw.profiles[].extensions[]`:
```json
{
  "id": "<32-char>",
  "name": "<display name>",
  "version": "1.2.3",
  "enabled": true,
  "installed_by": "user|admin|external|extension|sideload|unknown",
  "manifest_version": 3,
  "permissions": ["tabs", "<all_urls>"],
  "update_url": "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
}
```

A finding is raised when:
- An extension requests broad host permissions (`<all_urls>`, `*://*/*`)
- An extension is install_by `external` or `sideload`
- An extension uses manifest v2 (deprecated)

## Invocation

```powershell
python edge_extensions\scripts\edge_extensions.py '{"extra":{"profile":"Default"}}'
```

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- ``_shared/sources/user_data`` (``EdgeProfileFilter``: ``profile_name / extension_id / enabled_only``)

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
