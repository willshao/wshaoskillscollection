---
id: edge_crash
name: Edge Crash Analyzer
version: 1.0
role: follow_up
description: Enumerate Edge Crashpad reports, group by signature, and report crash frequency over a time window.
runtime:
  python: scripts/edge_crash_analyzer.py
needs_admin: false
triggers_for: [crash, hang, render_process_gone]
---

## When to use
After `edge_diagnostics` classifies a `crash`, `hang`, or `render_process_gone`
problem, or directly when the user says Edge keeps crashing.

## Inputs

| Field | Required | Description |
|---|---|---|
| `time_range.start` / `time_range.end` | no | ISO 8601. Defaults to last 24h. |
| `extra.user_data_dir` | no | Override Edge User Data dir. Defaults to `%LOCALAPPDATA%\Microsoft\Edge\User Data`. |

## What it inspects

`<UserDataDir>\Crashpad\reports\*.dmp` — Edge's Crashpad minidump store.
Also reads `<UserDataDir>\Crashpad\settings.dat` size and the most recent
`pending` records to estimate upload backlog.

## Output

`raw.reports` — newest first, capped at 50:

```json
{
  "file": "abcdef.dmp",
  "size_bytes": 482113,
  "mtime": "2026-05-26T08:14:09",
  "minutes_ago": 7
}
```

`raw.signatures` — best-effort top frame extraction from each minidump using
PowerShell `Format-Hex` heuristics (module strings near the start of the
file). This is approximate; for true symbolicated stacks, use WinDbg with
Microsoft public symbols.

`root_cause` — natural-language summary when one signature dominates.

## Invocation

```powershell
python edge_crash\scripts\edge_crash_analyzer.py '{"time_range":{"start":"2026-05-26T00:00:00","end":"2026-05-26T23:59:59"}}'
```

## Notes
- Read-only. Never deletes minidumps.
- If Crashpad is disabled by policy (`MetricsReportingEnabled=0`) there will
  be no reports; the skill will say so explicitly.

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- ``_shared/sources/crashpad`` (``CrashpadFilter``: ``signature / process_type / min_size_bytes``)

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
