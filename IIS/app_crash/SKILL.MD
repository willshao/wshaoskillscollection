---
id: app_crash
name: Application Crash Analyzer
version: 2.0
role: follow_up
description: Pull .NET / IIS worker process crash events from the Application log within the IIS time window, classify the exception family, and suggest remediation.
runtime:
  python: scripts/app_crash_analyzer.py
  pwsh:   scripts/app_crash_analyzer.ps1
needs_admin: true
triggers_for: [5xx_error]
---

## When to use
- 500/503 responses correlated to .NET unhandled exceptions
- App pool recycling unexpectedly

## Inputs (JSON context)

| Field | Required | Description |
|---|---|---|
| `time_range.start` / `time_range.end` | yes | ISO 8601 |

## Output

```json
{
  "total_events": 12,
  "family_distribution": {"null_reference": 8, "operation_timeout": 4},
  "top_family": "null_reference",
  "samples": [
    {
      "time": "2026-04-21T10:15:30",
      "provider": ".NET Runtime",
      "id": 1026,
      "family": "null_reference",
      "top_frame": "MyApp.OrdersController.GetById",
      "snippet": "..."
    }
  ]
}
```

Crash families: `memory_exhaustion | stack_overflow | null_reference | invalid_argument | operation_timeout | database_error | invalid_operation | io_error | thread_aborted | unclassified`.

## Invocation

```powershell
'{"time_range":{"start":"2026-04-21T10:00:00","end":"2026-04-21T10:30:00"}}' `
  | python app_crash/scripts/app_crash_analyzer.py
```

## Notes
- Queries Application log providers: `.NET Runtime`, `Application Error`, `IIS-W3SVC-WP`, `ASP.NET 4.0.30319.0`.
- `confidence=high` only when the dominant family is non-`unclassified`.

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- ``_shared/logs/evtx`` (queried with ``EvtxFilter(providers=[".NET Runtime"], event_ids=[1000,1026])``). Crash-signature classification stays in this skill.

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
