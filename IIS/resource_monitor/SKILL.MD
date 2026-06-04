---
id: resource_monitor
name: System Resource Monitor
version: 2.0
role: follow_up
status: framework
description: (FRAMEWORK STUB) Will sample CPU/memory/disk perf counters scoped to w3wp processes and flag pressure during the IIS time window.
runtime:
  python: scripts/resource_monitor.py
needs_admin: true
triggers_for: [high_latency]
---

## When to use
- IIS shows `high_latency` and you want to rule out resource pressure

## Inputs (JSON context)

| Field | Required | Description |
|---|---|---|
| `time_range.start` / `time_range.end` | yes | ISO 8601 |

## Output (current behaviour)

Standard envelope; framework stub with TODO list. `confidence=low`.

## Planned implementation

```powershell
Get-Counter '\Processor(_Total)\% Processor Time'
Get-Counter '\Memory\Available MBytes'
Get-Counter '\Process(w3wp*)\Working Set'
Get-Counter '\PhysicalDisk(_Total)\Avg. Disk sec/Read'
Get-Counter '\PhysicalDisk(_Total)\Avg. Disk sec/Write'
```

Flag windows where:
- CPU > 85% sustained
- Available memory < 10%
- Disk latency p95 > 25 ms

## Notes
- Until implemented, capture a baseline manually with `perfmon` or `Get-Counter -Continuous`.

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- ``_shared/logs/perf_counter`` (filter dataclass ``PerfCounterFilter``: ``counter_paths / min_value / max_value``)

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
