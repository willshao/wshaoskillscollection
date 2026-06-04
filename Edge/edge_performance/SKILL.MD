---
id: edge_performance
name: Edge Performance Sampler
version: 1.0
role: follow_up
description: Sample currently running msedge.exe processes, report CPU / memory / handle counts per process role, and flag heavy outliers.
runtime:
  python: scripts/edge_performance.py
needs_admin: false
triggers_for: [slow_startup, high_cpu, high_memory, page_slow]
---

## When to use
Right after the user reports that Edge is sluggish, eating CPU, or hogging
memory. Best when Edge is running at the time you invoke the skill.

## Inputs

| Field | Required | Description |
|---|---|---|
| `extra.sample_seconds` | no | How long to sample CPU (default 2). |
| `extra.top_n` | no | How many processes to return in `raw.top_processes` (default 10). |

## Method

Uses PowerShell `Get-Process msedge` to capture per-PID:

- `CPU` total seconds since process start
- `WorkingSet64` / `PrivateMemorySize64`
- `HandleCount`, `Threads.Count`
- Command line via `Get-CimInstance Win32_Process` so we can split by role:
  `--type=renderer`, `gpu-process`, `utility`, etc.

It samples CPU twice with a configurable interval to estimate the *current*
CPU% (not the cumulative average since launch).

## Output

`raw.summary`:
```json
{
  "process_count": 14,
  "total_working_set_mb": 2840,
  "total_cpu_pct": 78,
  "by_role": {
    "browser": 1, "renderer": 8, "gpu-process": 1, "utility": 3, "extension": 1
  }
}
```

`raw.top_processes` — sorted by current CPU% then memory.

## Invocation

```powershell
python edge_performance\scripts\edge_performance.py '{"extra":{"sample_seconds":3,"top_n":15}}'
```

## Notes
- This skill reads-only. It does NOT terminate any process.
- On non-Windows systems it returns an empty payload with a note.
- For deeper profiling, capture an ETW trace and use WPA, or use Edge's
  built-in `edge://tracing`.

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- ``_shared/sources/processes`` (``ProcessFilter``: ``min_cpu_seconds / min_working_set_mb / name_contains``)

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
