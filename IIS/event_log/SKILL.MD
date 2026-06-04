---
id: event_log
name: Windows Event Log Correlator
version: 2.0
role: follow_up
description: Query Application/System event logs around the IIS time window, correlate within ±2 minutes, infer a likely system-level root cause.
runtime:
  python: scripts/event_log_analyzer.py
  pwsh:   scripts/event_log_analyzer.ps1
needs_admin: true
triggers_for: [5xx_error, high_latency, auth_error]
---

## When to use
After IIS finds 5xx, latency, or auth issues — to confirm whether a system event explains them.

## Inputs (JSON context)

| Field | Required | Description |
|---|---|---|
| `time_range.start` / `time_range.end` | yes | ISO 8601 (with or without `Z`) |
| `problem_type` | recommended | One of `5xx_error / high_latency / auth_error`; tunes root-cause hint matching |
| `extra.evtx_paths` | optional | List of saved `.evtx` files (offline mode). Equivalent to `--evtx` repeated on the CLI. |

CLI flags: `--logs Application System Setup`, `--tolerance-min 2.0`, `--evtx <path>` (repeatable).

### Offline `.evtx` mode

When at least one `.evtx` path is supplied (via `--evtx` or `extra.evtx_paths`), the live event log is **not** queried; events come from the saved files via `Get-WinEvent -Path`. The output is the same shape; `raw.source` is set to `evtx:<paths>` (vs `live_eventlog:<logs>`), and `raw.evtx_paths` lists the inputs.

```powershell
# direct offline analysis
'{"time_range":{"start":"2026-05-26T10:00:00","end":"2026-05-26T10:30:00"},"problem_type":"5xx_error","extra":{"evtx_paths":["C:\\incidents\\Application.evtx","C:\\incidents\\System.evtx"]}}' `
  | python event_log/scripts/event_log_analyzer.py

# or with CLI flags
python event_log/scripts/event_log_analyzer.py @ctx.json --evtx C:\incidents\Application.evtx --evtx C:\incidents\System.evtx
```

## Output

`raw.correlated` contains the event records that landed inside the window:
```json
{
  "event_id": 1000,
  "name": ".NET application crash",
  "severity": "critical",
  "time": "2026-04-21T10:15:30",
  "provider": "Application Error",
  "correlation": "strong",
  "minutes_from_window_start": 0.5
}
```

`root_cause` — natural-language summary of the strongest match.
`confidence` — `high` if event id matches a hint for the problem type, `medium` if any critical event landed in window, otherwise `low`.

## Invocation

```powershell
# from orchestrator (normal path)
# or directly with stdin:
'{"time_range":{"start":"2026-04-21T10:00:00","end":"2026-04-21T10:30:00"},"problem_type":"5xx_error"}' `
  | python event_log/scripts/event_log_analyzer.py
```

## Notes
- Uses `Get-WinEvent -FilterHashtable` (fast, supports modern logs).
- Returns gracefully empty when not on Windows or when not elevated for protected logs.
- **Does not query the Security log** — use the [security_audit](../security_audit/SKILL.MD) skill for that.

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- ``_shared/logs/evtx`` (filter dataclass ``EvtxFilter``: ``log_names / event_ids / providers / levels / keywords``). Interpretation tables (``EVENT_ID_MAP``, ``ROOT_CAUSE_HINTS``) stay in this skill.

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
