---
id: httperror
name: HTTP.SYS Error Log Analyzer
version: 2.0
role: follow_up
description: Parse C:\Windows\System32\LogFiles\HTTPERR\httperr*.log to find HTTP.SYS-level reasons (timeouts, dropped connections, app pool failures) that don't appear in IIS logs.
runtime:
  python: scripts/httperr_analyzer.py
  pwsh:   scripts/httperr_analyzer.ps1
needs_admin: false
triggers_for: [5xx_error]
---

## When to use
- IIS shows 5xx but the application logs nothing
- Suspected SSL/TLS handshake failures
- App pool failed to dequeue requests in time

## Inputs (JSON context)

| Field | Required | Description |
|---|---|---|
| `time_range.start` / `time_range.end` | recommended | Filters log entries to the IIS window (±2 min) |
| `extra.folder` | optional | Discover & aggregate every `httperr*.log` under this folder. Equivalent to `--folder`. |
| `extra.no_recursive` | optional | With `extra.folder`, do not descend into subdirectories. |

CLI flags:
- `--log <path>` — override the default location (single file mode).
- `--folder <dir>` — discover and aggregate every HTTPERR log under `<dir>`.
- `--no-recursive` — only used with `--folder`.

**Resolution order**: `--log` > `--folder` (or `extra.folder`) > the default `C:\Windows\System32\LogFiles\HTTPERR\` location.

### Folder input

When `--folder` / `extra.folder` is provided, the skill calls `_shared.log_discovery.discover_logs` to find every `httperr*.log` (recursively by default), runs the single-file analyzer on each, and aggregates the results into one envelope. `raw.log_files` lists every analyzed file, `raw.per_file` keeps the per-file breakdown, and `raw.detected_other_logs` mirrors the `iis_logs` / `ftp_logs` convention so the agent can route remaining log kinds to the matching skill.

```powershell
# folder mode
python httperror/scripts/httperr_analyzer.py --folder C:\incidents\2026-05-26 '{}'

# folder + time window (from orchestrator)
'{"time_range":{"start":"2026-05-26T10:00:00","end":"2026-05-26T10:30:00"},"extra":{"folder":"C:\\incidents\\2026-05-26"}}' `
  | python httperror/scripts/httperr_analyzer.py
```

## Output

`raw` contains:
```json
{
  "log_file": "C:\\Windows\\System32\\LogFiles\\HTTPERR\\httperr1.log",
  "rows_in_window": 124,
  "top_reasons": [["Timer_AppPool", 60], ["Connection_Abandoned_By_AppPool", 25]],
  "top_client_ip": {"ip": "10.0.0.7", "count": 80},
  "ddos_suspected": true
}
```

`root_cause` — the most common HTTP.SYS reason phrase.

## Invocation

```powershell
'{"time_range":{"start":"2026-04-21T10:00:00","end":"2026-04-21T10:30:00"}}' `
  | python httperror/scripts/httperr_analyzer.py

# point at a sample file (handy for tests / dev machines)
python httperror/scripts/httperr_analyzer.py --log C:\samples\httperr1.log '{}'
```

## Notes
- Returns `ok=true` with an info finding when no HTTPERR file exists (an environmental state, not a failure).
- Common reason phrases are translated in `REASON_HINTS`; unmapped phrases pass through verbatim.

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- ``_shared/logs/httperr`` (filter dataclass ``HttpErrFilter``: ``reason / client_ip / app_pool / contains``)

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
