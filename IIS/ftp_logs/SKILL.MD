---
id: ftp_logs
name: FTP Log Analyzer
version: 1.0
role: entry_point
description: Parse Microsoft FTP Service W3C logs, reconstruct sessions (connect → auth → transfer → quit), classify FTP-specific problems, and recommend follow-up skills.
runtime:
  python: scripts/ftp_analyzer.py
needs_admin: false
---

## When to use
- Investigating FTP errors (530 auth failures, 550 access denied, 425 data-channel issues).
- Spotting brute-force or credential-stuffing patterns against FTP.
- Auditing upload / download volumes per user, IP, or path.
- Verifying that a given session’s commands followed the expected order
  (connect → USER → PASS → CWD/LIST/STOR/RETR → QUIT).

Use it standalone, or after `iis_logs` flagged FTP files in
`raw.detected_other_logs.ftp_w3c`.

## Inputs

| Name | Type | Required | Notes |
|---|---|---|---|
| `log` | path | yes | A single `.log` file **or a directory** — the skill recursively scans it and consumes only files classified as Microsoft FTP Service W3C logs. |
| `--no-recursive` | flag | no | Disable subdirectory walk. |
| `--bucket DUR` | string | no | Bucket size for the time series (`30s`, `1m`, `5m`, `1h`). Default `1m`. |
| `--around TS` | repeatable | no | Anchor timestamp (e.g. `"2026-05-26 10:15:30"`). Returns commands inside `±--window`. |
| `--window DUR` | string | no | Half-width of each `--around` query. Default `5m`. |
| `--filter EXPR` | string | no | Multi-key filter (see syntax below). Applied to global search and inside every `--around` window. |
| `--report PATH` | path | no | Write a self-contained HTML report (with SVG charts) to PATH. |

This skill reads FTP log files directly; it does **not** consume a JSON context.

### Filter syntax

Comma-separated `key=value` pairs. Supported keys:

| Key | Meaning |
|---|---|
| `user=NAME` | Exact `cs-username` match |
| `cmd=STOR` | Exact `cs-method` (case-insensitive: USER, PASS, CWD, LIST, RETR, STOR, …) |
| `status=550` or `status=500-599` | Single status or inclusive range |
| `ip=10.0.0.1` or `ip=10.0.0.0/24` | Exact IP or CIDR |
| `path=^/uploads/` | `cs-uri-stem` regex |
| `min-bytes=1024` | `cs-bytes + sc-bytes ≥ N` |
| `min-time=2000` | `time-taken ≥ N` ms |
| `uri=...` `q=...` `method=...` `ua=...` | Accepted but typically unused for FTP |

## Output (contract envelope)

Conforms to [`skill_result.schema.json`](../_shared/schemas/skill_result.schema.json).

Key fields in `raw`:

```jsonc
{
  "log_files_parsed": 2,
  "session_stats":     { "total_sessions": 14, "bytes_up": 12345, ... },
  "sessions":          [ { "key": "sid:42", "client_ip": "...", "events": [...] } ],
  "problems":          [ { "type": "ftp_auth_failure", "severity": "warning", ... } ],
  "skills_to_trigger": ["firewall", "security_audit"],
  "timeseries":        { "bucket_seconds": 60, "buckets": [...] },
  "search":            { "filter": "...", "summary": {...}, "results": [...] },
  "around":            { "<ts>": { "window_seconds": 300, "entries": [...] } },
  "detected_other_logs": { "iis_w3c": ["..."], "httperr": ["..."] },
  "report_html_path":  "C:\\path\\to\\report.html"
}
```

## Detection thresholds

| Problem | Threshold |
|---|---|
| `ftp_auth_failure` | one IP produces > 10 PASS 5xx responses |
| `ftp_upload_error` | failed transfer commands (STOR/STOU/APPE/RETR) > 5% of total transfers |
| `ftp_brute_force`  | one IP fails PASS for ≥ 5 distinct usernames |
| `ftp_incomplete_session` | > 20% of sessions ended without QUIT |

## Invocation

```powershell
# basic — recursively scan a directory, auto-classify
python ftp_logs/scripts/ftp_analyzer.py "C:\inetpub\logs\LogFiles\FTPSVC1"

# focused investigation around an incident
python ftp_logs/scripts/ftp_analyzer.py "C:\inetpub\logs\LogFiles\FTPSVC1" `
       --around "2026-05-26 10:15:30" --window 5m `
       --filter "cmd=STOR,status=500-599" `
       --report ftp_incident.html

# brute-force hunt
python ftp_logs/scripts/ftp_analyzer.py "C:\inetpub\logs\LogFiles\FTPSVC1" `
       --filter "ip=10.0.0.0/24,cmd=PASS,status=500-599"
```

## Session reconstruction

The analyzer groups events by `x-session` when present, otherwise falls back to
a per-IP heuristic that opens a new session at each `USER` command. Each
session reports:

- `client_ip`, `username`, `start`, `end`, `duration_ms`
- `auth_ok` (any PASS = 230), `auth_failed_attempts`
- `commands_count`, `transfers`, `bytes_up`, `bytes_down`, `errors`
- `terminated_cleanly` (saw a QUIT)
- ordered `events[]` of `{ts, cmd, uri, status, bytes_up, bytes_down}`

## Notes
- W3C field layout is read dynamically from `#Fields:` — works regardless of column ordering.
- No external Python dependencies (stdlib only).
- HTML report embeds all charts as inline SVG; no network access required.
- Companion skill: [`iis_logs`](../IIS_logs/SKILL.MD) for HTTP traffic in the same folder.

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- ``_shared/logs/ftp_w3c`` (filter dataclass ``FtpFilter`` / ``log_filters.FilterSpec``)

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
