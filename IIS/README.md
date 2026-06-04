# IIS Diagnostics Skills Collection

A set of **composable, AI-driven diagnostic skills** for Windows IIS troubleshooting. Each skill is an independent Python module that reads a specific log kind, emits a structured JSON result, and cooperates with the others through a shared envelope contract.

---

## Table of Contents

1. [Overview](#overview)
2. [Skills Reference](#skills-reference)
3. [Diagnostic Flow](#diagnostic-flow)
4. [Standard JSON Contract](#standard-json-contract)
5. [Invocation Methods](#invocation-methods)
6. [Filters & Time-Window Queries](#filters--time-window-queries)
7. [HTML Reports](#html-reports)
8. [Missing-Log Gate](#missing-log-gate)
9. [Playbook & Problem Types](#playbook--problem-types)
10. [Shared Log Readers](#shared-log-readers)
11. [Project Conventions](#project-conventions)

---

## Overview

```
Incident folder / log file
        │
        ▼
┌───────────────────┐       auto-discovers all log kinds
│    orchestrator   │──────────────────────────────────────┐
└───────────────────┘                                      │
        │  dispatches entry skills                         │
        ▼                                                  │
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ iis_logs │  │ ftp_logs │  │httperror │  │event_log │  │  netlog  │
└──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘
        │  emits problem_types
        ▼
  follow-up skills triggered per problem_type
┌──────────┐  ┌──────────────┐  ┌──────────────────┐  ┌──────────┐
│app_crash │  │security_audit│  │resource_monitor  │  │ firewall │
└──────────┘  └──────────────┘  └──────────────────┘  └──────────┘
        │
        ▼
  fused SkillResult envelope  →  HTML report (optional)
```

---

## Skills Reference

| Skill ID | Folder | Entry Script | Role | Admin? |
|---|---|---|---|---|
| `iis_logs` | `IIS_logs/` | `scripts/iis_analyzer.py` | Entry point | No |
| `ftp_logs` | `ftp_logs/` | `scripts/ftp_analyzer.py` | Entry point | No |
| `httperror` | `httperror/` | `scripts/httperr_analyzer.py` | Follow-up | No |
| `event_log` | `event_log/` | `scripts/event_log_analyzer.py` | Follow-up | Yes |
| `app_crash` | `app_crash/` | `scripts/app_crash_analyzer.py` | Follow-up | Yes |
| `security_audit` | `security_audit/` | `scripts/security_audit_analyzer.py` | Follow-up | Yes |
| `resource_monitor` | `resource_monitor/` | `scripts/resource_monitor.py` | Follow-up | Yes |
| `firewall` | `firewall/` | `scripts/firewall_analyzer.py` | Follow-up | Yes |
| `netlog` | `netlog/` | `scripts/netlog_analyzer.py` | Follow-up | No |
| `orchestrator` | `orchestrator/` | `scripts/skill_orchestrator.py` | Coordinator | No |

### iis_logs
Parses IIS W3C access logs. Computes KPIs (RPS, status distribution, latency percentiles), classifies problem types (`5xx_error`, `high_latency`, `auth_error`, `not_found`, `traffic_spike`), and recommends follow-up skills. Supports time-window filtering, regex filtering, and HTML+SVG reporting.

### ftp_logs
Parses Microsoft FTP Service W3C logs. Reconstructs complete sessions (CONNECT → USER/PASS → STOR/RETR → QUIT), detects auth failures, brute-force attacks, transfer errors, and incomplete sessions. Problem types: `ftp_auth_failure`, `ftp_upload_error`, `ftp_brute_force`, `ftp_incomplete_session`.

### httperror
Parses HTTP.SYS error logs (`%SystemRoot%\System32\LogFiles\HTTPERR\httperr*.log`). Reveals server-side disconnect reasons not visible in W3C logs. Triggered by `5xx_error`.

### event_log
Queries the Windows Event Log (Application, System, Security channels). Correlates events to the IIS error time window. Also accepts exported `.evtx` files via `extra.evtx_paths`. Triggered by `5xx_error`, `high_latency`, `auth_error`.

### app_crash
Parses .NET crash events from the Windows Application Event Log. Classifies exception type and suggests mitigations. Triggered by `5xx_error`.

### security_audit
Diagnoses authentication and permission failures. Triggered by `auth_error`. *(Framework stub — PowerShell implementation complete.)*

### resource_monitor
Samples CPU/memory/disk performance counters. Triggered by `high_latency`. *(Framework stub — PowerShell implementation complete.)*

### firewall
Parses Windows Firewall log for DDoS / port-scan patterns. Triggered by `suspicious_traffic`. *(Framework stub — PowerShell implementation complete.)*

### netlog
Parses Chromium `edge://net-export` JSON files. Provides the **client-side view** invisible to IIS. Detects TLS/cert failures, DNS failures, proxy mis-configuration, Kerberos SPN mismatches, HTTP auth handshake loops. Problem types: `cert_error`, `dns_issue`, `proxy_issue`, `client_request_failure`, `kerberos_spn_mismatch`, `auth_handshake_loop`, `tls_handshake_failure`. Auto-discovered when a matching `.json` file is present in the folder.

### orchestrator
**The recommended starting point for any incident folder.** Discovers all log kinds, dispatches entry skills, performs secondary fan-out, computes the missing-log gate, and optionally writes an HTML report.

---

## Diagnostic Flow

### Flow 1 — Folder / Incident Bundle (recommended)

```
python orchestrator/scripts/skill_orchestrator.py C:\incident\logs --report C:\report.html
```

1. **Discovery** — scans for `.log` (IIS/FTP/HTTPERR), `.evtx`, `.json` (net-export).
2. **Entry skills** — `iis_logs`, `ftp_logs`, `httperror`, `event_log`, `netlog` run in parallel.
3. **Problem aggregation** — all `raw.problems` are merged.
4. **Secondary fan-out** — invokes `app_crash`, `security_audit`, `resource_monitor`, `firewall` per `skills_to_trigger`.
5. **Missing-log gate** — surfaces gaps between expected and provided log kinds.
6. **Report** — HTML with SVG charts, cross-log context, missing-log table.

### Flow 2 — Single Log File

```
python IIS_logs/scripts/iis_analyzer.py C:\logs\u_ex260504.log
```

Read `raw.skills_to_trigger` from the output and invoke each follow-up.

### Flow 3 — Legacy Fan-Out

```
python orchestrator/scripts/skill_orchestrator.py @iis_result.json
```

### Problem → Auto-triggered Skills

| Problem Type | Severity | Triggered Skills |
|---|---|---|
| `5xx_error` | critical | `httperror`, `event_log`, `app_crash` |
| `high_latency` | warning | `resource_monitor`, `event_log` |
| `auth_error` | warning | `security_audit`, `event_log`, `netlog` |
| `suspicious_traffic` | warning | `firewall` |
| `cert_error` | critical | `netlog` |
| `dns_issue` | warning | `netlog` |
| `proxy_issue` | warning | `netlog` |
| `kerberos_spn_mismatch` | critical | `security_audit`, `event_log` |
| `tls_handshake_failure` | critical | `netlog`, `event_log` |
| `ftp_brute_force` | critical | `firewall` |
| `ftp_auth_failure` | warning | `firewall`, `security_audit` |

---

## Standard JSON Contract

### Input

```json
{
  "time_range": { "start": "2026-05-04T10:00:00", "end": "2026-05-04T10:30:00" },
  "problem_type": "5xx_error",
  "extra": {
    "evtx_paths": ["C:\\incident\\app.evtx"],
    "netlog_paths": ["C:\\incident\\netlog.json"]
  }
}
```

### Output envelope (v2.1)

```json
{
  "skill": "iis_logs",
  "ok": true,
  "findings": [
    { "summary": "60 5xx errors (49%)", "severity": "critical", "evidence": {} }
  ],
  "root_cause": "Application pool recycling under load",
  "confidence": "high",
  "recommendations": ["[fix:...] Recycle app pool", "[next:...] run event_log"],
  "solutions": [
    { "problem_ref": "5xx_error", "title": "Restart the application pool",
      "severity": "critical", "steps": ["Restart-WebAppPool -Name <pool>"] }
  ],
  "next_steps": [ { "action": "Correlate with event log", "skill": "event_log" } ],
  "additional_logs_needed": [
    { "log_kind": "evtx", "why": "Need Application/System events",
      "how_to_collect": "wevtutil epl Application app.evtx", "skill": "event_log" }
  ],
  "raw": { "problems": [...], "skills_to_trigger": ["event_log", "httperror"] }
}
```

---

## Invocation Methods

### Python CLI

```bash
# Single file
python IIS_logs/scripts/iis_analyzer.py C:\logs\u_ex260504.log

# Folder with time window
python IIS_logs/scripts/iis_analyzer.py C:\logs --around "2026-05-04 10:15:00" --window 15m

# With filter + HTML report
python IIS_logs/scripts/iis_analyzer.py C:\logs --filter "status=500-599,method=POST" --report C:\out\report.html

# httperror folder mode
python httperror/scripts/httperr_analyzer.py --folder C:\logs\HTTPERR

# Offline evtx
python event_log/scripts/event_log_analyzer.py "{\"extra\":{\"evtx_paths\":[\"C:\\\\incident\\\\app.evtx\"]}}"

# Net-export netlog
python netlog/scripts/netlog_analyzer.py "{\"extra\":{\"netlog_paths\":[\"C:\\\\incident\\\\netlog.json\"]}}"

# Full orchestration
python orchestrator/scripts/skill_orchestrator.py C:\incident --report C:\out\report.html

# Error-anchor discovery
python orchestrator/scripts/skill_orchestrator.py C:\incident --error "NullReferenceException"
```

### PowerShell (fallback)

```powershell
pwsh IIS_logs/scripts/iis_analyzer.ps1 C:\logs\u_ex260504.log
pwsh event_log/scripts/event_log_analyzer.ps1
```

### JSON context file

```bash
echo '{"problem_type":"5xx_error","time_range":{"start":"2026-05-04T10:00:00","end":"2026-05-04T10:30:00"}}' > ctx.json
python IIS_logs/scripts/iis_analyzer.py @ctx.json
```

### Via GitHub Copilot CLI

Launch `copilot` from this folder so `AGENTS.md` is loaded:

```
analyze C:\inetpub\logs\LogFiles\W3SVC1\u_ex260504.log — compute KPIs and run all follow-ups

investigate the 5xx spike between 10:00 and 10:30 on 2026-05-04 under C:\incident\logs, produce an HTML report

my site returns 503 intermittently — check C:\logs\iis and find the root cause
```

---

## Filters & Time-Window Queries

### `--around` / `--window`

```bash
python IIS_logs/scripts/iis_analyzer.py C:\logs --around "2026-05-04 10:15:00" --window 15m
# Multiple anchors:
python IIS_logs/scripts/iis_analyzer.py C:\logs --around "10:15:00" --around "10:45:00" --window 5m
```

### `--filter` keys

```
method=POST          uri=/api/checkout (regex)    status=500-599
ip=10.0.0.0/8        min-time=2000 (ms)           ua=python-requests (regex)
q=checkout           user=jsmith (FTP)            cmd=STOR (FTP)
```

### `--error REGEX` (orchestrator)

```bash
python orchestrator/scripts/skill_orchestrator.py C:\incident --error "Timer_AppPool|503"
```

### JSON `extra` fields

| Field | Skill | Purpose |
|---|---|---|
| `extra.evtx_paths` | `event_log`, `orchestrator` | Offline `.evtx` files |
| `extra.netlog_paths` | `netlog`, `orchestrator` | `edge://net-export` JSON files |
| `extra.folder` | `httperror`, `iis_logs`, `ftp_logs` | Folder to scan |
| `extra.no_recursive` | `httperror` | Disable recursive scan |

---

## HTML Reports

```bash
python orchestrator/scripts/skill_orchestrator.py C:\incident --report C:\out\diagnosis.html
```

Sections: Discovery · Anchors · Error locator · Per-skill results · Root cause chain · Cross-log context · **Missing required logs** · Solutions · Next steps · Additional logs needed.

---

## Missing-Log Gate

```
expected = playbook.logs_for(problem_types) ∪ child.additional_logs_needed
provided = discovered_files ∪ skills_run_successfully
missing  = expected − provided
```

Each missing kind → `warning` Finding + `raw.missing_logs` row + HTML table row.

To close a gap: drop the missing file into the incident folder and re-run.

---

## Playbook & Problem Types

| Problem Type | Severity | Description |
|---|---|---|
| `5xx_error` | critical | HTTP 500–599 from IIS |
| `high_latency` | warning | Elevated p95/p99 response time |
| `auth_error` | warning | Authentication/authorisation failures |
| `suspicious_traffic` | warning | Anomalous request patterns |
| `not_found` | info | High 404 rate |
| `traffic_spike` | warning | Sudden request volume increase |
| `cert_error` | critical | TLS certificate validation failure |
| `dns_issue` | warning | DNS resolution failure |
| `proxy_issue` | warning | Proxy mis-configuration |
| `client_request_failure` | warning | Generic client-side failure |
| `kerberos_spn_mismatch` | critical | Wrong Kerberos SPN |
| `auth_handshake_loop` | warning | HTTP auth negotiate loop |
| `tls_handshake_failure` | critical | TLS handshake error |
| `ftp_auth_failure` | warning | FTP login failure |
| `ftp_upload_error` | warning | FTP transfer error |
| `ftp_brute_force` | critical | FTP credential stuffing |
| `ftp_incomplete_session` | info | FTP session not completed cleanly |

---

## Shared Log Readers

All parsing is in `_shared/logs/`. Skills never touch log bytes directly:

```python
from _shared.logs import iis_w3c
iis_w3c.discover(folder, recursive=True)         # → list[Path]
iis_w3c.iter_entries(path)                       # → Iterator[dict]
iis_w3c.query(sources, time_range, filter, ...)  # → {entries, summary, truncated, sources_used}
```

Log classification (`_shared/log_discovery.py`): `.evtx` → EVTX · `.json` structural sniff → NETLOG · `httperr*.log` prefix → HTTPERR · `#Software: Microsoft Internet Information Services` header → IIS · `#Software: Microsoft FTP Service` header → FTP.

---

## Project Conventions

- Python 3.10+, standard library only.
- Runnable from any working directory.
- PowerShell variants exist for `iis_logs`, `httperror`, `event_log`, `app_crash` — prefer Python.
- Admin required: `event_log`, `security_audit`, `resource_monitor`, `firewall`.
- Framework stubs: `security_audit`, `resource_monitor`, `firewall` (Python layer pending full port).
- Registry: [`_shared/registry.json`](_shared/registry.json) · Contract: [`_shared/contract.py`](_shared/contract.py)
