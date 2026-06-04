---
id: edge_diagnostics
name: Edge Diagnostics (Entry Point)
version: 1.0
role: entry_point
description: Detect Microsoft Edge installation, channel, version, profile path, managed status, and recent crashes. Classify problem types and recommend follow-up skills.
runtime:
  python: scripts/edge_diagnostics.py
needs_admin: false
---

## When to use
First step for any Edge troubleshooting request. Run me before any other skill
in this collection unless the user has already stated a specific problem type
or asked a knowledge question (use `edge_qa` for those).

## Inputs

| Field | Required | Description |
|---|---|---|
| `extra.symptoms` | no | Free-text symptoms the user described. Used to bias classification. |
| `time_range`     | no | If provided, downstream skills will scope their work to this window. |
| `extra.profile`  | no | Profile name to inspect (default: `Default`). |
| `--auto-trigger` | flag | After analysis, pipe my output to the orchestrator. |

The skill consumes a JSON context like every other skill in this collection.
Without any context it still works — it scans the local Edge install.

## Output (contract envelope)

```json
{
  "raw": {
    "environment": {
      "installed": true,
      "channel": "Stable",
      "version": "126.0.2592.81",
      "exe": "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
      "user_data_dir": "C:/Users/<u>/AppData/Local/Microsoft/Edge/User Data",
      "is_running": true,
      "running_processes": 14,
      "is_managed": true
    },
    "problems": [
      { "type": "crash", "severity": "critical", "evidence": {...} }
    ],
    "skills_to_trigger": ["edge_crash", "edge_policy"]
  }
}
```

`problems[].type` ∈ `crash | hang | render_process_gone | slow_startup |
high_cpu | high_memory | page_slow | page_load_failure | cert_error |
proxy_issue | dns_issue | sync_error | update_blocked | extension_issue |
extension_blocked | managed_browser | feature_blocked | question`.

The mapping from problem type → follow-up skills lives in
[_shared/registry.json](../_shared/registry.json).

## Symptom keyword classifier

The skill scans `extra.symptoms` (lower-cased) for keywords and tags the
matching problem types. Examples:

| Keyword(s)                                              | Problem type        |
|---------------------------------------------------------|---------------------|
| `crash`, `crashes`, `crashed`, `aw snap`, `gone`        | `crash`             |
| `hang`, `freeze`, `frozen`, `not responding`            | `hang`              |
| `slow startup`, `takes forever to open`, `cold start`   | `slow_startup`      |
| `high cpu`, `100% cpu`, `cpu spike`                     | `high_cpu`          |
| `high memory`, `memory leak`, `using all my ram`        | `high_memory`       |
| `cert`, `certificate`, `net::err_cert`, `not secure`    | `cert_error`        |
| `proxy`, `pac file`, `err_proxy`                        | `proxy_issue`       |
| `dns`, `err_name_not_resolved`                          | `dns_issue`         |
| `sync`, `signed out`, `sync error`                      | `sync_error`        |
| `update`, `cannot update`, `update blocked`             | `update_blocked`    |
| `extension`, `add-on`, `addon`                          | `extension_issue`   |
| `policy`, `managed by your organization`                | `managed_browser`   |

It also independently inspects the system (Crashpad reports, managed
registry hive, running processes) and adds derived problem types even when
the user gives no symptoms.

## Invocation

```powershell
# Auto-scan, classify, and orchestrate follow-ups
python edge_diagnostics\scripts\edge_diagnostics.py --auto-trigger

# With user-supplied symptoms
python edge_diagnostics\scripts\edge_diagnostics.py '{"extra":{"symptoms":"edge keeps crashing on startup and i see managed by your organization"}}'
```

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- ``_shared/sources/crashpad`` (``CrashpadFilter``), ``_shared/sources/processes`` (``ProcessFilter``), ``_shared/sources/user_data`` (``EdgeProfileFilter``)

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
