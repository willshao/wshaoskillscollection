---
id: security_audit
name: Security Audit Analyzer
version: 2.0
role: follow_up
status: framework
description: (FRAMEWORK STUB) Will query the Security log for failed logons (4625), object-access denials (4656/4663), and privilege use (4672) and correlate to IIS 401/403 entries.
runtime:
  python: scripts/security_audit_analyzer.py
needs_admin: true
triggers_for: [auth_error]
---

## When to use
- IIS 401/403 spikes (`auth_error` problem type)

## Inputs (JSON context)

| Field | Required | Description |
|---|---|---|
| `time_range.start` / `time_range.end` | yes | ISO 8601 |

## Output (current behaviour)

Returns a contract envelope with a single info finding noting the framework status and the implementation TODO list. `confidence=low`. Safe to call from the orchestrator today.

## Planned implementation

1. `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4656,4663,4672; StartTime=…; EndTime=…}`
2. Group failures by principal + target resource
3. Cross-reference IP/time with IIS 401/403 entries from the parent context
4. Report top failing principals and most-targeted resources

## Notes
- Security log access requires elevation **and** audit policy enabled (`AuditPol /get /category:*`).
- Until implemented, treat 401/403 spikes as app pool identity / NTFS ACL configuration issues.

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- ``_shared/logs/evtx`` (queried with ``EvtxFilter(log_names=["Security"])``)

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
