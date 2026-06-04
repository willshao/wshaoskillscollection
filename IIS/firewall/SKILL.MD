---
id: firewall
name: Firewall / WAF Analyzer
version: 2.0
role: follow_up
status: framework
description: (FRAMEWORK STUB) Will parse Windows Firewall log (pfirewall.log) and any WAF logs to confirm DDoS-like patterns flagged by iis_logs.
runtime:
  python: scripts/firewall_analyzer.py
needs_admin: true
triggers_for: [suspicious_traffic]
---

## When to use
- IIS reports `suspicious_traffic` (a single IP dominating the log)
- You need evidence to support a temporary block rule

## Inputs (JSON context)

| Field | Required | Description |
|---|---|---|
| `time_range.start` / `time_range.end` | yes | ISO 8601 |
| `extra.suspicious_ip` | recommended | The client IP flagged by iis_logs |

## Output (current behaviour)

Standard envelope; framework stub. `confidence=low`.

## Planned implementation

1. Default log: `C:\Windows\System32\LogFiles\Firewall\pfirewall.log`
2. Parse W3C-style header to detect column layout
3. Aggregate `DROP` actions per source IP within window
4. Cross-check `extra.suspicious_ip` against drop counts
5. Recommend a `New-NetFirewallRule -Action Block -RemoteAddress …` snippet

## Notes
- Firewall logging may be off by default — check `netsh advfirewall show currentprofile logging`.
- Until implemented, use `iis_logs.problems[].evidence.client_ip` directly to author a temporary block rule.

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- ``_shared/logs/firewall`` (filter dataclass ``FirewallFilter``: ``action / protocol / src_ip / dst_port``)

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
