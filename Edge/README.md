# Microsoft Edge Diagnostics Skills Collection

A set of **composable, AI-driven diagnostic skills** for troubleshooting Microsoft Edge (Chromium) on Windows. Each skill is an independent Python module targeting a specific data source, emitting a structured JSON result through a shared envelope contract.

---

## Table of Contents

1. [Overview](#overview)
2. [Skills Reference](#skills-reference)
3. [Diagnostic Flow](#diagnostic-flow)
4. [Standard JSON Contract](#standard-json-contract)
5. [Invocation Methods](#invocation-methods)
6. [Orchestrator Aggregation](#orchestrator-aggregation)
7. [Missing-Log Gate](#missing-log-gate)
8. [Playbook & Problem Types](#playbook--problem-types)
9. [Shared Source Readers](#shared-source-readers)
10. [Project Conventions](#project-conventions)

---

## Overview

```
User / Copilot CLI
        │
        ▼
┌─────────────────────┐
│   edge_diagnostics  │  ← always the first call for troubleshooting
└─────────────────────┘
        │  emits: problems[], environment, skills_to_trigger[]
        ▼
┌──────────────────────────────────────────────────────────────┐
│                        orchestrator                          │
│  fuses results, computes missing-log gate, writes summary    │
└──────────────────────────────────────────────────────────────┘
        │  dispatches follow-up skills
        ▼
┌────────────┐ ┌───────────────┐ ┌──────────────┐ ┌─────────────┐
│ edge_crash │ │edge_performance│ │ edge_network │ │ edge_policy │
└────────────┘ └───────────────┘ └──────────────┘ └─────────────┘
┌──────────────────┐ ┌──────────────┐ ┌─────────┐
│ edge_extensions  │ │ edge_netlog  │ │ edge_qa │
└──────────────────┘ └──────────────┘ └─────────┘
        │
        ▼
  fused SkillResult envelope  →  raw.operator_summary (Markdown)
```

---

## Skills Reference

| Skill ID | Folder | Entry Script | Role | Admin? |
|---|---|---|---|---|
| `edge_diagnostics` | `edge_diagnostics/` | `scripts/edge_diagnostics.py` | Entry point | No |
| `edge_crash` | `edge_crash/` | `scripts/edge_crash_analyzer.py` | Follow-up | No |
| `edge_performance` | `edge_performance/` | `scripts/edge_performance.py` | Follow-up | No |
| `edge_network` | `edge_network/` | `scripts/edge_network.py` | Follow-up | No |
| `edge_policy` | `edge_policy/` | `scripts/edge_policy.py` | Follow-up | No |
| `edge_extensions` | `edge_extensions/` | `scripts/edge_extensions.py` | Follow-up | No |
| `edge_netlog` | `edge_netlog/` | `scripts/edge_netlog.py` | Follow-up | No |
| `edge_qa` | `edge_qa/` | `scripts/edge_qa.py` | Knowledge base | No |
| `orchestrator` | `orchestrator/` | `scripts/edge_orchestrator.py` | Coordinator | No |

### edge_diagnostics
**The mandatory first step.** Detects the installed Edge channel (Stable / Beta / Dev / Canary), version, profile path, managed status (is the browser controlled by Group Policy?), and recent Crashpad reports. Classifies problem types from the environment snapshot and populates `skills_to_trigger`. Also accepts `--auto-trigger` to run follow-ups automatically.

### edge_crash
Enumerates Crashpad crash reports under `User Data/Crashpad/reports/`. Classifies crash signatures (GPU crash, renderer killed, OOM, etc.) and suggests targeted mitigations. Triggered by `crash`, `hang`, `render_process_gone`.

### edge_performance
Samples live `msedge.exe` processes via the process table — CPU seconds, working-set size, handle count, renderer/GPU/utility type. Flags heavy renderer tabs or GPU memory pressure. Triggered by `slow_startup`, `high_cpu`, `high_memory`, `page_slow`.

### edge_network
Diagnoses proxy settings, DNS resolution, and certificate validity affecting Edge connectivity. Correlates against system-level network configuration. Triggered by `page_load_failure`, `cert_error`, `proxy_issue`, `dns_issue`, `sync_error`.

### edge_policy
Reads the `HKLM\Software\Policies\Microsoft\Edge` and `HKCU\Software\Policies\Microsoft\Edge` registry hives. Lists all applied Group Policy / Intune / MDM policies and flags ones that could block features or updates. Triggered by `managed_browser`, `feature_blocked`, `update_blocked`, `extension_blocked`.

### edge_extensions
Enumerates installed extensions per profile from `Preferences` / `Secure Preferences`. Flags risky extensions (unusual permissions, disabled by policy, force-installed). Triggered by `extension_issue`, `high_memory`, `page_slow`.

### edge_netlog
Parses Chromium `edge://net-export` JSON files — the **browser's own network event log**. Classifies:
- Certificate / TLS failures (`cert_error`)
- DNS resolution failures (`dns_issue`)
- Proxy resolution failures (`proxy_issue`)
- Generic URL request failures (`page_load_failure`)
- Slow requests above threshold (`page_slow`)

Triggered by `page_load_failure`, `cert_error`, `proxy_issue`, `dns_issue`, `page_slow`. Also triggered automatically when `extra.netlog_paths` is supplied to `edge_diagnostics`.

### edge_qa
A built-in knowledge-base skill for common Edge questions: feature flags, keyboard shortcuts, IE mode, sync behaviour, profile management, enterprise deployment, etc. Triggered by `question` problem type or direct `edge_qa` invocation.

**Microsoft Learn MCP integration.** The Python skill itself cannot call MCP tools (they only exist inside the Copilot CLI agent). Instead it publishes a `raw.mslearn_lookup` block whose `suggested_calls[]` array tells the agent which `microsoft_docs_search` / `microsoft_docs_fetch` queries to run. The agent then merges the live MS Learn results into its final answer and cites the URLs. See [edge_qa/SKILL.MD](edge_qa/SKILL.MD) for the full contract; set `extra.use_mslearn: false` for fully offline use.

### orchestrator
Receives the `edge_diagnostics` output, dispatches all listed follow-up skills, deduplicates advisory fields, computes the missing-log gate, and writes `raw.operator_summary` (a Markdown summary terminal-friendly without an HTML report).

---

## Diagnostic Flow

### Flow 1 — Standard Troubleshooting

```bash
# Step 1: Run edge_diagnostics
python edge_diagnostics/scripts/edge_diagnostics.py '{}'

# Step 2: Pass its output to the orchestrator
python edge_diagnostics/scripts/edge_diagnostics.py '{}' | \
  python orchestrator/scripts/edge_orchestrator.py @-
```

Or in one command:

```bash
python edge_diagnostics/scripts/edge_diagnostics.py --auto-trigger
```

### Flow 2 — Targeted Problem

```bash
# You already know it is a crash
python orchestrator/scripts/edge_orchestrator.py \
  '{"skills_to_trigger":["edge_crash","edge_policy"],"problems":[{"type":"crash","severity":"critical","summary":"Edge crashes on startup"}]}'
```

### Flow 3 — Knowledge Question

```bash
# 1. Local KB lookup + emit MS Learn MCP suggestions
python edge_qa/scripts/edge_qa.py '{"question":"How do I configure IE mode via Group Policy?"}'

# 2. The agent (Copilot CLI) reads raw.mslearn_lookup.suggested_calls and runs:
#      microsoft_docs_search("Microsoft Edge How do I configure IE mode via Group Policy?")
#      microsoft_docs_search("Microsoft Edge Enable Internet Explorer (IE) mode for a site")
#      microsoft_docs_fetch("https://learn.microsoft.com/deployedge/edge-ie-mode")
#    then merges the live results with the local KB answer and cites the URLs.

# Offline-only (skip MCP suggestions):
python edge_qa/scripts/edge_qa.py '{"question":"How do I enable IE mode?","extra":{"use_mslearn":false}}'
```

### Flow 4 — Netlog Analysis

```bash
# Collect: open edge://net-export → Start Logging → reproduce → Stop → save JSON
# Analyse:
python edge_netlog/scripts/edge_netlog.py \
  '{"extra":{"netlog_paths":["C:\\Users\\user\\Downloads\\chrome-net-export-log.json"]}}'

# Or via orchestrator with netlog pre-supplied:
python orchestrator/scripts/edge_orchestrator.py \
  '{"skills_to_trigger":["edge_policy"],"problems":[{"type":"page_load_failure","severity":"critical","summary":"Page fails"}],"extra":{"netlog_paths":["C:\\netlog.json"]}}'
```

### Problem → Auto-triggered Skills

| Problem Type | Severity | Triggered Skills |
|---|---|---|
| `crash` | critical | `edge_crash`, `edge_extensions`, `edge_policy` |
| `hang` | critical | `edge_crash`, `edge_performance`, `edge_extensions` |
| `render_process_gone` | critical | `edge_crash`, `edge_extensions` |
| `slow_startup` | warning | `edge_performance`, `edge_extensions`, `edge_policy` |
| `high_cpu` | warning | `edge_performance`, `edge_extensions` |
| `high_memory` | warning | `edge_performance`, `edge_extensions` |
| `page_slow` | warning | `edge_network`, `edge_netlog`, `edge_performance` |
| `page_load_failure` | critical | `edge_network`, `edge_netlog`, `edge_policy` |
| `cert_error` | critical | `edge_network`, `edge_netlog`, `edge_policy` |
| `proxy_issue` | warning | `edge_network`, `edge_netlog`, `edge_policy` |
| `dns_issue` | warning | `edge_network`, `edge_netlog` |
| `sync_error` | warning | `edge_network`, `edge_policy` |
| `update_blocked` | warning | `edge_policy` |
| `extension_issue` | warning | `edge_extensions`, `edge_policy` |
| `managed_browser` | info | `edge_policy` |
| `question` | info | `edge_qa` |

---

## Standard JSON Contract

### Input

```json
{
  "time_range": { "start": "2026-05-04T10:00:00", "end": "2026-05-04T10:30:00" },
  "problem_type": "crash",
  "question": "Why does Edge crash on startup?",
  "extra": {
    "profile": "Default",
    "netlog_paths": ["C:\\Users\\user\\Downloads\\netlog.json"]
  }
}
```

### Output envelope (v2.1)

```json
{
  "skill": "edge_crash",
  "ok": true,
  "findings": [
    { "summary": "3 crash reports in last 24h — signature: GPU_PROCESS_LAUNCH_FAILED",
      "severity": "critical", "evidence": { "count": 3, "signature": "GPU_PROCESS_LAUNCH_FAILED" } }
  ],
  "root_cause": "GPU process fails to launch — likely driver issue",
  "confidence": "high",
  "recommendations": ["[fix:...] Update graphics driver", "[next:...] run edge_policy"],
  "solutions": [
    { "problem_ref": "crash", "title": "Update or rollback graphics driver",
      "severity": "critical", "steps": ["Device Manager → Display Adapters → Update Driver"],
      "references": ["https://learn.microsoft.com/microsoft-edge/..."] }
  ],
  "next_steps": [
    { "action": "Check if HW acceleration is forced on by policy", "skill": "edge_policy" }
  ],
  "additional_logs_needed": [
    { "log_kind": "netlog", "why": "Check if crash correlates with a network call",
      "how_to_collect": "Open edge://net-export, reproduce, stop, save JSON", "skill": "edge_netlog" }
  ],
  "raw": { "crash_reports": [], "observed_problem_types": ["crash"] }
}
```

**Key fields:**
- `ok` — `false` only on unrecoverable skill error.
- `confidence` — `high / medium / low`.
- `raw.operator_summary` (orchestrator only) — terminal-friendly Markdown summary.
- `raw.missing_logs` (orchestrator only) — log kinds required but not provided.

---

## Invocation Methods

### Python CLI

```bash
# edge_diagnostics: basic environment scan
python edge_diagnostics/scripts/edge_diagnostics.py '{}'

# edge_diagnostics: auto-trigger all recommended follow-ups
python edge_diagnostics/scripts/edge_diagnostics.py --auto-trigger

# edge_crash: with time range
python edge_crash/scripts/edge_crash_analyzer.py \
  '{"time_range":{"start":"2026-05-04T10:00:00","end":"2026-05-04T10:30:00"}}'

# edge_policy: inspect applied policies
python edge_policy/scripts/edge_policy.py '{}'

# edge_netlog: analyse a net-export JSON
python edge_netlog/scripts/edge_netlog.py \
  '{"extra":{"netlog_paths":["C:\\Users\\user\\Downloads\\netlog.json"]}}'

# edge_qa: answer a question
python edge_qa/scripts/edge_qa.py '{"question":"How do I enable IE mode?"}'

# orchestrator: full orchestration from a diagnostics result
python orchestrator/scripts/edge_orchestrator.py @diagnostics_result.json
```

### JSON Context File

```bash
echo '{"problem_type":"page_load_failure","extra":{"netlog_paths":["C:\\netlog.json"]}}' > ctx.json
python edge_netlog/scripts/edge_netlog.py @ctx.json
```

### Via GitHub Copilot CLI

Launch `copilot` from this folder (so `AGENTS.md` is loaded):

```
my Edge keeps crashing on startup — run edge_diagnostics, then orchestrate the follow-ups it recommends

investigate the Edge crash spike between 10:00 and 10:30 today: run edge_crash with that window

how do I configure IE mode site list via Group Policy? use edge_qa

Edge shows NET::ERR_CERT_AUTHORITY_INVALID — analyse the net-export log at C:\netlog.json
```

---

## Orchestrator Aggregation

The orchestrator fuses every child skill's results onto one envelope and writes three extra `raw` fields:

### `raw.cross_source_context`
```json
{
  "sources_used": ["crashpad", "edge_registry"],
  "shared_problem_types": ["crash"],
  "skills_run": ["edge_crash", "edge_policy"],
  "had_input_problems": true
}
```

### `raw.missing_logs`
```json
[
  {
    "log_kind": "netlog",
    "why": "Required to diagnose proxy/TLS failures from the browser side",
    "how_to_collect": "Open edge://net-export, click Start Logging To Disk, reproduce, Stop.",
    "skill": "edge_netlog"
  }
]
```

### `raw.operator_summary`
A Markdown string with:
- `# Edge orchestrator summary`
- Top findings grouped by severity
- Solutions / Next steps / Additional logs sections
- `## Missing required logs` section (if any)

Readable directly on the terminal even without an HTML viewer.

---

## Missing-Log Gate

```
expected = playbook.logs_for(problem_types) ∪ child.additional_logs_needed
provided = EXTRA_KEY_TO_KIND resolved from extra.* ∪ SKILL_PRODUCES_KINDS for successful skills
missing  = expected − provided
```

To close the `netlog` gap:
```bash
# Collect from Edge:
#   1. Open a new Edge tab
#   2. Navigate to edge://net-export
#   3. Click "Start Logging To Disk" → choose output file
#   4. Reproduce the issue
#   5. Click "Stop"
#   6. Pass the JSON file:
python orchestrator/scripts/edge_orchestrator.py \
  '{"problems":[{"type":"page_load_failure","severity":"critical","summary":"..."}],
    "extra":{"netlog_paths":["C:\\netlog.json"]}}'
```

---

## Playbook & Problem Types

`_shared/playbook.json` maps each `problem_type` to solutions, next steps, and required logs. Skills call `playbook.merge_into_result(result, problem_types)` to auto-populate advisories.

| Problem Type | Severity | Description |
|---|---|---|
| `crash` | critical | Edge process crashed |
| `hang` | critical | Edge became unresponsive |
| `render_process_gone` | critical | Renderer process killed (Aw, Snap!) |
| `slow_startup` | warning | Edge takes unusually long to open |
| `high_cpu` | warning | `msedge.exe` consuming excessive CPU |
| `high_memory` | warning | `msedge.exe` consuming excessive RAM |
| `page_slow` | warning | Pages load slowly |
| `page_load_failure` | critical | Page cannot load |
| `cert_error` | critical | TLS certificate error |
| `proxy_issue` | warning | Proxy mis-configuration |
| `dns_issue` | warning | DNS resolution failure |
| `sync_error` | warning | Edge sync not working |
| `update_blocked` | warning | Edge update prevented by policy |
| `extension_issue` | warning | Extension causing problems |
| `extension_blocked` | info | Extension blocked by policy |
| `managed_browser` | info | Browser managed by Group Policy / Intune |
| `feature_blocked` | info | Feature disabled by policy |
| `question` | info | User has a knowledge question |

---

## Shared Source Readers

All data access is in `_shared/sources/`. Skills never access Edge files directly:

```python
from _shared.sources import crashpad, edge_registry, user_data, processes, netlog

# Uniform surface on every module:
module.discover(...)           # → list of available sources
module.iter_entries(source)    # → Iterator[dict]
module.summarise(entries)      # → dict
module.apply_filter(entries, filter) # → Iterator[dict]
module.query(...)              # → {entries, summary, truncated, sources_used}
```

| Module | Filter Dataclass | What It Reads |
|---|---|---|
| `crashpad` | `CrashpadFilter(signature, process_type, min_size_bytes)` | `User Data/Crashpad/reports/*.dmp` |
| `edge_registry` | `PolicyFilter(category, name_contains, hive)` | `HKLM/HKCU\Software\Policies\Microsoft\Edge` |
| `user_data` | `EdgeProfileFilter(profile_name, extension_id, enabled_only)` | Profile `Preferences`, `Extensions/` |
| `processes` | `ProcessFilter(min_cpu_seconds, min_working_set_mb)` | Live `msedge.exe` snapshot |
| `netlog` | `NetlogFilter(source_type, phase, contains)` | `edge://net-export` JSON |

---

## Project Conventions

- **Python 3.10+, standard library only** — no third-party packages.
- All scripts are **runnable from any working directory**.
- **Read-only by design** — no skill modifies Edge settings or terminates processes.
- **Windows-first** — scripts degrade gracefully on other OSes (emit `ok: true` with an empty payload and a note in `findings`).
- `needs_elevation: true` in `raw` when a skill hits a permission limit.
- Registry: [`_shared/registry.json`](_shared/registry.json) · Contract: [`_shared/contract.py`](_shared/contract.py)
