---
id: orchestrator
name: Skill Orchestrator
version: 3.0
role: coordinator|entry_point
description: Folder-first entry point that discovers IIS / FTP / HTTPERR / EVTX logs, dispatches the right entry skills (optionally driven by --around anchors or --error REGEX), performs secondary fan-out, and optionally writes an HTML report. Also keeps the legacy pipe mode that fans out an IIS analyzer payload.
runtime:
  python: scripts/skill_orchestrator.py
needs_admin: inherits_from_subskills
---

## Two modes (auto-detected)

| Mode | Triggered when | What it does |
|---|---|---|
| **Folder mode** *(new)* | First positional arg is an existing directory | Walks the folder, classifies every log, runs entry skills, fuses results |
| **Legacy pipe mode** | Arg is JSON, `@file`, a `.json` path, or stdin contains JSON | Same v2 fan-out behaviour — accepts IIS analyzer payload, runs `skills_to_trigger` in parallel |

Both modes share the same `--per-skill-timeout` / `--total-timeout` knobs.

---

## Folder mode

### When to use

- The user provides a directory (incident bundle, copied `LogFiles\`, support upload …) containing **a mix of log kinds** (`*.log`, `*.evtx`).
- The user describes a symptom (`NullReferenceException`, `503`, `Timer_AppPool`, …) but does not know the exact timestamp.
- The user wants an HTML one-pager summarising what every skill found.

### Invocation

```powershell
# 1) folder only — let the orchestrator discover everything
python orchestrator/scripts/skill_orchestrator.py C:\incidents\2026-05-26

# 2) folder + explicit anchor(s)
python orchestrator/scripts/skill_orchestrator.py C:\incidents\2026-05-26 `
    --around "2026-05-26 10:15:30" --around "2026-05-26 10:17:00" --window 5m

# 3) folder + error-driven anchor discovery
python orchestrator/scripts/skill_orchestrator.py C:\incidents\2026-05-26 `
    --error "NullReferenceException|Timer_AppPool" --window 5m `
    --report C:\incidents\report.html
```

### Flow

```
folder
  ├─ discover_logs (IIS / FTP / HTTPERR / EVTX / unknown)
  ├─ [optional] find_error_anchors  ← --error REGEX
  ├─ dedup_anchors  ← --around + error anchors
  ├─ compute bounding time_range
  ├─ dispatch entry skills (in parallel where safe):
  │    iis_logs   <folder> --around T1 --around T2 --window 5m
  │    ftp_logs   <folder> --around T1 --around T2 --window 5m
  │    httperror  via JSON {extra.folder, time_range}
  │    event_log  via JSON {extra.evtx_paths, time_range}
  ├─ secondary fan-out — re-uses legacy orchestrate() for any raw.skills_to_trigger
  └─ fuse findings + optional HTML report
```

### CLI

| Flag | Default | Meaning |
|---|---|---|
| `<folder>` (positional) | — | Folder to scan. If this is **not** a directory, legacy pipe mode is used instead. |
| `--around TS` | (repeatable, none) | Anchor timestamp (e.g. `"2026-05-26 10:15:30"`). |
| `--window DUR` | `5m` | Window applied symmetrically around every anchor. |
| `--error REGEX` | none | Case-insensitive regex; every matching line's timestamp becomes an extra anchor. |
| `--no-recursive` | off | Do not descend into subdirectories. |
| `--report PATH` | none | Write a self-contained HTML summary. |
| `--per-skill-timeout SEC` | `60` | Per-subprocess timeout. |
| `--total-timeout SEC` | `180` | Total wait time for the secondary fan-out. |

### Folder-mode output

```json
{
  "skill": "orchestrator",
  "ok": true,
  "findings": [ "[iis_logs] ...", "[httperror] ...", "[event_log] ..." ],
  "root_cause": "iis_logs: ... → event_log: ...",
  "confidence": "high|medium|low",
  "raw": {
    "mode": "folder",
    "input": {"folder": "...", "recursive": true, "anchors": [...],
              "window": "5m", "window_seconds": 300,
              "error_pattern": "NullReferenceException", "time_range": {...}},
    "discovery": {"iis_w3c": [...], "ftp_w3c": [...], "httperr": [...],
                  "evtx": [...], "unknown": [...]},
    "error_locator": {"pattern": "...", "hits": [...], "derived_anchors": [...]},
    "executed": ["iis_logs", "httperror", "event_log"],
    "results":  {"iis_logs": {...}, "httperror": {...}, "event_log": {...}},
    "secondary": { ...envelope from legacy orchestrate() if any... },
    "root_cause_chain": [{"skill": "iis_logs", "finding": "..."}, ...],
    "report_html_path": "C:\\incidents\\report.html"
  }
}
```

### Notes

- **EVTX files are recognised by extension only** — the orchestrator forwards them to `event_log` via `extra.evtx_paths`; the error locator skips them with an info record.
- **Bounding window**: when both `--around` and `--error` produce anchors, the orchestrator builds **one** `time_range` covering all of them (earliest − window … latest + window) and passes it to the JSON-driven skills (`httperror`, `event_log`).
- **iis_logs / ftp_logs** receive each anchor as a separate `--around` so they keep per-anchor mini-reports.
- **No anchors at all**: the orchestrator still runs `iis_logs` / `ftp_logs` for baseline stats; `httperror` runs in folder mode without time filtering; `event_log` is skipped (live mode is meaningless without a window).

---

## Legacy pipe mode *(backward compatible)*

Unchanged from v2. Use this when an `iis_logs` payload already exists.

### When to use
- After [iis_logs](../IIS_logs/SKILL.MD) has produced problems
- For one-shot "diagnose this incident" requests from a captured payload

### Inputs

Reads the IIS analyzer payload as JSON from the first positional argument, `@file.json`, or stdin. Accepts both the full envelope and just its `raw` block.

| Field | Required | Description |
|---|---|---|
| `skills_to_trigger` | yes | List of skill ids to run |
| `problems` | yes | Each problem's `type` picks the right `problem_type` per sub-skill |
| `metrics.time_range` | recommended | Forwarded to every sub-skill as `time_range` |

### Invocation

```powershell
# pipe (recommended)
python IIS_logs/scripts/iis_analyzer.py <log> | python orchestrator/scripts/skill_orchestrator.py

# from a saved file
python orchestrator/scripts/skill_orchestrator.py @C:\temp\iis_out.json

# tunables
python orchestrator/scripts/skill_orchestrator.py --per-skill-timeout 90 --total-timeout 240 @ctx.json
```

### Legacy output

`raw` contains:
```json
{
  "executed": ["app_crash","event_log","httperror"],
  "results":  { "<skill_id>": <subskill envelope>, ... },
  "root_cause_chain": [ { "skill": "...", "finding": "..." } ]
}
```

Confidence rule: `successes/total ≥ 0.8 → high`, `≥ 0.5 → medium`, otherwise `low`.

---

## Common notes
- Skill paths come from [_shared/registry.json](../_shared/registry.json) — never hard-coded.
- Up to 3 sub-skills run in parallel (`ThreadPoolExecutor`).
- A sub-skill returning `ok=false` causes orchestrator `ok=false` but does **not** abort the run; other sub-skills still execute.
- Idempotent: re-running with the same input is safe.

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- Aggregates every child skill's advisory fields with dedup keys ``(problem_ref,title)`` / ``(action,skill)`` / ``(log_kind,skill)``. Adds ``raw.cross_log_context = {available, time_range, correlatable, note}`` describing which log kinds were discovered together. HTML report renders ``Solutions`` / ``Next steps`` / ``Additional logs needed`` / ``Cross-log context`` as top-level ``<h2>`` sections.

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
