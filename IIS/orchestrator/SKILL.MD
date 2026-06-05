---
id: orchestrator
name: Skill Orchestrator
version: 3.2
role: coordinator|entry_point
description: Folder-first entry point that discovers IIS / FTP / HTTPERR / EVTX / netlog logs, dispatches the right entry skills (optionally driven by --around anchors or --error REGEX), performs secondary fan-out, and optionally writes an HTML report. Also keeps the legacy pipe mode that fans out an IIS analyzer payload.
runtime:
  python: scripts/skill_orchestrator.py
needs_admin: inherits_from_subskills
---

> **Single entry point.** When the user supplies a folder containing **any mix** of IIS `*.log`, FTP `*.log`, HTTPERR `*.log`, Windows `*.evtx`, or Chromium net-export `*.json` files, prefer **this** skill over invoking `iis_logs` / `netlog` / `event_log` directly. The orchestrator handles discovery, classification, dispatch, and result fusion in one call. The list of sub-skills that actually ran is reported as `executed_summary` at the top level of the JSON envelope (and as `raw.executed`).

## Agent invocation & reporting rules (read first)

> These rules exist because the per-sub-skill `subprocess.run()` calls happen **inside one Python process** and are otherwise invisible to the agent UI.

**1. Invocation — pass the folder as a positional argument.** Do **NOT** pass JSON like `{"extra":{"folder":"..."}}`; that targets legacy pipe mode and (unless auto-promoted) will return "Nothing to orchestrate" without running any sub-skill.

```powershell
# CORRECT — folder as positional arg
python IIS\orchestrator\scripts\skill_orchestrator.py "C:\path\to\logs" --report "C:\path\to\diagnosis.html"
```

**2. Always surface stderr to the user.** The orchestrator prints a live `>>> running skill: iis_logs / netlog / event_log ...` trace on **stderr**. You **must** both save it to `orch.err` *and* print its full contents to the chat/terminal — never just redirect and drop it.

```powershell
python IIS\orchestrator\scripts\skill_orchestrator.py "<folder>" --report orch.html > orch.json 2> orch.err
Write-Host "----- orchestrator stderr (orch.err) -----"
Get-Content orch.err
Write-Host "----- end orchestrator stderr -----"
```

Bash equivalent: `python ... "<folder>" --report orch.html > orch.json 2> orch.err; echo '----- orch.err -----'; cat orch.err`

**3. When summarising the JSON to the user, always read these keys (in this order) and quote them verbatim:**

| Key | Why it must be surfaced |
|---|---|
| `executed_summary` (top level) | One-line "iis_logs OK, netlog OK, ..." — proves which sub-skills ran |
| `raw.discovery` | Per-log-kind file count — proves what the orchestrator saw in the folder |
| `raw.executed` | Ordered list of sub-skill ids actually invoked |
| `raw.results[<skill>].findings` | The per-sub-skill findings (already merged into top-level `findings` with a `[<skill>]` prefix) |
| `findings`, `solutions`, `next_steps`, `additional_logs_needed`, `root_cause` | Standard envelope sections |

A minimal Python summary snippet the agent should reuse:

```python
import json
d = json.load(open(r"<orch.json>", encoding="utf-8"))
print("executed_summary:", d.get("executed_summary"))
print("discovery:", {k: len(v) for k, v in (d.get("raw", {}).get("discovery") or {}).items()})
print("executed:", d.get("raw", {}).get("executed"))
print("root_cause:", d.get("root_cause"))
for f in d.get("findings", []): print("-", f.get("severity"), "|", f.get("summary"))
```

**4. Folder-mode JSON mistake is auto-corrected.** If you do accidentally pass `{"extra":{"folder":"<existing dir>"}}`, the orchestrator now auto-promotes that into folder mode (logs `[orchestrator] auto-promoting JSON 'extra.folder' to folder mode: ...` on stderr). The output envelope will still contain `executed_summary` / `raw.discovery` / `raw.executed` — surface them per rule 3.

## Two modes (auto-detected)

| Mode | Triggered when | What it does |
|---|---|---|
| **Folder mode** *(new)* | First positional arg is an existing directory | Walks the folder, classifies every log, runs entry skills, fuses results |
| **Legacy pipe mode** | Arg is JSON, `@file`, a `.json` path, or stdin contains JSON | Same v2 fan-out behaviour — accepts IIS analyzer payload, runs `skills_to_trigger` in parallel |

Both modes share the same `--per-skill-timeout` / `--total-timeout` knobs.

---

## Folder mode

### When to use

- The user provides a directory (incident bundle, copied `LogFiles\`, support upload …) containing **a mix of log kinds** (`*.log`, `*.evtx`, net-export `*.json`).
- The user describes a symptom (`NullReferenceException`, `503`, `Timer_AppPool`, TLS / auth / proxy errors …) but does not know the exact timestamp.
- The user wants an HTML one-pager summarising what every skill found.
- **Any time a folder may contain a net-export JSON** (`edge://net-export` / `chrome://net-export` capture) alongside other logs — the orchestrator auto-dispatches the `netlog` sub-skill, so do not call `netlog` manually first.

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
  ├─ discover_logs (IIS / FTP / HTTPERR / EVTX / netlog / unknown)
  ├─ [optional] find_error_anchors  ← --error REGEX
  ├─ dedup_anchors  ← --around + error anchors
  ├─ compute bounding time_range
  ├─ dispatch entry skills (in parallel where safe):
  │    iis_logs   <folder> --around T1 --around T2 --window 5m
  │    ftp_logs   <folder> --around T1 --around T2 --window 5m
  │    httperror  via JSON {extra.folder, time_range}
  │    event_log  via JSON {extra.evtx_paths, time_range}
  │    netlog     via JSON {extra.netlog_paths, time_range}
  ├─ secondary fan-out — re-uses legacy orchestrate() for any raw.skills_to_trigger
  └─ fuse findings + optional HTML report
```

**netlog classification rule** — a `*.json` file qualifies as a Chromium net-export capture only if the first 256 bytes contain `"constants"` *and* one of `"logSourceType"` / `"logEventTypes"` / `"clientInfo"` appears within the first 1 MB (see [_shared/log_discovery.py](../_shared/log_discovery.py)). Files that fail this sniff are bucketed as `unknown` and skipped — rename or re-export them if you expect them to be picked up.

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
  "executed_summary": "iis_logs OK, netlog OK, event_log OK",
  "findings": [ "[iis_logs] ...", "[netlog] ...", "[event_log] ..." ],
  "root_cause": "iis_logs: ... → netlog: ...",
  "confidence": "high|medium|low",
  "raw": {
    "mode": "folder",
    "input": {"folder": "...", "recursive": true, "anchors": [...],
              "window": "5m", "window_seconds": 300,
              "error_pattern": "NullReferenceException", "time_range": {...}},
    "discovery": {"iis_w3c": [...], "ftp_w3c": [...], "httperr": [...],
                  "evtx": [...], "netlog": [...], "unknown": [...]},
    "error_locator": {"pattern": "...", "hits": [...], "derived_anchors": [...]},
    "executed": ["iis_logs", "netlog", "event_log"],
    "results":  {"iis_logs": {...}, "netlog": {...}, "event_log": {...}},
    "secondary": { ...envelope from legacy orchestrate() if any... },
    "root_cause_chain": [{"skill": "iis_logs", "finding": "..."}, ...],
    "report_html_path": "C:\\incidents\\report.html"
  }
}
```

**`executed_summary`** is a top-level, single-line, human-readable string that lists which entry skills the orchestrator actually invoked and whether each one succeeded. Agents that present this skill's result back to the user **should quote `executed_summary` verbatim** so it is visible which sub-skills ran (the per-skill child invocations happen inside one Python subprocess and are otherwise invisible to the agent UI).

### Notes

- **EVTX files are recognised by extension only** — the orchestrator forwards them to `event_log` via `extra.evtx_paths`; the error locator skips them with an info record.
- **netlog files** are auto-dispatched to the `netlog` sub-skill via `extra.netlog_paths` whenever any `*.json` file passes the net-export sniff (see Flow above). They are skipped by the `--error` text scanner.
- **Bounding window**: when both `--around` and `--error` produce anchors, the orchestrator builds **one** `time_range` covering all of them (earliest − window … latest + window) and passes it to the JSON-driven skills (`httperror`, `event_log`, `netlog`).
- **iis_logs / ftp_logs** receive each anchor as a separate `--around` so they keep per-anchor mini-reports.
- **No anchors at all**: the orchestrator still runs `iis_logs` / `ftp_logs` / `netlog` for baseline stats; `httperror` runs in folder mode without time filtering; `event_log` is skipped (live mode is meaningless without a window).
- **Sub-skill invocation is internal** — child analyzers run as `subprocess.run()` calls inside one Python process. The agent UI sees a single command. To verify which sub-skills ran, read `executed_summary` (top level) or `raw.executed` / `raw.results` from the JSON envelope, or watch the `>>> running skill: ...` lines on **stderr**.

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
