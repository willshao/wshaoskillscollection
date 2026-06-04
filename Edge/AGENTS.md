# AGENTS.md — Microsoft Edge Diagnostics Skills

This folder ships a **set of composable skills** for answering questions about
Microsoft Edge (Chromium) and troubleshooting Edge issues on Windows.

This file is auto-loaded by GitHub Copilot CLI (`copilot`) when you launch it
from this folder, and it tells the agent how to use the skills below.

## What you have

A skill collection rooted at this folder. Each subfolder is one skill:

| Skill id | Folder | Entry script | What it does |
|---|---|---|---|
| `edge_diagnostics` | `edge_diagnostics/` | `scripts/edge_diagnostics.py` | Entry point. Detects Edge install, channel, version, profile path, managed status, recent crashes; classifies problem types; recommends follow-ups. |
| `edge_crash` | `edge_crash/` | `scripts/edge_crash_analyzer.py` | Enumerate Crashpad reports, classify crash signature, suggest mitigations. |
| `edge_performance` | `edge_performance/` | `scripts/edge_performance.py` | Sample live `msedge.exe` processes (CPU / memory / handle count) and flag heavy renderers. |
| `edge_network` | `edge_network/` | `scripts/edge_network.py` | Diagnose proxy / DNS / certificate / connectivity issues affecting Edge. |
| `edge_policy` | `edge_policy/` | `scripts/edge_policy.py` | Inspect `HKLM/HKCU\Software\Policies\Microsoft\Edge`, list applied managed policies. |
| `edge_extensions` | `edge_extensions/` | `scripts/edge_extensions.py` | Enumerate installed extensions per profile; flag risky/disabled/forced ones. |
| `edge_netlog` | `edge_netlog/` | `scripts/edge_netlog.py` | Parse Chromium `edge://net-export` JSON files. Classifies certificate / DNS / proxy / generic page-load failures and slow URL requests. Feeds `page_load_failure`, `cert_error`, `dns_issue`, `proxy_issue`, `page_slow`. |
| `edge_qa` | `edge_qa/` | `scripts/edge_qa.py` | Knowledge-base Q&A for common Edge questions (flags, keyboard shortcuts, IE mode, sync, profiles, etc.). |
| `orchestrator` | `orchestrator/` | `scripts/edge_orchestrator.py` | Run multiple skills based on a problem set, fuse results. |

The authoritative registry is [_shared/registry.json](_shared/registry.json).
All skills follow a uniform JSON contract defined in [_shared/contract.py](_shared/contract.py).

## Standard contract (every skill)

Input — first positional argument is a JSON string OR `@path/to/file.json`:
```json
{
  "time_range": {"start": "2026-05-26T10:00:00", "end": "2026-05-26T10:30:00"},
  "problem_type": "crash",
  "question": "How do I enable IE mode for a site?",
  "extra": { "profile": "Default" }
}
```

Output — a single JSON object on stdout (envelope v2.1):
```json
{
  "skill": "<id>",
  "ok": true,
  "findings": [{ "summary": "...", "severity": "critical|warning|info", "evidence": {} }],
  "root_cause": "<short string or null>",
  "confidence": "high|medium|low",
  "recommendations": ["[fix:...] ...", "[next:...] ...", "[logs:...] ..."],
  "solutions": [ { "problem_ref": "crash", "title": "...", "severity": "critical|warning|info", "steps": ["..."], "references": ["..."] } ],
  "next_steps": [ { "action": "...", "why": "...", "skill": "<next-skill-id>" } ],
  "additional_logs_needed": [ { "log_kind": "crashpad|netlog|registry|user_data|processes", "why": "...", "how_to_collect": "...", "skill": "<consumer>" } ],
  "raw": { ... skill-specific payload ... }
}
```

`solutions`, `next_steps`, `additional_logs_needed` are seeded from [_shared/playbook.json](_shared/playbook.json) keyed on `problem_type`, via `_shared.playbook.merge_into_result(result, problem_types=[...])`. Skills may append context-specific entries. When `recommendations` is empty, the envelope auto-flattens the three structured fields into `[fix:...]` / `[next:...]` / `[logs:...]` strings for legacy consumers. JSON is always emitted ASCII-safe.

Errors go to stderr; exit code != 0 means the skill failed.

## Shared source readers ([_shared/sources/](_shared/sources/))

Skills do **not** parse Edge data sources inline anymore. Each kind has one canonical reader exposing a uniform `discover / iter_entries / summarise / apply_filter / around_window / query` surface:

| Module | Filter dataclass | What it reads |
|---|---|---|
| `crashpad` | `CrashpadFilter(signature, process_type, min_size_bytes)` | `User Data/Crashpad/reports/*.dmp` metadata |
| `edge_registry` | `PolicyFilter(category, name_contains, subkey_contains, hive)` | `HKLM/HKCU\Software\Policies\Microsoft\Edge` (Windows-only) |
| `user_data` | `EdgeProfileFilter(profile_name, extension_id, enabled_only)` | Profile `Preferences`, `Secure Preferences`, `Extensions/` |
| `processes` | `ProcessFilter(min_cpu_seconds, min_working_set_mb, name_contains)` | live `msedge.exe` snapshot (CPU / WS / handle count / type) |
| `netlog` (Chromium net-export) | `NetlogFilter(source_type, phase, contains)` | Edge `--log-net-log` / `edge://net-export` JSON; the `edge_netlog` skill is the primary consumer. |

Each `query()` returns `{"entries": [...], "summary": {...}, "truncated": bool, "sources_used": [...]}`.

## Orchestrator aggregation

[orchestrator/scripts/edge_orchestrator.py](orchestrator/scripts/edge_orchestrator.py) dedups every child skill's `solutions` / `next_steps` / `additional_logs_needed` onto its own envelope, and writes two extra raw fields:

- `raw.cross_source_context = { sources_used, shared_problem_types, skills_run, had_input_problems }` — which `_shared/sources/*` were exercised across the run.
- `raw.missing_logs = [{ log_kind, why, how_to_collect, skill }, …]` — log kinds the playbook or a child skill flagged as required but the user did not provide. Each missing kind is also emitted as a `warning` `Finding` and rendered in the `## Missing required logs` section of `raw.operator_summary`. Pass `extra.netlog_paths` (or any future `extra.*_paths`) to close the gap for that kind.
- `raw.operator_summary` — a Markdown string (`# Edge orchestrator summary` + top findings + the three advisory sections + missing-log section if any) that is terminal-friendly even without an HTML report.

## How to ask Copilot CLI to use these skills

Always launch `copilot` from this folder so `AGENTS.md` is loaded.

**General troubleshooting (let the entry skill decide):**
```
my Edge keeps crashing on startup — run edge_diagnostics, then orchestrate the follow-ups it recommends
```

**Targeted scenario:**
```
investigate the Edge crash spike between 10:00 and 10:30 today: run edge_crash with that window, then summarize the top signatures
```

**Ask a question (Q&A KB):**
```
how do I configure IE mode site list via Group Policy? use edge_qa
```

**Direct invocation by the agent:**
- Single skill: `python <skill>/scripts/<entry>.py '<json-context>'`
- Auto-orchestrate: `python edge_diagnostics/scripts/edge_diagnostics.py --auto-trigger`
- Full orchestration: `python orchestrator/scripts/edge_orchestrator.py '<diagnostics-result-json>'`

## Rules for the agent

1. **Always start from `edge_diagnostics`** for troubleshooting requests, unless
   the user has already named the problem type or is asking a knowledge question.
2. For knowledge questions ("how do I…", "what is…", "where is…"), go straight
   to `edge_qa`.
3. **Only call follow-up skills that `edge_diagnostics` listed in
   `skills_to_trigger`** — do not invent new ones.
4. **Pass `time_range` from the diagnostics result** to every downstream skill
   when a window is known; do not fall back to "now − 1h" silently.
5. **Treat skills as black boxes via the contract above.** Don't re-scrape
   Edge's profile folder yourself if a skill already exposes that data.
6. **Some skills are read-only by design** — none of these scripts modify Edge
   settings or terminate processes. If a fix requires changes, describe the
   change and ask the user to apply it.
7. **No admin rights are required** for the default actions. Some
   investigations (e.g., reading another user's profile, querying enterprise
   policy in HKLM) may need elevation; the affected skill will report
   `needs_elevation: true` in its `raw` block when it hits this limit.

## Project conventions

- Python 3.10+, standard library only.
- All scripts must be runnable from any cwd (use `Path(__file__).parent` for
  sibling lookups).
- Skill paths and capabilities live in [_shared/registry.json](_shared/registry.json)
  — update it when you add or move a skill.
- This collection targets **Windows** first (where Edge is most commonly
  deployed and managed). Scripts degrade gracefully on other OSes by emitting
  an `ok: true` envelope with an empty payload and a note in `findings`.
