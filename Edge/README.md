# Microsoft Edge Diagnostics Skills

A composable, dependency-free skill collection for answering questions about
Microsoft Edge (Chromium) and troubleshooting common Edge issues on Windows.

See **[AGENTS.md](AGENTS.md)** for the full skill catalog, contract, and
invocation rules — that file is also what GitHub Copilot CLI loads
automatically when you start `copilot` from this folder.

## Quick start

```powershell
# 1) From this folder, launch copilot
copilot

# 2) Ask a question
> my Edge is using 4 GB of RAM with 6 tabs open, what's going on?

# 3) Or invoke a skill directly
python edge_diagnostics\scripts\edge_diagnostics.py --auto-trigger
python edge_qa\scripts\edge_qa.py '{"question":"how do I enable IE mode?"}'
```

## What's in a report? (envelope v2.1)

Every skill's JSON envelope — and the orchestrator's `raw.operator_summary`
Markdown — carries three structured advisory sections in addition to the
raw findings:

| Field | Purpose |
|---|---|
| `solutions[]` | Concrete fixes for key problems (`problem_ref`, `title`, `severity`, ordered `steps`, optional `references`). |
| `next_steps[]` | Investigation actions to take next (`action`, `why`, optional `skill` to run). |
| `additional_logs_needed[]` | Extra data sources required to deepen analysis (`log_kind`, `why`, `how_to_collect`, optional `skill`). |

Content is seeded from [_shared/playbook.json](_shared/playbook.json) keyed on
`problem_type`, via `_shared.playbook.merge_into_result(...)`. Skills may
append context-specific entries. Legacy `recommendations: string[]` is
auto-populated when empty (prefixes `[fix:...]`, `[next:...]`, `[logs:...]`)
so older consumers keep working.

The orchestrator dedups all three across child skills, writes the
aggregates to its own envelope, and adds:

- `raw.cross_source_context` — which `_shared/sources/*` were exercised and any shared problem types across skills.
- `raw.operator_summary` — a terminal-friendly Markdown summary with the three sections inlined.

## Shared source readers ([_shared/sources/](_shared/sources/))

Skills no longer parse Edge data sources inline. Each kind has one canonical
reader exposing a uniform `discover / iter_entries / summarise / apply_filter
/ around_window / query` surface:

| Module | Filter dataclass | Reads |
|---|---|---|
| `crashpad` | `CrashpadFilter` | Crashpad `.dmp` reports under `User Data/Crashpad` |
| `edge_registry` | `PolicyFilter` | Edge managed policies under `HKLM/HKCU\Software\Policies\Microsoft\Edge` |
| `user_data` | `EdgeProfileFilter` | Profile `Preferences` + `Extensions/` enumeration |
| `processes` | `ProcessFilter` | live `msedge.exe` snapshot (CPU / WS / handle count) |
| `netlog` | `NetlogFilter` | Edge `--log-net-log` JSON (stub) |

## Skills at a glance

| Skill | Role | What it answers |
|---|---|---|
| `edge_diagnostics` | entry_point | Is Edge installed? What channel/version? Are there recent crashes? What should I look at next? |
| `edge_crash` | follow-up | Why is Edge crashing? Group recent Crashpad reports by signature. |
| `edge_performance` | follow-up | Which `msedge.exe` processes are hot right now? Renderer vs GPU vs utility breakdown. |
| `edge_network` | follow-up | DNS / proxy / certificate / connectivity sanity checks. |
| `edge_policy` | follow-up | What managed policies are applied to this Edge install? |
| `edge_extensions` | follow-up | What extensions are installed, force-installed, or disabled? |
| `edge_qa` | knowledge_base | Common Edge questions (IE mode, sync, flags, shortcuts, profiles, reset). |
| `orchestrator` | coordinator | Run multiple skills in parallel based on a problem set and fuse the results. |

## Requirements

- Windows 10/11 (other OSes degrade gracefully).
- Python 3.10+.
- No third-party Python packages required.
- No admin rights for the default code paths.

## Layout

```
Edge/
├── AGENTS.md            # Loaded by copilot CLI
├── README.md            # You are here
├── _shared/
│   ├── contract.py      # Skill envelope + context helpers
│   └── registry.json    # Canonical skill registry
├── edge_diagnostics/    # Entry-point skill
├── edge_crash/
├── edge_performance/
├── edge_network/
├── edge_policy/
├── edge_extensions/
├── edge_qa/
│   ├── scripts/
│   └── kb/              # Q&A knowledge-base JSON
└── orchestrator/
```
