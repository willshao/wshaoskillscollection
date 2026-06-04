---
id: edge_qa
name: Edge Q&A Knowledge Base
version: 1.0
role: knowledge_base
description: Answer common Microsoft Edge questions from a local knowledge base. Lightweight keyword search across curated entries.
runtime:
  python: scripts/edge_qa.py
needs_admin: false
triggers_for: [question]
---

## When to use
The user asks a "how do I…", "what is…", "where is…", or "can I…" question
about Microsoft Edge. Do **not** use this for live troubleshooting that needs
to inspect the machine; use `edge_diagnostics` for that.

## Inputs

| Field | Required | Description |
|---|---|---|
| `question` | yes | Free-text question. |
| `extra.top_k` | no | Number of answers to return (default 3). |

## Method

A small, hand-curated knowledge base lives at [kb/kb.json](kb/kb.json). Each
entry has a list of `keywords` and `aliases`. The skill scores each entry by
the number of keyword/alias hits in the lowercased question, breaks ties by
the order in the file, and returns the top-K with full answers.

When no entry scores above zero, the skill returns a generic "I don't have a
canned answer; here are pointers to official docs" response so the agent
doesn't hallucinate.

## Output

```json
{
  "raw": {
    "question": "how do i enable ie mode?",
    "matches": [
      {
        "id": "ie_mode_enable",
        "title": "Enable IE mode for a site",
        "score": 4,
        "answer": "1. Open edge://settings/defaultBrowser …",
        "doc_links": ["https://learn.microsoft.com/..."]
      }
    ]
  }
}
```

`findings` mirror the matches so the agent can summarize them inline.

## Extending the KB

Add a new entry to [kb/kb.json](kb/kb.json):

```json
{
  "id": "unique_id",
  "title": "Human-readable title",
  "keywords": ["primary", "verbs", "and", "nouns"],
  "aliases": ["alternative phrases", "common typos"],
  "answer": "Markdown answer body…",
  "doc_links": ["https://learn.microsoft.com/..."]
}
```

## Invocation

```powershell
python edge_qa\scripts\edge_qa.py '{"question":"how do I reset Edge to defaults?"}'
```

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- None. ``edge_qa`` answers from a static KB and only uses the playbook merge.

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
