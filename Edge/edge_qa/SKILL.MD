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
| `extra.use_mslearn` | no | Emit `raw.mslearn_lookup` MCP suggestions (default `true`). Set to `false` for fully offline use. |

## Method

A small, hand-curated knowledge base lives at [kb/kb.json](kb/kb.json). Each
entry has a list of `keywords` and `aliases`. The skill scores each entry by
the number of keyword/alias hits in the lowercased question, breaks ties by
the order in the file, and returns the top-K with full answers.

When no entry scores above zero, the skill returns a generic "I don't have a
canned answer; here are pointers to official docs" response so the agent
doesn't hallucinate.

## MS Learn MCP integration

The Python skill **cannot** call MCP tools itself — `microsoft_docs_search`,
`microsoft_docs_fetch`, and `microsoft_code_sample_search` are only available
to the AI agent running inside Copilot CLI. Instead, the skill publishes a
structured `raw.mslearn_lookup` block that tells the agent which MCP queries
to run. This makes the contract explicit and keeps the script itself
hermetic / offline-safe.

The agent contract is:

1. The user asks a question → agent invokes `edge_qa`.
2. `edge_qa` returns its local KB matches *plus* a `raw.mslearn_lookup` block:
   ```json
   {
     "raw": {
       "mslearn_lookup": {
         "enabled": true,
         "rationale": "edge_qa returns curated KB answers that may lag …",
         "site_filter_hint": "site:learn.microsoft.com (microsoft-edge OR deployedge)",
         "suggested_calls": [
           { "tool": "microsoft_docs_search",
             "query": "Microsoft Edge how do I enable IE mode?",
             "why": "Find current official documentation that answers the question." },
           { "tool": "microsoft_docs_search",
             "query": "Microsoft Edge Enable Internet Explorer (IE) mode for a site",
             "why": "Cross-check KB entry 'ie_mode_enable' against the latest docs." },
           { "tool": "microsoft_docs_fetch",
             "query": "https://learn.microsoft.com/deployedge/edge-ie-mode",
             "why": "Retrieve the full, current page content for the top KB reference." }
         ]
       }
     },
     "next_steps": [
       { "action": "Call microsoft_docs_search / microsoft_docs_fetch with …",
         "skill": "microsoft_docs_mcp" }
     ]
   }
   ```
3. The agent loops over `suggested_calls`, invokes each MCP tool with the
   given `query`, and **merges** the live results into its final reply —
   citing the returned URLs.
4. If the local KB had **zero matches**, the MCP results become the primary
   answer (the skill confidence is `low` to signal this).
5. To force fully offline behaviour (e.g. in air-gapped environments or
   automated tests), set `extra.use_mslearn: false`; the skill then omits the
   `mslearn_lookup` block entirely.

The recommendations list also carries a `[mcp:microsoft_docs_search]` tag so
the agent sees the MCP cue even when only reading flattened
`recommendations[]`.

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
# Default: local KB + MS Learn MCP suggestions
python edge_qa\scripts\edge_qa.py '{"question":"how do I reset Edge to defaults?"}'

# Offline-only (no MS Learn suggestions)
python edge_qa\scripts\edge_qa.py '{"question":"how do I reset Edge to defaults?","extra":{"use_mslearn":false}}'
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
